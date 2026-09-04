use anyhow::{Context, Result, anyhow};
use atrium_xrpc::{
    InputDataOrBytes,
    error::{ErrorResponseBody, XrpcErrorKind},
    http,
};
use regorus::{Value, value::Object};

use crate::{
    policy::{PolicyVm, PolicyVmOutput},
    xrpc::{XrpcEndpoint, XrpcError, XrpcOutput, XrpcRequest, XrpcResult},
};

/// Async host functions registered on every pipeline-layer policy VM.
pub const HOST_FNS: &[&str] = &["xrpc"];
/// Rego entrypoint evaluated to produce a request's result.
pub const ENTRYPOINT: &str = "data.arbiter.result";

/// Rego entrypoint evaluated to produce a scope policy's decision: a plain
/// boolean answering "is this request within the virtual scope"
pub const SCOPE_ENTRYPOINT: &str = "data.arbiter.allow";

/// Compile a Rego policy with the arbiter's host functions and entrypoint,
/// validating it before it is installed.
///
/// This runs the full [`PolicyVm`] compile path (including the async host
/// functions) so that malformed policies — bad Rego syntax, missing
/// entrypoint, or calls to the `xrpc` builtin with the wrong arity — are
/// caught here rather than at evaluation time. This is the right validator
/// for pipeline layers (see [`Layer`]); scope policies are validated with
/// [`ScopePolicy::new`], which compiles without host functions instead.
pub fn validate_policy(policy: &str) -> Result<()> {
    PolicyVm::new(policy, Value::new_object(), ENTRYPOINT, HOST_FNS)
        .map(|_| ())
}

/// The marker key used inside Rego values to refer to a binary payload stored
/// out-of-band in the machine's `buffers` list.
///
/// Rego cannot represent raw bytes, so wherever a byte payload would appear
/// (request body, response output, error body) the policy instead sees an
/// object of the form `{ "$__bytes__": <index> }`, where `<index>` refers to an
/// entry in [`ArbiterReqMachine::buffers`].
pub const BYTES_KEY: &str = "$__bytes__";

/// Per-request context injected into the Rego `input` of pipeline-layer
/// policies (a [`ScopePolicy`] sees only the request core, without these
/// fields).
///
/// These fields vary per request and have no other delivery channel (the
/// `PolicyVm`'s `data` is baked at compile time and `request_to_input`
/// otherwise only carries the XRPC method/params/body). The policy reads them
/// as `input.arbiterDid`, `input.pdsEndpoint`, `input.callerDid`, and
/// `input.xrpcEndpoint`.
#[derive(Debug, Clone, Default)]
pub struct RequestCtx {
    /// The DID of the stewarded account this arbiter is named after; the
    /// subject the request acts on behalf of.
    pub arbiter_did: String,
    /// The stewarded account's PDS endpoint URL (`#atproto_pds` resolved).
    pub pds_endpoint: String,
    /// The verified caller DID (from the serviceAuth token `sub`).
    pub caller_did: String,
    /// The destination `did#service` the policy should forward to.
    pub xrpc_endpoint: String,
}
/// The state of an arbiter for an individual ATProto account.
#[derive(Debug)]
pub struct Arbiter {
    /// The policy pipeline evaluated for every request.
    pub(crate) pipeline: Pipeline,
}

impl Arbiter {
    /// Create a new arbiter from the given policy pipeline.
    ///
    /// Layers are evaluated in order for each request (see [`Pipeline`] for
    /// the layer output convention). They must have been compiled with the
    /// arbiter's async host functions (see [`HOST_FNS`] and
    /// [`Layer::compile`]) so the request machine can interpret their `xrpc`
    /// suspensions.
    pub fn new(pipeline: Pipeline) -> Self {
        Self { pipeline }
    }

    /// Get a state machine that may be driven to respond to the provided XRPC
    /// request.
    pub fn handle_request(&self, req: XrpcRequest, ctx: RequestCtx) -> ArbiterReqMachine {
        ArbiterReqMachine::new(self.pipeline.clone(), req, ctx)
    }
}

/// One layer of an arbiter's policy pipeline: a compiled policy plus the
/// provenance of the record it was loaded from.
///
/// A layer is compiled with the arbiter's async host functions ([`HOST_FNS`])
/// and the [`ENTRYPOINT`] rule (`data.arbiter.result`), so it may suspend on
/// `xrpc` host calls; [`Layer::compile`] runs that compilation and validation.
/// The provenance (the `at://` URI of the policy record this layer was loaded
/// from, and the record CID/revision at load time) lets a host (the server,
/// simulator) reload exactly the layers whose underlying records change.
#[derive(Clone, Debug)]
pub struct Layer {
    /// The compiled policy evaluated for this layer.
    pub policy: PolicyVm,
    /// The `at://` URI of the policy record this layer was loaded from, e.g.
    /// `at://did:plc:abc/town.muni.arbiter.policy/my-policy`.
    pub uri: String,
    /// The record CID (revision) of the policy record at the time the layer
    /// was loaded, when known. `None` for layers loaded without a revision.
    pub cid: Option<String>,
}

impl Layer {
    /// Bundle an already-compiled policy with its provenance.
    pub fn new(policy: PolicyVm, uri: impl Into<String>, cid: Option<String>) -> Self {
        Self {
            policy,
            uri: uri.into(),
            cid,
        }
    }

    /// Compile a layer from Rego source and record its provenance.
    ///
    /// Runs the full [`PolicyVm`] compile path (with [`HOST_FNS`] and
    /// [`ENTRYPOINT`]), so malformed policies — bad Rego syntax, a missing
    /// entrypoint, or `xrpc` calls with the wrong arity — fail here rather
    /// than at evaluation time.
    pub fn compile(policy: &str, uri: impl Into<String>, cid: Option<String>) -> Result<Self> {
        let policy = PolicyVm::new(policy, Value::new_object(), ENTRYPOINT, HOST_FNS)?;
        Ok(Self::new(policy, uri, cid))
    }
}

/// An ordered pipeline of policy [`Layer`]s.
///
/// Layers are composed positionally, in the order given, and every layer is
/// started with the same request input (the shape the request machine builds:
/// `method`, `nsid`, `parameters`, `body`, `encoding`, plus the [`RequestCtx`]
/// fields `arbiterDid`, `pdsEndpoint`, `callerDid`, and `xrpcEndpoint`).
///
/// # Layer output convention
///
/// Each layer's `data.arbiter.result` output is interpreted as:
///
/// - `{ "handleBuiltin": true }` — **hand off**: the request is handed to the
///   arbiter's built-in handler; the machine ends with
///   [`ArbiterReqMachineStep::HandToBuiltin`] and later layers are not
///   evaluated. This marker is checked before the pass marker, so it wins
///   when both are present;
/// - `{ "pass": true }` — defer to the next layer;
/// - `{ "ok": true, "output" | "bytes": ... }` — **handle**: the layer's
///   output becomes the response and later layers are not evaluated;
/// - `{ "ok": false, "error": { status, ... } }` — **deny**: the layer's
///   error becomes the response and later layers are not evaluated.
///
/// The first layer that hands off, handles, or denies wins. When every layer
/// passes — or the pipeline is empty — the request is denied with a default
/// 403 (`error: "Denied"`) response. Any other layer output is malformed and
/// surfaces as a 500 `InternalError` response.
///
/// ```text
/// let mut pipeline = Pipeline::new();
/// pipeline.push(Layer::compile(src, at_uri, Some(record_cid))?);
/// let arbiter = Arbiter::new(pipeline);
/// ```
#[derive(Clone, Debug, Default)]
pub struct Pipeline {
    /// The layers in evaluation order.
    layers: Vec<Layer>,
}

impl Pipeline {
    /// Create an empty pipeline. Requests evaluated against an empty pipeline
    /// are denied by default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a pipeline from an already-ordered list of layers.
    pub fn from_layers(layers: Vec<Layer>) -> Self {
        Self { layers }
    }

    /// Append a layer to the end of the pipeline.
    pub fn push(&mut self, layer: Layer) {
        self.layers.push(layer);
    }

    /// Borrow the layers in evaluation order.
    pub fn layers(&self) -> &[Layer] {
        &self.layers
    }

    /// The number of layers in the pipeline.
    pub fn len(&self) -> usize {
        self.layers.len()
    }

    /// Whether the pipeline has no layers (every request is denied).
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }
}

/// A pure scope policy: an allow/deny predicate answering a single question —
/// *is this request within the virtual scope?*
///
/// Scope policies are compiled with **no host functions** and evaluated
/// synchronously: evaluation cannot suspend, issue remote requests, or
/// observe anything besides the request core, so a scope policy is a pure
/// function of the request.
///
/// The Rego source must define the [`SCOPE_ENTRYPOINT`] rule
/// (`data.arbiter.allow`) returning a boolean:
///
/// ```rego
/// package arbiter
///
/// default allow := false
///
/// allow if {
///     input.method == "GET"
///     startswith(input.nsid, "com.example.calendars")
/// }
/// ```
///
/// The policy's `input` is the request core `{ method, nsid, parameters,
/// body, encoding }` — the pipeline-layer input minus the [`RequestCtx`]
/// context fields, which scope policies never see. A `body` is the JSON
/// value, null, or a [`BYTES_KEY`] marker; scope policies have no host
/// functions, so a marker body can never be resolved to bytes.
///
/// [`ScopePolicy::evaluate`] returns `Ok(true)` only for a boolean `true`
/// result. A boolean `false`, an undefined rule, or any non-boolean value
/// denies the request; evaluation failures return `Err`, which fail-closed
/// callers treat as a deny.
///
/// The source is fully validated at construction time (see [`PolicyVm::new`]):
/// malformed Rego, a missing entrypoint, or any reference to a host function
/// fails compilation — never at evaluation time.
#[derive(Clone, Debug)]
pub struct ScopePolicy {
    vm: PolicyVm,
}

impl ScopePolicy {
    /// Compile and validate a scope policy from Rego source.
    ///
    /// Compiles with no host functions against the [`SCOPE_ENTRYPOINT`] rule.
    /// Fails on malformed Rego, a missing `data.arbiter.allow` entrypoint, or
    /// any use of host functions — scope policies are pure functions of the
    /// request core and have none.
    pub fn new(policy: &str) -> Result<Self> {
        let vm = PolicyVm::new(policy, Value::new_object(), SCOPE_ENTRYPOINT, &[])?;
        Ok(Self { vm })
    }

    /// Evaluate the scope policy synchronously against a request.
    ///
    /// Returns `Ok(true)` only when `data.arbiter.allow` evaluates to boolean
    /// `true`. A boolean `false`, an undefined rule, or any non-boolean result
    /// denies the request (`Ok(false)`). Returns `Err` when evaluation itself
    /// fails (a VM error, e.g. the execution time limit) — fail-closed callers
    /// should treat `Err` as a deny.
    pub fn evaluate(&self, req: &XrpcRequest) -> Result<bool> {
        // Scope policies cannot make host calls, so no buffer is ever
        // resolved here; the throwaway list only backs the shared request-core
        // conversion for byte-marker bodies.
        let mut buffers = Vec::new();
        let input = ArbiterReqMachine::request_core_to_input(&mut buffers, req)?.into_value();
        let mut vm = self.vm.clone();
        let PolicyVmOutput::Completed(value) = vm.start(input)? else {
            // Unreachable: with no host functions registered the VM has
            // nothing to suspend on.
            anyhow::bail!("scope policy suspended despite having no host functions");
        };
        Ok(matches!(value, Value::Bool(true)))
    }
}

/// A state machine for an individual arbiter request, that may be driven to
/// completion by the caller.
///
/// The machine is sans-io: it evaluates the arbiter's policy pipeline and,
/// whenever a layer triggers a request to a remote XRPC endpoint (via the
/// `xrpc` host function), it suspends and surfaces a
/// [`ArbiterReqMachineStep::RemoteXrpcRequest`] to the caller; the caller is
/// responsible for actually issuing the request and feeding the response back
/// in via [`ArbiterReqMachine::resume`]. When a layer hands the request to the
/// arbiter's built-in handler (`{ "handleBuiltin": true }`), the machine ends
/// with [`ArbiterReqMachineStep::HandToBuiltin`], leaving the built-in serving
/// to the caller.
pub struct ArbiterReqMachine {
    /// The XRPC request that we are responding to.
    req: XrpcRequest,
    /// The policy pipeline layers used to respond to the request.
    pipeline: Pipeline,
    /// The list of bytes buffers used by the machine.
    ///
    /// Binary payloads that Rego cannot represent are stashed here and
    /// referred to from policy values via the [`BYTES_KEY`] marker.
    buffers: Vec<Vec<u8>>,
    /// The Rego `input` value for the request, computed at [`Self::start`]
    /// and reused to start every pipeline layer (all layers evaluate the
    /// same input).
    input: Option<Value>,
    /// The current status of the machine.
    status: ArbiterReqMachineStatus,
    ctx: RequestCtx,
}

impl std::fmt::Debug for ArbiterReqMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArbiterReqMachine")
            .field("req_method", &self.req.method)
            .field("req_nsid", &self.req.nsid)
            .field(
                "buffers",
                &format_args!(
                    "{} buffer(s), {} byte(s) total",
                    self.buffers.len(),
                    self.buffers.iter().map(Vec::len).sum::<usize>()
                ),
            )
            .field("status", &self.status)
            .finish()
    }
}

/// The internal status of an arbiter request machine.
///
/// Between [`ArbiterReqMachine::start`] / [`ArbiterReqMachine::resume`] calls
/// the machine is either freshly initialized, waiting on a remote XRPC
/// response (with the active layer's policy VM stashed), or done. While
/// driving, the active layer's policy VM is held in the locals of the driving
/// loop.
enum ArbiterReqMachineStatus {
    /// Machine has just been initialized and has not yet been started.
    Init,
    /// A policy layer has triggered a remote XRPC call which we are waiting on
    /// the response to.
    ///
    /// `frame` is the policy VM that issued the remote request (suspended
    /// inside its host-function call) and `layer` is the index of that layer
    /// in the pipeline, needed to advance past it if it completes with a pass
    /// once the response arrives.
    ///
    /// `frame` is boxed because it is moved out of the enum on resume (via
    /// `std::mem::replace`), and `PolicyVm` is large enough that boxing avoids
    /// a large enum variant size penalty.
    WaitingOnRemoteXrpcResp {
        frame: Box<PolicyVm>,
        layer: usize,
    },
    /// The machine has produced its final result.
    Done,
}

impl std::fmt::Debug for ArbiterReqMachineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init => write!(f, "Init"),
            Self::WaitingOnRemoteXrpcResp { frame: _, layer } => f
                .debug_struct("WaitingOnRemoteXrpcResp")
                .field("frame", &"..")
                .field("layer", layer)
                .finish(),
            Self::Done => write!(f, "Done"),
        }
    }
}

/// The result of a step in the evaluation of the arbiter request machine.
pub enum ArbiterReqMachineStep {
    /// The policy evaluation is completed with an XRPC response.
    Completed(XrpcResult),
    /// The pipeline has handed the request to the arbiter's built-in handler
    /// (a layer completed with `{ "handleBuiltin": true }`): evaluation is
    /// terminal and the caller serves the request itself.
    ///
    /// The machine is generic and never decides whether the request's NSID
    /// actually has a built-in implementation. The caller (the server) maps
    /// this step onto its built-in handler registry and must surface an
    /// error when the NSID has no built-in.
    HandToBuiltin,
    /// The policy evaluation has triggered a request to a remote XRPC endpoint.
    /// The caller must execute the XRPC request and provide the response to the
    /// machine to continue.
    RemoteXrpcRequest {
        /// The endpoint to send the request to.
        endpoint: XrpcEndpoint,
        /// The request to send.
        request: XrpcRequest,
    },
}

impl std::fmt::Debug for ArbiterReqMachineStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Completed(result) => match result {
                Ok(out) => match out {
                    XrpcOutput::Data(json) => f
                        .debug_tuple("Completed")
                        .field(&format_args!("Ok(Data({json}))"))
                        .finish(),
                    XrpcOutput::Bytes(b) => f
                        .debug_tuple("Completed")
                        .field(&format_args!("Ok(Bytes({}b))", b.len()))
                        .finish(),
                },
                Err(err) => f
                    .debug_tuple("Completed")
                    .field(&format_args!(
                        "Err({} {})",
                        err.status,
                        err.error.as_ref().map_or("", |e| match e {
                            XrpcErrorKind::Undefined(erb) => erb.error.as_deref().unwrap_or(""),
                            XrpcErrorKind::Custom(_) => "Custom",
                        })
                    ))
                    .finish(),
            },
            Self::HandToBuiltin => write!(f, "HandToBuiltin"),
            Self::RemoteXrpcRequest { endpoint, request } => f
                .debug_struct("RemoteXrpcRequest")
                .field("endpoint", endpoint)
                .field("method", &request.method)
                .field("nsid", &request.nsid)
                .field("parameters", &request.parameters)
                .field(
                    "input",
                    &request.input.as_ref().map(|i| match i {
                        InputDataOrBytes::Data(_) => String::from("Data(..)"),
                        InputDataOrBytes::Bytes(b) => format!("Bytes({}b)", b.len()),
                    }),
                )
                .field("encoding", &request.encoding)
                .finish(),
        }
    }
}

/// The layer a machine transition evaluates: its pipeline index, the running
/// VM frame, and the output that frame just produced.
///
/// # Index invariant
///
/// `index` is only ever minted by [`ArbiterReqMachine::start_layer`] (so it is
/// always in-bounds for the machine's pipeline snapshot — `start_layer` uses
/// `get`, it cannot return `Some` out of bounds) or recycled from a
/// suspension, which stored a previously validated index. Every use funnels
/// back through `start_layer`, whose out-of-bounds case is the exhaustion
/// encoding (default deny) — never a panic or a wrong-layer path.
struct ActiveLayer {
    index: usize,
    frame: PolicyVm,
    output: PolicyVmOutput,
}

/// The transition handed to [`ArbiterReqMachine::drive_from`].
///
/// [`Transition::Exhausted`] is only producible on the start path — the
/// pipeline is empty or every layer passed. A resumed layer is by definition
/// still active, so [`ArbiterReqMachine::resume_inner`] can only produce
/// [`Transition::Active`]: the invalid combination is unrepresentable.
enum Transition {
    /// A layer produced an output: evaluate it (pass, handle, deny, or
    /// builtin handoff).
    Active(ActiveLayer),
    /// The pipeline had no layer to evaluate — it is empty, or every layer
    /// passed and the index ran past the end. This is a designed terminal
    /// state, not a failure: the fail-closed contract maps it to the default
    /// deny response (403-class), while genuine internal failures travel as
    /// `Err` and surface as 500 InternalServerError. Encoding exhaustion as
    /// a variant (rather than an error payload) keeps that distinction
    /// type-level: callers can never mistake an expected pass-chain
    /// completion for a broken machine.
    Exhausted,
}

impl ArbiterReqMachine {
    /// Create a new [`ArbiterReqMachine`].
    pub fn new(pipeline: Pipeline, req: XrpcRequest, ctx: RequestCtx) -> Self {
        Self {
            req,
            pipeline,
            buffers: Vec::new(),
            input: None,
            status: ArbiterReqMachineStatus::Init,
            ctx,
        }
    }

    /// Start evaluating the request against the first pipeline layer.
    ///
    /// Returns the first step of the evaluation: a completed result, a
    /// hand-off of the request to the arbiter's built-in handler
    /// ([`ArbiterReqMachineStep::HandToBuiltin`]), or a request to a remote
    /// XRPC endpoint that must be fulfilled before continuing via
    /// [`Self::resume`].
    ///
    /// # Panics
    ///
    /// Panics if called more than once on the same machine.
    pub fn start(&mut self) -> ArbiterReqMachineStep {
        if !matches!(self.status, ArbiterReqMachineStatus::Init) {
            panic!("ArbiterReqMachine::start called more than once");
        }
        let first = self.start_inner();
        self.drive_from(first)
    }

    /// Resume evaluation after a [`ArbiterReqMachineStep::RemoteXrpcRequest`],
    /// supplying the response to the in-flight remote XRPC request. Returns the
    /// next step of the evaluation.
    ///
    /// # Panics
    ///
    /// Panics if called when the machine is not waiting on a remote XRPC
    /// response (i.e. without a preceding [`ArbiterReqMachineStep::RemoteXrpcRequest`]).
    pub fn resume(&mut self, response: XrpcResult) -> ArbiterReqMachineStep {
        let first = self.resume_inner(response);
        self.drive_from(first)
    }

    /// Produce the first transition for [`Self::start`]: pipeline layer 0,
    /// started with the request input, or [`Transition::Exhausted`] when the
    /// pipeline is empty (converted to the default deny by
    /// [`Self::drive_from`]).
    ///
    /// Errors here (e.g. input conversion or policy start failures) are
    /// converted to an error XRPC response by [`Self::drive_from`].
    fn start_inner(&mut self) -> Result<Transition> {
        let input = Self::request_to_input(&mut self.buffers, &self.req, &self.ctx)?;
        self.input = Some(input);
        Ok(match self.start_layer(0)? {
            Some(active) => Transition::Active(active),
            None => Transition::Exhausted,
        })
    }

    /// Produce the next transition for [`Self::resume`]: the suspended
    /// layer's VM resumed with the remote response value. Always
    /// [`Transition::Active`] — a resumed layer is by definition still active.
    ///
    /// Panics on host-contract violations (resuming when not waiting). Other
    /// errors are converted to an error XRPC response by [`Self::drive_from`].
    fn resume_inner(&mut self, response: XrpcResult) -> Result<Transition> {
        let (mut frame, index) = match std::mem::replace(
            &mut self.status,
            ArbiterReqMachineStatus::Done,
        ) {
            ArbiterReqMachineStatus::WaitingOnRemoteXrpcResp { frame, layer } => {
                (*frame, layer)
            }
            other => {
                self.status = other;
                panic!(
                    "ArbiterReqMachine::resume called when not waiting on a remote XRPC response"
                );
            }
        };
        let value = Self::xrpc_result_to_value(&mut self.buffers, &response)?;
        let output = frame.resume(value)?;
        Ok(Transition::Active(ActiveLayer { index, frame, output }))
    }

    /// Take the result of [`Self::start_inner`] / [`Self::resume_inner`] and
    /// drive the machine to its next step, converting any internal error into a
    /// terminal error XRPC response.
    ///
    /// Host-contract violations panic (handled by the inner functions); policy
    /// and runtime errors — VM execution failures, malformed policy output,
    /// invalid host-call arguments — become
    /// [`ArbiterReqMachineStep::Completed`] carrying an `Err` [`XrpcResult`]
    /// with a 500 status. This keeps the caller's driving loop simple: it only
    /// ever matches on [`ArbiterReqMachineStep`], never on `Result::Err`.
    fn drive_from(&mut self, transition: Result<Transition>) -> ArbiterReqMachineStep {
        let active = match transition {
            Ok(Transition::Active(active)) => active,
            // The pipeline is empty: there is no layer to start, so the
            // request is denied by default.
            Ok(Transition::Exhausted) => {
                self.status = ArbiterReqMachineStatus::Done;
                return ArbiterReqMachineStep::Completed(Err(Self::default_deny()));
            }
            Err(e) => {
                self.status = ArbiterReqMachineStatus::Done;
                return ArbiterReqMachineStep::Completed(Err(Self::internal_error(e)));
            }
        };
        match self.drive_loop(active) {
            Ok(step) => step,
            Err(e) => {
                self.status = ArbiterReqMachineStatus::Done;
                ArbiterReqMachineStep::Completed(Err(Self::internal_error(e)))
            }
        }
    }

    /// Drive the currently active policy layer to its next suspension or
    /// completion, advancing through the pipeline when a layer passes.
    ///
    /// `active` carries the active layer's index, its policy VM, and an
    /// [`PolicyVmOutput`] freshly produced by starting or resuming it. The
    /// function loops, driving the frame forward, until it either:
    /// - completes with `{ "handleBuiltin": true }` → the request is handed to
    ///   the arbiter's built-in handler: emits
    ///   [`ArbiterReqMachineStep::HandToBuiltin`], or
    /// - completes with a handle/deny output (the layer decided) → emits
    ///   [`ArbiterReqMachineStep::Completed`], or
    /// - completes with `{ "pass": true }` → the next layer is started and
    ///   driven in turn; past the end of the pipeline the request is denied
    ///   with the default deny response, or
    /// - triggers an `xrpc` host call → suspends, stashes the layer's VM into
    ///   [`ArbiterReqMachineStatus::WaitingOnRemoteXrpcResp`], and emits
    ///   [`ArbiterReqMachineStep::RemoteXrpcRequest`].
    ///
    /// The built-in handoff is checked before the pass marker, so a layer
    /// emitting both `{ "handleBuiltin": true }` and `{ "pass": true }` hands
    /// off rather than deferring.
    ///
    /// An unknown host function resumes the issuing policy with an error
    /// envelope so the policy can decide how to handle it. Any other error
    /// (VM failure, bad conversion, invalid host-call arguments) propagates
    /// via `?` and is turned into an error XRPC response by
    /// [`Self::drive_from`].
    fn drive_loop(&mut self, active: ActiveLayer) -> Result<ArbiterReqMachineStep> {
        let ActiveLayer {
            mut index,
            mut frame,
            mut output,
        } = active;
        loop {
            match output {
                PolicyVmOutput::Completed(value) => {
                    if is_handle_builtin_output(&value) {
                        // The layer handed the request to the arbiter's
                        // built-in handler: evaluation is terminal. The
                        // machine is generic — whether the request's NSID
                        // actually has a built-in implementation is decided
                        // by the caller (the server), which maps this step
                        // onto its built-in handler registry.
                        self.status = ArbiterReqMachineStatus::Done;
                        return Ok(ArbiterReqMachineStep::HandToBuiltin);
                    }
                    if is_pass_output(&value) {
                        // The layer passed: defer to the next layer in the
                        // pipeline.
                        index += 1;
                        match self.start_layer(index)? {
                            Some(next) => {
                                index = next.index;
                                frame = next.frame;
                                output = next.output;
                                continue;
                            }
                            // Fell off the end of the pipeline: the request is
                            // denied by default.
                            None => {
                                self.status = ArbiterReqMachineStatus::Done;
                                return Ok(ArbiterReqMachineStep::Completed(Err(
                                    Self::default_deny(),
                                )));
                            }
                        }
                    }
                    // The layer handled (ok=true) or denied (ok=false): its
                    // output is the final result.
                    let result = Self::value_to_xrpc_result(&self.buffers, &value)?;
                    self.status = ArbiterReqMachineStatus::Done;
                    return Ok(ArbiterReqMachineStep::Completed(result));
                }
                PolicyVmOutput::HostCall { fn_name, arg } => {
                    match fn_name.as_str() {
                        "xrpc" => {
                            let endpoint = Self::field_string(&arg, "did")?;
                            let request = Self::arg_to_xrpc_request(&self.buffers, &arg)?;
                            self.status = ArbiterReqMachineStatus::WaitingOnRemoteXrpcResp {
                                frame: Box::new(frame),
                                layer: index,
                            };
                            return Ok(ArbiterReqMachineStep::RemoteXrpcRequest {
                                endpoint,
                                request,
                            });
                        }
                        other => {
                            // Unknown host function: resume the issuing policy
                            // with an error envelope so it can decide how to
                            // handle the failure.
                            let err = Self::error_envelope(
                                http::StatusCode::BAD_REQUEST.as_u16(),
                                "unknown_host_function",
                                Some(&format!("no host function `{other}`")),
                            );
                            output = frame.resume(err)?;
                        }
                    }
                }
            }
        }
    }

    /// Start the pipeline layer at `layer_idx` in a fresh execution context,
    /// with the request input. Returns `Ok(None)` when `layer_idx` is past the
    /// end of the pipeline.
    fn start_layer(&self, layer_idx: usize) -> Result<Option<ActiveLayer>> {
        let Some(layer) = self.pipeline.layers.get(layer_idx) else {
            return Ok(None);
        };
        let input = self
            .input
            .clone()
            .expect("input is computed before the first layer is started");
        let mut frame = layer.policy.clone();
        let output = frame.start(input)?;
        Ok(Some(ActiveLayer {
            index: layer_idx,
            frame,
            output,
        }))
    }

    /// Convert an internal error into a 500 [`XrpcError`] so it can be surfaced
    /// as a terminal error XRPC response.
    pub(crate) fn internal_error(e: anyhow::Error) -> XrpcError {
        XrpcError {
            status: http::StatusCode::INTERNAL_SERVER_ERROR,
            error: Some(XrpcErrorKind::Undefined(ErrorResponseBody {
                error: Some("InternalError".to_string()),
                message: Some(format!("{e:#}")),
            })),
        }
    }

    /// The default deny response for a request no pipeline layer handled:
    /// every layer passed, or the pipeline is empty.
    fn default_deny() -> XrpcError {
        XrpcError {
            status: http::StatusCode::FORBIDDEN,
            error: Some(XrpcErrorKind::Undefined(ErrorResponseBody {
                error: Some("Denied".to_string()),
                message: Some("request denied by the arbiter policy pipeline".to_string()),
            })),
        }
    }

    // ----- value <-> XRPC conversions --------------------------------------

    /// Build the request-core portion of the Rego `input` value:
    /// `{ method, nsid, parameters, body, encoding }`, where `body` is either
    /// the JSON value or a [`BYTES_KEY`] marker (with the bytes stashed into
    /// `buffers`).
    ///
    /// This is the entire input a [`ScopePolicy`] sees; pipeline layers
    /// receive these fields plus the [`RequestCtx`] context (see
    /// [`Self::request_to_input`]).
    fn request_core_to_input(buffers: &mut Vec<Vec<u8>>, req: &XrpcRequest) -> Result<Object> {
        let mut input = Object::new();
        input.insert(Value::from("method"), Value::from(req.method.as_str()));
        input.insert(Value::from("nsid"), Value::from(req.nsid.as_str()));
        let parameters = match &req.parameters {
            Some(p) => Value::from(p.clone()),
            None => Value::Null,
        };
        input.insert(Value::from("parameters"), parameters);
        let body = match &req.input {
            None => Value::Null,
            Some(InputDataOrBytes::Data(json)) => Value::from(json.clone()),
            Some(InputDataOrBytes::Bytes(bytes)) => stash_bytes(buffers, bytes),
        };
        input.insert(Value::from("body"), body);
        input.insert(
            Value::from("encoding"),
            req.encoding.clone().map(Value::from).unwrap_or(Value::Null),
        );
        Ok(input)
    }

    /// Convert an incoming [`XrpcRequest`] into the full Rego `input` value
    /// that every pipeline layer receives: the request core (see
    /// [`Self::request_core_to_input`]) plus the [`RequestCtx`] context
    /// fields.
    fn request_to_input(
        buffers: &mut Vec<Vec<u8>>,
        req: &XrpcRequest,
        ctx: &RequestCtx,
    ) -> Result<Value> {
        let mut input = Self::request_core_to_input(buffers, req)?;
        // Per-request context (see `RequestCtx`).
        input.insert(
            Value::from("arbiterDid"),
            Value::from(ctx.arbiter_did.as_str()),
        );
        input.insert(
            Value::from("pdsEndpoint"),
            Value::from(ctx.pds_endpoint.as_str()),
        );
        input.insert(
            Value::from("callerDid"),
            Value::from(ctx.caller_did.as_str()),
        );
        input.insert(
            Value::from("xrpcEndpoint"),
            Value::from(ctx.xrpc_endpoint.as_str()),
        );
        Ok(input.into_value())
    }

    /// Convert an `xrpc` host-call argument object into an
    /// [`XrpcRequest`] suitable for issuing to a remote endpoint.
    ///
    /// The argument has the shape `{ did, method, nsid, parameters, body }`. A
    /// `body` that is a [`BYTES_KEY`] marker is resolved
    /// against `buffers`; otherwise the body is treated as JSON.
    fn arg_to_xrpc_request(buffers: &[Vec<u8>], arg: &Value) -> Result<XrpcRequest> {
        let method_str = Self::field_string(arg, "method")?;
        let method = match method_str.as_str() {
            "GET" => http::Method::GET,
            "POST" => http::Method::POST,
            "PUT" => http::Method::PUT,
            "DELETE" => http::Method::DELETE,
            "PATCH" => http::Method::PATCH,
            other => http::Method::from_bytes(other.as_bytes()).map_err(anyhow::Error::msg)?,
        };
        let nsid = Self::field_string(arg, "nsid")?;
        let parameters = match field(arg, "parameters") {
            None | Some(Value::Null) | Some(Value::Undefined) => None,
            Some(v) => Some(serde_json::to_value(v)?),
        };
        let input = match field(arg, "body") {
            None => None,
            Some(Value::Null) | Some(Value::Undefined) => None,
            Some(v) if is_bytes_marker(v) => {
                let idx = bytes_index(v)?;
                Some(InputDataOrBytes::Bytes(buffer(buffers, idx)?.to_vec()))
            }
            Some(v) => Some(InputDataOrBytes::Data(serde_json::to_value(v)?)),
        };
        let encoding = match field(arg, "encoding") {
            None | Some(Value::Null) | Some(Value::Undefined) => None,
            Some(v) => Some(
                v.as_string()
                    .context("host call arg field `encoding` must be a string")?
                    .to_string(),
            ),
        };
        Ok(XrpcRequest {
            method,
            nsid,
            parameters,
            input,
            encoding,
        })
    }

    /// Convert a pipeline layer's handle/deny output value into an
    /// [`XrpcResult`] (the response the layer decided on, per the convention
    /// documented on [`Pipeline`]).
    ///
    /// The value is the ok/err envelope:
    /// - `{ "ok": true, "output": <json> }` → `Ok(Data(json))`
    /// - `{ "ok": true, "bytes": {"$__bytes__": n} }` → `Ok(Bytes(..))`
    /// - `{ "ok": false, "error": { status, error?, message?, body? } }` →
    ///   `Err(XrpcError { .. })`
    ///
    /// On an `ok` envelope a `bytes` field takes precedence over `output`; if
    /// neither is present, `output` defaults to JSON null (i.e. `Ok(Data(null))`).
    fn value_to_xrpc_result(buffers: &[Vec<u8>], value: &Value) -> Result<XrpcResult> {
        value
            .as_object()
            .context("policy result must be an object envelope")?;
        let ok = field_bool(value, "ok")?;
        if ok {
            if let Some(bytes_marker) = field(value, "bytes") {
                let idx = bytes_index(bytes_marker)?;
                let bytes = buffer(buffers, idx)?.to_vec();
                return Ok(Ok(XrpcOutput::Bytes(bytes)));
            }
            let output = field(value, "output").cloned().unwrap_or(Value::Null);
            let json = serde_json::to_value(&output)?;
            return Ok(Ok(XrpcOutput::Data(json)));
        }
        let err = field(value, "error").context("policy error result missing `error`")?;
        let err_obj = err.as_object().context("`error` must be an object")?;
        let status = field_u16(err, "status")?;
        let status = http::StatusCode::from_u16(status).map_err(anyhow::Error::msg)?;
        let kind = match err_obj.get(&Value::from("body")) {
            Some(body) => {
                let json = serde_json::to_value(body)?;
                XrpcErrorKind::Custom(json)
            }
            None => {
                let erb = ErrorResponseBody {
                    error: err_obj
                        .get(&Value::from("error"))
                        .and_then(|v| v.as_string().ok())
                        .map(|s| s.to_string()),
                    message: err_obj
                        .get(&Value::from("message"))
                        .and_then(|v| v.as_string().ok())
                        .map(|s| s.to_string()),
                };
                XrpcErrorKind::Undefined(erb)
            }
        };
        Ok(Err(XrpcError {
            status,
            error: Some(kind),
        }))
    }

    /// Convert an [`XrpcResult`] into the ok/err envelope value that is passed
    /// back to a policy as the result of an `xrpc` host call.
    ///
    /// A `Bytes` output is stashed into `buffers` and represented via a
    /// [`BYTES_KEY`] marker. Error bodies are JSON-only, matching atrium's
    /// `XrpcError` shape.
    fn xrpc_result_to_value(buffers: &mut Vec<Vec<u8>>, result: &XrpcResult) -> Result<Value> {
        let mut obj = Object::new();
        match result {
            Ok(out) => {
                obj.insert(Value::from("ok"), Value::from(true));
                match out {
                    XrpcOutput::Data(json) => {
                        obj.insert(Value::from("output"), Value::from(json.clone()));
                    }
                    XrpcOutput::Bytes(bytes) => {
                        obj.insert(Value::from("bytes"), stash_bytes(buffers, bytes));
                    }
                }
            }
            Err(err) => {
                obj.insert(Value::from("ok"), Value::from(false));
                let mut eobj = Object::new();
                eobj.insert(
                    Value::from("status"),
                    Value::from(err.status.as_u16() as u64),
                );
                match &err.error {
                    Some(XrpcErrorKind::Custom(json)) => {
                        eobj.insert(Value::from("body"), Value::from(json.clone()));
                    }
                    Some(XrpcErrorKind::Undefined(erb)) => {
                        if let Some(s) = &erb.error {
                            eobj.insert(Value::from("error"), Value::from(s.clone()));
                        }
                        if let Some(s) = &erb.message {
                            eobj.insert(Value::from("message"), Value::from(s.clone()));
                        }
                    }
                    None => {}
                }
                obj.insert(Value::from("error"), eobj.into_value());
            }
        }
        Ok(obj.into_value())
    }

    /// Build an ok/err error envelope value, used to resume a policy that
    /// called an unknown host function.
    fn error_envelope(status: u16, error: &str, message: Option<&str>) -> Value {
        let mut eobj = Object::new();
        eobj.insert(Value::from("status"), Value::from(status as u64));
        eobj.insert(Value::from("error"), Value::from(error));
        if let Some(m) = message {
            eobj.insert(Value::from("message"), Value::from(m));
        }
        let mut obj = Object::new();
        obj.insert(Value::from("ok"), Value::from(false));
        obj.insert(Value::from("error"), eobj.into_value());
        obj.into_value()
    }

    /// Read a string field from a host-call argument object.
    fn field_string(arg: &Value, key: &str) -> Result<String> {
        let obj = arg.as_object().context("host call arg must be an object")?;
        let v = obj
            .get(&Value::from(key))
            .with_context(|| format!("host call arg missing string field `{key}`"))?;
        let s = v
            .as_string()
            .with_context(|| format!("host call arg field `{key}` must be a string"))?;
        Ok(s.to_string())
    }
}

// ----- bytes marker + field accessors --------------------------------------

/// Stash `bytes` into `buffers` and return a [`BYTES_KEY`] marker value
/// referring to the new buffer index.
fn stash_bytes(buffers: &mut Vec<Vec<u8>>, bytes: &[u8]) -> Value {
    let idx = buffers.len();
    buffers.push(bytes.to_vec());
    bytes_marker(idx)
}

/// Build a `{ "$__bytes__": idx }` marker value.
fn bytes_marker(idx: usize) -> Value {
    let mut o = Object::new();
    o.insert(Value::from(BYTES_KEY), Value::from(idx as u64));
    o.into_value()
}

/// Whether `value` is a [`BYTES_KEY`] marker object.
fn is_bytes_marker(value: &Value) -> bool {
    value
        .as_object()
        .ok()
        .and_then(|o| o.get(&Value::from(BYTES_KEY)))
        .is_some_and(|v| v.as_u64().is_ok())
}

/// Extract the buffer index from a [`BYTES_KEY`] marker object.
fn bytes_index(value: &Value) -> Result<usize> {
    let obj = value
        .as_object()
        .context("expected a `$__bytes__` marker object")?;
    let idx = obj
        .get(&Value::from(BYTES_KEY))
        .context("missing `$__bytes__` field")?
        .as_u64()
        .context("`$__bytes__` must be a non-negative integer")?;
    Ok(idx as usize)
}

/// Borrow the buffer at `idx`.
fn buffer(buffers: &[Vec<u8>], idx: usize) -> Result<&[u8]> {
    buffers
        .get(idx)
        .map(Vec::as_slice)
        .with_context(|| format!("invalid `$__bytes__` buffer index {idx}"))
}

/// Get the value of a field of an object value, or `None` if absent.
fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_object()
        .ok()
        .and_then(|o| o.get(&Value::from(key)))
}

/// Read a required boolean field from an object value.
fn field_bool(value: &Value, key: &str) -> Result<bool> {
    let v = field(value, key).with_context(|| format!("missing boolean field `{key}`"))?;
    v.as_bool()
        .map(|b| *b)
        .with_context(|| format!("field `{key}` must be a boolean"))
}

/// Whether a layer's output value is the pass marker, `{ "pass": true }`,
/// which defers the decision to the next pipeline layer.
fn is_pass_output(value: &Value) -> bool {
    matches!(field(value, "pass"), Some(v) if matches!(v.as_bool(), Ok(&true)))
}

/// Whether a layer's output value is the built-in-handler handoff marker,
/// `{ "handleBuiltin": true }`, which ends evaluation and hands the request
/// to the arbiter's built-in handler.
fn is_handle_builtin_output(value: &Value) -> bool {
    matches!(field(value, "handleBuiltin"), Some(v) if matches!(v.as_bool(), Ok(&true)))
}

/// Read a required `u16` field from an object value.
fn field_u16(value: &Value, key: &str) -> Result<u16> {
    let obj = value
        .as_object()
        .with_context(|| format!("expected object to read field `{key}`"))?;
    let v = obj
        .get(&Value::from(key))
        .with_context(|| format!("missing numeric field `{key}`"))?;
    let n = v
        .as_u64()
        .with_context(|| format!("field `{key}` must be a non-negative integer"))?;
    u16::try_from(n).map_err(|_| anyhow!("field `{key}` ({n}) does not fit in a u16 status code"))
}
