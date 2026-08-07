use std::collections::HashMap;

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

/// Async host functions registered on every arbiter policy VM (mirrors
/// `arbiter-server::policy::HOST_FNS`).
pub const HOST_FNS: &[&str] = &["xrpc", "policy"];
/// Rego entrypoint evaluated to produce a request's result (mirrors
/// `arbiter-server::policy::ENTRYPOINT`).
pub const ENTRYPOINT: &str = "data.arbiter.result";

/// Compile a Rego policy with the arbiter's host functions and entrypoint,
/// validating it before it is installed.
///
/// This runs the full [`PolicyVm`] compile path (including the async host
/// functions) so that malformed policies — bad Rego syntax, missing
/// entrypoint, or calls to the `xrpc`/`policy` builtins with the wrong
/// arity — are caught here rather than at evaluation time.
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
/// The maximum depth of nested `policy` host-function calls (sub-policy
/// invocations) permitted while evaluating a single request. Bounds the
/// `callers` stack so a recursive or cyclic policy cannot grow it without
/// limit.
const MAX_POLICY_DEPTH: usize = 16;

/// Per-request context injected into the Rego policy's `input` value.
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
    /// The policies for this arbiter.
    pub(crate) policies: Policies,
}

impl Arbiter {
    /// Create a new arbiter from the given root and sub-policies.
    ///
    /// The policies must have been compiled with the `xrpc` and `policy`
    /// builtins registered as async host functions (see
    /// [`PolicyVm::new`]); the request machine interprets those host calls.
    pub fn new(policies: Policies) -> Self {
        Self { policies }
    }

    /// Get a state machine that may be driven to respond to the provided XRPC
    /// request.
    pub fn handle_request(&self, req: XrpcRequest, ctx: RequestCtx) -> ArbiterReqMachine {
        ArbiterReqMachine::new(self.policies.clone(), req, ctx)
    }
}

/// A root policy and optional sub-policies.
#[derive(Clone, Debug)]
pub struct Policies {
    /// The root policy is the first policy and is run for every single request.
    ///
    /// It may _optionally_ offload decisions to other sub-policies as a part
    /// of its execution.
    root_policy: PolicyVm,
    /// The set of installed sub-policies. Sub-policies are allowed to send
    /// requests to other sub-policies if they wish.
    sub_policies: HashMap<String, PolicyVm>,
}

impl Policies {
    /// Create a new set of policies from a root policy and a map of named
    /// sub-policies.
    pub fn new(root_policy: PolicyVm, sub_policies: HashMap<String, PolicyVm>) -> Self {
        Self {
            root_policy,
            sub_policies,
        }
    }

    /// Borrow the root policy.
    fn root(&self) -> &PolicyVm {
        &self.root_policy
    }

    /// Borrow a named sub-policy.
    fn sub(&self, name: &str) -> Option<&PolicyVm> {
        self.sub_policies.get(name)
    }
}

/// A state machine for an individual arbiter request, that may be driven to
/// completion by the caller.
///
/// The machine is sans-io: it runs the installed Rego policies and, whenever a
/// policy triggers a request to a remote XRPC endpoint (via the `xrpc` host
/// function), it suspends and surfaces a
/// [`ArbiterReqMachineStep::RemoteXrpcRequest`] to the caller. The caller is
/// responsible for actually issuing the request and feeding the response back
/// in via [`ArbiterReqMachine::resume`].
pub struct ArbiterReqMachine {
    /// The XRPC request that we are responding to.
    req: XrpcRequest,
    /// The policies to be used to respond to the request.
    policies: Policies,
    /// The list of bytes buffers used by the machine.
    ///
    /// Binary payloads that Rego cannot represent are stashed here and
    /// referred to from policy values via the [`BYTES_KEY`] marker.
    buffers: Vec<Vec<u8>>,
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
/// response (with the entire in-flight policy stack stashed), or done. While
/// driving, the active policy stack is held in the locals of the driving loop.
enum ArbiterReqMachineStatus {
    /// Machine has just been initialized and has not yet been started.
    Init,
    /// A policy has triggered a remote XRPC call which we are waiting on the
    /// response to.
    ///
    /// `frame` is the policy VM that issued the remote request (suspended
    /// inside its host-function call), and `callers` is the stack of policy VMs
    /// waiting for `frame` (a sub-policy) to complete.
    ///
    /// `frame` is boxed because it is moved out of the enum on resume (via
    /// `std::mem::replace`), and `PolicyVm` is large enough that boxing avoids
    /// a large enum variant size penalty.
    WaitingOnRemoteXrpcResp {
        frame: Box<PolicyVm>,
        callers: Vec<PolicyVm>,
    },
    /// The machine has produced its final result.
    Done,
}

impl std::fmt::Debug for ArbiterReqMachineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init => write!(f, "Init"),
            Self::WaitingOnRemoteXrpcResp { frame: _, callers } => f
                .debug_struct("WaitingOnRemoteXrpcResp")
                .field("frame", &"..")
                .field("callers", &format_args!("{} frames", callers.len()))
                .finish(),
            Self::Done => write!(f, "Done"),
        }
    }
}

/// The result of a step in the evaluation of the arbiter request machine.
pub enum ArbiterReqMachineStep {
    /// The policy evaluation is completed with an XRPC response.
    Completed(XrpcResult),
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

impl ArbiterReqMachine {
    /// Create a new [`ArbiterReqMachine]
    pub fn new(policies: Policies, req: XrpcRequest, ctx: RequestCtx) -> Self {
        Self {
            req,
            policies,
            buffers: Vec::new(),
            status: ArbiterReqMachineStatus::Init,
            ctx,
        }
    }

    /// Start evaluating the request against the root policy.
    ///
    /// Returns the first step of the evaluation: either a completed result or a
    /// request to a remote XRPC endpoint that must be fulfilled before
    /// continuing via [`Self::resume`].
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

    /// Produce the first `(frame, callers, output)` triple for [`Self::start`].
    ///
    /// Errors here (e.g. policy compilation/input conversion failures) are
    /// converted to an error XRPC response by [`Self::drive_from`].
    fn start_inner(&mut self) -> Result<(PolicyVm, Vec<PolicyVm>, PolicyVmOutput)> {
        let input = Self::request_to_input(&mut self.buffers, &self.req, &self.ctx)?;
        let mut root = self.policies.root().clone();
        let output = root.start(input)?;
        Ok((root, Vec::new(), output))
    }

    /// Produce the next `(frame, callers, output)` triple for [`Self::resume`].
    ///
    /// Panics on host-contract violations (resuming when not waiting). Other
    /// errors are converted to an error XRPC response by [`Self::drive_from`].
    fn resume_inner(
        &mut self,
        response: XrpcResult,
    ) -> Result<(PolicyVm, Vec<PolicyVm>, PolicyVmOutput)> {
        let (mut frame, callers) = match std::mem::replace(
            &mut self.status,
            ArbiterReqMachineStatus::Done,
        ) {
            ArbiterReqMachineStatus::WaitingOnRemoteXrpcResp { frame, callers } => {
                (*frame, callers)
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
        Ok((frame, callers, output))
    }

    /// Take the result of [`Self::start_inner`] / [`Self::resume_inner`] and
    /// drive the machine to its next step, converting any internal error into a
    /// terminal error XRPC response.
    ///
    /// Host-contract violations panic (handled by the inner functions); policy
    /// and runtime errors — VM execution failures, malformed policy output,
    /// missing sub-policies, invalid host-call arguments — become
    /// [`ArbiterReqMachineStep::Completed`] carrying an `Err` [`XrpcResult`]
    /// with a 500 status. This keeps the caller's driving loop simple: it only
    /// ever matches on [`ArbiterReqMachineStep`], never on `Result::Err`.
    fn drive_from(
        &mut self,
        first: Result<(PolicyVm, Vec<PolicyVm>, PolicyVmOutput)>,
    ) -> ArbiterReqMachineStep {
        let (frame, callers, output) = match first {
            Ok(triple) => triple,
            Err(e) => {
                self.status = ArbiterReqMachineStatus::Done;
                return ArbiterReqMachineStep::Completed(Err(Self::internal_error(e)));
            }
        };
        match self.drive_loop(frame, callers, output) {
            Ok(step) => step,
            Err(e) => {
                self.status = ArbiterReqMachineStatus::Done;
                ArbiterReqMachineStep::Completed(Err(Self::internal_error(e)))
            }
        }
    }

    /// Drive the currently active policy frame to its next suspension or
    /// completion, handling host-function calls recursively.
    ///
    /// `frame` is the active policy (with an [`PolicyVmOutput`] freshly
    /// produced by starting or resuming it) and `callers` is the stack of
    /// policy VMs waiting for `frame` (a sub-policy) to complete. The function
    /// loops, driving `frame` forward, until it either:
    ///
    /// - completes with no callers left (the root policy finished) → emits
    ///   [`ArbiterReqMachineStep::Completed`], or
    /// - triggers an `xrpc` host call → suspends, stashes the stack into
    ///   [`ArbiterReqMachineStatus::WaitingOnRemoteXrpcResp`], and emits
    ///   [`ArbiterReqMachineStep::RemoteXrpcRequest`].
    ///
    /// A `policy` host call is handled inline: the caller frame is pushed onto
    /// `callers` and the named sub-policy is started and driven in turn. An
    /// unknown host function resumes the issuing policy with an error envelope
    /// so the policy can decide how to handle it. Any other error (VM failure,
    /// bad conversion, missing sub-policy) propagates via `?` and is turned
    /// into an error XRPC response by [`Self::drive_from`].
    /// A `policy` host call that would exceed [`MAX_POLICY_DEPTH`] aborts with a
    /// terminal error (surfaced as a 500 XRPC response) rather than resuming the
    /// policy, so a runaway recursive policy cannot loop forever.
    fn drive_loop(
        &mut self,
        mut frame: PolicyVm,
        mut callers: Vec<PolicyVm>,
        mut output: PolicyVmOutput,
    ) -> Result<ArbiterReqMachineStep> {
        loop {
            match output {
                PolicyVmOutput::Completed(value) => {
                    if let Some(mut caller) = callers.pop() {
                        // A sub-policy finished; resume its caller with the
                        // envelope value the sub-policy produced.
                        output = caller.resume(value)?;
                        frame = caller;
                        continue;
                    }
                    // The root policy finished: this is the final result.
                    let result = Self::value_to_xrpc_result(&self.buffers, &value)?;
                    self.status = ArbiterReqMachineStatus::Done;
                    return Ok(ArbiterReqMachineStep::Completed(result));
                }
                PolicyVmOutput::HostCall { fn_name, arg } => {
                    match fn_name.as_str() {
                        "policy" => {
                            if callers.len() >= MAX_POLICY_DEPTH {
                                anyhow::bail!(
                                    "policy call depth limit ({MAX_POLICY_DEPTH}) exceeded"
                                );
                            }
                            let name = Self::field_string(&arg, "name")?;
                            let input = Self::arg_to_policy_input(&arg)?;
                            let mut sub = self
                                .policies
                                .sub(&name)
                                .with_context(|| format!("no sub-policy named `{name}`"))?
                                .clone();
                            let sub_output = sub.start(input)?;
                            callers.push(frame);
                            frame = sub;
                            output = sub_output;
                        }
                        "xrpc" => {
                            let endpoint = Self::field_string(&arg, "did")?;
                            let request = Self::arg_to_xrpc_request(&self.buffers, &arg)?;
                            self.status = ArbiterReqMachineStatus::WaitingOnRemoteXrpcResp {
                                frame: Box::new(frame),
                                callers,
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

    /// Convert an internal error into a 500 [`XrpcError`] so it can be surfaced
    /// as a terminal error XRPC response.
    fn internal_error(e: anyhow::Error) -> XrpcError {
        XrpcError {
            status: http::StatusCode::INTERNAL_SERVER_ERROR,
            error: Some(XrpcErrorKind::Undefined(ErrorResponseBody {
                error: Some("InternalError".to_string()),
                message: Some(format!("{e:#}")),
            })),
        }
    }

    // ----- value <-> XRPC conversions --------------------------------------

    /// Convert an incoming [`XrpcRequest`] into the Rego `input` value that the
    /// root policy (and any sub-policy) receives.
    ///
    /// The input has the shape `{ method, nsid, parameters, body }`, where
    /// `body` is either the JSON value or a [`BYTES_KEY`] marker (with the
    /// bytes stashed into `buffers`).
    fn request_to_input(
        buffers: &mut Vec<Vec<u8>>,
        req: &XrpcRequest,
        ctx: &RequestCtx,
    ) -> Result<Value> {
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

    /// Convert a `policy` host-call argument object into the `input` value for
    /// the named sub-policy.
    ///
    /// The sub-policy receives the same `{ method, nsid, parameters, body,
    /// encoding }` shape as the root policy. A [`BYTES_KEY`] marker in `body`
    /// is passed through unchanged: the buffer index stays valid because
    /// `buffers` is shared across the whole machine. `encoding` defaults to
    /// null if the host-call argument omits it.
    fn arg_to_policy_input(arg: &Value) -> Result<Value> {
        let obj = arg
            .as_object()
            .context("policy host call arg must be an object")?;
        let mut input = Object::new();
        for key in ["method", "nsid", "parameters", "body", "encoding"] {
            let v = obj.get(&Value::from(key)).cloned().unwrap_or(Value::Null);
            input.insert(Value::from(key), v);
        }
        Ok(input.into_value())
    }

    /// Convert the final root-policy result value into an [`XrpcResult`].
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
    /// back to a policy as the result of an `xrpc` host call (and,
    /// symmetrically, produced by sub-policies).
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
        .copied()
        .with_context(|| format!("field `{key}` must be a boolean"))
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
