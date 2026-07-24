//! Pure sans-IO arbiter state machine.
//!
//! The state machine ([`StateMachine`]) manages a **single arbiter** — its
//! spaces, members, and policy evaluation.  Everything outside that
//! (routing, persistence, cross-arbiter remote resolution) belongs to the
//! IO layer / harness.
//!
//! # Architecture
//!
//! ```text
//! Event ──→ StateMachine ──→ Vec<IoAction>
//! ```
//!
//! Feed the machine an [`Event`]; it returns zero or more [`IoAction`]s.
//! The IO layer fulfills those actions and feeds results back as new
//! events.
//!
//! # Async runtime integration (feature `futures`)
//!
//! Enable the `futures` feature for the [`futures`] module, which provides
//! an async [`Io`](futures::Io) trait and a [`process_event`](futures::process_event)
//! helper that recursively drives an event to completion.  No external
//! runtime dependency required — the trait uses native `async fn`.
//!
//! # Policy entry point
//!
//! The state machine evaluates a single Rego entry point:
//! `data.arbiter.response`.  The policy MUST return an object with at
//! least `"body"` and `"status"` fields:
//!
//! ```json
//! {"body": {...}, "status": 200}
//! ```
//!
//! The policy uses the built-in `xrpc_local` and `xrpc_remote` functions
//! to query data from the host (for authorization) and invoke built-in
//! XRPC operations (both queries and procedures).  Every built-in XRPC is
//! available through `xrpc_local` — the policy is the sole router.

use std::collections::HashMap;

use policy_core::{HostRequest, VmResult, VmSession, XrpcMethod, regorus};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use policy_core;

pub type Did = String;
pub type SpaceKey = String;
pub type JobId = u64;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur when constructing a [`StateMachine`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum CreateError {
    /// The config is missing the required `$type` field.
    #[error("Arbiter config must have `$type` set to 'town.muni.arbiter.server.v1.config'")]
    MissingType,

    /// The `$type` field is present but has an unexpected value.
    #[error("Arbiter config `$type` must be 'town.muni.arbiter.server.v1.config', got '{0}'")]
    InvalidType(String),

    /// The config is missing the required `policy` field.
    #[error("Arbiter config must have a `policy` field (Rego source)")]
    MissingPolicy,
}

/// Validate that a config value has the required `$type` and `policy` fields.
///
/// Returns the policy.
pub fn validate_config(config: &Value) -> Result<String, CreateError> {
    let type_str = config
        .get("$type")
        .and_then(|v| v.as_str())
        .ok_or(CreateError::MissingType)?;
    if type_str != "town.muni.arbiter.server.v1.config" {
        return Err(CreateError::InvalidType(type_str.into()));
    }
    let Some(policy) = config.get("policy").and_then(|v| v.as_str()) else {
        return Err(CreateError::MissingPolicy);
    };
    Ok(policy.into())
}

/// Unique identifier for a space, combining its key and type.
/// Both fields are required — `space_type` is part of the space's identity.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpaceId {
    pub space_type: String,
    pub space_key: SpaceKey,
}

/// An incoming event to the state machine.
#[derive(Debug, Clone)]
pub enum Event {
    /// An incoming XRPC call from the HTTP server, with caller DID already
    /// resolved by the IO layer.
    IncomingXrpc {
        nsid: String,
        method: XrpcMethod,
        params: Value,
        caller_did: Did,
    },

    /// The result of an XRPC request that was triggered by the arbiter.
    XrpcRemoteResult {
        status: u16,
        body: Value,
        job_id: JobId,
    },
}

/// A request sent by the state machine for the IO layer to perform some action.
#[derive(Debug, Clone)]
pub enum IoAction {
    /// Send an XRPC response.
    SendXrpcResponse { body: Value, status: u16 },

    /// Resolve a remote XRPC query from the policy engine.
    SendXrpcRequest {
        did: String,
        method: XrpcMethod,
        nsid: String,
        input: Value,
        job_id: JobId,
    },
}

// ---------------------------------------------------------------------------
// XrpcResponse  —  status + body helper
// ---------------------------------------------------------------------------

/// The status-code and body of an XRPC response.
///
/// Used as a return type from [`resolve_local`](StateMachine::resolve_local)
/// and the async [`Io`](crate::futures::Io) trait — anywhere we need to
/// pass around an XRPC-style response without embedding it in JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrpcResponse {
    pub status: u16,
    pub body: Value,
}

impl XrpcResponse {
    /// Build an error response with the given status and message.
    pub fn error(status: u16, msg: impl Into<String>) -> Self {
        XrpcResponse {
            status,
            body: serde_json::json!({
                "$type": "town.muni.arbiter.server.v1.error",
                "error": msg.into()
            }),
        }
    }

    /// Convert to the canonical JSON map that the Rego VM expects:
    /// `{"status": …, "body": …}`.
    pub fn to_json(&self) -> Value {
        serde_json::json!({"status": self.status, "body": self.body})
    }

    /// Try to parse an [`XrpcResponse`] from a JSON value that has
    /// `"status"` and `"body"` keys.
    pub fn from_json(val: &Value) -> Option<Self> {
        let status = val.get("status")?.as_u64()? as u16;
        let body = val.get("body")?.clone();
        Some(XrpcResponse { status, body })
    }
}

// ---------------------------------------------------------------------------
// JSON-serialisable types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberEntry {
    pub did: Did,
    pub access: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Space {
    pub key: SpaceKey,
    pub space_type: String,
    pub config: Value,
    pub members: Vec<MemberEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbiterState {
    pub did: Did,
    pub version: u64,
    pub config: Value,
    pub spaces: HashMap<SpaceId, Space>,
}

impl ArbiterState {
    /// Create a new arbiter with the given DID and initial owner.
    pub fn create(did: Did, config: Value) -> Self {
        ArbiterState {
            did,
            version: 1,
            config,
            spaces: Default::default(),
        }
    }

    /// Look up a space by its full [`SpaceId`].
    pub fn get_space(&self, id: &SpaceId) -> Option<&Space> {
        self.spaces.get(id)
    }

    /// Mutable variant of [`get_space`](Self::get_space).
    pub fn get_space_mut(&mut self, id: &SpaceId) -> Option<&mut Space> {
        self.spaces.get_mut(id)
    }
}

// ---------------------------------------------------------------------------
// NSID constants
// ---------------------------------------------------------------------------

pub struct NSID;
impl NSID {
    pub const GET_ARBITER_CONFIG: &'static str = "town.muni.arbiter.getArbiterConfig";
    pub const SET_ARBITER_CONFIG: &'static str = "town.muni.arbiter.setArbiterConfig";
    pub const CREATE_ARBITER: &'static str = "town.muni.arbiter.createArbiter";
    pub const CREATE_APP_PASSWORD_ARBITER: &'static str =
        "town.muni.arbiter.createAppPasswordArbiter";
    pub const DELETE_ARBITER: &'static str = "town.muni.arbiter.deleteArbiter";
    pub const CREATE_SPACE: &'static str = "town.muni.arbiter.createSpace";
    pub const GET_SPACE_CONFIG: &'static str = "town.muni.arbiter.getSpaceConfig";
    pub const SET_SPACE_CONFIG: &'static str = "town.muni.arbiter.setSpaceConfig";
    pub const DELETE_SPACE: &'static str = "town.muni.arbiter.deleteSpace";
    pub const LIST_SPACES: &'static str = "town.muni.arbiter.listSpaces";
    pub const GET_SPACE_MEMBERS: &'static str = "town.muni.arbiter.getSpaceMembers";
    pub const RESOLVE_SPACE_MEMBERS: &'static str = "town.muni.arbiter.resolveSpaceMembers";
    pub const SET_SPACE_MEMBER_ACCESS: &'static str = "town.muni.arbiter.setSpaceMemberAccess";
    pub const REMOVE_SPACE_MEMBER: &'static str = "town.muni.arbiter.removeSpaceMember";
}

/// Returns `true` if the NSID is a read-only (query) operation.
pub fn is_readonly_nsid(nsid: &str) -> bool {
    matches!(
        nsid,
        NSID::GET_ARBITER_CONFIG
            | NSID::GET_SPACE_CONFIG
            | NSID::GET_SPACE_MEMBERS
            | NSID::RESOLVE_SPACE_MEMBERS
            | NSID::LIST_SPACES
    )
}

/// Returns the [`XrpcMethod`] appropriate for the given NSID.
pub fn nsid_method(nsid: &str) -> XrpcMethod {
    if is_readonly_nsid(nsid) {
        XrpcMethod::Query
    } else {
        XrpcMethod::Procedure
    }
}

// ---------------------------------------------------------------------------
// Rego ↔ serde_json conversion  (pub for consumers like integration tests)
// ---------------------------------------------------------------------------

fn serde_to_rego(val: Value) -> regorus::Value {
    serde_json::from_value(val).unwrap()
}
fn rego_to_serde(val: regorus::Value) -> Value {
    serde_json::to_value(val).unwrap()
}

// ---------------------------------------------------------------------------
// Pending state for in-progress operations
// ---------------------------------------------------------------------------

/// A policy evaluation that is waiting for an XRPC remote result.
struct PendingEval {
    session: VmSession,
    ctx: EvalContext,
}

/// Describes how to step a [`VmSession`] — either starting fresh or
/// resuming with a value from a previous suspension.
enum EvalStep<'a> {
    Start,
    Resume(&'a regorus::Value),
}

/// Context captured when an incoming XRPC evaluation starts.
///
/// Currently carries only the arbiter version for compare-and-swap.
/// Additional request metadata (caller DID, NSID, etc.) can be added
/// when needed for tracing or error reporting.
#[derive(Clone)]
struct EvalContext {
    /// The arbiter version at the time this evaluation started.
    /// Used for compare-and-swap: mutations check that the version
    /// hasn't changed before applying.
    start_version: u64,
}

// ---------------------------------------------------------------------------
// State machine  (one per arbiter)
// ---------------------------------------------------------------------------

pub struct StateMachine {
    pub arbiter: ArbiterState,
    next_job_id: JobId,
    /// Jobs whose policy evaluation is suspended awaiting an XRPC remote result.
    /// Keyed by the remote job_id (allocated when the VM suspends on XrpcRemote).
    pending_jobs: HashMap<JobId, PendingEval>,
}

impl StateMachine {
    pub fn new(arbiter: ArbiterState) -> Self {
        Self {
            arbiter,
            next_job_id: 1,
            pending_jobs: HashMap::new(),
        }
    }

    pub fn create(did: Did, config: Value) -> Result<Self, CreateError> {
        validate_config(&config)?;
        Ok(Self::new(ArbiterState::create(did, config)))
    }

    fn alloc_job_id(&mut self) -> JobId {
        let id = self.next_job_id;
        self.next_job_id += 1;
        id
    }

    // -------------------------------------------------------------------
    // Main entry point
    // -------------------------------------------------------------------

    pub fn handle_event(&mut self, event: Event) -> Vec<IoAction> {
        dbg!(&event);
        let out = match event {
            Event::IncomingXrpc {
                nsid,
                method,
                params,
                caller_did,
            } => self.start_policy_eval(nsid, method, params, caller_did),
            Event::XrpcRemoteResult {
                body,
                status,
                job_id,
            } => self.resume_pending_eval(job_id, status, body),
        };
        dbg!(out)
    }

    // -------------------------------------------------------------------
    // Policy evaluation
    // -------------------------------------------------------------------

    /// Start evaluating `data.arbiter.response` with the given operation
    /// context.  When the policy completes, its return value IS the response.
    fn start_policy_eval(
        &mut self,
        nsid: String,
        method: XrpcMethod,
        params: Value,
        caller_did: Did,
    ) -> Vec<IoAction> {
        let Ok(policy) = validate_config(&self.arbiter.config) else {
            return vec![IoAction::SendXrpcResponse {
                body: serde_json::json!({
                    "$type": "town.muni.arbiter.server.v1.error",
                    "error": "Arbiter policy invalid, cannot process request."
                }),
                status: 500,
            }];
        };

        let data = serde_json::json!({ "arbiter": { "config": &self.arbiter.config, "did": &self.arbiter.did } });
        let input = serde_json::json!({
            "caller": { "did": &caller_did },
            "operation": { "nsid": &nsid, "method": &method.to_string(), "params": &params },
        });

        let rego_data = serde_to_rego(data);
        let rego_input = serde_to_rego(input);

        let entry_points = ["data.arbiter.response"];

        let session = match VmSession::new(&policy, &rego_data, &rego_input, &entry_points) {
            Ok(s) => s,
            Err(e) => {
                return vec![IoAction::SendXrpcResponse {
                    body: serde_json::json!({
                        "$type": "town.muni.arbiter.server.v1.error",
                        "error": format!("ErrPolicyCompile: {e}")
                    }),
                    status: 500,
                }];
            }
        };

        let ctx = EvalContext {
            start_version: self.arbiter.version,
        };
        self.eval(session, ctx, EvalStep::Start)
    }

    /// Continue evaluation — either starting fresh or resuming with a value.
    fn eval(
        &mut self,
        mut session: VmSession,
        ctx: EvalContext,
        step: EvalStep<'_>,
    ) -> Vec<IoAction> {
        let result = match &step {
            EvalStep::Start => session.start(),
            EvalStep::Resume(val) => session.resume(val),
        };
        let error_label = match &step {
            EvalStep::Start => "ErrPolicyEval",
            EvalStep::Resume(_) => "ErrPolicyResume",
        };
        match result {
            Ok(VmResult::Completed(val)) => self.on_policy_completed(val),
            Ok(VmResult::Suspended(req)) => self.handle_vm_suspension(req, session, ctx),
            Err(e) => {
                vec![IoAction::SendXrpcResponse {
                    body: serde_json::json!({
                        "$type": "town.muni.arbiter.server.v1.error",
                        "error": format!("{error_label}: {e}")
                    }),
                    status: 500,
                }]
            }
        }
    }

    // -------------------------------------------------------------------
    // Response building from completed policy value
    // -------------------------------------------------------------------

    fn on_policy_completed(&self, val: regorus::Value) -> Vec<IoAction> {
        let response = rego_to_serde(val);

        // Extract status and body from the policy response.
        let status = response
            .get("status")
            .and_then(|v| v.as_u64())
            .unwrap_or(500) as u16;
        let body = response.get("body").cloned().unwrap_or_else(|| {
            serde_json::json!({
                "$type": "town.muni.arbiter.server.v1.error",
                "error": "ErrInvalidPolicyResponse: missing `body`"
            })
        });

        vec![IoAction::SendXrpcResponse { body, status }]
    }

    // -------------------------------------------------------------------
    // VmSession suspension handling
    // -------------------------------------------------------------------

    fn handle_vm_suspension(
        &mut self,
        req: HostRequest,
        session: VmSession,
        ctx: EvalContext,
    ) -> Vec<IoAction> {
        match req {
            HostRequest::XrpcLocal {
                nsid,
                method,
                input,
            } => {
                let resolved =
                    self.resolve_local(method, &nsid, &rego_to_serde(input), ctx.start_version);
                let resolved_rego = serde_to_rego(resolved.to_json());
                self.eval(session, ctx, EvalStep::Resume(&resolved_rego))
            }
            HostRequest::XrpcRemote {
                did,
                method,
                nsid,
                input,
            } => {
                let j = self.alloc_job_id();
                self.pending_jobs.insert(j, PendingEval { session, ctx });
                vec![IoAction::SendXrpcRequest {
                    did: did.to_string(),
                    method,
                    nsid: nsid.to_string(),
                    input: rego_to_serde(input),
                    job_id: j,
                }]
            }
        }
    }

    fn resume_pending_eval(&mut self, job_id: JobId, status: u16, body: Value) -> Vec<IoAction> {
        let Some(pending) = self.pending_jobs.remove(&job_id) else {
            // No job found for this job_id — stale or already handled.
            return vec![];
        };
        let resolved_rego = serde_to_rego(serde_json::json!({"status": status, "body": body}));
        self.eval(
            pending.session,
            pending.ctx,
            EvalStep::Resume(&resolved_rego),
        )
    }

    // -------------------------------------------------------------------
    // Local XRPC resolution  (reads from / mutates our own arbiter state)
    // -------------------------------------------------------------------

    /// Resolve a built-in XRPC call (query or procedure) against this
    /// arbiter's state.  Returns the **response body** — the policy wraps
    /// it into the final response object.
    ///
    /// Validates that the [`XrpcMethod`] matches the NSID (queries must use
    /// `Query`, procedures must use `Procedure`) before dispatching.
    ///
    /// Mutations (procedures) use compare-and-swap: they check that
    /// `arbiter.version == start_version` before applying.  If the version
    /// has changed, the mutation is rejected with `ErrVersionMismatch`.
    fn resolve_local(
        &mut self,
        method: XrpcMethod,
        nsid: &str,
        params: &Value,
        start_version: u64,
    ) -> XrpcResponse {
        // Validate that queries use XrpcMethod::Query and procedures use
        // XrpcMethod::Procedure. The Rego built-in `xrpc_local` already
        // carries the method from the policy — this is a defence-in-depth
        // check to catch misconfigurations early.
        let expected = nsid_method(nsid);
        if method != expected {
            return XrpcResponse::error(
                400,
                format!("ErrMethodMismatch: expected {expected}, got {method}"),
            );
        }

        match nsid {
            // ── Queries ──────────────────────────────────────────────
            NSID::GET_ARBITER_CONFIG => XrpcResponse {
                status: 200,
                body: serde_json::json!({
                    "$type": "town.muni.arbiter.server.v1.config",
                    "config": &self.arbiter.config
                }),
            },

            NSID::GET_SPACE_CONFIG => {
                let Some(space_id) = self.space_id_from_params(params) else {
                    return XrpcResponse::error(400, "ErrMissingParam: spaceKey/spaceType");
                };
                let config = self.arbiter.get_space(&space_id).map(|s| &s.config);
                XrpcResponse {
                    status: 200,
                    body: serde_json::json!({
                        "config": config,
                        "spaceType": &space_id.space_type,
                    }),
                }
            }

            NSID::GET_SPACE_MEMBERS => {
                let Some(space_id) = self.space_id_from_params(params) else {
                    return XrpcResponse::error(400, "ErrMissingParam: spaceKey/spaceType");
                };
                let members: Vec<Value> = self
                    .arbiter
                    .get_space(&space_id)
                    .map(|s| {
                        s.members
                            .iter()
                            .map(|m| {
                                serde_json::json!({
                                    "did": m.did, "access": m.access
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                XrpcResponse {
                    status: 200,
                    body: serde_json::json!({"members": members}),
                }
            }

            NSID::LIST_SPACES => {
                let spaces: Vec<Value> = self
                    .arbiter
                    .spaces
                    .iter()
                    .map(|(id, s)| {
                        serde_json::json!({
                            "spaceKey": id.space_key,
                            "spaceType": id.space_type,
                            "config": s.config,
                        })
                    })
                    .collect();
                XrpcResponse {
                    status: 200,
                    body: serde_json::json!({"spaces": spaces}),
                }
            }

            NSID::RESOLVE_SPACE_MEMBERS => {
                // resolveSpaceMembers returns the raw resolved members from
                // the policy's resolve_result rule.  Since the policy now
                // handles everything through a single response entry point,
                // we don't have a separate resolve_result rule.  Delegate
                // to a full policy eval on the same arbiter.
                //
                // For now, fall back to getSpaceMembers as a reasonable
                // default — the policy can override by not calling this
                // and doing the resolution in Rego directly.
                let Some(space_id) = self.space_id_from_params(params) else {
                    return XrpcResponse::error(400, "ErrMissingParam: spaceKey/spaceType");
                };
                let members: Vec<Value> = self
                    .arbiter
                    .get_space(&space_id)
                    .map(|s| {
                        s.members
                            .iter()
                            .map(|m| serde_json::json!({"did": m.did, "access": m.access}))
                            .collect()
                    })
                    .unwrap_or_default();
                XrpcResponse {
                    status: 200,
                    body: serde_json::json!({
                        "members": members,
                        "missingSpaces": [],
                    }),
                }
            }

            // ── Procedures ───────────────────────────────────────────
            NSID::SET_ARBITER_CONFIG => {
                if self.arbiter.version != start_version {
                    return XrpcResponse::error(409, "ErrVersionMismatch");
                }
                let Some(new_config) = params.get("config") else {
                    return XrpcResponse::error(400, "ErrMissingParam: config");
                };
                // Validate that the new config has the required fields.
                if let Err(err) = validate_config(new_config) {
                    return XrpcResponse::error(400, format!("ErrInvalidConfig: {err}"));
                }
                self.arbiter.config = new_config.clone();
                self.arbiter.version += 1;
                XrpcResponse {
                    status: 200,
                    body: serde_json::json!({
                        "$type": "town.muni.arbiter.server.v1.ok"
                    }),
                }
            }

            NSID::DELETE_ARBITER => {
                // The host IO layer should handle deletion.  Signal success.
                XrpcResponse {
                    status: 200,
                    body: serde_json::json!({}),
                }
            }

            NSID::CREATE_SPACE => {
                if self.arbiter.version != start_version {
                    return XrpcResponse::error(409, "ErrVersionMismatch");
                }
                let (st, sk) = match self.space_params(params) {
                    Some(p) => p,
                    None => {
                        return XrpcResponse::error(400, "ErrMissingParam: spaceKey/spaceType");
                    }
                };
                let space_id = SpaceId {
                    space_key: sk.clone(),
                    space_type: st.clone(),
                };
                if self.arbiter.spaces.contains_key(&space_id) {
                    return XrpcResponse::error(409, "ErrSpaceExists");
                }
                let config = params.get("config").cloned().unwrap_or_default();
                let space = Space {
                    key: sk,
                    space_type: st,
                    config,
                    members: vec![],
                };
                self.arbiter.spaces.insert(space_id, space);
                self.arbiter.version += 1;
                XrpcResponse {
                    status: 200,
                    body: serde_json::json!({}),
                }
            }

            NSID::SET_SPACE_CONFIG => {
                if self.arbiter.version != start_version {
                    return XrpcResponse::error(409, "ErrVersionMismatch");
                }
                let (st, sk) = match self.space_params(params) {
                    Some(p) => p,
                    None => {
                        return XrpcResponse::error(400, "ErrMissingParam: spaceKey/spaceType");
                    }
                };
                let space_id = SpaceId {
                    space_key: sk,
                    space_type: st,
                };
                if let Some(space) = self.arbiter.spaces.get_mut(&space_id) {
                    if let Some(c) = params.get("config") {
                        space.config = c.clone();
                    }
                    self.arbiter.version += 1;
                    XrpcResponse {
                        status: 200,
                        body: serde_json::json!({}),
                    }
                } else {
                    XrpcResponse::error(404, "ErrSpaceNotExists")
                }
            }

            NSID::DELETE_SPACE => {
                if self.arbiter.version != start_version {
                    return XrpcResponse::error(409, "ErrVersionMismatch");
                }
                let (st, sk) = match self.space_params(params) {
                    Some(p) => p,
                    None => {
                        return XrpcResponse::error(400, "ErrMissingParam: spaceKey/spaceType");
                    }
                };
                if sk == "$admin" && st == "town.muni.arbiter.config.adminSpace" {
                    return XrpcResponse::error(403, "ErrCannotDeleteAdminSpace");
                }
                let space_id = SpaceId {
                    space_key: sk,
                    space_type: st,
                };
                if self.arbiter.spaces.remove(&space_id).is_none() {
                    return XrpcResponse::error(404, "ErrSpaceNotExists");
                }
                self.arbiter.version += 1;
                XrpcResponse {
                    status: 200,
                    body: serde_json::json!({}),
                }
            }

            NSID::SET_SPACE_MEMBER_ACCESS => {
                if self.arbiter.version != start_version {
                    return XrpcResponse::error(409, "ErrVersionMismatch");
                }
                let (st, sk) = match self.space_params(params) {
                    Some(p) => p,
                    None => {
                        return XrpcResponse::error(400, "ErrMissingParam: spaceKey/spaceType");
                    }
                };
                let space_id = SpaceId {
                    space_key: sk,
                    space_type: st,
                };
                let md = params
                    .get("memberDid")
                    .or_else(|| params.get("member").and_then(|m| m.get("did")))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let md = match md {
                    Some(d) => d,
                    None => {
                        return XrpcResponse::error(400, "ErrMissingParam: memberDid");
                    }
                };
                if let Some(space) = self.arbiter.spaces.get_mut(&space_id) {
                    let access = params.get("access").cloned().unwrap_or_default();
                    if let Some(existing) = space.members.iter_mut().find(|m| m.did == md) {
                        existing.access = access;
                    } else {
                        space.members.push(MemberEntry { did: md, access });
                    }
                    self.arbiter.version += 1;
                    XrpcResponse {
                        status: 200,
                        body: serde_json::json!({}),
                    }
                } else {
                    XrpcResponse::error(404, "ErrSpaceNotExists")
                }
            }

            NSID::REMOVE_SPACE_MEMBER => {
                if self.arbiter.version != start_version {
                    return XrpcResponse::error(409, "ErrVersionMismatch");
                }
                let (st, sk) = match self.space_params(params) {
                    Some(p) => p,
                    None => {
                        return XrpcResponse::error(400, "ErrMissingParam: spaceKey/spaceType");
                    }
                };
                let space_id = SpaceId {
                    space_key: sk,
                    space_type: st,
                };
                let md = params
                    .get("memberDid")
                    .or_else(|| params.get("member").and_then(|m| m.get("did")))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let md = match md {
                    Some(d) => d,
                    None => {
                        return XrpcResponse::error(400, "ErrMissingParam: memberDid");
                    }
                };
                if let Some(space) = self.arbiter.spaces.get_mut(&space_id) {
                    space.members.retain(|m| m.did != md);
                    self.arbiter.version += 1;
                    XrpcResponse {
                        status: 200,
                        body: serde_json::json!({}),
                    }
                } else {
                    XrpcResponse::error(404, "ErrSpaceNotExists")
                }
            }

            // Unknown NSID — not a built-in operation.
            _ => XrpcResponse::error(400, "ErrUnknownMethod"),
        }
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    /// Extract `(spaceType, spaceKey)` from XRPC params.
    fn space_params(&self, params: &Value) -> Option<(String, String)> {
        let sk = params.get("spaceKey").and_then(|v| v.as_str())?;
        let st = params.get("spaceType").and_then(|v| v.as_str())?;
        Some((st.to_string(), sk.to_string()))
    }

    /// Extract a [`SpaceId`] from XRPC params.
    fn space_id_from_params(&self, params: &Value) -> Option<SpaceId> {
        let (space_type, key) = self.space_params(params)?;
        Some(SpaceId {
            space_key: key,
            space_type,
        })
    }
}

#[cfg(feature = "futures")]
pub mod futures;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_arbiter_state() {
        let arb = ArbiterState::create(
            "did:plc:abc".into(),
            serde_json::json!({
                "$type": "town.muni.arbiter.server.v1.config",
                "policy": "package arbiter\nimport rego.v1\n",
            }),
        );
        assert_eq!(arb.did, "did:plc:abc");
        assert_eq!(
            arb.config.get("$type").and_then(|v| v.as_str()),
            Some("town.muni.arbiter.server.v1.config")
        );
    }

    #[test]
    fn test_is_readonly_nsid() {
        assert!(is_readonly_nsid(NSID::GET_ARBITER_CONFIG));
        assert!(!is_readonly_nsid(NSID::SET_ARBITER_CONFIG));
    }

    #[test]
    fn test_nsid_method() {
        assert_eq!(nsid_method(NSID::GET_ARBITER_CONFIG), XrpcMethod::Query);
        assert_eq!(nsid_method(NSID::SET_ARBITER_CONFIG), XrpcMethod::Procedure);
    }

    #[test]
    fn test_serde_rego_roundtrip() {
        let original = serde_json::json!({"s": "hello", "n": 42, "b": true, "a": [1, 2]});
        let rego = serde_to_rego(original.clone());
        let back = rego_to_serde(rego);
        assert_eq!(original, back);
    }

    #[test]
    fn test_get_arbiter_config_with_caller_did() {
        // A policy that directly returns the config as a response.
        let policy = r#"
            package arbiter
            import rego.v1

            response := {"status": 200, "body": {"config": data.arbiter.config}}
        "#;
        let mut sm = StateMachine::create(
            "did:plc:abc".into(),
            serde_json::json!({
                "$type": "town.muni.arbiter.server.v1.config",
                "policy": policy,
                "key": "val",
            }),
        )
        .expect("valid config");
        let actions = sm.handle_event(Event::IncomingXrpc {
            nsid: NSID::GET_ARBITER_CONFIG.into(),
            method: XrpcMethod::Query,
            params: serde_json::json!({}),
            caller_did: "did:plc:alice".into(),
        });
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            IoAction::SendXrpcResponse { body, status } => {
                assert_eq!(*status, 200);
                assert_eq!(
                    body.get("config")
                        .and_then(|c| c.get("key"))
                        .and_then(|v| v.as_str()),
                    Some("val")
                );
            }
            _ => panic!("expected SendXrpcResponse"),
        }
    }

    #[test]
    fn test_incoming_xrpc_carries_caller_did() {
        let policy = r#"
            package arbiter
            import rego.v1

            response := {"status": 200, "body": {"callerDid": input.caller.did}}
        "#;
        let mut sm = StateMachine::create(
            "did:plc:abc".into(),
            serde_json::json!({
                "$type": "town.muni.arbiter.server.v1.config",
                "policy": policy,
            }),
        )
        .expect("valid config");
        let actions = sm.handle_event(Event::IncomingXrpc {
            nsid: NSID::GET_ARBITER_CONFIG.into(),
            method: XrpcMethod::Query,
            params: serde_json::json!({}),
            caller_did: "did:plc:bob".into(),
        });
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            IoAction::SendXrpcResponse { body, .. } => {
                assert_eq!(
                    body.get("callerDid").and_then(|v| v.as_str()),
                    Some("did:plc:bob")
                );
            }
            _ => panic!("expected SendXrpcResponse"),
        }
    }
}
