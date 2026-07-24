//! Sans-IO policy evaluation engine with suspendable XRPC resolution.
//!
//! Provides [`VmSession`], which wraps a single `RegoVM` for evaluating a
//! Rego policy with suspendable execution. Policies can request host data
//! via two built-in functions without blocking:
//!
//! - `xrpc_local(path, input)` — request data from the local host
//! - `xrpc_remote(did, path, input)` — request data from a remote DID
//!
//! When the policy calls one of these functions, the VM suspends and returns
//! a [`HostRequest`]. The caller resolves it and calls
//! [`VmSession::resume`] with the result.
//!
//! Because `RegoVM` is `Send + Sync` (with regorus's `arc` feature), each
//! caller owns its own `VmSession` — no pool needed.

use std::fmt::Display;

pub use regorus;

use regorus::{
    PolicyModule, Value,
    languages::rego::compiler::{Compiler, CompilerError},
    rvm::{
        RegoVM,
        vm::{ExecutionMode, ExecutionState, SuspendReason, VmError},
    },
};

/// The method of an XRPC request: either query or procedure.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum XrpcMethod {
    Query,
    Procedure,
}

impl std::fmt::Display for XrpcMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                XrpcMethod::Query => "query",
                XrpcMethod::Procedure => "procedure",
            }
        )
    }
}
impl std::str::FromStr for XrpcMethod {
    type Err = XrpcMethodFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "query" => Ok(XrpcMethod::Query),
            "procedure" => Ok(XrpcMethod::Procedure),
            _ => Err(XrpcMethodFromStrError),
        }
    }
}
/// Error returned when parsing a string into an [`XrpcMethod`] fails.
#[derive(Debug, thiserror::Error)]
#[error("Invalid XRPC method")]
pub struct XrpcMethodFromStrError;

/// Errors that can occur during policy compilation or VM execution.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Policy compilation (parsing, type-checking, RVM bytecode generation) failed.
    #[error("Policy compilation failed: {0}")]
    Compile(Box<dyn std::error::Error + Send + Sync>),

    /// VM execution error (runtime failures from the RegoVM).
    #[error("VM execution error: {0}")]
    Vm(#[from] VmError),

    /// The VM suspended but the suspension reason could not be parsed into a
    /// known [`HostRequest`].
    #[error("VM suspended with unrecognized reason")]
    UnexpectedSuspension,

    /// The VM entered an unexpected state after an execute or resume call.
    #[error("Unexpected VM state: {0}")]
    UnexpectedState(String),

    /// [`resume`](VmSession::resume) was called when the VM was not in a
    /// suspended state.
    #[error("VM is not in a suspended state")]
    VmNotSuspended,

    #[error("Error parsing function call: {0}")]
    FunctionCallError(String),

    #[error("Could not parse XRPC method: expected either `query` or `procedure`")]
    MethodParseError(#[from] XrpcMethodFromStrError),
}

impl From<CompilerError> for Error {
    fn from(err: CompilerError) -> Self {
        Error::Compile(Box::new(err))
    }
}

impl From<regorus::languages::rego::compiler::SpannedCompilerError> for Error {
    fn from(err: regorus::languages::rego::compiler::SpannedCompilerError) -> Self {
        Error::Compile(Box::new(err))
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A request from the policy VM to the host.
///
/// Returned inside [`VmResult::Suspended`] when the policy calls one of the
/// built-in XRPC functions. The host must resolve the request and call
/// [`VmSession::resume`] with the result.
#[derive(Debug, Clone, PartialEq)]
pub enum HostRequest {
    /// Resolve an XRPC query on the local host.
    XrpcLocal {
        /// The XRPC call NSID (e.g. `"town.muni.arbiter.resolveSpaceMembers"`).
        nsid: String,
        /// The XRPC method.
        method: XrpcMethod,
        /// The input parameters.
        input: Value,
    },
    /// Resolve an XRPC query on a remote host identified by DID.
    XrpcRemote {
        /// The DID of the remote host.
        did: String,
        /// The XRPC method.
        method: XrpcMethod,
        /// The XRPC method NSID.
        nsid: String,
        /// The input parameters.
        input: Value,
    },
}

/// Result of evaluating or resuming a policy without errors.
///
/// The non-error outcomes are completion with a [`Value`] or suspension
/// with a [`HostRequest`]. Errors are represented separately so that
/// [`start`](VmSession::start) and [`resume`](VmSession::resume) return
/// `Result<VmResult, Error>`, enabling the `?` operator.
#[derive(Debug)]
pub enum VmResult {
    /// Evaluation completed with a value.
    Completed(Value),
    /// Evaluation suspended, waiting for host to provide data.
    Suspended(HostRequest),
}

// ---------------------------------------------------------------------------
// VmSession
// ---------------------------------------------------------------------------

/// A single RegoVM evaluation session with built-in XRPC support.
///
/// Each session wraps one [`RegoVM`] and a response cache. When the policy
/// calls `xrpc_local` or `xrpc_remote`, the VM suspends and returns a
/// [`HostRequest`] to the caller. The caller resolves it and calls
/// [`resume`](Self::resume).
///
/// If the policy calls the same XRPC function with the same arguments
/// multiple times (e.g., from different rule bodies), the cache
/// auto-resolves the duplicate without returning to the caller.
///
/// `VmSession` is `Send + Sync` because `RegoVM` is, so it can be stored
/// directly in a state machine without an external pool.
#[derive(Debug)]
pub struct VmSession {
    vm: RegoVM,
}

impl VmSession {
    /// Create a new session, compiling the policy and configuring the VM.
    ///
    /// `entry_points` specifies which rules to compile. The first entry
    /// point is the main rule. Pass multiple entry points when the compiled
    /// program needs to support querying different rules (e.g.,
    /// `resolved_members` in addition to `allow`).
    ///
    /// This method only sets up the VM — it does **not** start executing.
    /// Call [`start`](Self::start) to begin evaluation.
    pub fn new(
        policy: &str,
        data: &Value,
        input: &Value,
        entry_points: &[&str],
    ) -> Result<Self, Error> {
        let vm = build_vm(policy, data, input, entry_points)?;
        Ok(Self { vm })
    }

    /// Start (or restart) evaluation from the first entry point.
    ///
    /// Runs the VM until it either completes or suspends waiting for host
    /// data. If suspended, the caller should resolve the [`HostRequest`]
    /// and call [`resume`](Self::resume).
    ///
    /// Errors from the VM are returned via the `Err` branch so callers can
    /// use the `?` operator.
    pub fn start(&mut self) -> Result<VmResult, Error> {
        self.run()
    }

    /// Resume a suspended evaluation with the host's response.
    ///
    /// Errors from the VM are returned via the `Err` branch so callers can
    /// use the `?` operator.
    pub fn resume(&mut self, resume_value: &Value) -> Result<VmResult, Error> {
        let this = &mut *self;
        match this.vm.resume(Some(resume_value.clone())) {
            Ok(_) => match this.vm.execution_state() {
                ExecutionState::Completed { result } => Ok(VmResult::Completed(result.clone())),
                ExecutionState::Suspended { reason, .. } => {
                    Ok(VmResult::Suspended(host_request_from_reason(reason)?))
                }
                ExecutionState::Error { error } => Err(Error::Vm(error.clone())),
                _ => panic!("Unexpected Rego VM state."),
            },
            Err(e) => Err(Error::Vm(e)),
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Run the VM to completion or first suspension.
    fn run(&mut self) -> Result<VmResult, Error> {
        match self.vm.execute() {
            Ok(_) => match self.vm.execution_state() {
                ExecutionState::Completed { result } => Ok(VmResult::Completed(result.clone())),
                ExecutionState::Suspended { reason, .. } => {
                    Ok(VmResult::Suspended(host_request_from_reason(reason)?))
                }
                state => Err(Error::UnexpectedState(format!(
                    "Unexpected VM state after execute: {state:?}"
                ))),
            },
            Err(e) => Err(Error::Vm(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// SuspendReason → HostRequest conversion
// ---------------------------------------------------------------------------

/// Parse a [`SuspendReason::HostAwait`] into a [`HostRequest`].
///
/// The argument is expected to be a Rego object produced by the policy
/// extension functions (see [`POLICY_EXTENSIONS`]).
fn host_request_from_reason(reason: &SuspendReason) -> Result<HostRequest, Error> {
    match reason {
        SuspendReason::HostAwait {
            argument,
            identifier,
            ..
        } => {
            let ident = identifier.as_string().map_err(func_call_err)?;
            let map = argument.as_object().map_err(func_call_err)?;

            match ident.as_ref() {
                "xrpc_local" => Ok(HostRequest::XrpcLocal {
                    nsid: map
                        .get(&Value::from("path"))
                        .ok_or(func_call_err("Missing field `path`"))?
                        .as_string()
                        .map_err(func_call_err)?
                        .to_string(),
                    method: map
                        .get(&Value::from("method"))
                        .ok_or(func_call_err("Missing field `method`"))?
                        .as_string()
                        .map_err(func_call_err)?
                        .parse()?,
                    input: map
                        .get(&Value::from("input"))
                        .ok_or(func_call_err("Missing field `input`"))?
                        .clone(),
                }),
                "xrpc_remote" => Ok(HostRequest::XrpcRemote {
                    did: map
                        .get(&Value::from("did"))
                        .ok_or(func_call_err("Missing field `did`"))?
                        .as_string()
                        .map_err(func_call_err)?
                        .to_string(),
                    method: map
                        .get(&Value::from("method"))
                        .ok_or(func_call_err("Missing field `method`"))?
                        .as_string()
                        .map_err(func_call_err)?
                        .parse()?,
                    nsid: map
                        .get(&Value::from("path"))
                        .ok_or(func_call_err("Missing field `path`"))?
                        .as_string()
                        .map_err(func_call_err)?
                        .to_string(),
                    input: map
                        .get(&Value::from("input"))
                        .ok_or(func_call_err("Missing field `input`"))?
                        .clone(),
                }),
                name => Err(func_call_err(format!("Unrecognized function `{name}`"))),
            }
        }
        _ => Err(Error::UnexpectedSuspension),
    }
}

// ---------------------------------------------------------------------------
// VM lifecycle
// ---------------------------------------------------------------------------

/// Build and configure a suspendable RegoVM from a policy, data, and input.
fn build_vm(
    policy: &str,
    data: &Value,
    input: &Value,
    entry_points: &[&str],
) -> Result<RegoVM, Error> {
    // Concatenate policy with built-in extensions
    let full_source = {
        let mut s = String::from(policy);
        s.push_str("\n\n");
        s.push_str(POLICY_EXTENSIONS);
        s
    };

    // Primary compilation pass: parses modules and resolves references
    let compiled_policy = regorus::compile_policy_with_entrypoint(
        data.clone(),
        &[PolicyModule {
            id: "".into(),
            content: full_source.into(),
        }],
        entry_points[0].into(),
    )
    .map_err(|e| Error::Compile(e.into()))?;

    // Secondary pass: compile to RVM bytecode with all entry points
    let program = Compiler::compile_from_policy(&compiled_policy, entry_points)?;

    // Configure the VM
    let mut vm = RegoVM::new();
    vm.load_program(program);
    vm.set_data(data.clone())?;
    vm.set_input(input.clone());
    vm.set_execution_mode(ExecutionMode::Suspendable);

    Ok(vm)
}

// ---------------------------------------------------------------------------
// Built-in Rego extensions
// ---------------------------------------------------------------------------

/// Rego extension code defining built-in XRPC functions.
///
/// These are automatically appended to every policy evaluated through
/// [`VmSession`]. They wrap `__builtin_host_await` with structured
/// request arguments that the Rust side parses into [`HostRequest`].
pub const POLICY_EXTENSIONS: &str = r#"
# Request data from the local host via XRPC.
# The VM suspends until the host resolves this and provides the response.
xrpc_local(method, path, inp) := result if {
    result := __builtin_host_await({"path": path, "method": method, "input": inp}, "xrpc_local")
}

# Request data from a remote host via XRPC.
# The VM suspends until the host resolves this and provides the response.
xrpc_remote(did, method, path, inp) := result if {
    result := __builtin_host_await({"did": did, "method": method, "path": path, "input": inp}, "xrpc_remote")
}
"#;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate that a policy source parses correctly.
///
/// Tests both the user's policy and the built-in extensions.
pub fn validate_policy(policy: &str) -> Result<(), Error> {
    let mut engine = regorus::Engine::new();
    let full_source = format!("{policy}\n\n{POLICY_EXTENSIONS}");
    engine
        .add_policy("validate.rego".to_string(), full_source)
        .map_err(|e| Error::Compile(e.into()))?;
    Ok(())
}

fn func_call_err<E: Display>(e: E) -> Error {
    Error::FunctionCallError(e.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn empty_obj() -> Value {
        Value::new_object()
    }

    fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::from(
            pairs
                .into_iter()
                .map(|(k, v)| (Value::from(k), v))
                .collect::<BTreeMap<Value, Value>>(),
        )
    }

    #[test]
    fn test_validate_valid_policy() {
        assert!(validate_policy("package example\nimport rego.v1\ndefault allow := true").is_ok());
    }

    #[test]
    fn test_validate_invalid_policy() {
        assert!(validate_policy("garbage {").is_err());
    }

    #[test]
    fn test_sync_allow() {
        let policy = r#"
            package example
            import rego.v1
            default allow := true
        "#;
        let data = empty_obj();
        let input = obj(vec![("test", Value::from(true))]);

        let mut session = VmSession::new(policy, &data, &input, &["data.example.allow"]).unwrap();
        let result = session.start().unwrap();
        match result {
            VmResult::Completed(value) => assert_eq!(value, Value::from(true)),
            VmResult::Suspended(r) => panic!("Unexpected suspension: {r:?}"),
        }
    }

    #[test]
    fn test_custom_entry_point() {
        let policy = r#"
            package example
            import rego.v1
            default allow := false
            custom_result := "hello" if { true }
        "#;
        let data = empty_obj();
        let input = empty_obj();

        let mut session =
            VmSession::new(policy, &data, &input, &["data.example.custom_result"]).unwrap();
        let result = session.start().unwrap();
        match result {
            VmResult::Completed(value) => assert_eq!(value, Value::from("hello")),
            VmResult::Suspended(r) => panic!("Unexpected suspension: {r:?}"),
        }
    }

    #[test]
    fn test_deny() {
        let policy = r#"
            package example
            import rego.v1
            default allow := false
        "#;
        let data = empty_obj();
        let input = empty_obj();

        let mut session = VmSession::new(policy, &data, &input, &["data.example.allow"]).unwrap();
        let result = session.start().unwrap();
        match result {
            VmResult::Completed(value) => assert_eq!(value, Value::from(false)),
            VmResult::Suspended(_) => panic!("Unexpected suspension"),
        }
    }

    #[test]
    fn test_multiple_entry_points() {
        let policy = r#"
            package example
            import rego.v1
            default allow := false
            items := ["a", "b", "c"] if { true }
        "#;
        let data = empty_obj();
        let input = empty_obj();

        let mut session = VmSession::new(
            policy,
            &data,
            &input,
            &["data.example.allow", "data.example.items"],
        )
        .unwrap();
        let result = session.start().unwrap();
        match result {
            VmResult::Completed(value) => {
                // Should evaluate the first entry point (allow)
                assert_eq!(value, Value::from(false))
            }
            VmResult::Suspended(_) => panic!("Unexpected suspension"),
        }
    }

    #[test]
    fn test_xrpc_local_suspend_and_resume() {
        let policy = r#"
            package example
            import rego.v1

            default allow := false

            allow if {
                result := xrpc_local("query", "some.query", {"key": "value"})
                result == "resolved"
            }
        "#;
        let data = empty_obj();
        let input = empty_obj();

        let mut session = VmSession::new(policy, &data, &input, &["data.example.allow"]).unwrap();
        let result = session.start().unwrap();
        let request = match result {
            VmResult::Suspended(r) => r,
            VmResult::Completed(v) => panic!("Expected suspension, got completed: {v:?}"),
        };

        match &request {
            HostRequest::XrpcLocal { nsid: path, .. } => assert_eq!(path, "some.query"),
            _ => panic!("Expected XrpcLocal"),
        }

        let result = session.resume(&Value::from("resolved")).unwrap();
        match result {
            VmResult::Completed(value) => assert_eq!(value, Value::from(true)),
            VmResult::Suspended(r) => panic!("Unexpected suspension: {r:?}"),
        }
    }

    #[test]
    fn test_xrpc_remote_suspend_and_resume() {
        let policy = r#"
            package example
            import rego.v1

            default allow := false

            allow if {
                result := xrpc_remote("did:plc:remote", "query", "remote.query", {"foo": "bar"})
                result == "remote_data"
            }
        "#;
        let data = empty_obj();
        let input = empty_obj();

        let mut session = VmSession::new(policy, &data, &input, &["data.example.allow"]).unwrap();
        let result = session.start().unwrap();
        let request = match result {
            VmResult::Suspended(r) => r,
            VmResult::Completed(v) => panic!("Expected suspension, got completed: {v:?}"),
        };

        match &request {
            HostRequest::XrpcRemote {
                did, nsid: path, ..
            } => {
                assert_eq!(did, "did:plc:remote");
                assert_eq!(path, "remote.query");
            }
            _ => panic!("Expected XrpcRemote"),
        }

        let result = session.resume(&Value::from("remote_data")).unwrap();
        match result {
            VmResult::Completed(value) => assert_eq!(value, Value::from(true)),
            VmResult::Suspended(r) => panic!("Unexpected suspension: {r:?}"),
        }
    }
}
