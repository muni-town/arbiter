use std::collections::HashMap;

use arbiter_core::{
    arbiter::{Arbiter, ArbiterReqMachineStep, BYTES_KEY, Policies},
    policy::PolicyVm,
    xrpc::{XrpcEndpoint, XrpcOutput, XrpcRequest, XrpcResult},
};
use atrium_xrpc::{InputDataOrBytes, http};
use regorus::Value;

/// Build a `PolicyVm` whose entrypoint is `data.arbiter.result`, registering the
/// three arbiter host functions as async builtins.
fn arbiter_policy(src: &str) -> PolicyVm {
    arbiter_policy_with_host_fns(src, &[])
}

/// Like [`arbiter_policy`] but registers `extra_host_fns` in addition to the
/// standard `pds`, `xrpc`, and `policy` host functions.
fn arbiter_policy_with_host_fns(src: &str, extra_host_fns: &[&str]) -> PolicyVm {
    let mut host_fns: Vec<&str> = vec!["pds", "xrpc", "policy"];
    host_fns.extend_from_slice(extra_host_fns);
    PolicyVm::new(
        src,
        Value::new_object(),
        "data.arbiter.result",
        &host_fns,
    )
    .expect("policy compiles")
}

fn make_req(
    method: http::Method,
    nsid: &str,
    input: Option<InputDataOrBytes<serde_json::Value>>,
) -> XrpcRequest {
    XrpcRequest {
        method,
        nsid: nsid.to_string(),
        parameters: None,
        input,
        encoding: None,
    }
}

/// A root policy that immediately returns a static success envelope.
#[test]
fn immediate_completion() {
    let root = arbiter_policy(
        r#"
        package arbiter
        result := { "ok": true, "output": { "got": input.nsid } }
        "#,
    );
    let arbiter = Arbiter::new(Policies::new(root, HashMap::new()));
    let mut machine = arbiter.handle_request(make_req(http::Method::GET, "com.example.foo", None));

    match machine.start() {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json, serde_json::json!({ "got": "com.example.foo" }));
        }
        _other => panic!("expected immediate completion, got something else"),
    }
}

/// A root policy that calls the `pds` host function and echoes its response.
#[test]
fn pds_host_call_roundtrip() {
    let root = arbiter_policy(
        r#"
        package arbiter
        result := { "ok": resp.ok, "output": resp.output }
        resp := pds({ "method": "GET", "nsid": "com.example.foo", "parameters": null, "body": null })
        "#,
    );
    let arbiter = Arbiter::new(Policies::new(root, HashMap::new()));
    let mut machine = arbiter.handle_request(make_req(http::Method::GET, "com.example.foo", None));

    let step = machine.start();
    let request = match step {
        ArbiterReqMachineStep::RemoteXrpcRequest { endpoint, request } => {
            assert!(matches!(endpoint, XrpcEndpoint::PdsAccount));
            assert_eq!(request.method, http::Method::GET);
            assert_eq!(request.nsid, "com.example.foo");
            request
        }
        _other => panic!("expected remote xrpc request, got something else"),
    };

    // The "PDS" responds with a JSON output.
    let response: XrpcResult = Ok(XrpcOutput::Data(serde_json::json!({ "record": "abc" })));
    let _ = request; // consumed by the (imaginary) transport
    match machine.resume(response) {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json, serde_json::json!({ "record": "abc" }));
        }
        _other => panic!("expected completion, got something else"),
    }
}

/// A root policy that calls the `xrpc` host function targeting a remote DID.
#[test]
fn xrpc_host_call_targeting_remote() {
    let root = arbiter_policy(
        r#"
        package arbiter
        result := { "ok": resp.ok, "output": resp.output }
        resp := xrpc({ "did": "did:web:example.com#atproto_pds", "method": "POST", "nsid": "com.example.bar", "parameters": null, "body": { "x": 1 } })
        "#,
    );
    let arbiter = Arbiter::new(Policies::new(root, HashMap::new()));
    let mut machine = arbiter.handle_request(make_req(http::Method::GET, "com.example.foo", None));

    match machine.start() {
        ArbiterReqMachineStep::RemoteXrpcRequest { endpoint, request } => {
            assert_eq!(
                endpoint,
                XrpcEndpoint::Remote("did:web:example.com#atproto_pds".to_string())
            );
            assert_eq!(request.method, http::Method::POST);
            assert_eq!(request.nsid, "com.example.bar");
            // JSON body is passed through as data.
            match request.input {
                Some(InputDataOrBytes::Data(json)) => {
                    assert_eq!(json, serde_json::json!({ "x": 1 }))
                }
                _other => panic!("expected JSON body, got something else"),
            }
        }
        _other => panic!("expected remote xrpc request, got something else"),
    }

    match machine.resume(Ok(XrpcOutput::Data(serde_json::json!({ "ok": true })))) {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json, serde_json::json!({ "ok": true }));
        }
        _other => panic!("expected completion, got something else"),
    }
}

/// The root policy offloads to a sub-policy via the `policy` host function.
/// The sub-policy runs to completion inline (no remote calls), and its result
/// becomes the root policy's result.
#[test]
fn sub_policy_invocation() {
    let sub = arbiter_policy(
        r#"
        package arbiter
        result := { "ok": true, "output": { "from_sub": input.nsid } }
        "#,
    );
    let root = arbiter_policy(
        r#"
        package arbiter
        result := sub
        sub := policy({ "name": "moderation", "method": input.method, "nsid": input.nsid, "parameters": null, "body": null })
        "#,
    );
    let mut subs = HashMap::new();
    subs.insert("moderation".to_string(), sub);
    let arbiter = Arbiter::new(Policies::new(root, subs));
    let mut machine = arbiter.handle_request(make_req(http::Method::POST, "com.example.foo", None));

    match machine.start() {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json, serde_json::json!({ "from_sub": "com.example.foo" }));
        }
        _other => panic!("expected completion, got something else"),
    }
}

/// A sub-policy that itself makes a `pds` call: the remote request bubbles up
/// to the caller, and after the response the root policy completes with the
/// sub-policy's derived result.
#[test]
fn sub_policy_with_remote_call() {
    let sub = arbiter_policy(
        r#"
        package arbiter
        result := { "ok": resp.ok, "output": { "pds_echo": resp.output } }
        resp := pds({ "method": "GET", "nsid": "com.example.fetch", "parameters": null, "body": null })
        "#,
    );
    let root = arbiter_policy(
        r#"
        package arbiter
        result := sub
        sub := policy({ "name": "moderation", "method": input.method, "nsid": input.nsid, "parameters": null, "body": null })
        "#,
    );
    let mut subs = HashMap::new();
    subs.insert("moderation".to_string(), sub);
    let arbiter = Arbiter::new(Policies::new(root, subs));
    let mut machine = arbiter.handle_request(make_req(http::Method::POST, "com.example.foo", None));

    match machine.start() {
        ArbiterReqMachineStep::RemoteXrpcRequest { endpoint, .. } => {
            assert!(matches!(endpoint, XrpcEndpoint::PdsAccount));
        }
        _other => panic!("expected remote xrpc request from sub-policy, got something else"),
    }

    match machine.resume(Ok(XrpcOutput::Data(serde_json::json!({ "v": 42 })))) {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json, serde_json::json!({ "pds_echo": { "v": 42 } }));
        }
        _other => panic!("expected completion, got something else"),
    }
}

/// Binary request body: bytes are stashed into the machine's buffers and passed
/// to the policy as a `{ "$__bytes__": <idx> }` marker. The policy forwards the
/// marker as the body of a `pds` call, which resolves back to real bytes in the
/// emitted `XrpcRequest`.
#[test]
fn bytes_request_body_roundtrips_through_host_call() {
    let root = arbiter_policy(
        r#"
        package arbiter
        result := resp
        resp := pds({ "method": "POST", "nsid": "com.example.upload", "parameters": null, "body": input.body })
        "#,
    );
    let arbiter = Arbiter::new(Policies::new(root, HashMap::new()));
    let payload = b"\x00\x01\x02\xff binary".to_vec();
    let mut machine = arbiter.handle_request(make_req(
        http::Method::POST,
        "com.example.upload",
        Some(InputDataOrBytes::Bytes(payload.clone())),
    ));

    let request = match machine.start() {
        ArbiterReqMachineStep::RemoteXrpcRequest { endpoint, request } => {
            assert!(matches!(endpoint, XrpcEndpoint::PdsAccount));
            request
        }
        _other => panic!("expected remote xrpc request, got something else"),
    };
    match request.input {
        Some(InputDataOrBytes::Bytes(bytes)) => assert_eq!(bytes, payload),
        _other => panic!("expected bytes body in emitted request, got something else"),
    }

    // The PDS responds with bytes output, which is stashed into buffers and
    // represented to the policy via a marker; the policy surfaces it as
    // `resp.bytes`, which the machine resolves back to bytes in the result.
    let resp_payload = b"response bytes".to_vec();
    match machine.resume(Ok(XrpcOutput::Bytes(resp_payload.clone()))) {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Bytes(bytes))) => {
            assert_eq!(bytes, resp_payload);
        }
        _other => panic!("expected byte output completion, got something else"),
    }
}

/// A root policy that returns an error envelope yields an `Err` XrpcResult.
#[test]
fn error_envelope_becomes_xrpc_error() {
    let root = arbiter_policy(
        r#"
        package arbiter
        result := { "ok": false, "error": { "status": 418, "error": "ImATeapot", "message": "nope" } }
        "#,
    );
    let arbiter = Arbiter::new(Policies::new(root, HashMap::new()));
    let mut machine = arbiter.handle_request(make_req(http::Method::GET, "com.example.foo", None));

    match machine.start() {
        ArbiterReqMachineStep::Completed(Err(err)) => {
            assert_eq!(err.status, http::StatusCode::IM_A_TEAPOT);
            let body = err.error.expect("error kind present");
            match body {
                atrium_xrpc::error::XrpcErrorKind::Undefined(erb) => {
                    assert_eq!(erb.error.as_deref(), Some("ImATeapot"));
                    assert_eq!(erb.message.as_deref(), Some("nope"));
                }
                _other => panic!("expected Undefined error kind, got something else"),
            }
        }
        _other => panic!("expected error completion, got something else"),
    }
}

/// A root policy that returns a malformed (non-object) result is converted to a
/// 500 error XRPC response rather than bubbling up a `Result::Err`.
#[test]
fn internal_error_becomes_500_xrpc_error() {
    let root = arbiter_policy(
        r#"
        package arbiter
        result := "not an object envelope"
        "#,
    );
    let arbiter = Arbiter::new(Policies::new(root, HashMap::new()));
    let mut machine = arbiter.handle_request(make_req(http::Method::GET, "com.example.foo", None));

    match machine.start() {
        ArbiterReqMachineStep::Completed(Err(err)) => {
            assert_eq!(err.status, http::StatusCode::INTERNAL_SERVER_ERROR);
            let body = err.error.expect("error kind present");
            match body {
                atrium_xrpc::error::XrpcErrorKind::Undefined(erb) => {
                    assert_eq!(erb.error.as_deref(), Some("InternalError"));
                    assert!(
                        erb.message.is_some(),
                        "error message should describe the failure"
                    );
                }
                _other => panic!("expected Undefined error kind"),
            }
        }
        _other => panic!("expected a 500 error completion, got something else"),
    }
}

/// Calling `resume` when not waiting on a remote response panics.
#[test]
#[should_panic(expected = "ArbiterReqMachine::resume called when not waiting")]
fn resume_without_pending_request_panics() {
    let root = arbiter_policy(
        r#"
        package arbiter
        result := { "ok": true, "output": {} }
        "#,
    );
    let arbiter = Arbiter::new(Policies::new(root, HashMap::new()));
    let mut machine = arbiter.handle_request(make_req(http::Method::GET, "com.example.foo", None));
    let _ = machine.start();
    let _ = machine.resume(Ok(XrpcOutput::Data(serde_json::Value::Null)));
}

/// Calling `start` more than once panics.
#[test]
#[should_panic(expected = "ArbiterReqMachine::start called more than once")]
fn start_called_twice_panics() {
    let root = arbiter_policy(
        r#"
        package arbiter
        result := { "ok": true, "output": {} }
        "#,
    );
    let arbiter = Arbiter::new(Policies::new(root, HashMap::new()));
    let mut machine = arbiter.handle_request(make_req(http::Method::GET, "com.example.foo", None));
    let _ = machine.start();
    let _ = machine.start();
}

/// The `$__bytes__` key is exported and matches the marker used internally.
#[test]
fn bytes_key_constant() {
    assert_eq!(BYTES_KEY, "$__bytes__");
}

/// A sub-policy that re-invokes itself via the `policy` host function hits the
/// depth limit and terminates with a 500 error instead of looping forever.
#[test]
fn policy_call_depth_limit_terminates() {
    let call = r#"
        package arbiter
        result := policy({ "name": "loop", "method": "GET", "nsid": "x", "parameters": null, "body": null })
    "#;
    let root = arbiter_policy(call);
    let mut subs = HashMap::new();
    subs.insert("loop".to_string(), arbiter_policy(call));
    let arbiter = Arbiter::new(Policies::new(root, subs));
    let mut machine = arbiter.handle_request(make_req(http::Method::GET, "com.example.foo", None));
    match machine.start() {
        ArbiterReqMachineStep::Completed(Err(e)) => {
            assert_eq!(e.status, http::StatusCode::INTERNAL_SERVER_ERROR);
        }
        _other => panic!("expected 500 completion from depth limit, got something else"),
    }
}

/// An `encoding` field on a `pds` host-call argument is propagated to the
/// emitted remote XRPC request.
#[test]
fn encoding_passed_through_on_outgoing_xrpc() {
    let root = arbiter_policy(
        r#"
        package arbiter
        result := pds({ "method": "POST", "nsid": "com.example.upload", "encoding": "application/octet-stream", "parameters": null, "body": input.body })
    "#,
    );
    let arbiter = Arbiter::new(Policies::new(root, HashMap::new()));
    let payload = b"hello".to_vec();
    let req = XrpcRequest {
        method: http::Method::GET,
        nsid: "com.example.foo".to_string(),
        parameters: None,
        input: Some(InputDataOrBytes::Bytes(payload.clone())),
        encoding: None,
    };
    let mut machine = arbiter.handle_request(req);
    match machine.start() {
        ArbiterReqMachineStep::RemoteXrpcRequest { endpoint, request } => {
            assert_eq!(endpoint, XrpcEndpoint::PdsAccount);
            assert_eq!(
                request.encoding.as_deref(),
                Some("application/octet-stream")
            );
            match request.input {
                Some(InputDataOrBytes::Bytes(b)) => assert_eq!(b, payload),
                _other => panic!("expected bytes body in emitted request, got something else"),
            }
        }
        _other => panic!("expected remote xrpc request, got something else"),
    }
}

/// The incoming request's `encoding` is surfaced to the policy as
/// `input.encoding`.
#[test]
fn incoming_encoding_surfaced_to_policy() {
    let root = arbiter_policy(
        r#"
        package arbiter
        result := { "ok": true, "output": input.encoding }
    "#,
    );
    let arbiter = Arbiter::new(Policies::new(root, HashMap::new()));
    let req = XrpcRequest {
        method: http::Method::GET,
        nsid: "com.example.foo".to_string(),
        parameters: None,
        input: None,
        encoding: Some("image/png".to_string()),
    };
    let mut machine = arbiter.handle_request(req);
    match machine.start() {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json.as_str(), Some("image/png"));
        }
        _other => panic!("expected data completion echoing the encoding, got something else"),
    }
}

/// The root policy forwards `input.encoding` to a sub-policy via the `policy`
/// host function, and the sub-policy sees it as `input.encoding`. When the
/// host-call argument omits `encoding`, the sub-policy receives null.
#[test]
fn encoding_forwarded_to_sub_policy() {
    let sub = arbiter_policy(
        r#"
        package arbiter
        result := { "ok": true, "output": input.encoding }
        "#,
    );
    let root = arbiter_policy(
        r#"
        package arbiter
        result := policy({ "name": "echo", "method": input.method, "nsid": input.nsid, "parameters": null, "body": null, "encoding": input.encoding })
        "#,
    );
    let mut subs = HashMap::new();
    subs.insert("echo".to_string(), sub);
    let arbiter = Arbiter::new(Policies::new(root, subs));

    // Forwarded encoding reaches the sub-policy.
    let req = XrpcRequest {
        method: http::Method::GET,
        nsid: "com.example.foo".to_string(),
        parameters: None,
        input: None,
        encoding: Some("image/png".to_string()),
    };
    let mut machine = arbiter.handle_request(req);
    match machine.start() {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json.as_str(), Some("image/png"));
        }
        _other => panic!("expected data completion echoing forwarded encoding"),
    }
}

/// A sub-policy whose `policy` host-call argument omits `encoding` receives
/// `input.encoding == null`.
#[test]
fn sub_policy_encoding_defaults_to_null() {
    let sub = arbiter_policy(
        r#"
        package arbiter
        result := { "ok": true, "output": input.encoding }
        "#,
    );
    let root = arbiter_policy(
        r#"
        package arbiter
        result := policy({ "name": "echo", "method": input.method, "nsid": input.nsid, "parameters": null, "body": null })
        "#,
    );
    let mut subs = HashMap::new();
    subs.insert("echo".to_string(), sub);
    let arbiter = Arbiter::new(Policies::new(root, subs));

    let mut machine = arbiter.handle_request(make_req(http::Method::GET, "com.example.foo", None));
    match machine.start() {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json, serde_json::Value::Null);
        }
        _other => panic!("expected data completion with null encoding"),
    }
}

/// A policy that calls an unregistered host function is resumed with an error
/// envelope. The policy can inspect `resp.ok` and handle the failure.
#[test]
fn unknown_host_function_returns_error_envelope() {
    let root = arbiter_policy_with_host_fns(
        r#"
        package arbiter
        result := resp
        resp := unknown_fn({ "x": 1 })
    "#,
        &["unknown_fn"],
    );
    let arbiter = Arbiter::new(Policies::new(root, HashMap::new()));
    let mut machine = arbiter.handle_request(make_req(http::Method::GET, "com.example.foo", None));

    match machine.start() {
        ArbiterReqMachineStep::Completed(Err(err)) => {
            assert_eq!(err.status, 400);
            match err.error.expect("error kind present") {
                atrium_xrpc::error::XrpcErrorKind::Undefined(erb) => {
                    assert_eq!(erb.error.as_deref(), Some("unknown_host_function"));
                }
                _other => panic!("expected Undefined error kind"),
            }
        }
        _other => panic!("expected error completion, got something else"),
    }
}
