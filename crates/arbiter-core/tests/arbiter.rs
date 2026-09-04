use arbiter_core::{
    arbiter::{
        Arbiter, ArbiterReqMachineStep, Pipeline, ScopePolicy, BYTES_KEY, Layer, RequestCtx,
    },
    futures::ArbiterAsyncIo,
    policy::PolicyVm,
    xrpc::{XrpcEndpoint, XrpcOutput, XrpcRequest, XrpcResult},
};
use atrium_xrpc::{InputDataOrBytes, http};
use regorus::Value;

/// Build a `PolicyVm` whose entrypoint is `data.arbiter.result`, registering
/// the arbiter's `xrpc` host function as an async builtin.
fn arbiter_policy(src: &str) -> PolicyVm {
    arbiter_policy_with_host_fns(src, &[])
}

/// Like [`arbiter_policy`] but registers `extra_host_fns` in addition to the
/// standard `xrpc` host function.
fn arbiter_policy_with_host_fns(src: &str, extra_host_fns: &[&str]) -> PolicyVm {
    let mut host_fns: Vec<&str> = vec!["xrpc"];
    host_fns.extend_from_slice(extra_host_fns);
    PolicyVm::new(src, Value::new_object(), "data.arbiter.result", &host_fns)
        .expect("policy compiles")
}

/// Compile a pipeline layer from Rego `src`, with a synthetic `at://` URI and
/// no record CID.
fn layer(name: &str, src: &str) -> Layer {
    Layer::compile(
        src,
        format!("at://did:plc:test/town.muni.arbiter.policy/{name}"),
        None,
    )
    .expect("layer policy compiles")
}

/// An [`Arbiter`] that evaluates the given layers, in order.
fn arbiter(layers: Vec<Layer>) -> Arbiter {
    Arbiter::new(Pipeline::from_layers(layers))
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

/// Assert that a machine step is the default deny (403 `Denied`) returned when
/// every layer passes or the pipeline is empty.
fn expect_default_deny(step: ArbiterReqMachineStep) {
    match step {
        ArbiterReqMachineStep::Completed(Err(err)) => {
            assert_eq!(err.status, http::StatusCode::FORBIDDEN);
            match err.error.expect("error kind present") {
                atrium_xrpc::error::XrpcErrorKind::Undefined(erb) => {
                    assert_eq!(erb.error.as_deref(), Some("Denied"));
                }
                _other => panic!("expected Undefined error kind"),
            }
        }
        _other => panic!("expected default deny completion, got something else"),
    }
}

/// A single layer that immediately handles with a static success envelope.
#[test]
fn immediate_completion() {
    let arbiter = arbiter(vec![layer(
        "root",
        r#"
        package arbiter
        result := { "ok": true, "output": { "got": input.nsid } }
        "#,
    )]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    match machine.start() {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json, serde_json::json!({ "got": "com.example.foo" }));
        }
        _other => panic!("expected immediate completion, got something else"),
    }
}

/// A layer that calls the `xrpc` host function targeting its own PDS account
/// endpoint and echoes its response.
#[test]
fn xrpc_host_call_roundtrip() {
    let arbiter = arbiter(vec![layer(
        "root",
        r#"
        package arbiter
        result := { "ok": resp.ok, "output": resp.output }
        resp := xrpc({ "did": "did:web:own-account.example#atproto_pds", "method": "GET", "nsid": "com.example.foo", "parameters": null, "body": null })
        "#,
    )]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    let request = match machine.start() {
        ArbiterReqMachineStep::RemoteXrpcRequest { endpoint, request } => {
            assert_eq!(endpoint, "did:web:own-account.example#atproto_pds");
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

/// A layer that calls the `xrpc` host function targeting a remote DID.
#[test]
fn xrpc_host_call_targeting_remote() {
    let arbiter = arbiter(vec![layer(
        "root",
        r#"
        package arbiter
        result := { "ok": resp.ok, "output": resp.output }
        resp := xrpc({ "did": "did:web:example.com#atproto_pds", "method": "POST", "nsid": "com.example.bar", "parameters": null, "body": { "x": 1 } })
        "#,
    )]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    match machine.start() {
        ArbiterReqMachineStep::RemoteXrpcRequest { endpoint, request } => {
            assert_eq!(endpoint, "did:web:example.com#atproto_pds".to_string());
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

/// Layers that output `{ "pass": true }` defer to the next layer; every layer
/// receives the same request input, and the last layer's handle wins.
#[test]
fn pass_chain_defers_through_multiple_layers() {
    let pass = r#"
        package arbiter
        result := { "pass": true }
        "#;
    let arbiter = arbiter(vec![
        layer("one", pass),
        layer("two", pass),
        layer(
            "three",
            r#"
            package arbiter
            result := { "ok": true, "output": { "handled_by": "three", "nsid": input.nsid } }
            "#,
        ),
    ]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    match machine.start() {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(
                json,
                serde_json::json!({ "handled_by": "three", "nsid": "com.example.foo" })
            );
        }
        _other => panic!("expected completion from the final layer, got something else"),
    }
}

/// The first layer that handles wins: later layers are not evaluated (the
/// second layer here would produce a 500 error if it were ever run).
#[test]
fn first_handle_wins() {
    let arbiter = arbiter(vec![
        layer(
            "one",
            r#"
            package arbiter
            result := { "ok": true, "output": { "from": "one" } }
            "#,
        ),
        layer(
            "never-run",
            r#"
            package arbiter
            result := "not an object envelope"
            "#,
        ),
    ]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    match machine.start() {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json, serde_json::json!({ "from": "one" }));
        }
        _other => panic!("expected completion from the first layer, got something else"),
    }
}

/// The first layer that denies wins and short-circuits: later layers are not
/// evaluated (the second layer here would produce a 500 error if it were ever
/// run), and the denying layer's error envelope is preserved.
#[test]
fn first_deny_wins_and_short_circuits() {
    let arbiter = arbiter(vec![
        layer(
            "one",
            r#"
            package arbiter
            result := { "ok": false, "error": { "status": 418, "error": "ImATeapot", "message": "denied by layer one" } }
            "#,
        ),
        layer(
            "never-run",
            r#"
            package arbiter
            result := "not an object envelope"
            "#,
        ),
    ]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    match machine.start() {
        ArbiterReqMachineStep::Completed(Err(err)) => {
            assert_eq!(err.status, http::StatusCode::IM_A_TEAPOT);
            match err.error.expect("error kind present") {
                atrium_xrpc::error::XrpcErrorKind::Undefined(erb) => {
                    assert_eq!(erb.error.as_deref(), Some("ImATeapot"));
                    assert_eq!(erb.message.as_deref(), Some("denied by layer one"));
                }
                _other => panic!("expected Undefined error kind"),
            }
        }
        _other => panic!("expected deny completion from the first layer, got something else"),
    }
}

/// When every layer passes, the request falls off the end of the pipeline and
/// is denied with the default error response.
#[test]
fn fall_off_end_denies() {
    let pass = r#"
        package arbiter
        result := { "pass": true }
        "#;
    let arbiter = arbiter(vec![layer("one", pass), layer("two", pass)]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    expect_default_deny(machine.start());
}

/// An empty pipeline has no layer to handle the request: deny by default.
#[test]
fn empty_pipeline_denies() {
    let arbiter = arbiter(vec![]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    expect_default_deny(machine.start());
}

/// A layer that outputs `{ "handleBuiltin": true }` hands the request to the
/// arbiter's built-in handler: the machine ends with `HandToBuiltin` instead
/// of producing an XRPC response.
#[test]
fn handle_builtin_output_hands_off_to_builtin() {
    let arbiter = arbiter(vec![layer(
        "one",
        r#"
        package arbiter
        result := { "handleBuiltin": true }
        "#,
    )]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    match machine.start() {
        ArbiterReqMachineStep::HandToBuiltin => {}
        _other => panic!("expected handoff to the built-in handler, got something else"),
    }
}

/// When a layer's output sets both markers, `{ "handleBuiltin": true }` wins
/// over `{ "pass": true }`: the layer hands off instead of deferring. With a
/// single layer, a pass would fall off the end into the default deny, so the
/// handoff is a sharp discriminator.
#[test]
fn handle_builtin_beats_pass_when_both_present() {
    let arbiter = arbiter(vec![layer(
        "one",
        r#"
        package arbiter
        result := { "handleBuiltin": true, "pass": true }
        "#,
    )]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    match machine.start() {
        ArbiterReqMachineStep::HandToBuiltin => {}
        _other => panic!(
            "expected handoff to win over the pass marker, got something else"
        ),
    }
}

/// A layer output of `{ "handleBuiltin": false }` is not a handoff (only
/// boolean `true` hands off), and with no `pass` marker or `ok`/`err`
/// envelope it is malformed, surfacing as a 500 InternalError response.
#[test]
fn handle_builtin_false_output_is_malformed() {
    let arbiter = arbiter(vec![layer(
        "one",
        r#"
        package arbiter
        result := { "handleBuiltin": false }
        "#,
    )]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    match machine.start() {
        ArbiterReqMachineStep::Completed(Err(err)) => {
            assert_eq!(err.status, http::StatusCode::INTERNAL_SERVER_ERROR);
            let body = err.error.expect("error kind present");
            match body {
                atrium_xrpc::error::XrpcErrorKind::Undefined(erb) => {
                    assert_eq!(erb.error.as_deref(), Some("InternalError"));
                }
                _other => panic!("expected Undefined error kind"),
            }
        }
        _other => panic!("expected 500 completion for a non-true handleBuiltin, got something else"),
    }
}

/// A `{ "handleBuiltin": true }` output in a later layer — after earlier
/// layers pass — still hands off, and it short-circuits: the trailing layer
/// here would produce a 500 error if it were ever run.
#[test]
fn handle_builtin_after_pass_chain_hands_off() {
    let pass = r#"
        package arbiter
        result := { "pass": true }
        "#;
    let arbiter = arbiter(vec![
        layer("one", pass),
        layer(
            "two",
            r#"
            package arbiter
            result := { "handleBuiltin": true }
            "#,
        ),
        layer(
            "never-run",
            r#"
            package arbiter
            result := "not an object envelope"
            "#,
        ),
    ]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    match machine.start() {
        ArbiterReqMachineStep::HandToBuiltin => {}
        _other => panic!("expected handoff from the second layer, got something else"),
    }
}

/// A layer that issues an `xrpc` host call suspends the pipeline; after the
/// response arrives the layer resumes, passes, and the next layer handles.
#[test]
fn layer_xrpc_suspension_then_next_layer_handles() {
    let arbiter = arbiter(vec![
        layer(
            "fetching",
            r#"
            package arbiter
            resp := xrpc({ "did": "did:web:own-account.example#atproto_pds", "method": "GET", "nsid": "com.example.lookup", "parameters": null, "body": null })
            result := { "pass": resp.ok }
            "#,
        ),
        layer(
            "handling",
            r#"
            package arbiter
            result := { "ok": true, "output": { "looked_up": input.nsid } }
            "#,
        ),
    ]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    match machine.start() {
        ArbiterReqMachineStep::RemoteXrpcRequest { endpoint, .. } => {
            assert_eq!(endpoint, "did:web:own-account.example#atproto_pds");
        }
        _other => panic!("expected remote xrpc request from the first layer, got something else"),
    }

    let response: XrpcResult = Ok(XrpcOutput::Data(serde_json::json!({ "ok": true })));
    match machine.resume(response) {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json, serde_json::json!({ "looked_up": "com.example.foo" }));
        }
        _other => panic!("expected completion from the second layer, got something else"),
    }
}

/// Layer provenance (the `at://` URI and record CID the layer was loaded from)
/// is retained and exposed on the pipeline's layers, and those layers still
/// evaluate in order.
#[test]
fn layer_provenance_is_retained_and_exposed() {
    let uri = "at://did:plc:remote/town.muni.arbiter.policy/shared-mod";
    let cid = "bafyrei-test-cid".to_string();
    let remote = Layer::compile(
        r#"
        package arbiter
        result := { "ok": true, "output": { "from": "remote" } }
        "#,
        uri,
        Some(cid.clone()),
    )
    .expect("layer policy compiles");
    let local = Layer::new(
        arbiter_policy(
            r#"
            package arbiter
            result := { "pass": true }
            "#,
        ),
        "at://did:plc:local/town.muni.arbiter.policy/local-layer",
        None,
    );
    let mut pipeline = Pipeline::new();
    pipeline.push(remote);
    pipeline.push(local);

    assert_eq!(pipeline.len(), 2);
    assert!(!pipeline.is_empty());
    assert_eq!(pipeline.layers()[0].uri, uri);
    assert_eq!(pipeline.layers()[0].cid.as_deref(), Some("bafyrei-test-cid"));
    assert_eq!(
        pipeline.layers()[1].uri,
        "at://did:plc:local/town.muni.arbiter.policy/local-layer"
    );
    assert_eq!(pipeline.layers()[1].cid, None);

    // The provenance-carrying layers still evaluate in order: the first
    // passes, the second handles.
    let arbiter = Arbiter::new(pipeline);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );
    match machine.start() {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json, serde_json::json!({ "from": "remote" }));
        }
        _other => panic!("expected completion from the remote layer, got something else"),
    }
}

/// Binary request body: bytes are stashed into the machine's buffers and passed
/// to the layer as a `{ "$__bytes__": <idx> }` marker. The layer forwards the
/// marker as the body of an `xrpc` call, which resolves back to real bytes in
/// the emitted `XrpcRequest`.
#[test]
fn bytes_request_body_roundtrips_through_host_call() {
    let arbiter = arbiter(vec![layer(
        "root",
        r#"
        package arbiter
        result := resp
        resp := xrpc({ "did": "did:web:own-account.example#atproto_pds", "method": "POST", "nsid": "com.example.upload", "parameters": null, "body": input.body })
        "#,
    )]);
    let payload = b"\x00\x01\x02\xff binary".to_vec();
    let mut machine = arbiter.handle_request(
        make_req(
            http::Method::POST,
            "com.example.upload",
            Some(InputDataOrBytes::Bytes(payload.clone())),
        ),
        RequestCtx::default(),
    );

    let request = match machine.start() {
        ArbiterReqMachineStep::RemoteXrpcRequest { endpoint, request } => {
            assert_eq!(endpoint, "did:web:own-account.example#atproto_pds");
            request
        }
        _other => panic!("expected remote xrpc request, got something else"),
    };
    match request.input {
        Some(InputDataOrBytes::Bytes(bytes)) => assert_eq!(bytes, payload),
        _other => panic!("expected bytes body in emitted request, got something else"),
    }

    // The PDS responds with bytes output, which is stashed into buffers and
    // represented to the layer via a marker; the layer surfaces it as
    // `resp.bytes`, which the machine resolves back to bytes in the result.
    let resp_payload = b"response bytes".to_vec();
    match machine.resume(Ok(XrpcOutput::Bytes(resp_payload.clone()))) {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Bytes(bytes))) => {
            assert_eq!(bytes, resp_payload);
        }
        _other => panic!("expected byte output completion, got something else"),
    }
}

/// A layer that returns an error envelope denies the request with an `Err`
/// XrpcResult carrying the layer's status and error body.
#[test]
fn error_envelope_becomes_xrpc_error() {
    let arbiter = arbiter(vec![layer(
        "root",
        r#"
        package arbiter
        result := { "ok": false, "error": { "status": 418, "error": "ImATeapot", "message": "nope" } }
        "#,
    )]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

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

/// A layer that returns a malformed (non-object, non-pass) output is converted
/// to a 500 error XRPC response rather than bubbling up a `Result::Err`.
#[test]
fn internal_error_becomes_500_xrpc_error() {
    let arbiter = arbiter(vec![layer(
        "root",
        r#"
        package arbiter
        result := "not an object envelope"
        "#,
    )]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

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

/// A layer output of `{ "pass": false }` is neither the pass marker nor a
/// valid ok/err envelope, so it surfaces as a 500 InternalError response.
#[test]
fn pass_false_output_is_internal_error() {
    let arbiter = arbiter(vec![layer(
        "one",
        r#"
        package arbiter
        result := { "pass": false }
        "#,
    )]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    match machine.start() {
        ArbiterReqMachineStep::Completed(Err(err)) => {
            assert_eq!(err.status, http::StatusCode::INTERNAL_SERVER_ERROR);
        }
        _other => panic!("expected 500 completion, got something else"),
    }
}

/// The async driver has no built-in handler registry: a layer that hands the
/// request to the arbiter's built-in handler surfaces as a 500 InternalError
/// XRPC error (not a panic, and no remote call is attempted) — callers that
/// need built-in handling must drive [`ArbiterReqMachine`] manually and map
/// the step themselves.
#[test]
fn async_driver_surfaces_hand_to_builtin_as_internal_error() {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    struct NeverIo;
    impl ArbiterAsyncIo for NeverIo {
        async fn xrpc_request(&self, _endpoint: XrpcEndpoint, _request: XrpcRequest) -> XrpcResult {
            panic!("the async driver must not issue remote calls for a handoff");
        }
    }

    let arbiter = arbiter(vec![layer(
        "gate",
        r#"
        package arbiter
        result := { "handleBuiltin": true }
        "#,
    )]);
    let machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

    // This crate's tests run without an async runtime; the handoff path
    // completes without suspending on IO, so a single poll with a noop waker
    // drives the future to completion.
    let mut fut = pin!(machine.into_future(&NeverIo));
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(Err(err)) => {
            assert_eq!(err.status, http::StatusCode::INTERNAL_SERVER_ERROR);
            match err.error.expect("error kind present") {
                atrium_xrpc::error::XrpcErrorKind::Undefined(erb) => {
                    assert_eq!(erb.error.as_deref(), Some("InternalError"));
                    let message = erb.message.expect("error message present");
                    assert!(
                        message.contains("built-in handler"),
                        "the message must point at the manual-driving contract: {message}"
                    );
                }
                other => panic!("expected Undefined error kind, got {other:?}"),
            }
        }
        Poll::Ready(Ok(_)) => panic!("a handoff must not complete successfully"),
        Poll::Pending => panic!("the handoff path must not suspend"),
    }
}

/// Calling `resume` when not waiting on a remote response panics.
#[test]
#[should_panic(expected = "ArbiterReqMachine::resume called when not waiting")]
fn resume_without_pending_request_panics() {
    let arbiter = arbiter(vec![layer(
        "root",
        r#"
        package arbiter
        result := { "ok": true, "output": {} }
        "#,
    )]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );
    let _ = machine.start();
    let _ = machine.resume(Ok(XrpcOutput::Data(serde_json::Value::Null)));
}

/// Calling `start` more than once panics.
#[test]
#[should_panic(expected = "ArbiterReqMachine::start called more than once")]
fn start_called_twice_panics() {
    let arbiter = arbiter(vec![layer(
        "root",
        r#"
        package arbiter
        result := { "ok": true, "output": {} }
        "#,
    )]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );
    let _ = machine.start();
    let _ = machine.start();
}

/// The `$__bytes__` key is exported and matches the marker used internally.
#[test]
fn bytes_key_constant() {
    assert_eq!(BYTES_KEY, "$__bytes__");
}

/// An `encoding` field on an `xrpc` host-call argument is propagated to the
/// emitted remote XRPC request.
#[test]
fn encoding_passed_through_on_outgoing_xrpc() {
    let arbiter = arbiter(vec![layer(
        "root",
        r#"
        package arbiter
        result := xrpc({ "did": "did:web:own-account.example#atproto_pds", "method": "POST", "nsid": "com.example.upload", "encoding": "application/octet-stream", "parameters": null, "body": input.body })
        "#,
    )]);
    let payload = b"hello".to_vec();
    let req = XrpcRequest {
        method: http::Method::GET,
        nsid: "com.example.foo".to_string(),
        parameters: None,
        input: Some(InputDataOrBytes::Bytes(payload.clone())),
        encoding: None,
    };
    let mut machine = arbiter.handle_request(req, RequestCtx::default());
    match machine.start() {
        ArbiterReqMachineStep::RemoteXrpcRequest { endpoint, request } => {
            assert_eq!(endpoint, "did:web:own-account.example#atproto_pds");
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

/// The incoming request's `encoding` is surfaced to the layer as
/// `input.encoding`.
#[test]
fn incoming_encoding_surfaced_to_policy() {
    let arbiter = arbiter(vec![layer(
        "root",
        r#"
        package arbiter
        result := { "ok": true, "output": input.encoding }
        "#,
    )]);
    let req = XrpcRequest {
        method: http::Method::GET,
        nsid: "com.example.foo".to_string(),
        parameters: None,
        input: None,
        encoding: Some("image/png".to_string()),
    };
    let mut machine = arbiter.handle_request(req, RequestCtx::default());
    match machine.start() {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json.as_str(), Some("image/png"));
        }
        _other => panic!("expected data completion echoing the encoding, got something else"),
    }
}

/// A policy that calls an unregistered host function is resumed with an error
/// envelope. The policy can inspect `resp.ok` and handle the failure.
#[test]
fn unknown_host_function_returns_error_envelope() {
    let arbiter = arbiter(vec![Layer::new(
        arbiter_policy_with_host_fns(
            r#"
            package arbiter
            result := resp
            resp := unknown_fn({ "x": 1 })
            "#,
            &["unknown_fn"],
        ),
        "at://did:plc:test/town.muni.arbiter.policy/unknown-fn",
        None,
    )]);
    let mut machine = arbiter.handle_request(
        make_req(http::Method::GET, "com.example.foo", None),
        RequestCtx::default(),
    );

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

/// A scope policy is a pure allow/deny predicate over the request core: it
/// answers "is this request within the virtual scope" with the boolean
/// `data.arbiter.allow` — `true` allows; `false` via `default` denies. Scope
/// policies see no context fields, only the request core (`method`, `nsid`,
/// `parameters`, `body`, `encoding`).
#[test]
fn scope_policy_allows_matching_and_denies_other_requests() {
    let scope = ScopePolicy::new(
        r#"
        package arbiter
        default allow := false
        allow if {
            input.method == "POST"
            startswith(input.nsid, "com.example.")
        }
        "#,
    )
    .expect("scope policy compiles");

    // Matching request: allowed.
    assert!(
        scope
            .evaluate(&make_req(http::Method::POST, "com.example.calendars.update", None))
            .expect("evaluation succeeds")
    );

    // Wrong method: denied by the `default`.
    assert!(
        !scope
            .evaluate(&make_req(http::Method::GET, "com.example.calendars.update", None))
            .expect("evaluation succeeds")
    );

    // Non-matching nsid: denied by the `default`.
    assert!(
        !scope
            .evaluate(&make_req(http::Method::POST, "org.other.thing", None))
            .expect("evaluation succeeds")
    );
}

/// An explicit `allow := false` denies even when the rule itself matches.
#[test]
fn scope_policy_explicit_false_denies() {
    let scope = ScopePolicy::new(
        r#"
        package arbiter
        allow := false if {
            input.method == "GET"
        }
        "#,
    )
    .expect("scope policy compiles");

    // The rule matches, but the decision is an explicit `false`: deny.
    assert!(
        !scope
            .evaluate(&make_req(http::Method::GET, "com.example.thing", None))
            .expect("evaluation succeeds")
    );
}

/// A scope policy without a `default allow` denies by omission: when no
/// `allow` rule matches, `data.arbiter.allow` is undefined, which denies
/// (rather than surfacing an evaluation error).
#[test]
fn scope_policy_undefined_allow_denies() {
    let scope = ScopePolicy::new(
        r#"
        package arbiter
        allow if {
            input.method == "GET"
        }
        "#,
    )
    .expect("scope policy compiles");

    // No rule matches: the entrypoint is undefined → deny.
    assert!(
        !scope
            .evaluate(&make_req(http::Method::POST, "com.example.thing", None))
            .expect("evaluation succeeds")
    );

    // The matching request is allowed.
    assert!(
        scope
            .evaluate(&make_req(http::Method::GET, "com.example.thing", None))
            .expect("evaluation succeeds")
    );
}

/// A scope policy whose `allow` rule evaluates to a non-boolean value denies:
/// only boolean `true` allows.
#[test]
fn scope_policy_non_boolean_allow_denies() {
    let scope = ScopePolicy::new(
        r#"
        package arbiter
        allow := "yes"
        "#,
    )
    .expect("scope policy compiles");

    assert!(
        !scope
            .evaluate(&make_req(http::Method::GET, "com.example.thing", None))
            .expect("evaluation succeeds")
    );
}

/// Malformed scope policies fail at construction (compile time), never at
/// evaluation time: bad Rego syntax, a missing `data.arbiter.allow`
/// entrypoint, or use of a host function (scope policies are pure and have
/// none).
#[test]
fn malformed_scope_policy_fails_compilation() {
    // Rego syntax error.
    assert!(ScopePolicy::new("allow :=").is_err());
    // Entrypoint rule absent (the policy only defines the pipeline
    // `data.arbiter.result` entrypoint).
    assert!(ScopePolicy::new("package arbiter\nresult := true").is_err());
    // Host functions are not available to scope policies.
    assert!(ScopePolicy::new(
        "package arbiter\nallow := xrpc({ \"did\": \"x\", \"method\": \"GET\", \"nsid\": \"y\" })"
    )
    .is_err());

    // A well-formed scope policy still compiles.
    assert!(ScopePolicy::new("package arbiter\ndefault allow := true").is_ok());
}