//! Unit tests for `ArbiterCollection` — the in-memory arbiter registry.
//!
//! These tests cover the critical security invariants from SERVER_PLAN.md §4:
//! - **Monotonic rev gating**: older/duplicate revs must not regress policy.
//! - **Fail-closed**: un-onboarded arbiters must refuse requests (503).
//! - **Lifecycle**: onboard / offboard / contains.

use std::collections::HashMap;

use arbiter_core::arbiter::{Arbiter, ArbiterReqMachineStep, Policies, RequestCtx};
use arbiter_core::policy::PolicyVm;
use arbiter_core::xrpc::{XrpcOutput, XrpcRequest};
use atrium_xrpc::http;
use regorus::Value;

use arbiter_server::error::AppError;
use arbiter_server::state::ArbiterCollection;

/// Build a simple `Arbiter` with a root policy that immediately returns success.
fn test_arbiter() -> Arbiter {
    let root = PolicyVm::new(
        r#"
        package arbiter
        result := { "ok": true, "output": { "got": input.nsid } }
        "#,
        Value::new_object(),
        "data.arbiter.result",
        &["xrpc", "policy"],
    )
    .expect("policy compiles");
    Arbiter::new(Policies::new(root, HashMap::new()))
}

/// An arbiter whose root policy echoes a fixed `tag`, so tests can tell which
/// policy instance is currently active.
fn tagged_arbiter(tag: &str) -> Arbiter {
    let src = format!(
        r#"
        package arbiter
        result := {{ "ok": true, "output": {{ "tag": "{tag}" }} }}
        "#
    );
    let root = PolicyVm::new(&src, Value::new_object(), "data.arbiter.result", &["xrpc", "policy"])
        .expect("policy compiles");
    Arbiter::new(Policies::new(root, HashMap::new()))
}

/// Run the arbiter's root policy for `did` and return the `tag` in the output,
/// asserting the machine completes immediately.
async fn active_tag(col: &ArbiterCollection, did: &str) -> String {
    let mut drive = col
        .begin_request(did, make_req(), RequestCtx::default())
        .await
        .expect("begin_request");
    match drive.machine.start() {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            json.get("tag").and_then(serde_json::Value::as_str).unwrap().to_string()
        }
        other => panic!("expected immediate Data completion, got {other:?}"),
    }
}

fn make_req() -> XrpcRequest {
    XrpcRequest {
        method: http::Method::GET,
        nsid: "com.example.foo".to_string(),
        parameters: None,
        input: None,
        encoding: None,
    }
}

const DID_A: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const PDS_A: &str = "http://pds-a.example";

/// Whether `col` currently serves `did` (i.e. it is onboarded and active).
/// Mirrors the removed `ArbiterCollection::contains` check that this file used
/// to rely on.
async fn is_serving(col: &ArbiterCollection, did: &str) -> bool {
    col.begin_request(did, make_req(), RequestCtx::default())
        .await
        .is_ok()
}

// ─── fail-closed ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn fail_closed_unonboarded() {
    let col = ArbiterCollection::new();
    let result = col
        .begin_request(DID_A, make_req(), RequestCtx::default())
        .await;
    let err = result.err().expect("un-onboarded DID must fail");
    assert!(
        matches!(&err, AppError::ArbiterNotReady(d) if d == DID_A),
        "expected ArbiterNotReady, got {err:?}"
    );
}

// ─── onboard → request succeeds ──────────────────────────────────────────────

#[tokio::test]
async fn onboard_then_request_succeeds() {
    let col = ArbiterCollection::new();
    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string(), None)
        .await;

    assert!(is_serving(&col, DID_A).await);

    let mut drive = col
        .begin_request(DID_A, make_req(), RequestCtx::default())
        .await
        .expect("onboarded DID must succeed");
    assert_eq!(drive.pds_endpoint, PDS_A);

    // The machine should complete immediately (policy returns static result).
    match drive.machine.start() {
        ArbiterReqMachineStep::Completed(Ok(XrpcOutput::Data(json))) => {
            assert_eq!(json, serde_json::json!({ "got": "com.example.foo" }));
        }
        ArbiterReqMachineStep::Completed(Ok(_other)) => {
            panic!("expected Data output, got a different output variant");
        }
        other => panic!("expected immediate completion, got {other:?}"),
    }
}

// ─── offboard → fail-closed again ────────────────────────────────────────────

#[tokio::test]
async fn offboard_then_fail_closed() {
    let col = ArbiterCollection::new();
    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string(), None)
        .await;
    assert!(
        col.offboard(DID_A).await,
        "offboard should return was-active"
    );
    assert!(!is_serving(&col, DID_A).await);

    let result = col
        .begin_request(DID_A, make_req(), RequestCtx::default())
        .await;
    let err = result.err().expect("offboarded DID must fail");
    assert!(matches!(&err, AppError::ArbiterNotReady(_)));
}

#[tokio::test]
async fn offboard_unknown_returns_false() {
    let col = ArbiterCollection::new();
    assert!(!col.offboard("did:plc:unknown").await);
}

// ─── stale onboard does not regress (concurrent reload race) ────────────────

#[tokio::test]
async fn stale_onboard_does_not_regress() {
    // Two concurrent reloads for the same DID: a slower load that read an older
    // PDS snapshot (lower floor) must NOT overwrite the newer active policy +
    // floor when it finishes last.
    let col = ArbiterCollection::new();

    // Fresh load at rev "ccc" with tag "new".
    col.onboard(
        DID_A.to_string(),
        tagged_arbiter("new"),
        PDS_A.to_string(),
        Some("ccc".to_string()),
    )
    .await;
    assert_eq!(active_tag(&col, DID_A).await, "new");

    // Stale load at rev "aaa" (older snapshot) finishing afterwards.
    col.onboard(
        DID_A.to_string(),
        tagged_arbiter("stale"),
        PDS_A.to_string(),
        Some("aaa".to_string()),
    )
    .await;

    // The newer policy and floor must remain active.
    assert_eq!(active_tag(&col, DID_A).await, "new", "stale load regressed policy");
    assert!(
        !col.is_newer(DID_A, "bbb").await,
        "stale load lowered the floor"
    );
    assert!(col.is_newer(DID_A, "ddd").await);
}

#[tokio::test]
async fn equal_floor_onboard_replaces() {
    // A load at the same floor (same PDS snapshot) is applied, not dropped.
    let col = ArbiterCollection::new();
    col.onboard(
        DID_A.to_string(),
        tagged_arbiter("v1"),
        PDS_A.to_string(),
        Some("bbb".to_string()),
    )
    .await;
    col.onboard(
        DID_A.to_string(),
        tagged_arbiter("v2"),
        PDS_A.to_string(),
        Some("bbb".to_string()),
    )
    .await;
    assert_eq!(active_tag(&col, DID_A).await, "v2");
}

// ─── monotonic rev gating ────────────────────────────────────────────────────

#[tokio::test]
async fn rev_first_is_always_newer_without_floor() {
    // With no floor (e.g. a fresh arbiter where we failed to read the PDS head),
    // any rev is accepted — there is nothing to compare against.
    let col = ArbiterCollection::new();
    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string(), None)
        .await;
    assert!(
        col.is_newer(DID_A, "aaa").await,
        "without a floor, the first rev should be accepted"
    );
}

#[tokio::test]
async fn rev_at_or_below_floor_rejected() {
    // The load-time floor (the PDS head we read when loading) must reject any
    // event at or below it: that state is already reflected in the loaded
    // records. This is the restart case that a per-key dedup map could not
    // handle on its own, since it starts empty.
    let col = ArbiterCollection::new();
    col.onboard(
        DID_A.to_string(),
        test_arbiter(),
        PDS_A.to_string(),
        Some("ccc".to_string()),
    )
    .await;
    assert!(
        !col.is_newer(DID_A, "ccc").await,
        "rev at the floor must be rejected (already loaded)"
    );
    assert!(
        !col.is_newer(DID_A, "aaa").await,
        "rev below the floor must be rejected"
    );
    assert!(
        col.is_newer(DID_A, "ddd").await,
        "rev above the floor must be accepted"
    );
}

#[tokio::test]
async fn rev_newer_accepted() {
    let col = ArbiterCollection::new();
    col.onboard(
        DID_A.to_string(),
        test_arbiter(),
        PDS_A.to_string(),
        Some("aaa".to_string()),
    )
    .await;
    assert!(
        col.is_newer(DID_A, "bbb").await,
        "lexicographically newer rev should be accepted"
    );
    assert!(
        col.is_newer(DID_A, "aaa1").await,
        "longer rev with common prefix should be newer"
    );
}

#[tokio::test]
async fn rev_older_rejected() {
    let col = ArbiterCollection::new();
    col.onboard(
        DID_A.to_string(),
        test_arbiter(),
        PDS_A.to_string(),
        Some("bbb".to_string()),
    )
    .await;
    assert!(
        !col.is_newer(DID_A, "aaa").await,
        "older rev must be rejected (no regression)"
    );
}

#[tokio::test]
async fn rev_duplicate_rejected() {
    let col = ArbiterCollection::new();
    col.onboard(
        DID_A.to_string(),
        test_arbiter(),
        PDS_A.to_string(),
        Some("aaa".to_string()),
    )
    .await;
    assert!(
        !col.is_newer(DID_A, "aaa").await,
        "duplicate rev at the floor must be rejected"
    );
}

#[tokio::test]
async fn rev_offboarded_did_accepted() {
    // A DID not currently in the collection (offboarded, or never loaded) has
    // no floor to regress, so any event is accepted. Filtering of genuinely
    // unknown (non-stewarded) DIDs happens upstream in the jetstream handler's
    // `stewarded` gate, not here — this is what lets a re-import (service
    // record rewritten after an offboard) re-onboard via jetstream.
    let col = ArbiterCollection::new();
    assert!(
        col.is_newer("did:plc:unknown", "aaa").await,
        "offboarded/never-loaded DID should accept revs"
    );
}

#[tokio::test]
async fn rev_floor_reset_on_reonboard() {
    // Re-onboarding replaces the floor; the new floor governs subsequent events.
    let col = ArbiterCollection::new();
    col.onboard(
        DID_A.to_string(),
        test_arbiter(),
        PDS_A.to_string(),
        Some("ccc".to_string()),
    )
    .await;
    assert!(!col.is_newer(DID_A, "ccc").await);

    col.onboard(
        DID_A.to_string(),
        test_arbiter(),
        PDS_A.to_string(),
        Some("eee".to_string()),
    )
    .await;
    assert!(!col.is_newer(DID_A, "ddd").await, "below new floor");
    assert!(col.is_newer(DID_A, "fff").await, "above new floor");
}

// ─── multiple DIDs ──────────────────────────────────────────────────────────

#[tokio::test]
async fn multiple_dids_independent() {
    let col = ArbiterCollection::new();
    let did_b = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
    let pds_b = "http://pds-b.example";

    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string(), None)
        .await;
    col.onboard(did_b.to_string(), test_arbiter(), pds_b.to_string(), None)
        .await;

    assert!(is_serving(&col, DID_A).await);
    assert!(is_serving(&col, did_b).await);

    // Offboard one, the other stays.
    col.offboard(DID_A).await;
    assert!(!is_serving(&col, DID_A).await);
    assert!(is_serving(&col, did_b).await, "other DID should survive");

    // The surviving arbiter still works.
    let drive = col
        .begin_request(did_b, make_req(), RequestCtx::default())
        .await
        .expect("surviving arbiter should work");
    assert_eq!(drive.pds_endpoint, pds_b);
}
