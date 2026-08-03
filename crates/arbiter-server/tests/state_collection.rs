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
    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string())
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
    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string())
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

// ─── onboard resets rev tracking ─────────────────────────────────────────────

#[tokio::test]
async fn onboard_resets_revs() {
    let col = ArbiterCollection::new();
    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string())
        .await;
    col.set_rev(DID_A, "root", "zzz".to_string()).await;
    assert!(
        !col.is_newer(DID_A, "root", "aaa").await,
        "rev should be tracked"
    );

    // Re-onboard resets revs.
    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string())
        .await;
    assert!(
        col.is_newer(DID_A, "root", "aaa").await,
        "rev tracking should be reset after re-onboard"
    );
}

// ─── monotonic rev gating ────────────────────────────────────────────────────

#[tokio::test]
async fn rev_first_is_always_newer() {
    let col = ArbiterCollection::new();
    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string())
        .await;
    assert!(
        col.is_newer(DID_A, "root", "aaa").await,
        "first rev for a key should always be newer"
    );
}

#[tokio::test]
async fn rev_newer_accepted() {
    let col = ArbiterCollection::new();
    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string())
        .await;
    col.set_rev(DID_A, "root", "aaa".to_string()).await;
    assert!(
        col.is_newer(DID_A, "root", "bbb").await,
        "lexicographically newer rev should be accepted"
    );
    assert!(
        col.is_newer(DID_A, "root", "aaa1").await,
        "longer rev with common prefix should be newer"
    );
}

#[tokio::test]
async fn rev_older_rejected() {
    let col = ArbiterCollection::new();
    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string())
        .await;
    col.set_rev(DID_A, "root", "bbb".to_string()).await;
    assert!(
        !col.is_newer(DID_A, "root", "aaa").await,
        "older rev must be rejected (no regression)"
    );
}

#[tokio::test]
async fn rev_duplicate_rejected() {
    let col = ArbiterCollection::new();
    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string())
        .await;
    col.set_rev(DID_A, "root", "aaa".to_string()).await;
    assert!(
        !col.is_newer(DID_A, "root", "aaa").await,
        "duplicate rev must be rejected"
    );
}

#[tokio::test]
async fn rev_unknown_did_rejected() {
    let col = ArbiterCollection::new();
    assert!(
        !col.is_newer("did:plc:unknown", "root", "aaa").await,
        "unknown DID should not accept revs"
    );
}

#[tokio::test]
async fn rev_per_key_independent() {
    let col = ArbiterCollection::new();
    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string())
        .await;

    // Set rev for "root" key.
    col.set_rev(DID_A, "root", "mmm".to_string()).await;
    assert!(
        !col.is_newer(DID_A, "root", "aaa").await,
        "root rev is tracked"
    );

    // "sub" key should be independent — first rev always newer.
    assert!(
        col.is_newer(DID_A, "sub/moderation", "aaa").await,
        "different key should not share rev tracking"
    );

    // Set "sub" rev and verify independence.
    col.set_rev(DID_A, "sub/moderation", "bbb".to_string())
        .await;
    assert!(
        col.is_newer(DID_A, "root", "zzz").await,
        "root key should accept newer rev independent of sub key"
    );
    assert!(
        col.is_newer(DID_A, "sub/moderation", "ccc").await,
        "sub key should accept newer rev independent of root key"
    );
    assert!(
        !col.is_newer(DID_A, "sub/moderation", "aaa").await,
        "sub key should reject older rev"
    );
}

#[tokio::test]
async fn rev_set_persists() {
    let col = ArbiterCollection::new();
    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string())
        .await;

    col.set_rev(DID_A, "root", "ccc".to_string()).await;
    // Verify the rev was stored by checking is_newer.
    assert!(
        !col.is_newer(DID_A, "root", "ccc").await,
        "same rev is not newer"
    );
    assert!(
        !col.is_newer(DID_A, "root", "bbb").await,
        "older rev is not newer"
    );
    assert!(
        col.is_newer(DID_A, "root", "ddd").await,
        "newer rev is newer"
    );
}

// ─── multiple DIDs ──────────────────────────────────────────────────────────

#[tokio::test]
async fn multiple_dids_independent() {
    let col = ArbiterCollection::new();
    let did_b = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
    let pds_b = "http://pds-b.example";

    col.onboard(DID_A.to_string(), test_arbiter(), PDS_A.to_string())
        .await;
    col.onboard(did_b.to_string(), test_arbiter(), pds_b.to_string())
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
