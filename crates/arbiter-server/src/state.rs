//! In-memory collection of active arbiters, keyed by stewarded-account DID.
//!
//! One arbiter per stewarded account. All methods take a short-lived lock:
//! `begin_request` only holds the lock long enough to create the owned request
//! machine, then releases it before the caller does any async I/O.

use std::collections::HashMap;

use arbiter_core::arbiter::{Arbiter, ArbiterReqMachine, RequestCtx};
use arbiter_core::xrpc::XrpcRequest;
use tokio::sync::Mutex;

use crate::error::AppError;

/// A loaded arbiter plus its per-arbiter state.
struct ArbiterEntry {
    arbiter: Arbiter,
    pds_endpoint: String,
    /// Last-applied repo `rev` per policy/service record key, for monotonic
    /// reload.
    revs: HashMap<String, String>,
}

/// The result of beginning a request: an owned request machine (the arbiter's
/// policies have been cloned into it) plus the stewarded account's PDS
/// endpoint, so the caller can drive the machine and proxy without holding the
/// collection lock.
pub struct RequestDrive {
    pub machine: ArbiterReqMachine,
    pub pds_endpoint: String,
}

/// The set of currently-active arbiters.
#[derive(Default)]
pub struct ArbiterCollection {
    inner: Mutex<HashMap<String, ArbiterEntry>>,
}

impl ArbiterCollection {
    pub fn new() -> Self {
        Self::default()
    }

    /// Onboard (or replace) an arbiter for the given DID with freshly loaded
    /// policies. Resets rev tracking.
    pub async fn onboard(&self, did: String, arbiter: Arbiter, pds_endpoint: String) {
        let mut map = self.inner.lock().await;
        map.insert(
            did,
            ArbiterEntry {
                arbiter,
                pds_endpoint,
                revs: HashMap::new(),
            },
        );
    }

    /// Replace an existing arbiter's policies (hot reload), keeping its PDS
    /// endpoint and rev tracking. No-op if the arbiter is not active.
    pub async fn update_policies(&self, did: &str, arbiter: Arbiter) {
        let mut map = self.inner.lock().await;
        if let Some(entry) = map.get_mut(did) {
            entry.arbiter = arbiter;
        }
    }

    /// Stop serving an arbiter (e.g. its service record disappeared). Keeps
    /// credentials; the arbiter may be re-onboarded later. Returns was-active.
    pub async fn offboard(&self, did: &str) -> bool {
        self.inner.lock().await.remove(did).is_some()
    }

    /// Whether an arbiter is currently active (policies loaded).
    pub async fn contains(&self, did: &str) -> bool {
        self.inner.lock().await.contains_key(did)
    }

    /// Begin a request against the arbiter for `did`. Fail-closed: a missing
    /// arbiter (not yet loaded / offboarded) yields `ArbiterNotReady`.
    pub async fn begin_request(
        &self,
        did: &str,
        req: XrpcRequest,
        ctx: RequestCtx,
    ) -> Result<RequestDrive, AppError> {
        let mut map = self.inner.lock().await;
        let entry = map
            .get_mut(did)
            .ok_or_else(|| AppError::ArbiterNotReady(did.to_string()))?;
        let machine = entry.arbiter.handle_request(req, ctx);
        Ok(RequestDrive {
            machine,
            pds_endpoint: entry.pds_endpoint.clone(),
        })
    }

    /// Whether the given `rev` is strictly newer than the last-applied rev for
    /// `key` (string comparison; atproto repo revs are TID-based and
    /// lexicographically ordered), or if no rev is stored yet.
    pub async fn is_newer(&self, did: &str, key: &str, rev: &str) -> bool {
        let map = self.inner.lock().await;
        match map.get(did) {
            Some(entry) => entry
                .revs
                .get(key)
                .is_none_or(|old| rev > old.as_str()),
            None => false,
        }
    }

    /// Record the last-applied `rev` for a record key.
    pub async fn set_rev(&self, did: &str, key: &str, rev: String) {
        let mut map = self.inner.lock().await;
        if let Some(entry) = map.get_mut(did) {
            entry.revs.insert(key.to_string(), rev);
        }
    }
}