//! In-memory collection of active arbiters, keyed by stewarded-account DID.
//!
//! One arbiter per stewarded account. All methods take a short-lived lock:
//! `begin_request` only holds the lock long enough to create the owned request
//! machine, then releases it before the caller does any async I/O.

use std::collections::HashMap;

use arbiter_core::arbiter::{Arbiter, ArbiterReqMachine, RequestCtx};
use arbiter_core::xrpc::XrpcRequest;
use tokio::sync::RwLock;

use crate::error::AppError;

/// The set of currently-active arbiters.
#[derive(Default)]
pub struct ArbiterCollection {
    /// `RwLock` so concurrent requests for *different* DIDs can clone their
    /// request machines in parallel (the hot path only reads). Writes are the
    /// rare jetstream lifecycle events (`onboard`/`offboard`/`set_rev`).
    inner: RwLock<HashMap<String, ArbiterEntry>>,
}

/// A loaded arbiter plus its per-arbiter state.
struct ArbiterEntry {
    arbiter: Arbiter,
    pds_endpoint: String,
    /// The repo `rev` the arbiter was loaded at (its PDS head commit, or a
    /// timestamp fallback). Any Jetstream event with `rev <= floor` refers to
    /// state already reflected in the loaded records, so it is discarded.
    ///
    /// This is the only rev state we need: every accepted event triggers a full
    /// reload that re-reads the PDS and replaces `rev_floor` with the then-current
    /// head. A replayed or out-of-order event at or below that head is rejected by
    /// the floor alone, so no per-record dedup map is necessary.
    rev_floor: Option<String>,
}

/// The result of beginning a request: an owned request machine (the arbiter's
/// policies have been cloned into it) plus the stewarded account's PDS
/// endpoint, so the caller can drive the machine and proxy without holding the
/// collection lock.
pub struct RequestDrive {
    pub machine: ArbiterReqMachine,
    pub pds_endpoint: String,
}

impl ArbiterCollection {
    pub fn new() -> Self {
        Self::default()
    }

    /// Onboard (or replace) an arbiter for the given DID with freshly loaded
    /// policies.
    ///
    /// `rev_floor` is the repo `rev` the policies were loaded at (the PDS head
    /// commit, captured before the records were read so the floor provably
    /// dominates the loaded state). Jetstream events at or below this rev
    /// describe state already reflected in the loaded records and are
    /// discarded. `None` means no floor could be determined (accept everything,
    /// risking only redundant reloads).
    ///
    /// The replacement is applied only if the incoming load is at least as
    /// fresh as the currently-applied floor (string comparison of repo revs).
    /// This closes a race where two reloads for the same DID run concurrently
    /// and a slower load, having read an older PDS snapshot, finishes last and
    /// would otherwise regress the active policy and its floor.
    pub async fn onboard(
        &self,
        did: String,
        arbiter: Arbiter,
        pds_endpoint: String,
        rev_floor: Option<String>,
    ) {
        let mut map = self.inner.write().await;
        match map.get_mut(&did) {
            Some(existing) => {
                // Only replace if the incoming floor is not older than the
                // current one. A fresh load at the same head is still applied
                // (both reflect the same PDS state).
                let apply = match (&existing.rev_floor, &rev_floor) {
                    (Some(cur), Some(new)) => new >= cur,
                    // No current floor: apply anything. No new floor: never
                    // regress a floored load.
                    (None, _) => true,
                    (Some(_), None) => false,
                };
                if apply {
                    existing.arbiter = arbiter;
                    existing.pds_endpoint = pds_endpoint;
                    existing.rev_floor = rev_floor;
                }
            }
            None => {
                map.insert(
                    did,
                    ArbiterEntry {
                        arbiter,
                        pds_endpoint,
                        rev_floor,
                    },
                );
            }
        }
    }

    /// Stop serving an arbiter (e.g. its service record disappeared). Keeps
    /// credentials; the arbiter may be re-onboarded later. Returns was-active.
    pub async fn offboard(&self, did: &str) -> bool {
        self.inner.write().await.remove(did).is_some()
    }

    /// Begin a request against the arbiter for `did`. Fail-closed: a missing
    /// arbiter (not yet loaded / offboarded) yields `ArbiterNotReady`.
    pub async fn begin_request(
        &self,
        did: &str,
        req: XrpcRequest,
        ctx: RequestCtx,
    ) -> Result<RequestDrive, AppError> {
        let map = self.inner.read().await;
        let entry = map
            .get(did)
            .ok_or_else(|| AppError::ArbiterNotReady(did.to_string()))?;
        let machine = entry.arbiter.handle_request(req, ctx);
        Ok(RequestDrive {
            machine,
            pds_endpoint: entry.pds_endpoint.clone(),
        })
    }

    /// Whether the given repo `rev` refers to a commit this server has not yet
    /// loaded. It is accepted iff it is strictly newer than the load-time
    /// floor (revs at or below the floor are already reflected in the loaded
    /// records).
    ///
    /// `rev`/`floor` comparison is string comparison: atproto repo revs are
    /// TID-based and lexicographically ordered, so a later commit sorts
    /// greater.
    pub async fn is_newer(&self, did: &str, rev: &str) -> bool {
        let map = self.inner.read().await;
        match map.get(did) {
            Some(entry) => entry.rev_floor.as_deref().is_none_or(|floor| rev > floor),
            // Not currently onboarded (offboarded or never loaded): there is no
            // floor to regress, so accept the event. This is what lets a
            // re-import (service record rewritten after an offboard) re-onboard
            // the arbiter via jetstream.
            None => true,
        }
    }
}
