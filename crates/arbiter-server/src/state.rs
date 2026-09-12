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
    /// The account's loaded config record's trusted scope prefixes
    /// (`town.muni.arbiter.config/self` `trustedScopes`). Scoped
    /// `<scope>.arbiter.proxy` requests are only accepted when the stripped
    /// scope prefix is listed here; anything else is rejected before any
    /// policy runs.
    trusted_scopes: Vec<String>,
    /// The repo `rev` the arbiter was loaded at (its PDS head commit, or a
    /// timestamp fallback). Any Jetstream event with `rev <= floor` refers to
    /// state already reflected in the loaded records, so it is discarded. The
    /// floor is only comparable within the *steward's* repo (repo revs are
    /// per-repo TID streams), so remote-record events are reloaded ungated
    /// (see the jetstream handler) — never gated against this floor.
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
    /// `trusted_scopes` are the account's config record's trusted scope
    /// prefixes, enforced by [`ArbiterCollection::check_trusted_scope`].
    /// `rev_floor` is the repo `rev` the policies were loaded at (the PDS head
    /// commit, captured before the records were read so the floor provably
    /// dominates the loaded state). Jetstream events at or below this rev
    /// describe state already reflected in the loaded records and are
    /// discarded. `None` means no floor could be determined (accept everything,
    /// risking only redundant reloads).
    ///
    /// Returns whether the entry was applied: `true` when the arbiter was
    /// newly inserted or the replacement was accepted; `false` when an
    /// existing entry with a newer `rev_floor` rejected the replacement (a
    /// concurrent load won the race and keeps its state). Callers that
    /// maintain state derived from the loaded pipeline (e.g. the policy
    /// module's reverse index) must only record it when this returns `true`,
    /// so the derived state mirrors the arbiter actually serving.
    pub async fn onboard(
        &self,
        did: String,
        arbiter: Arbiter,
        pds_endpoint: String,
        trusted_scopes: Vec<String>,
        rev_floor: Option<String>,
    ) -> bool {
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
                    existing.trusted_scopes = trusted_scopes;
                    existing.rev_floor = rev_floor;
                    true
                } else {
                    false
                }
            }
            None => {
                map.insert(
                    did,
                    ArbiterEntry {
                        arbiter,
                        pds_endpoint,
                        trusted_scopes,
                        rev_floor,
                    },
                );
                true
            }
        }
    }

    /// Stop serving an arbiter (e.g. its service record disappeared). Keeps
    /// credentials; the arbiter may be re-onboarded later. Returns was-active.
    pub async fn offboard(&self, did: &str) -> bool {
        self.inner.write().await.remove(did).is_some()
    }

    /// Whether `did` is currently serving (has an onboarded entry; offboard
    /// removes the entry).
    ///
    /// The reconnect refresh uses this to heal only arbiters that are *not*
    /// serving: a serving arbiter's pipeline was built from record-store
    /// state that a verified cursor replay has proven current, so
    /// re-onboarding it would be a no-op.
    pub async fn is_online(&self, did: &str) -> bool {
        self.inner.read().await.contains_key(did)
    }

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

    /// Gate a scoped `<scope>.arbiter.proxy` request on the account's loaded
    /// config record's trusted scopes.
    ///
    /// Fail-closed: an un-onboarded/offboarded arbiter yields
    /// `ArbiterNotReady`; a scope prefix that is not listed in the loaded
    /// config's `trustedScopes` yields `Forbidden` — the request is rejected
    /// before any policy (scope gate or pipeline) runs.
    pub async fn check_trusted_scope(&self, did: &str, prefix: &str) -> Result<(), AppError> {
        let map = self.inner.read().await;
        let entry = map
            .get(did)
            .ok_or_else(|| AppError::ArbiterNotReady(did.to_string()))?;
        if entry.trusted_scopes.iter().any(|s| s == prefix) {
            Ok(())
        } else {
            Err(AppError::Forbidden(format!(
                "scope `{prefix}` is not trusted by `{did}`"
            )))
        }
    }

    /// Whether the given repo `rev` refers to a commit this server has not yet
    /// loaded. It is accepted iff it is strictly newer than the load-time
    /// floor (revs at or below the floor are already reflected in the loaded
    /// records).
    ///
    /// Only meaningful for the steward repo's own rev stream: the floor is
    /// that repo's head, so callers must not gate events from other repos
    /// (e.g. remote policy-record writes) against it — cross-repo revs are
    /// incomparable. The jetstream handler reloads remote-record events
    /// ungated for exactly this reason.
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
