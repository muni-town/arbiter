//! serviceAuth verification.
//!
//! `CallerDid` is an axum extractor that verifies the caller's serviceAuth JWT
//! (issued by the caller's PDS via `com.atproto.server.getServiceAuth`) and
//! yields the caller DID (token `sub`) and the bound `lxm`.
//!
//! Verification model: the token is signed **by the caller's PDS**, not by the
//! account itself. The `iss` claim is the PDS DID; we resolve that PDS DID
//! document, extract its signing key from the verification methods, and verify
//! the JWT signature against it. This is a different key path than verifying
//! against the caller's own DID-document keys.

use std::sync::{Arc, LazyLock};

use atproto_identity::key::{identify_key, KeyData};
use atproto_identity::traits::IdentityResolver;
use atproto_oauth::encoding::FromBase64;
use atproto_oauth::jwt::{verify, Claims};
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use moka::future::Cache;

use crate::error::AppError;
use crate::CONFIG;
use crate::AppState;

/// Cache of PDS signing keys, keyed by PDS DID (the JWT `iss` claim).
///
/// serviceAuth tokens are signed by the caller's PDS, so the verifying key is
/// read from the PDS DID document (not the account's). Resolving a DID document
/// on every request would be expensive and rate-limit-prone, so the extracted
/// `KeyData` is memoized here.
static PDS_SIGNING_KEYS: LazyLock<Cache<String, KeyData>> = LazyLock::new(|| Cache::new(256));

/// The verified caller, extracted from a `Authorization: Bearer <serviceAuth>`
/// token. `did` is the token `sub`; `lxm` is the bound XRPC method. The
/// **handler** is responsible for checking `lxm == <request path NSID>` (the
/// extractor cannot see the path).
pub struct CallerDid {
    pub did: String,
    pub lxm: String,
}

impl FromRequestParts<Arc<AppState>> for CallerDid {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // 1. Extract `Authorization: Bearer <jwt>`.
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".into()))?;
        let jwt = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| {
                AppError::Unauthorized("Authorization header is not a Bearer token".into())
            })?
            .trim();
        if jwt.is_empty() {
            return Err(AppError::Unauthorized("empty Bearer token".into()));
        }

        // 2. Decode the claims WITHOUT verifying, to read `iss` (the PDS DID)
        //    so we know which PDS signing key to verify against.
        let claims_segment = jwt
            .split('.')
            .nth(1)
            .ok_or_else(|| AppError::Unauthorized("malformed serviceAuth JWT".into()))?;
        let unverified: Claims = Claims::from_base64(claims_segment).map_err(|e| {
            AppError::Unauthorized(format!("unable to decode serviceAuth claims: {e}"))
        })?;
        let pds_did = unverified
            .jose
            .issuer
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized("serviceAuth missing `iss` claim".into()))?;

        // 3. Resolve the PDS signing key (cached, keyed by PDS DID).
        let key_data = match PDS_SIGNING_KEYS.get(pds_did).await {
            Some(k) => k,
            None => {
                let key = resolve_pds_signing_key(&*state.resolver, pds_did).await?;
                PDS_SIGNING_KEYS
                    .insert(pds_did.to_string(), key.clone())
                    .await;
                key
            }
        };

        // 4. Verify the JWT signature against the PDS signing key. `verify`
        //    also rejects expired (`exp` past) and not-yet-valid (`nbf`) tokens.
        let claims = verify(jwt, &key_data).map_err(|e| {
            AppError::Unauthorized(format!("serviceAuth verification failed: {e}"))
        })?;

        // 5. Check `aud == CONFIG.server_did`.
        let aud = claims
            .jose
            .audience
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized("serviceAuth missing `aud` claim".into()))?;
        if aud != CONFIG.server_did {
            return Err(AppError::Unauthorized(format!(
                "serviceAuth `aud` `{aud}` does not match this server `{}`",
                CONFIG.server_did
            )));
        }

        // 6. Extract `sub` (caller DID) and `lxm` (bound NSID).
        let did = claims
            .jose
            .subject
            .ok_or_else(|| AppError::Unauthorized("serviceAuth missing `sub` claim".into()))?;
        let lxm = claims
            .private
            .get("lxm")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| AppError::Unauthorized("serviceAuth missing `lxm` claim".into()))?;

        Ok(CallerDid { did, lxm })
    }
}

/// Resolve a PDS DID document via `resolver` and extract its signing key from
/// the first `Multikey` verification method.
pub async fn resolve_pds_signing_key(
    resolver: &dyn IdentityResolver,
    pds_did: &str,
) -> Result<KeyData, AppError> {
    let doc = resolver.resolve(pds_did).await.map_err(|e| {
        AppError::Unauthorized(format!("unable to resolve PDS DID `{pds_did}`: {e}"))
    })?;
    let multibase = doc.did_keys().into_iter().next().ok_or_else(|| {
        AppError::Unauthorized(format!("PDS `{pds_did}` exposes no signing key"))
    })?;
    // `did_keys()` returns the raw multibase value; `identify_key` expects a
    // `did:key:`-prefixed (or bare multibase) string.
    let full = if multibase.starts_with("did:key:") {
        multibase.to_string()
    } else {
        format!("did:key:{multibase}")
    };
    identify_key(&full)
        .map_err(|e| AppError::Unauthorized(format!("invalid PDS signing key: {e}")))
}