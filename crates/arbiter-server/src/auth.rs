//! serviceAuth verification.
//!
//! `CallerDid` is an axum extractor that verifies the caller's serviceAuth JWT
//! (issued via `com.atproto.server.getServiceAuth`) and yields the caller DID
//! (the token `iss`) and the bound `lxm`.
//!
//! Verification model: the token is signed **by the caller account** (not by
//! the PDS). The `iss` claim is the caller's DID; we resolve that DID document,
//! extract its signing key from the verification methods, and verify the JWT
//! signature against it. The caller DID is the `iss` claim — canonical ATProto
//! serviceAuth tokens carry no `sub` claim.

use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use atproto_identity::key::{KeyData, identify_key};
use atproto_identity::model::VerificationMethod;
use atproto_identity::traits::IdentityResolver;
use atproto_oauth::encoding::FromBase64;
use atproto_oauth::jwt::{Claims, verify};
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use moka::future::Cache;

use crate::AppState;
use crate::CONFIG;
use crate::error::AppError;

/// Maximum acceptable age of a serviceAuth token (seconds). serviceAuth tokens
/// are short-lived (default 60s; at most a few minutes), so we reject anything
/// older than this. This bounds how long a replayed token stays valid and how
/// long a `jti` lingers in the replay cache.
const MAX_TOKEN_AGE_SECS: u64 = 5 * 60;

/// Maximum forward clock skew tolerated on `iat` (seconds), so a slightly
/// fast verifier clock doesn't reject a freshly-minted token.
const MAX_CLOCK_SKEW_SECS: u64 = 30;

/// Cache of seen `jti` values for replay protection, keyed by `(issuer DID, jti)`.
/// Entries live for [`MAX_TOKEN_AGE_SECS`] — as long as the token could
/// legitimately be valid — so a replayed token within that window is rejected.
static SEEN_JTIS: LazyLock<Cache<(String, String), ()>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(100_000)
        .time_to_live(Duration::from_secs(MAX_TOKEN_AGE_SECS))
        .build()
});

/// Cache of signing keys, keyed by `(issuer DID, kid)` (the JWT `iss` claim
/// and the token header's `kid`).
///
/// serviceAuth tokens are signed by the caller account, so the verifying key
/// is read from the caller's own DID document. Resolving a DID document on
/// every request would be expensive and rate-limit-prone, so the extracted
/// `KeyData` is memoized here. Keying by `kid` as well as the issuer DID means
/// a key rotation (which changes the `kid`) naturally misses the stale cache
/// entry and resolves the current key instead of serving the old one for the
/// whole TTL. A short TTL still bounds how long a *deleted* key lingers.
static PDS_SIGNING_KEYS: LazyLock<Cache<(String, String), KeyData>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(256)
        .time_to_live(Duration::from_secs(12 * 60 * 60))
        .build()
});

/// The verified caller, extracted from a `Authorization: Bearer <serviceAuth>`
/// token. `did` is the token `iss` (the caller account); `lxm` is the bound
/// XRPC method. The **handler** is responsible for checking `lxm == <request
/// path NSID>` (the extractor cannot see the path).
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

        // 2. Decode the claims WITHOUT verifying, to read `iss` (the caller
        //    account DID) so we know which signing key to verify against. In
        //    canonical ATProto, serviceAuth tokens are signed by the *caller
        //    account's* signing key with `iss` = the caller account DID (and no
        //    `sub` claim). Resolving that DID's document and extracting its key
        //    is therefore the correct verification path.
        let claims_segment = jwt
            .split('.')
            .nth(1)
            .ok_or_else(|| AppError::Unauthorized("malformed serviceAuth JWT".into()))?;
        let unverified: Claims = Claims::from_base64(claims_segment).map_err(|e| {
            AppError::Unauthorized(format!("unable to decode serviceAuth claims: {e}"))
        })?;
        let issuer_did = unverified
            .jose
            .issuer
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized("serviceAuth missing `iss` claim".into()))?;

        // Decode the header (unverified) to read the `kid`, so we select the
        // specific signing key the token claims to be signed with rather than
        // blindly taking the first key in the PDS's DID document.
        let header_segment = jwt
            .split('.')
            .next()
            .ok_or_else(|| AppError::Unauthorized("malformed serviceAuth JWT".into()))?;
        let unverified_header: atproto_oauth::jwt::Header = FromBase64::from_base64(header_segment)
            .map_err(|e| AppError::Unauthorized(format!("unable to decode serviceAuth header: {e}")))?;
        let kid = unverified_header.key_id;

        // 3. Resolve the caller's signing key named by `kid` (cached by
        //    (issuer DID, kid)). If `kid` is absent we fall back to the first
        //    key in the issuer's DID document.
        let key_data = match PDS_SIGNING_KEYS
            .get(&(issuer_did.to_string(), kid.clone().unwrap_or_default()))
            .await
        {
            Some(k) => k,
            None => {
                let key =
                    resolve_pds_signing_key(&*state.resolver, issuer_did, kid.as_deref()).await?;
                PDS_SIGNING_KEYS
                    .insert((issuer_did.to_string(), kid.clone().unwrap_or_default()), key.clone())
                    .await;
                key
            }
        };

        // 4. Verify the JWT signature against the PDS signing key. `verify`
        //    also rejects expired (`exp` past) and not-yet-valid (`nbf`) tokens.
        let claims = verify(jwt, &key_data)
            .map_err(|e| AppError::Unauthorized(format!("serviceAuth verification failed: {e}")))?;

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

        // 5b. Reject stale tokens and enforce replay protection.
        //     - `iat` must be within a small clock-skew window (rejects
        //       replayed or overly-aged tokens, and tokens whose lifetime is
        //       absurdly long even if `exp` is far out).
        //     - `jti` must be present and unique per (issuer, jti) within the
        //       token's plausible lifetime.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
            AppError::Unauthorized("system clock error".into())
        })?.as_secs();
        let iat = claims
            .jose
            .issued_at
            .ok_or_else(|| AppError::Unauthorized("serviceAuth missing `iat` claim".into()))?;
        if now.saturating_sub(iat) > MAX_TOKEN_AGE_SECS + MAX_CLOCK_SKEW_SECS {
            return Err(AppError::Unauthorized(format!(
                "serviceAuth token is too old (iat {iat}, now {now})"
            )));
        }
        if iat > now + MAX_CLOCK_SKEW_SECS {
            return Err(AppError::Unauthorized("serviceAuth token is from the future".into()));
        }
        let jti = claims
            .jose
            .json_web_token_id
            .clone()
            .ok_or_else(|| AppError::Unauthorized("serviceAuth missing `jti` claim".into()))?;
        let jti_key = (issuer_did.to_string(), jti);
        if SEEN_JTIS.get(&jti_key).await.is_some() {
            return Err(AppError::Unauthorized("serviceAuth token replay detected".into()));
        }
        SEEN_JTIS.insert(jti_key, ()).await;

        // 6. The caller DID is the token `iss` (the account that requested the
        //    service auth). Canonical ATProto serviceAuth tokens carry no `sub`
        //    claim, so we do not require one.
        let did = issuer_did.to_string();
        let lxm = claims
            .private
            .get("lxm")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| AppError::Unauthorized("serviceAuth missing `lxm` claim".into()))?;

        Ok(CallerDid { did, lxm })
    }
}

/// Resolve the DID document for `issuer_did` (the token `iss`, i.e. the caller
/// account) via `resolver` and extract the `Multikey` signing key named by
/// `kid` (the JWT header's key id, in `did:key:` form).
///
/// The `kid` lets us pick the specific signing key a token claims to be signed
/// with, so an account exposing multiple keys is handled correctly. When `kid`
/// is `None`, the first `Multikey` verification method is used as a fallback.
pub async fn resolve_pds_signing_key(
    resolver: &dyn IdentityResolver,
    issuer_did: &str,
    kid: Option<&str>,
) -> Result<KeyData, AppError> {
    let doc = resolver.resolve(issuer_did).await.map_err(|e| {
        AppError::Unauthorized(format!("unable to resolve issuer DID `{issuer_did}`: {e}"))
    })?;
    let multibase = match kid {
        // The header `kid` is the public key's `did:key:` string; a DID doc
        // `Multikey` stores the raw multibase (`z...`) under the same key.
        Some(kid) if kid.starts_with("did:key:") => {
            let want = kid.strip_prefix("did:key:").unwrap();
            doc.verification_method.iter().find_map(|vm| match vm {
                VerificationMethod::Multikey {
                    public_key_multibase,
                    ..
                } if public_key_multibase == want => Some(public_key_multibase.as_str()),
                _ => None,
            })
        }
        Some(kid) => {
            // Non-standard `kid`; still allow matching a bare-multibase kid.
            doc.verification_method.iter().find_map(|vm| match vm {
                VerificationMethod::Multikey {
                    public_key_multibase,
                    ..
                } if public_key_multibase == kid => Some(public_key_multibase.as_str()),
                _ => None,
            })
        }
        None => None,
    };
    let multibase = multibase.or_else(|| doc.did_keys().into_iter().next()).ok_or_else(|| {
        AppError::Unauthorized(format!("issuer `{issuer_did}` exposes no signing key matching kid"))
    })?;

    let full = if multibase.starts_with("did:key:") {
        multibase.to_string()
    } else {
        format!("did:key:{multibase}")
    };
    identify_key(&full).map_err(|e| AppError::Unauthorized(format!("invalid signing key: {e}")))
}
