//! WebAssembly bindings for [`arbiter-core`].
//!
//! Provides an [`ArbiterStateMachine`] that wraps the sans-IO [`StateMachine`]
//! for use in the browser.  Complex types are passed as [`JsValue`] and
//! deserialized by `serde-wasm-bindgen` — JS callers pass objects/arrays
//! directly without manual stringification.
//!
//! # Architecture
//!
//! The simulator keeps a collection of [`ArbiterStateMachine`]s (one per DID)
//! and drives them by feeding events and routing actions:
//!
//! ```text
//! ┌──────────────┐   IncomingXrpc    ┌──────────────────┐
//! │   Simulator   │ ───────────────→ │ ArbiterStateMachine │
//! │  (JS / TS)   │                  │   (Rust WASM)     │
//! │              │ ←─────────────── │                   │
//! └──────────────┘    Vec<IoAction>  └──────────────────┘
//! ```
//!
//! - `handleIncomingXrpc` → feed an XRPC call from a user/client
//! - `handleRemoteResult` → feed the response from a remote XRPC request
//!
//! Each call returns an array of [`IoActionView`] objects.  The simulator
//! processes them: sends responses back, or routes `xrpc_remote` requests
//! to the target machine.

// use serde::Serialize;
// use serde_wasm_bindgen::Serializer;
use wasm_bindgen::prelude::*;

/// Install a panic hook that logs the panic message to the console.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

// // ---------------------------------------------------------------------------
// // Serialization helpers
// // ---------------------------------------------------------------------------

// /// Serialize any serde-able value to a JsValue (maps become plain objects).
// fn to_js_value<T: Serialize>(v: &T) -> Result<JsValue, JsValue> {
//     v.serialize(&Serializer::json_compatible())
//         .map_err(|e| JsValue::from_str(&e.to_string()))
// }

// /// Deserialize a JsValue into a Rust type.
// fn from_js_value<T: serde::de::DeserializeOwned>(v: JsValue) -> Result<T, JsValue> {
//     serde_wasm_bindgen::from_value(v).map_err(|e| JsValue::from_str(&e.to_string()))
// }

// // ---------------------------------------------------------------------------
// // ArbiterStateMachine — wraps arbiter_core::StateMachine
// // ---------------------------------------------------------------------------

// /// A single arbiter's state machine, exposed to JavaScript/WASM.
// ///
// /// Create one with [`new`](Self::new) or [`fromState`](Self::from_state),
// /// then feed events with [`handleIncomingXrpc`](Self::handle_incoming_xrpc)
// /// and [`handleRemoteResult`](Self::handle_remote_result).
// ///
// /// Each method returns an array of action objects that the host must process.
// #[wasm_bindgen]
// pub struct ArbiterStateMachine {
//     inner: StateMachine,
// }

// #[wasm_bindgen]
// impl ArbiterStateMachine {
//     /// Create a new arbiter with an initial owner.
//     ///
//     /// - `did` — the arbiter's DID (e.g. `"did:plc:abc"`)
//     /// - `config` — a JS object with the arbiter's configuration.
//     ///   It MUST include `$type: "town.muni.arbiter.server.v1.config"`
//     ///   and a `policy` (the raw Rego source) field.
//     /// - `owner_did` — the initial owner's DID
//     #[wasm_bindgen(constructor)]
//     pub fn new(
//         did: &str,
//         config: JsValue,
//         policy: &str,
//         owner_did: &str,
//     ) -> Result<ArbiterStateMachine, JsValue> {
//         let mut config: serde_json::Value = from_js_value(config)?;
//         // Merge the policy and $type into the config object — always override
//         // $type to the canonical value so existing JS callers (which use
//         // legacy $type values like "town.muni.arbiter.config.regoPolicy")
//         // continue to work.
//         if let Some(obj) = config.as_object_mut() {
//             obj.insert("policy".into(), serde_json::Value::String(policy.into()));
//             obj.insert(
//                 "$type".into(),
//                 serde_json::Value::String("town.muni.arbiter.server.v1.config".into()),
//             );
//         }
//         let mut sm = StateMachine::create(did.into(), config).map_err(|e| {
//             JsValue::from_str(&format!("Failed to create arbiter state machine: {e}"))
//         })?;
//         // Bootstrap admin space with owner
//         Self::init_admin_space(&mut sm, owner_did);
//         Ok(ArbiterStateMachine { inner: sm })
//     }

//     /// Bootstrap the `$admin` space with an Owner member.
//     fn init_admin_space(sm: &mut StateMachine, owner_did: &str) {
//         let admin_id = SpaceId {
//             space_key: "$admin".into(),
//             space_type: "town.muni.arbiter.config.adminSpace".into(),
//         };
//         sm.arbiter.spaces.insert(
//             admin_id,
//             arbiter_core::Space {
//                 key: "$admin".into(),
//                 space_type: "town.muni.arbiter.config.adminSpace".into(),
//                 config: serde_json::json!({}),
//                 members: vec![arbiter_core::MemberEntry {
//                     did: owner_did.into(),
//                     access: serde_json::json!({"level": "Owner"}),
//                 }],
//             },
//         );
//     }

//     /// Restore a state machine from a previously serialised arbiter state.
//     ///
//     /// The argument must be a JS object produced by
//     /// [`serialiseState`](Self::serialise_state).
//     #[wasm_bindgen(js_name = fromState)]
//     pub fn from_state(state: JsValue) -> Result<ArbiterStateMachine, JsValue> {
//         let arbiter: ArbiterState = from_js_value(state)?;
//         Ok(ArbiterStateMachine {
//             inner: StateMachine::new(arbiter),
//         })
//     }

//     /// Serialise the current arbiter state into a plain JS object (for
//     /// snapshots / persistence).
//     ///
//     /// The spaces HashMap is serialized as an array of [key, value] pairs
//     /// to avoid JSON key restrictions on non-string keys.
//     #[wasm_bindgen(js_name = serialiseState)]
//     pub fn serialise_state(&self) -> Result<JsValue, JsValue> {
//         let arbiter = &self.inner.arbiter;
//         // Convert HashMap<SpaceId, Space> to Vec<(SerialisableSpaceId, &Space)>
//         // to avoid serde_json's "Map key is not a string" error.
//         // Convert HashMap<SpaceId, Space> to Vec<[SpaceId, Space]> pairs
//         // to avoid serde_json's "Map key is not a string" error.
//         // This matches the format that serde expects for HashMap with non-string
//         // keys (sequence of [key, value] tuples).
//         let spaces: Vec<[SerialisableSpaceEntry; 2]> = arbiter
//             .spaces
//             .iter()
//             .map(|(id, space)| {
//                 [
//                     SerialisableSpaceEntry::Key(SerialisableSpaceId {
//                         space_type: &id.space_type,
//                         space_key: &id.space_key,
//                     }),
//                     SerialisableSpaceEntry::Value(space),
//                 ]
//             })
//             .collect();
//         to_js_value(&StateView {
//             did: &arbiter.did,
//             version: arbiter.version,
//             config: &arbiter.config,
//             spaces: &spaces,
//         })
//     }

//     // -------------------------------------------------------------------
//     // State accessors
//     // -------------------------------------------------------------------

//     /// The arbiter's DID.
//     #[wasm_bindgen(getter)]
//     pub fn did(&self) -> String {
//         self.inner.arbiter.did.clone()
//     }

//     /// The arbiter's version number (incremented on each mutation).
//     #[wasm_bindgen(getter)]
//     pub fn version(&self) -> u64 {
//         self.inner.arbiter.version
//     }

//     /// The arbiter's configuration object.
//     #[wasm_bindgen(getter)]
//     pub fn config(&self) -> Result<JsValue, JsValue> {
//         to_js_value(&self.inner.arbiter.config)
//     }

//     /// The arbiter's Rego policy source string.
//     #[wasm_bindgen(getter)]
//     pub fn policy(&self) -> String {
//         self.inner
//             .arbiter
//             .config
//             .get("policy")
//             .and_then(|v| v.as_str())
//             .unwrap_or("")
//             .to_string()
//     }

//     /// Set the arbiter's Rego policy.  The state machine will use it for
//     /// subsequent evaluations.  (Does not validate — call [`validate_policy`]
//     /// first.)
//     #[wasm_bindgen(js_name = setPolicy)]
//     pub fn set_policy(&mut self, policy: &str) {
//         if let Some(obj) = self.inner.arbiter.config.as_object_mut() {
//             obj.insert("policy".into(), serde_json::Value::String(policy.into()));
//         }
//     }

//     // -------------------------------------------------------------------
//     // Space access
//     // -------------------------------------------------------------------

//     /// Get information about a space.  Returns `null` if the space does not
//     /// exist.
//     ///
//     /// - `space_key` — the space's key (e.g. `"$admin"`, `"team"`)
//     /// - `space_type` — the space's type
//     ///   (e.g. `"town.muni.arbiter.config.adminSpace"`)
//     #[wasm_bindgen(js_name = getSpace)]
//     pub fn get_space(&self, space_key: &str, space_type: &str) -> Result<JsValue, JsValue> {
//         let id = SpaceId {
//             space_key: space_key.into(),
//             space_type: space_type.into(),
//         };
//         match self.inner.arbiter.get_space(&id) {
//             Some(space) => to_js_value(&SpaceView {
//                 key: &space.key,
//                 space_type: &space.space_type,
//                 config: &space.config,
//                 members: &space.members,
//             }),
//             None => Ok(JsValue::NULL),
//         }
//     }

//     /// List all spaces on this arbiter as an array of objects.
//     #[wasm_bindgen(js_name = listSpaces)]
//     pub fn list_spaces(&self) -> Result<JsValue, JsValue> {
//         let spaces: Vec<SpaceView<'_>> = self
//             .inner
//             .arbiter
//             .spaces
//             .values()
//             .map(|s| SpaceView {
//                 key: &s.key,
//                 space_type: &s.space_type,
//                 config: &s.config,
//                 members: &s.members,
//             })
//             .collect();
//         to_js_value(&spaces)
//     }

//     // -------------------------------------------------------------------
//     // Event handling
//     // -------------------------------------------------------------------

//     /// Feed an incoming XRPC call to the state machine.
//     ///
//     /// Returns an array of action objects that the host must process.
//     ///
//     /// - `nsid` — the XRPC method NSID
//     ///   (e.g. `"town.muni.arbiter.getArbiterConfig"`)
//     /// - `method` — `"query"` or `"procedure"`
//     /// - `params` — a JS object with the call parameters
//     /// - `caller_did` — the DID of the caller
//     #[wasm_bindgen(js_name = handleIncomingXrpc)]
//     pub fn handle_incoming_xrpc(
//         &mut self,
//         nsid: &str,
//         method: &str,
//         params: JsValue,
//         caller_did: &str,
//     ) -> Result<JsValue, JsValue> {
//         let method = parse_method(method)?;
//         let params: serde_json::Value = from_js_value(params)?;
//         let event = Event::IncomingXrpc {
//             nsid: nsid.into(),
//             method,
//             params,
//             caller_did: caller_did.into(),
//         };
//         let actions = self.inner.handle_event(event);
//         io_actions_to_js(actions)
//     }

//     /// Feed the result of a remote XRPC request back to the state machine.
//     ///
//     /// Returns an array of action objects (may include further remote
//     /// requests or a final response).
//     ///
//     /// - `status` — the HTTP status code
//     /// - `body` — the response body (any JS value)
//     /// - `job_id` — the job ID from the original [`IoActionView`] request
//     #[wasm_bindgen(js_name = handleRemoteResult)]
//     pub fn handle_remote_result(
//         &mut self,
//         status: u16,
//         body: JsValue,
//         job_id: u64,
//     ) -> Result<JsValue, JsValue> {
//         let body: serde_json::Value = from_js_value(body)?;
//         let event = Event::XrpcRemoteResult {
//             status,
//             body,
//             job_id,
//         };
//         let actions = self.inner.handle_event(event);
//         io_actions_to_js(actions)
//     }
// }

// // ---------------------------------------------------------------------------
// // IoAction conversion
// // ---------------------------------------------------------------------------

// /// Convert a `Vec<IoAction>` into a JS array of plain objects.
// fn io_actions_to_js(actions: Vec<IoAction>) -> Result<JsValue, JsValue> {
//     let mut result = Vec::with_capacity(actions.len());
//     for action in actions {
//         match action {
//             IoAction::SendXrpcResponse { body, status } => {
//                 result.push(IoActionView::Response { body, status });
//             }
//             IoAction::SendXrpcRequest {
//                 did,
//                 method,
//                 nsid,
//                 input,
//                 job_id,
//             } => {
//                 result.push(IoActionView::Request {
//                     did,
//                     method: method.to_string(),
//                     nsid,
//                     input,
//                     job_id,
//                 });
//             }
//         }
//     }
//     to_js_value(&result)
// }

// // ---------------------------------------------------------------------------
// // Serialisable view types
// // ---------------------------------------------------------------------------

// /// A serialisable view of an [`IoAction`] for JS consumption.
// #[derive(Serialize)]
// #[serde(tag = "kind")]
// enum IoActionView {
//     #[serde(rename = "response")]
//     Response {
//         body: serde_json::Value,
//         status: u16,
//     },
//     #[serde(rename = "request")]
//     Request {
//         did: String,
//         method: String,
//         nsid: String,
//         input: serde_json::Value,
//         #[serde(rename = "jobId")]
//         job_id: u64,
//     },
// }

// /// A serialisable view of a [`Space`] for JS consumption.
// #[derive(Serialize)]
// struct SpaceView<'a> {
//     key: &'a str,
//     #[serde(rename = "spaceType")]
//     space_type: &'a str,
//     config: &'a serde_json::Value,
//     members: &'a [arbiter_core::MemberEntry],
// }

// // ---------------------------------------------------------------------------
// // State serialisation helpers  (avoids HashMap non-string key issue)
// // ---------------------------------------------------------------------------

// /// A view of [`ArbiterState`] with spaces as an array of [key, value] pairs.
// #[derive(Serialize)]
// struct StateView<'a> {
//     did: &'a str,
//     version: u64,
//     config: &'a serde_json::Value,
//     spaces: &'a [[SerialisableSpaceEntry<'a>; 2]],
// }

// /// Either a space key or a space value in the serialised state.
// #[derive(Serialize)]
// #[serde(untagged)]
// enum SerialisableSpaceEntry<'a> {
//     Key(SerialisableSpaceId<'a>),
//     Value(&'a arbiter_core::Space),
// }

// /// A serialisable view of [`SpaceId`].
// #[derive(Serialize)]
// struct SerialisableSpaceId<'a> {
//     #[serde(rename = "space_type")]
//     space_type: &'a str,
//     #[serde(rename = "space_key")]
//     space_key: &'a str,
// }

// // ---------------------------------------------------------------------------
// // Standalone helpers
// // ---------------------------------------------------------------------------

/// Validate a Rego policy string. Throws a JavaScript exception on error.
#[wasm_bindgen]
pub fn validate_policy(policy: &str) -> Result<(), JsValue> {
    arbiter_core::arbiter::validate_policy(policy).map_err(|e| JsValue::from_str(&format!("{e:#}")))
}

// // ---------------------------------------------------------------------------

// fn parse_method(s: &str) -> Result<XrpcMethod, JsValue> {
//     match s {
//         "query" => Ok(XrpcMethod::Query),
//         "procedure" => Ok(XrpcMethod::Procedure),
//         _ => Err(JsValue::from_str(&format!(
//             "Invalid XRPC method: expected \"query\" or \"procedure\", got \"{s}\""
//         ))),
//     }
// }

// // ---------------------------------------------------------------------------
// // Tests
// // ---------------------------------------------------------------------------

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_parse_method() {
//         assert!(parse_method("query").is_ok());
//         assert!(parse_method("procedure").is_ok());
//         assert!(parse_method("invalid").is_err());
//     }
// }
