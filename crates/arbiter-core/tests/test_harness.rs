//! Test harness for the sans-IO arbiter state machine.
//!
//! Manages a collection of [`StateMachine`]s (one per arbiter DID) and
//! routes incoming XRPC calls and remote resolution requests between them.
//! Remote space resolution is simulated by routing through the target
//! arbiter's [`StateMachine`] — the same path the real server would take.

use std::collections::{HashMap, HashSet};

// use arbiter_core::{
//     Event, IoAction, MemberEntry, NSID, Space, SpaceId, StateMachine, XrpcResponse, nsid_method,
//     policy_core::XrpcMethod,
// };
// use serde_json::Value;

// // ---------------------------------------------------------------------------
// // Test driver
// // ---------------------------------------------------------------------------

// /// Manages multiple [`StateMachine`]s and routes events between them.
// pub struct TestDriver {
//     pub machines: HashMap<String, StateMachine>,
//     default_policy: String,
//     /// Track which arbiters are online for offline tests.
//     online: HashSet<String>,
// }

// impl TestDriver {
//     pub fn new(default_policy: &str) -> Self {
//         Self {
//             machines: HashMap::new(),
//             default_policy: default_policy.to_string(),
//             online: HashSet::new(),
//         }
//     }

//     /// Create an arbiter with the default policy and insert its state machine.
//     ///
//     /// The admin space is initialised with the given `owner_did` as an Owner.
//     pub fn create_default_arbiter(&mut self, did: &str, owner_did: &str) {
//         let policy = self.default_policy.clone();
//         let config = serde_json::json!({
//             "$type": "town.muni.arbiter.server.v1.config",
//             "policy": policy,
//         });
//         let mut sm = StateMachine::create(did.into(), config)
//             .expect("Invalid arbiter config");
//         Self::init_admin_space(&mut sm, owner_did);
//         self.machines.insert(did.into(), sm);
//         self.online.insert(did.to_string());
//     }

//     /// Create an arbiter with a custom policy.
//     ///
//     /// The admin space is initialised with the given `owner_did` as an Owner.
//     pub fn create_arbiter(&mut self, did: &str, owner_did: &str, policy: &str) {
//         let config = serde_json::json!({
//             "$type": "town.muni.arbiter.server.v1.config",
//             "policy": policy,
//         });
//         let mut sm = StateMachine::create(did.into(), config)
//             .expect("Invalid arbiter config");
//         Self::init_admin_space(&mut sm, owner_did);
//         self.machines.insert(did.into(), sm);
//         self.online.insert(did.to_string());
//     }

//     /// Bootstrap the `$admin` space with an Owner member.
//     fn init_admin_space(sm: &mut StateMachine, owner_did: &str) {
//         let admin_id = SpaceId {
//             space_key: "$admin".into(),
//             space_type: "town.muni.arbiter.config.adminSpace".into(),
//         };
//         sm.arbiter.spaces.insert(
//             admin_id,
//             Space {
//                 key: "$admin".into(),
//                 space_type: "town.muni.arbiter.config.adminSpace".into(),
//                 config: serde_json::json!({}),
//                 members: vec![MemberEntry {
//                     did: owner_did.into(),
//                     access: serde_json::json!({"level": "Owner"}),
//                 }],
//             },
//         );
//     }

//     /// Perform an XRPC operation and assert it succeeds.
//     pub fn assert_ok(
//         &mut self,
//         arbiter_did: &str,
//         user_did: &str,
//         space_key: &str,
//         operation: &str,
//         extra_params: Option<Value>,
//     ) -> Option<Value> {
//         let result = self.call_method(arbiter_did, user_did, space_key, operation, extra_params);
//         match result {
//             Ok(body) => body,
//             Err(msg) => panic!(
//                 "Expected success for {user_did}@{arbiter_did}/{space_key} ({operation}), got error: {msg}"
//             ),
//         }
//     }

//     /// Perform an XRPC operation and assert it is denied.
//     pub fn assert_denied(
//         &mut self,
//         arbiter_did: &str,
//         user_did: &str,
//         space_key: &str,
//         operation: &str,
//         extra_params: Option<Value>,
//     ) {
//         let result = self.call_method(arbiter_did, user_did, space_key, operation, extra_params);
//         match result {
//             Ok(_) => panic!(
//                 "Expected denial for {user_did}@{arbiter_did}/{space_key} ({operation}), got success"
//             ),
//             Err(msg) => {
//                 assert!(
//                     msg.contains("denied")
//                         || msg.contains("Denied")
//                         || msg.contains("Permission")
//                         || msg.contains("Err"),
//                     "Expected a denial error, got: {msg}"
//                 );
//             }
//         }
//     }

//     /// Resolve space members and return the member list.
//     pub fn resolved_members(
//         &mut self,
//         arbiter_did: &str,
//         user_did: &str,
//         space_key: &str,
//     ) -> Vec<ResolvedMember> {
//         let params = serde_json::json!({"spaceKey": space_key});
//         let result = self.call_method(
//             arbiter_did,
//             user_did,
//             space_key,
//             "resolveSpaceMembers",
//             Some(params),
//         );
//         let body = match result {
//             Ok(Some(b)) => b,
//             Ok(None) => return vec![],
//             Err(msg) => panic!("resolveSpaceMembers failed: {msg}"),
//         };
//         body.get("members")
//             .and_then(|m| m.as_array())
//             .map(|arr| {
//                 arr.iter()
//                     .map(|v| ResolvedMember {
//                         did: v
//                             .get("did")
//                             .and_then(|d| d.as_str())
//                             .unwrap_or("")
//                             .to_string(),
//                         access: v.get("access").cloned().unwrap_or(Value::Null),
//                     })
//                     .collect()
//             })
//             .unwrap_or_default()
//     }

//     // -------------------------------------------------------------------
//     // Internal
//     // -------------------------------------------------------------------

//     /// Perform an XRPC operation with a raw NSID (for testing proxy etc.).
//     pub fn call_nsid(
//         &mut self,
//         arbiter_did: &str,
//         user_did: &str,
//         nsid: &str,
//         method: XrpcMethod,
//         params: Value,
//     ) -> Result<Option<Value>, String> {
//         let sm = match self.machines.get_mut(arbiter_did) {
//             Some(s) => s,
//             None => return Err("Arbiter not found".into()),
//         };

//         let actions = sm.handle_event(Event::IncomingXrpc {
//             nsid: nsid.to_string(),
//             method,
//             params,
//             caller_did: user_did.to_string(),
//         });
//         self.drive_actions(arbiter_did, actions)
//     }

//     fn call_method(
//         &mut self,
//         arbiter_did: &str,
//         user_did: &str,
//         space_key: &str,
//         operation: &str,
//         extra_params: Option<Value>,
//     ) -> Result<Option<Value>, String> {
//         let nsid = self.operation_to_nsid(operation);

//         let sm = match self.machines.get_mut(arbiter_did) {
//             Some(s) => s,
//             None => return Err("Arbiter not found".into()),
//         };

//         let mut params = serde_json::json!({
//             "arbiterDid": arbiter_did,
//             "spaceKey": space_key,
//             "spaceType": if space_key == "$admin" {
//                 "town.muni.arbiter.config.adminSpace"
//             } else {
//                 "town.muni.arbiter.config.space"
//             },
//         });
//         if let Some(extras) = extra_params {
//             if let Some(obj) = extras.as_object() {
//                 for (k, v) in obj {
//                     params[k] = v.clone();
//                 }
//             }
//         }

//         let actions = sm.handle_event(Event::IncomingXrpc {
//             nsid: nsid.clone(),
//             method: nsid_method(&nsid),
//             params,
//             caller_did: user_did.to_string(),
//         });
//         self.drive_actions(arbiter_did, actions)
//     }

//     /// Drive IO actions, routing XrpcRemote to the correct target machine.
//     fn drive_actions(
//         &mut self,
//         source_did: &str,
//         actions: Vec<IoAction>,
//     ) -> Result<Option<Value>, String> {
//         let mut pending: Vec<(String, IoAction)> = actions
//             .into_iter()
//             .map(|a| (source_did.to_string(), a))
//             .collect();
//         let mut response: Option<Value> = None;

//         while let Some((_src, action)) = pending.pop() {
//             match action {
//                 IoAction::SendXrpcResponse { body, status } => {
//                     if status >= 400 {
//                         let err = body
//                             .get("error")
//                             .and_then(|e| e.as_str())
//                             .unwrap_or("unknown")
//                             .to_string();
//                         return Err(err);
//                     }
//                     response = Some(body);
//                 }

//                 IoAction::SendXrpcRequest {
//                     did,
//                     nsid,
//                     method,
//                     input,
//                     job_id,
//                 } => {
//                     // Route to the target arbiter's state machine.
//                     // The caller for the remote is the SOURCE arbiter's DID.
//                     let caller = &_src;

//                     let resp = if nsid == "com.atproto.repo.getRecord"
//                         && method == XrpcMethod::Query
//                     {
//                         XrpcResponse {
//                             status: 200,
//                             body: serde_json::json!({ "demo": "record "}),
//                         }
//                     } else {
//                         self.simulate_remote_resolution(
//                             caller,
//                             &did,
//                             &nsid,
//                             &method,
//                             &input,
//                         )
//                     };

//                     if let Some(sm) = self.machines.get_mut(&_src) {
//                         let new = sm.handle_event(Event::XrpcRemoteResult {
//                             status: resp.status,
//                             body: resp.body,
//                             job_id,
//                         });
//                         pending.extend(new.into_iter().map(|a| (_src.clone(), a)));
//                     }
//                 }
//             }
//         }

//         Ok(response)
//     }

//     /// Resolve a remote XRPC request by routing through the target
//     /// state machine's policy, using the NSID from the request.
//     fn simulate_remote_resolution(
//         &mut self,
//         caller_did: &str,
//         target_did: &str,
//         nsid: &str,
//         method: &policy_core::XrpcMethod,
//         input: &Value,
//     ) -> XrpcResponse {
//         let base_did = target_did.split('#').next().unwrap_or(target_did);

//         if !self.online.contains(base_did) {
//             return XrpcResponse {
//                 status: 500,
//                 body: Value::Null,
//             };
//         }

//         let event = Event::IncomingXrpc {
//             nsid: nsid.to_string(),
//             method: method.clone(),
//             params: input.clone(),
//             caller_did: caller_did.to_string(),
//         };

//         let machine = match self.machines.get_mut(base_did) {
//             Some(m) => m,
//             None => {
//                 return XrpcResponse {
//                     status: 404,
//                     body: Value::Null,
//                 };
//             }
//         };

//         let actions = machine.handle_event(event);
//         self.drive_to_response(base_did, actions)
//     }

//     /// Drive a machine's IO actions until we get a SendResponse, routing
//     /// child XrpcLocal / XrpcRemote through the appropriate machines.
//     fn drive_to_response(
//         &mut self,
//         arbiter_did: &str,
//         actions: Vec<IoAction>,
//     ) -> XrpcResponse {
//         let mut pending: Vec<(String, IoAction)> = actions
//             .into_iter()
//             .map(|a| (arbiter_did.to_string(), a))
//             .collect();

//         while let Some((src, action)) = pending.pop() {
//             match action {
//                 IoAction::SendXrpcResponse { body, status } => {
//                     return XrpcResponse { status, body };
//                 }

//                 IoAction::SendXrpcRequest {
//                     did,
//                     nsid,
//                     method,
//                     input,
//                     job_id,
//                 } => {
//                     let resp =
//                         self.simulate_remote_resolution(&src, &did, &nsid, &method, &input);
//                     if let Some(sm) = self.machines.get_mut(&src) {
//                         let new = sm.handle_event(Event::XrpcRemoteResult {
//                             status: resp.status,
//                             body: resp.body,
//                             job_id,
//                         });
//                         pending.extend(new.into_iter().map(|a| (src.clone(), a)));
//                     }
//                 }
//             }
//         }

//         XrpcResponse {
//             status: 400,
//             body: Value::Null,
//         }
//     }

//     // -------------------------------------------------------------------
//     // Helpers
//     // -------------------------------------------------------------------

//     fn operation_to_nsid(&self, operation: &str) -> String {
//         match operation {
//             "createSpace" => NSID::CREATE_SPACE,
//             "deleteSpace" => NSID::DELETE_SPACE,
//             "setSpaceMemberAccess" => NSID::SET_SPACE_MEMBER_ACCESS,
//             "removeSpaceMember" => NSID::REMOVE_SPACE_MEMBER,
//             "deleteArbiter" => NSID::DELETE_ARBITER,
//             "resolveSpaceMembers" => NSID::RESOLVE_SPACE_MEMBERS,
//             "getSpaceConfig" => NSID::GET_SPACE_CONFIG,
//             other => panic!("Unknown operation: {other}"),
//         }
//         .into()
//     }

//     pub fn arbiter_exists(&self, did: &str) -> bool {
//         self.machines.contains_key(did)
//     }

//     /// Toggle an arbiter between online and offline.
//     pub fn toggle_arbiter_offline(&mut self, did: &str) {
//         if self.online.contains(did) {
//             self.online.remove(did);
//         } else {
//             self.online.insert(did.to_string());
//         }
//     }

//     pub fn set_space_config(
//         &mut self,
//         arbiter_did: &str,
//         space_key: &str,
//         space_type: &str,
//         config: Value,
//     ) {
//         if let Some(sm) = self.machines.get_mut(arbiter_did) {
//             let id = SpaceId {
//                 space_key: space_key.into(),
//                 space_type: space_type.into(),
//             };
//             if let Some(space) = sm.arbiter.get_space_mut(&id) {
//                 space.config = config;
//             }
//         }
//     }
// }

// // ---------------------------------------------------------------------------

// #[derive(Debug, Clone)]
// pub struct ResolvedMember {
//     pub did: String,
//     pub access: Value,
// }
