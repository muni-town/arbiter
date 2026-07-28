//! Integration tests for the access-levels policy via the sans-IO
//! [`TestDriver`] harness.
//!
//! Ported from `arbiter-simulator/src/lib/simulator.test.ts`.

mod test_harness;

// use arbiter_core::{SpaceId, policy_core::XrpcMethod};
// use serde_json::Value;
// use test_harness::{ResolvedMember, TestDriver};

// const DEFAULT_POLICY: &str = include_str!("../../../policies/arbiter/access-levels.rego");

// fn access(level: &str) -> Value {
//     serde_json::json!({"level": level})
// }

// #[track_caller]
// fn assert_member_exists(members: &[ResolvedMember], expected_did: &str, expected_level: &str) {
//     let found = members.iter().find(|m| m.did == expected_did);
//     assert!(
//         found.is_some(),
//         "Member {expected_did} not found in members: {members:?}"
//     );
//     let level = found
//         .unwrap()
//         .access
//         .get("level")
//         .and_then(|v: &Value| v.as_str())
//         .unwrap_or("(none)");
//     assert_eq!(
//         level, expected_level,
//         "Member {expected_did}: expected level {expected_level}, got {level}"
//     );
// }

// // ── Basic owner operations ─────────────────────────────────────────────

// #[test]
// fn owner_can_create_spaces() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_ok("org", "alice", "team", "createSpace", None);
//     h.assert_ok("org", "alice", "docs", "createSpace", None);
// }

// #[test]
// fn non_member_cannot_create_space() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_denied("org", "stranger", "team", "createSpace", None);
// }

// #[test]
// fn owner_can_delete_arbiter() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     // deleteArbiter succeeds for the owner.
//     h.assert_ok("org", "alice", "$admin", "deleteArbiter", None);
//     // The arbiter still exists in the harness (the harness doesn't auto-remove it).
//     assert!(h.arbiter_exists("org"));
// }

// #[test]
// fn non_owner_cannot_delete_arbiter() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_denied("org", "stranger", "$admin", "deleteArbiter", None);
// }

// #[test]
// fn multiple_owners_cannot_delete_arbiter() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_ok(
//         "org",
//         "alice",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "bob", "access": access("Owner")})),
//     );
//     h.assert_denied("org", "alice", "$admin", "deleteArbiter", None);
//     h.assert_denied("org", "bob", "$admin", "deleteArbiter", None);
// }

// #[test]
// fn owner_can_delete_space() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_ok("org", "alice", "team", "createSpace", None);
//     h.assert_ok("org", "alice", "team", "deleteSpace", None);
//     assert!(
//         h.machines
//             .get("org")
//             .unwrap()
//             .arbiter
//             .spaces
//             .get(&SpaceId {
//                 space_key: "team".into(),
//                 space_type: "town.muni.arbiter.config.space".into(),
//             })
//             .is_none()
//     );
// }

// #[test]
// fn owner_cannot_delete_admin_space() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_denied("org", "alice", "$admin", "deleteSpace", None);
//     assert!(
//         h.machines
//             .get("org")
//             .unwrap()
//             .arbiter
//             .spaces
//             .get(&SpaceId {
//                 space_key: "$admin".into(),
//                 space_type: "town.muni.arbiter.config.adminSpace".into(),
//             })
//             .is_some()
//     );
// }

// // ── Access level hierarchy ───────────────────────────────────────────

// #[test]
// fn owner_can_add_members() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_ok(
//         "org",
//         "alice",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "bob", "access": access("Owner")})),
//     );
//     h.assert_ok(
//         "org",
//         "alice",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "carol", "access": access("IsMember")})),
//     );
// }

// #[test]
// fn read_member_cannot_create_space() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_ok(
//         "org",
//         "alice",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "bob", "access": access("ReadMemberList")})),
//     );
//     h.assert_denied("org", "bob", "team", "createSpace", None);
// }

// #[test]
// fn cannot_grant_higher_access_than_own() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_ok(
//         "org",
//         "alice",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "bob", "access": access("AddMembers")})),
//     );
//     // Bob can add someone with IsMember (lower)
//     h.assert_ok(
//         "org",
//         "bob",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "carol", "access": access("IsMember")})),
//     );
//     // Bob cannot add someone with Owner (higher)
//     h.assert_denied(
//         "org",
//         "bob",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "dave", "access": access("Owner")})),
//     );
//     // Bob cannot add someone with ConfigureSpace (higher)
//     h.assert_denied(
//         "org",
//         "bob",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "eve", "access": access("ConfigureSpace")})),
//     );
// }

// #[test]
// fn need_remove_members_to_modify_existing() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_ok(
//         "org",
//         "alice",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "bob", "access": access("IsMember")})),
//     );
//     h.assert_ok(
//         "org",
//         "alice",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "carol", "access": access("AddMembers")})),
//     );
//     // Carol can add a new member
//     h.assert_ok(
//         "org",
//         "carol",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "dave", "access": access("ReadMemberList")})),
//     );
//     // Carol cannot modify bob's existing entry (needs RemoveMembers)
//     h.assert_denied(
//         "org",
//         "carol",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "bob", "access": access("ReadMemberList")})),
//     );
//     // Alice (Owner) can modify anyone
//     h.assert_ok(
//         "org",
//         "alice",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "bob", "access": access("ReadMemberList")})),
//     );
// }

// // ── Resolved member lists ────────────────────────────────────────────

// #[test]
// fn owner_sees_themselves_in_admin_space() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     let members = h.resolved_members("org", "alice", "$admin");
//     assert!(!members.is_empty());
//     assert_member_exists(&members, "alice", "Owner");
// }

// #[test]
// fn resolve_includes_all_direct_members() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_ok(
//         "org",
//         "alice",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "bob", "access": access("IsMember")})),
//     );
//     h.assert_ok(
//         "org",
//         "alice",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "carol", "access": access("ReadMemberList")})),
//     );
//     let members = h.resolved_members("org", "alice", "$admin");
//     assert_member_exists(&members, "alice", "Owner");
//     assert_member_exists(&members, "bob", "IsMember");
//     assert_member_exists(&members, "carol", "ReadMemberList");
// }

// // ── Local space delegation ───────────────────────────────────────────

// #[test]
// fn access_limited_by_parent_delegation() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_ok("org", "alice", "team", "createSpace", None);
//     h.assert_ok(
//         "org",
//         "alice",
//         "team",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "bob", "access": access("Owner")})),
//     );
//     h.assert_ok("org", "alice", "$admin", "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "space:town.muni.arbiter.config.space/team", "access": access("ReadMemberList")})));
//     let members = h.resolved_members("org", "alice", "$admin");
//     assert_member_exists(&members, "bob", "ReadMemberList");
// }

// #[test]
// fn members_of_child_space_inherit_access() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_ok("org", "alice", "team", "createSpace", None);
//     h.assert_ok(
//         "org",
//         "alice",
//         "team",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "bob", "access": access("IsMember")})),
//     );
//     h.assert_ok("org", "alice", "$admin", "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "space:town.muni.arbiter.config.space/team", "access": access("IsMember")})));
//     let members = h.resolved_members("org", "alice", "$admin");
//     assert_member_exists(&members, "bob", "IsMember");
// }

// #[test]
// fn public_members_allows_non_member_access() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_ok("org", "alice", "team", "createSpace", None);
//     h.assert_ok(
//         "org",
//         "alice",
//         "team",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "bob", "access": access("IsMember")})),
//     );
//     h.set_space_config(
//         "org",
//         "team",
//         "town.muni.arbiter.config.space",
//         serde_json::json!({"publicMembers": true, "publicRecords": false}),
//     );
//     let members = h.resolved_members("org", "stranger", "team");
//     assert!(!members.is_empty());
//     assert_member_exists(&members, "bob", "IsMember");
// }

// // ── Remote space resolution ──────────────────────────────────────────

// #[test]
// fn remote_space_resolution_works() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.create_default_arbiter("partner", "carol");
//     h.assert_ok("partner", "carol", "shared", "createSpace", None);
//     h.set_space_config(
//         "partner",
//         "shared",
//         "town.muni.arbiter.config.space",
//         serde_json::json!({"publicMembers": true, "publicRecords": false}),
//     );
//     h.assert_ok(
//         "partner",
//         "carol",
//         "shared",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "dave", "access": access("Owner")})),
//     );
//     h.assert_ok("org", "alice", "team", "createSpace", None);
//     h.assert_ok("org", "alice", "team", "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "partner|town.muni.arbiter.config.space|shared", "access": access("IsMember")})));
//     let members = h.resolved_members("org", "alice", "team");
//     assert_member_exists(&members, "dave", "IsMember");
// }

// #[test]
// fn remote_access_limited_by_parent() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.create_default_arbiter("partner", "carol");
//     h.assert_ok("partner", "carol", "shared", "createSpace", None);
//     h.set_space_config(
//         "partner",
//         "shared",
//         "town.muni.arbiter.config.space",
//         serde_json::json!({"publicMembers": true, "publicRecords": false}),
//     );
//     h.assert_ok(
//         "partner",
//         "carol",
//         "shared",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "dave", "access": access("Owner")})),
//     );
//     h.assert_ok("org", "alice", "team", "createSpace", None);
//     h.assert_ok("org", "alice", "team", "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "partner|town.muni.arbiter.config.space|shared", "access": access("ReadMemberList")})));
//     let members = h.resolved_members("org", "alice", "team");
//     assert_member_exists(&members, "dave", "ReadMemberList");
// }

// #[test]
// fn remote_arbiter_denies_unauthorised_caller() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.create_default_arbiter("partner", "carol");
//     h.assert_ok("partner", "carol", "restricted", "createSpace", None);
//     h.assert_ok(
//         "partner",
//         "carol",
//         "restricted",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "dave", "access": access("Owner")})),
//     );
//     h.assert_ok("org", "alice", "team", "createSpace", None);
//     h.assert_ok("org", "alice", "team", "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "partner|town.muni.arbiter.config.space|restricted", "access": access("IsMember")})));
//     let members = h.resolved_members("org", "alice", "team");
//     assert!(!members.iter().any(|m| m.did == "dave"));
// }

// #[test]
// fn remote_arbiter_grants_caller_via_member_access() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.create_default_arbiter("partner", "carol");
//     h.assert_ok("partner", "carol", "shared", "createSpace", None);
//     h.assert_ok(
//         "partner",
//         "carol",
//         "shared",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "dave", "access": access("Owner")})),
//     );
//     h.assert_ok(
//         "partner",
//         "carol",
//         "shared",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "org", "access": access("ReadMemberList")})),
//     );
//     h.assert_ok("org", "alice", "team", "createSpace", None);
//     h.assert_ok("org", "alice", "team", "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "partner|town.muni.arbiter.config.space|shared", "access": access("IsMember")})));
//     let members = h.resolved_members("org", "alice", "team");
//     assert_member_exists(&members, "dave", "IsMember");
// }

// // ── Custom policies ──────────────────────────────────────────────────

// #[test]
// fn allow_all_policy() {
//     let allow_all = r#"
//         package arbiter
//         import rego.v1

//         default allow := true

//         resolved_members contains {"did": input.caller.did, "access": {"level": "Owner"}} if { true }

//         response := {"status": 200, "body": {"members": resolved_members, "missingSpaces": []}} if {
//             input.operation.nsid == "town.muni.arbiter.resolveSpaceMembers"
//         }

//         response := {"status": 200, "body": xrpc_local(input.operation.method, input.operation.nsid, input.operation.params)} if {
//             input.operation.nsid != "town.muni.arbiter.resolveSpaceMembers"
//         }
//     "#;
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_arbiter("org", "alice", allow_all);
//     h.assert_ok("org", "stranger", "team", "createSpace", None);
//     h.assert_ok(
//         "org",
//         "stranger",
//         "team",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "alice", "access": access("Owner")})),
//     );
//     let members = h.resolved_members("org", "stranger", "$admin");
//     assert_member_exists(&members, "stranger", "Owner");
// }

// #[test]
// fn deny_all_policy() {
//     let deny_all = r#"
//         package arbiter
//         import rego.v1
//         default response := {"status": 403, "body": {"error": "ErrPermissionDenied"}}
//     "#;
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_arbiter("org", "alice", deny_all);
//     h.assert_denied("org", "alice", "team", "createSpace", None);
// }

// // ── Edge cases ──────────────────────────────────────────────────────

// #[test]
// fn remote_arbiter_offline_excludes_remote_members() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.create_default_arbiter("partner", "carol");
//     h.assert_ok("partner", "carol", "shared", "createSpace", None);
//     h.set_space_config(
//         "partner",
//         "shared",
//         "town.muni.arbiter.config.space",
//         serde_json::json!({"publicMembers": true, "publicRecords": false}),
//     );
//     h.assert_ok(
//         "partner",
//         "carol",
//         "shared",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "dave", "access": access("Owner")})),
//     );
//     h.assert_ok("org", "alice", "team", "createSpace", None);
//     h.assert_ok("org", "alice", "team", "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "partner|town.muni.arbiter.config.space|shared", "access": access("ReadMemberList")})));

//     // Online: Dave visible
//     let online = h.resolved_members("org", "alice", "team");
//     assert_member_exists(&online, "dave", "ReadMemberList");

//     // Offline: Dave absent
//     h.toggle_arbiter_offline("partner");
//     let offline = h.resolved_members("org", "alice", "team");
//     assert!(!offline.iter().any(|m| m.did == "dave"));

//     // Back online: Dave returns
//     h.toggle_arbiter_offline("partner");
//     let back = h.resolved_members("org", "alice", "team");
//     assert_member_exists(&back, "dave", "ReadMemberList");
// }

// #[test]
// fn public_members_toggle_controls_stranger_access() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_ok("org", "alice", "team", "createSpace", None);
//     h.assert_ok(
//         "org",
//         "alice",
//         "team",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "bob", "access": access("IsMember")})),
//     );
//     // Not public: stranger denied
//     h.assert_denied("org", "stranger", "team", "resolveSpaceMembers", None);
//     // Make public
//     h.set_space_config(
//         "org",
//         "team",
//         "town.muni.arbiter.config.space",
//         serde_json::json!({"publicMembers": true, "publicRecords": false}),
//     );
//     let members = h.resolved_members("org", "stranger", "team");
//     assert_member_exists(&members, "bob", "IsMember");
//     // Un-public
//     h.set_space_config(
//         "org",
//         "team",
//         "town.muni.arbiter.config.space",
//         serde_json::json!({"publicMembers": false, "publicRecords": false}),
//     );
//     h.assert_denied("org", "stranger", "team", "resolveSpaceMembers", None);
// }

// #[test]
// fn space_scoped_owner_cannot_create_spaces_globally() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.assert_ok("org", "alice", "team", "createSpace", None);
//     h.assert_ok(
//         "org",
//         "alice",
//         "team",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "bob", "access": access("Owner")})),
//     );
//     // Bob is Owner in team
//     h.assert_ok(
//         "org",
//         "bob",
//         "team",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "carol", "access": access("IsMember")})),
//     );
//     // But Bob only has ReadMemberList in $admin — can't create spaces
//     h.assert_denied("org", "bob", "newspace", "createSpace", None);
//     // Alice (Owner in $admin) can
//     h.assert_ok("org", "alice", "newspace", "createSpace", None);
// }

// // ── Nested local delegation ─────────────────────────────────────────

// #[test]
// fn resolves_deeply_nested_local_delegations() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("arb1", "alice");
//     h.assert_ok("arb1", "alice", "members", "createSpace", None);
//     h.assert_ok("arb1", "alice", "moderators", "createSpace", None);
//     h.assert_ok("arb1", "alice", "#general", "createSpace", None);

//     h.assert_ok("arb1", "alice", "members", "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "space:town.muni.arbiter.config.space/moderators", "access": access("RemoveMembers")})));
//     h.assert_ok("arb1", "alice", "#general", "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "space:town.muni.arbiter.config.space/members", "access": access("RemoveMembers")})));
//     h.assert_ok(
//         "arb1",
//         "alice",
//         "moderators",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "carol", "access": access("RemoveMembers")})),
//     );
//     h.assert_ok(
//         "arb1",
//         "alice",
//         "members",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "george", "access": access("IsMember")})),
//     );

//     let members = h.resolved_members("arb1", "alice", "#general");
//     assert_member_exists(&members, "alice", "Owner");
//     assert_member_exists(&members, "george", "IsMember");
//     assert_member_exists(&members, "carol", "RemoveMembers");
// }

// // ── Cross-arbiter remote delegation ──────────────────────────────────

// #[test]
// fn resolves_members_across_arbiter_boundaries_with_nested_delegations() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);

//     h.create_default_arbiter("muni-town", "alice");
//     h.assert_ok("muni-town", "alice", "members", "createSpace", None);
//     h.assert_ok("muni-town", "alice", "moderators", "createSpace", None);

//     h.set_space_config(
//         "muni-town",
//         "members",
//         "town.muni.arbiter.config.space",
//         serde_json::json!({"publicMembers": true, "publicRecords": false}),
//     );

//     h.assert_ok("muni-town", "alice", "members", "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "space:town.muni.arbiter.config.space/moderators", "access": access("RemoveMembers")})));
//     h.assert_ok(
//         "muni-town",
//         "alice",
//         "members",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "george", "access": access("IsMember")})),
//     );
//     h.assert_ok(
//         "muni-town",
//         "alice",
//         "moderators",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "carol", "access": access("RemoveMembers")})),
//     );

//     h.create_default_arbiter("spicy-lobster", "bob");
//     h.assert_ok("spicy-lobster", "bob", "members", "createSpace", None);
//     h.assert_ok("spicy-lobster", "bob", "#general", "createSpace", None);

//     h.assert_ok(
//         "spicy-lobster",
//         "bob",
//         "members",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "mary", "access": access("IsMember")})),
//     );
//     h.assert_ok("spicy-lobster", "bob", "members", "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "muni-town|town.muni.arbiter.config.space|members", "access": access("IsMember")})));
//     h.assert_ok("spicy-lobster", "bob", "#general", "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "space:town.muni.arbiter.config.space/members", "access": access("RemoveMembers")})));

//     let members = h.resolved_members("spicy-lobster", "bob", "#general");
//     assert_member_exists(&members, "bob", "Owner");
//     assert_member_exists(&members, "mary", "IsMember");
//     assert_member_exists(&members, "alice", "IsMember");
//     assert_member_exists(&members, "george", "IsMember");
//     assert_member_exists(&members, "carol", "IsMember");
// }

// // ── Deep remote chain ────────────────────────────────────────────────

// #[test]
// fn deep_remote_chain_resolves() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");
//     h.create_default_arbiter("partner", "carol");

//     h.assert_ok("partner", "carol", "users", "createSpace", None);
//     h.set_space_config(
//         "partner",
//         "users",
//         "town.muni.arbiter.config.space",
//         serde_json::json!({"publicMembers": true, "publicRecords": false}),
//     );
//     h.assert_ok(
//         "partner",
//         "carol",
//         "users",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "dave", "access": access("Owner")})),
//     );

//     h.assert_ok("org", "alice", "team", "createSpace", None);
//     h.assert_ok("org", "alice", "team", "setSpaceMemberAccess",
//         Some(serde_json::json!({"memberDid": "partner|town.muni.arbiter.config.space|users", "access": access("IsMember")})));

//     let members = h.resolved_members("org", "alice", "team");
//     assert_member_exists(&members, "dave", "IsMember");
// }

// // ── UI flow regressions ─────────────────────────────────────────────

// #[test]
// fn create_arbiter_with_ui_style_config_then_resolve_members() {
//     // Match CreateArbiterBar.svelte: creates arbiter with only $type config.
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     // Use a minimal config like the UI would send.
//     h.create_arbiter("arbiter1", "alice", DEFAULT_POLICY);

//     // Resolve members right after creation.
//     let members = h.resolved_members("arbiter1", "alice", "$admin");
//     assert_eq!(members.len(), 1);
//     assert_member_exists(&members, "alice", "Owner");
// }

// #[test]
// fn add_member_to_admin_space_via_set_space_member_access() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");

//     // Match DetailPanel handleAddMember flow: add member with $type access config.
//     h.assert_ok(
//         "org",
//         "alice",
//         "$admin",
//         "setSpaceMemberAccess",
//         Some(serde_json::json!({
//             "memberDid": "bob",
//             "access": {"$type": "town.muni.arbiter.config.accessLevel", "level": "IsMember"},
//         })),
//     );

//     let members = h.resolved_members("org", "alice", "$admin");
//     assert_member_exists(&members, "bob", "IsMember");
// }

// #[test]
// fn create_space_with_explicit_key_ui_flow() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);
//     h.create_default_arbiter("org", "alice");

//     // Match handleCreateSpace in ArbiterActions.svelte.
//     h.assert_ok(
//         "org",
//         "alice",
//         "test",
//         "createSpace",
//         Some(serde_json::json!({
//             "spaceType": "town.muni.arbiter.config.space",
//             "config": {
//                 "$type": "town.muni.arbiter.config.space",
//                 "publicRecords": false,
//                 "publicMembers": false,
//             },
//         })),
//     );

//     let space = h
//         .machines
//         .get("org")
//         .unwrap()
//         .arbiter
//         .spaces
//         .get(&SpaceId {
//             space_key: "test".into(),
//             space_type: "town.muni.arbiter.config.space".into(),
//         })
//         .unwrap();
//     assert_eq!(space.key, "test");
// }

// // ── Proxy to backend ─────────────────────────────────────────────

// #[test]
// fn unknown_nsid_proxies_to_backend() {
//     let mut h = TestDriver::new(DEFAULT_POLICY);

//     // Frontend arbiter with backend_did configured.
//     h.create_arbiter(
//         "org",
//         "alice",
//         r#"
// package arbiter
// import rego.v1

// arbiter_xrpc_nsids := {
//     "town.muni.arbiter.getArbiterConfig",
//     "town.muni.arbiter.setArbiterConfig",
//     "town.muni.arbiter.deleteArbiter",
//     "town.muni.arbiter.createSpace",
//     "town.muni.arbiter.getSpaceConfig",
//     "town.muni.arbiter.setSpaceConfig",
//     "town.muni.arbiter.deleteSpace",
//     "town.muni.arbiter.listSpaces",
//     "town.muni.arbiter.getSpaceMembers",
//     "town.muni.arbiter.setSpaceMemberAccess",
//     "town.muni.arbiter.removeSpaceMember",
// }

// response := {"status": 403, "body": {"error": "ErrPermissionDenied"}} if not allow

// default allow := false

// allow if {
//     input.operation.nsid in arbiter_xrpc_nsids
// }

// allow if {
//     input.operation.nsid == "com.atproto.repo.getRecord"
// }

// response := {
//     "status": 200,
//     "body": xrpc_local(input.operation.method, input.operation.nsid, input.operation.params),
// } if {
//     allow
//     input.operation.nsid in arbiter_xrpc_nsids
// }

// response := xrpc_remote(
//     data.arbiter.config.backend_did,
//     input.operation.method,
//     input.operation.nsid,
//     input.operation.params,
// ) if {
//     allow
//     not input.operation.nsid in arbiter_xrpc_nsids
//     data.arbiter.config.backend_did
// }
// "#,
//     );

//     // Set backend_did on the org arbiter's config, preserving $type and policy.
//     if let Some(sm) = h.machines.get_mut("org") {
//         if let Some(obj) = sm.arbiter.config.as_object_mut() {
//             obj.insert(
//                 "backend_did".into(),
//                 serde_json::Value::String("backend".into()),
//             );
//         }
//     }

//     let result = h.call_nsid(
//         "org",
//         "alice",
//         "com.atproto.repo.getRecord",
//         XrpcMethod::Query,
//         serde_json::json!({"repo": "did:plc:example", "collection": "app.bsky.feed.post", "rkey": "123"}),
//     );

//     result.expect("Expected proxy to succeed");
// }
