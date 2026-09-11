# Default Rego policy for a Muni Town arbiter.
#
# This policy is installed as the (single) layer of the community's policy
# pipeline, and the pipeline evaluates it against every incoming XRPC
# request. The layer receives:
#   input.callerDid    — the requester's DID
#   input.arbiterDid   — the stewarded account's DID
#   input.pdsEndpoint  — the steward's PDS endpoint
#   input.xrpcEndpoint — the arbiter server's XRPC endpoint
#   input.method       — the XRPC method ("GET"/"POST"/...)
#   input.nsid         — the XRPC method NSID
#   input.parameters   — query parameters (or null)
#   input.body         — the JSON body (or null)
#   input.encoding     — the request body encoding (or null)
#
# The layer's `data.arbiter.result` output is interpreted as one of:
#   { "handleBuiltin": true }                    → hand off: the request is
#     served by the arbiter's built-in handler (later layers are not run)
#   { "pass": true }                             → defer to the next layer
#   { "ok": true,  "output": <response body> }   → handle: forward the body
#   { "ok": false, "error": { status, error } }  → deny with an error
# Falling off the end of the pipeline (or an empty pipeline) denies.
#
# This policy is owner-agnostic: one copy can be published once and shared by
# every community. It has no per-community owner placeholder. Instead,
# day-to-day adminship is resolved at evaluation time from the account's
# `town.muni.arbiter.simple.admins` record (rkey `self` in the stewarded
# account's repo), which the policy fetches through the `xrpc` host function
# on every request. Rewriting that record rotates the day-to-day adminship
# with effect on the next request. The `town.muni.arbiter.recovery/self`
# record remains the separate, ultimate trust root: it designates the
# recovery admin that the arbiter server itself gates
# `town.muni.arbiter.resetConfig` on, outside of this policy.
#
# An admin — a DID listed in the admins record, or the stewarded account
# itself — gets:
#   - Management requests (any `town.muni.arbiter.*` NSID) handed to the
#     arbiter's built-in handler.
#   - Every other request proxied to the steward's PDS (`did#atproto_pds`),
#     authenticated as the stewarded account, via the `xrpc` host function.
# Everyone else is denied, and a failed admins-record fetch denies too
# (fail-closed).

package arbiter

import rego.v1

# By default we deny every request: non-admin callers, and any caller whose
# admins-record fetch failed (fail-closed).
default result := {
	"ok": false,
	"error": {
		"status": 403,
		"error": "Denied",
		"message": "caller is not an admin of this arbiter",
	},
}

# The stewarded account's day-to-day admins, loaded fresh on every request via
# the `xrpc` host function (GET `com.atproto.repo.getRecord` against the
# steward's PDS). On success the envelope is
# `{ "ok": true, "output": <getRecord response> }`; on failure it is
# `{ "ok": false, "error": { status, ... } }` — in which case `is_admin`
# below simply won't match and the request falls through to the deny default.
admins_resp := xrpc({
	"did": concat("#", [input.arbiterDid, "atproto_pds"]),
	"method": "GET",
	"nsid": "com.atproto.repo.getRecord",
	"parameters": {
		"repo": input.arbiterDid,
		"collection": "town.muni.arbiter.simple.admins",
		"rkey": "self",
	},
	"body": null,
	"encoding": null,
})

# A caller is an admin when the admins record lists their DID...
is_admin if {
	admins_resp.ok
	admins_resp.output.value.admins[_] == input.callerDid
}

# ...or when the caller is the stewarded account itself (the account's own
# service calls).
is_admin if {
	input.callerDid == input.arbiterDid
}

# Management NSIDs are served by the arbiter's built-in handler: a management
# request from an admin is handed off so the built-in handler can perform it,
# and any other caller is denied.
result := {"handleBuiltin": true} if {
	is_admin
	startswith(input.nsid, "town.muni.arbiter.")
}

# Admin-issued non-management requests are proxied to the steward's PDS as
# the stewarded account: the policy issues the request itself and returns the
# response — the xrpc ok/err envelope is exactly the layer's handle/deny
# output.
result := xrpc({
	"did": concat("#", [input.arbiterDid, "atproto_pds"]),
	"method": input.method,
	"nsid": input.nsid,
	"parameters": input.parameters,
	"body": input.body,
	"encoding": input.encoding,
}) if {
	is_admin
	not startswith(input.nsid, "town.muni.arbiter.")
}