#
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
# Allowed requests are proxied to the steward's PDS (`did#atproto_pds`)
# authenticated as the stewarded account, via the `xrpc` host function.
# Management requests (installPolicy / resetConfig) are instead handed to
# the arbiter's built-in handler.
#
# The `${owner}` placeholder is substituted with the selected admin DID before
# the policy is written to the account's PDS.

package arbiter

import rego.v1

# By default we deny every request.
default result := {"ok": false, "error": {"status": 403, "error": "ErrPermissionDenied"}}

# Management NSIDs are served by the arbiter's built-in handler: a management
# request from an allowed caller is handed off so the built-in handler can
# perform it, and any other caller is denied.
management_nsids := {"town.muni.arbiter.installPolicy", "town.muni.arbiter.resetConfig"}

result := {"handleBuiltin": true} if {
	input.nsid in management_nsids
	allow
}

# Allowed non-management requests are proxied to the steward's PDS as the
# stewarded account.
result := xrpc({
	"did": concat("#", [input.arbiterDid, "atproto_pds"]),
	"method": input.method,
	"nsid": input.nsid,
	"parameters": input.parameters,
	"body": input.body,
	"encoding": input.encoding,
}) if {
	allow
	not input.nsid in management_nsids
}

# The stewarded account itself is always allowed.
allow if input.callerDid == input.arbiterDid

# The owner is always allowed.
allow if input.callerDid == "${owner}"

default allow := false
