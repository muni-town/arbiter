#
# Default root Rego policy for a Muni Town arbiter.
#
# The arbiter evaluates this against every incoming XRPC request. The policy
# receives:
#   input.callerDid  — the requester's DID
#   input.arbiterDid — the stewarded account's DID
#   input.method     — the XRPC method ("GET"/"POST"/...)
#   input.nsid       — the XRPC method NSID
#   input.parameters — query parameters (or null)
#   input.body       — the JSON body (or null)
#
# The policy returns an ok/err envelope evaluated as `data.arbiter.result`:
#   { "ok": true,  "output": <response body> }  → forward the body
#   { "ok": false, "error": { status, error } } → deny with an error
#
# Allowed requests are proxied to the steward's PDS (`did#atproto_pds`)
# authenticated as the stewarded account, via the `xrpc` host function.
#
# The `${owner}` placeholder is substituted with the selected admin DID before
# the policy is written to the account's PDS.

package arbiter

import rego.v1

# By default we deny every request.
default result := {"ok": false, "error": {"status": 403, "error": "ErrPermissionDenied"}}

# Allowed requests are proxied to the steward's PDS as the stewarded account.
result := xrpc({
	"did": concat("#", [input.arbiterDid, "atproto_pds"]),
	"method": input.method,
	"nsid": input.nsid,
	"parameters": input.parameters,
	"body": input.body,
}) if allow

# The stewarded account itself is always allowed.
allow if input.callerDid == input.arbiterDid

# The owner is always allowed.
allow if input.callerDid == "${owner}"

default allow := false
