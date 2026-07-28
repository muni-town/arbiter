# Current Project Planning & Implementation Status

**Overall Focus:** Think about the minimal flow for the arbiter server as XRPC
requests come in, get processed by the policy, and make requests to the PDS.

## Notes

The PDS is going to be the main datastore for the arbiter. The main policy itself,
all the other subpolicies, and the member list will just be records on the PDS
for now.

## Implementation

- Each logical arbiter will have a PDS account.
- The arbiter server will manage multiple arbiters.
- I have `policy.rs` in `arbiter-core` in a good place: a simple wrapper around
  the `RegoVM`.
- `axum` looks like a good minimal webserver to go with.
- `atrium_xrpc` types will serve well for parsing / serialization of the XRPC stuff.
  - I think at the `arbiter-core` level it might make sense to just deal with
    the atrium xrpc types and then expect the server to parse into those types.
  - There is an extra consideration we need to make about how we are going to
    pass XRPC requests to Rego at this point because the request may have
    `parameters` in the query string as well as a `body` that could have any
    mime type or else be JSON. Rego doesn't support bytes in the policy ( which
    makes sense as it is unnecessary ) so that means we will need to be a little
    more sophisticated with the way we pass data and responses to it.