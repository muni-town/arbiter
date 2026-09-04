# Current Project Planning & Implementation Status

## Notes

- `arbiter-core` is essentially finished.
- The arbiter server will manage multiple arbiters.
- The PDS is going to be the main datastore for the arbiter. The community
  policy pipeline and the community config (trusted scopes) will just be
  records on the PDS.
  - The arbiter-core `Pipeline` struct shows the basic structure: an ordered
    list of layers, each an `at://` reference to a policy record.
- The arbiter server will need local storage for the PDS passwords /
  AppPasswords and the DID keys for accounts that it has created.
- Previously we required an arbiter to have a service record on the DID doc.
  That will no longer be necessary.
  - We can create a `town.muni.arbiter.service/self` record with a `did` field
    that will point to something like `did:web:arbiter.example.com`.
  - _That_ `did` referenced in the `town.muni.arbiter.service` record will have
    an `#arbiter` service endpoint that points at the arbiter server URL.
- The arbiter policies will be loaded from PDS records.
  - When the arbiter server starts up it will fetch the community config
    (`town.muni.arbiter.config/self`) and resolve the pipeline from the PDS.
  - The arbiter server will also subscribe to the jetstream so that it can
    monitor changes to the config and policy records (including remote
    app-owned policies). When an update comes in over the jetstream it will
    reinstantiate the arbiter instance so that subsequent requests will go
    through the updated policies.
  - `town.muni.arbiter.config/self` holds `trustedScopes` and the ordered
    `pipeline` of `at://` URIs; `town.muni.arbiter.policy/<rkey>` records hold
    the Rego source for each layer.
  - Scoped `*.arbiter.proxy` endpoints are gated first by the trusted-scope
    whitelist and the permission-set-embedded scope policy (entrypoint
    `data.arbiter.allow`), then by the community pipeline.
- We're switching from `salvo` to `axum` for http.
- We'll use Turso and Toasty for arbiter server storage:
  https://docs.turso.tech/sdk/rust/orm/toasty
- We don't need all the arbiter XRPCs about members and spaces at all anymore.
  - The only built-in XRPCs we need are the ones for creating arbiters, either
    from imports of existing accounts or for creating new accounts.
  - All other XRPC requests will be required to have an `arbiter-proxy` header
    containing the DID and service fragment describing the destination service,
    and an `arbiter-did` header with the DID of the account that we will be
    acting on behalf of.
    - The `arbiter-did` will be used to select the arbiter that will do the
      policy evaluation, a `data.pdsEndpoint` will be added
      as`arbiter-did#atproto_pds` to the policy context along with
      `data.arbiterDid` which will just be the arbiter DID, and
      `input.xrpcEndpoint`, which will the intended destination of the XRPC
      request.