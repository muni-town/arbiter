use serde_json::Value as JsonValue;

/// A destination for an XRPC request: a DID with a service endpoint suffix
/// such as `did:web:example.com#atproto_pds`. The DID is not validated by this
/// library; the endpoint to use (including the arbiter's own PDS account)
/// is supplied by the policy, e.g. via its input.
pub type XrpcEndpoint = String;

pub type XrpcRequest = atrium_xrpc::XrpcRequest<JsonValue, JsonValue>;
pub type XrpcResult = Result<XrpcOutput, XrpcError>;

pub type XrpcOutput = atrium_xrpc::OutputDataOrBytes<JsonValue>;
pub type XrpcError = atrium_xrpc::error::XrpcError<JsonValue>;
