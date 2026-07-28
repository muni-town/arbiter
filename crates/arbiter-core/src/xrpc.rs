use serde_json::Value as JsonValue;

/// A destination for an XRPC request.
pub enum XrpcEndpoint {
    /// The request should be sent to the PDS account that is managed by this
    /// arbiter.
    PdsAccount,
    /// The request should be sent to a remote XRPC endpoint. This should be a
    /// valid DID with a service endpoint suffix such as `#atproto_pds`, but it
    /// is not validated by this library.
    Remote(String)
}

pub type XrpcRequest = atrium_xrpc::XrpcRequest<JsonValue, JsonValue>;
pub type XrpcResult = Result<XrpcOutput, XrpcError>;

pub type XrpcOutput = atrium_xrpc::OutputDataOrBytes<JsonValue>;
pub type XrpcError = atrium_xrpc::error::XrpcError<JsonValue>;
