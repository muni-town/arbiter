use crate::{
    arbiter::{Arbiter, ArbiterReqMachine, ArbiterReqMachineStep, Pipeline, RequestCtx},
    xrpc::{XrpcEndpoint, XrpcRequest, XrpcResult},
};

/// Async IO implementation that must be provided to
/// [`ArbiterReqMachine::into_future`] if you want to use a future instead of
/// manually advancing the state machine.
///
/// `Send + Sync` is required because [`ArbiterReqMachine::into_future`]
/// borrows `&self` across an `.await`, so the produced future is only `Send`
/// when the IO implementation is `Sync` (and the request future it returns is
/// `Send`, declared below).
pub trait ArbiterAsyncIo: Send + Sync {
    /// Send a request to the given endpoint on behalf of the arbiter's policy.
    fn xrpc_request(
        &self,
        endpoint: XrpcEndpoint,
        request: XrpcRequest,
    ) -> impl Future<Output = XrpcResult> + Send;
}

/// An async version of the [`Arbiter`].
pub struct AsyncArbiter<Io: ArbiterAsyncIo> {
    pipeline: Pipeline,
    io: Io,
}

impl Arbiter {
    /// Convert this arbiter into an [`AsyncArbiter`] that is easier to use in
    /// an async context without having to manually drive the state machine.
    pub fn into_async<Io: ArbiterAsyncIo>(self, io: Io) -> AsyncArbiter<Io> {
        AsyncArbiter {
            pipeline: self.pipeline,
            io,
        }
    }
}

impl<Io: ArbiterAsyncIo> AsyncArbiter<Io> {
    /// Create a new [`AsyncArbiter`] from its policy pipeline and
    /// [`ArbiterAsyncIo`] implementation.
    pub fn new(pipeline: Pipeline, io: Io) -> Self {
        Self { pipeline, io }
    }

    /// Handle an XRPC request by routing through the arbiter's policy pipeline.
    pub async fn handle_request(&self, req: XrpcRequest, ctx: RequestCtx) -> XrpcResult {
        ArbiterReqMachine::new(self.pipeline.clone(), req, ctx)
            .into_future(&self.io)
            .await
    }
}

impl ArbiterReqMachine {
    /// Convert the [`ArbiterReqMachine`] into a future that will automatically
    /// advance the state machine using the provided IO implementation.
    ///
    /// The async driver has no built-in handler registry, so a pipeline layer
    /// that hands the request to the arbiter's built-in handler
    /// ([`ArbiterReqMachineStep::HandToBuiltin`]) cannot be fulfilled here and
    /// surfaces as a 500 `InternalError` response. Callers that need built-in
    /// handling must drive [`ArbiterReqMachine`] manually and map the step
    /// themselves.
    pub fn into_future<Io: ArbiterAsyncIo>(mut self, io: &Io) -> impl Future<Output = XrpcResult> {
        use ArbiterReqMachineStep::*;
        async move {
            let mut step = self.start();
            loop {
                match step {
                    Completed(result) => return result,
                    HandToBuiltin => {
                        return Err(Self::internal_error(anyhow::anyhow!(
                            "the policy pipeline handed the request to the arbiter's \
                             built-in handler, which the async driver cannot execute"
                        )));
                    }
                    RemoteXrpcRequest { endpoint, request } => {
                        let resp = io.xrpc_request(endpoint, request).await;
                        step = self.resume(resp);
                    }
                }
            }
        }
    }
}
