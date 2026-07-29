use crate::{
    arbiter::{Arbiter, ArbiterReqMachine, ArbiterReqMachineStep, Policies, RequestCtx},
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
    policies: Policies,
    io: Io,
}

impl Arbiter {
    /// Convert this arbiter into an [`AsyncArbiter`] that is easier to use in
    /// an async context without having to manually drive the state machine.
    pub fn into_async<Io: ArbiterAsyncIo>(self, io: Io) -> AsyncArbiter<Io> {
        AsyncArbiter {
            policies: self.policies,
            io,
        }
    }
}

impl<Io: ArbiterAsyncIo> AsyncArbiter<Io> {
    /// Create a new [`AsyncArbiter`] from it's policies and [`ArbiterAsyncIo`]
    /// implementation.
    pub fn new(policies: Policies, io: Io) -> Self {
        Self { policies, io }
    }

    /// Handle an XRPC request by routing through the arbiter's policies.
    pub async fn handle_request(&self, req: XrpcRequest, ctx: RequestCtx) -> XrpcResult {
        ArbiterReqMachine::new(self.policies.clone(), req, ctx)
            .into_future(&self.io)
            .await
    }
}

impl ArbiterReqMachine {
    /// Convert the [`ArbiterReqMachine`] into a future that will automatically
    /// advance the state machine using the provided IO implementation.
    pub fn into_future<Io: ArbiterAsyncIo>(mut self, io: &Io) -> impl Future<Output = XrpcResult> {
        use ArbiterReqMachineStep::*;
        async move {
            let mut step = self.start();
            loop {
                match step {
                    Completed(result) => return result,
                    RemoteXrpcRequest { endpoint, request } => {
                        let resp = io.xrpc_request(endpoint, request).await;
                        step = self.resume(resp);
                    }
                }
            }
        }
    }
}
