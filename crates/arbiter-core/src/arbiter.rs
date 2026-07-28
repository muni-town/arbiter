use std::collections::HashMap;

use crate::{
    policy::PolicyVm,
    xrpc::{XrpcEndpoint, XrpcRequest, XrpcResult},
};

/// The state of an arbiter for an individual ATProto account.
pub struct Arbiter {
    /// the policies for this arbiter.
    policies: Policies,
}

/// A root policy and optional sub-policies.
#[derive(Clone)]
pub struct Policies {
    /// The root policy is the first policy and is run for every single request.
    ///
    /// It may _optionally_ offload decisions to other sub-policies as a part of
    /// it's execution.
    root_policy: PolicyVm,
    /// The set of installed sub-policies. Sub-policies are allowed to send
    /// requests to other sub-policies if they wish.
    sub_policies: HashMap<String, PolicyVm>,
}

impl Policies {
    fn get(&mut self, id: &PolicyId) -> Option<&mut PolicyVm> {
        todo!();
    }
}

/// The identifier for a policy
#[derive(Clone)]
pub enum PolicyId {
    /// The root policy.
    Root,
    /// A named sub-policy.
    Sub(String),
}

/// A state machine for an individual arbiter request, that may be driven to c
pub struct ArbiterReqMachine {
    /// The XRPC request that we are responding to.
    req: XrpcRequest,
    /// The policies to be used to respond to the request.
    policies: Policies,
    /// The list of bytes buffers used by the machine.
    buffers: Vec<Vec<u8>>,
    /// The current status of the machine.
    status: ArbiterReqMachineStatus,
}

/// The different possible status of the arbiter request machine.
pub enum ArbiterReqMachineStatus {
    /// Machine has just been initialized
    Init,
    /// A policy has triggered a remote XRPC call which we are waiting on the
    /// response to.
    WaitingOnRemoteXrpcResp {
        /// The ID of the policy that is waiting for the response.
        policy: PolicyId,
    },
}

/// The result of a step in th evaluation o the arbiter req machine.
pub enum ArbiterReqMachineStep {
    /// The policy evaluation is completed with an XRPC response.
    Completed(XrpcResult),
    /// The policy evaluation has triggered a request to a remot XRPC endpoint.
    /// The caller must execute the XRPC request and provide the response to the
    /// machine to continue.
    RemoteXrpcRequest {
        /// The endpoint to send the request to.
        endpoint: XrpcEndpoint,
        /// The request to send.
        request: XrpcRequest,
    },
}

pub enum ArbiterReqMachineContinuation {
    /// Provide the resposne to the in-flight remote XRPC request that is being
    /// waited for.
    RemoteXrpcResponse(XrpcResult),
}

impl ArbiterReqMachine {
    pub fn start() -> ArbiterReqMachineStep {
        todo!()
    }
    pub fn resume(continuation: ArbiterReqMachineContinuation) -> ArbiterReqMachineStep {
        todo!()
    }
}

impl Arbiter {
    /// Get a state machine that may be driven to respond to the provided XRPC
    /// request.
    pub fn handle_request(&self, req: XrpcRequest) -> ArbiterReqMachine {
        ArbiterReqMachine {
            req,
            policies: self.policies.clone(),
            id_counter: 0,
        }
    }
}
