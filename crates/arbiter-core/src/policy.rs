//! Core policy engine.
//!
//! This module is responsible for executing the Rego policies that power the
//! arbiter. It is relatively low-level, providing a state machine for Rego
//! execution with custom host functions, but no arbiter-specific functionality.
//!
//! Status: Basically Complete ✅

use anyhow::{Context, Result};
use regorus::{
    PolicyModule, Value,
    languages::rego::compiler::Compiler,
    rvm::{
        RegoVM,
        vm::{ExecutionState, SuspendReason},
    },
};

/// A thin wrapper around a [Rego][`regorus`] [VM][`RegoVM`] that makes it
/// simpler to compile a policy and evaluate it while also responding to custom
/// async builtins.
pub struct PolicyVm {
    data: Value,
    vm: RegoVM,
}

impl Clone for PolicyVm {
    /// Clone the policy and data, but create a new, fresh VM execution context.
    fn clone(&self) -> Self {
        // Clone the program and data
        let program = self.vm.get_program().clone();
        let data = self.data.clone();

        // Create a new VM using the same program and dta
        let mut vm = RegoVM::new();
        vm.load_program(program);
        vm.set_data(data.clone()).unwrap();
        vm.set_execution_mode(regorus::rvm::vm::ExecutionMode::Suspendable);

        Self { data, vm }
    }
}

pub enum PolicyVmOutput {
    /// The policy has called a host function.
    ///
    /// The host will need to execute the named funtion with the given args and
    /// then resume the policy execution.
    HostCall { fn_name: String, arg: Value },
    /// The policy has completed and returned a value
    Completed(Value),
}

impl PolicyVm {
    /// Create a new policy VM.
    ///
    /// - `policy`: the Rego policy source code to create the VM for.
    /// - `data`: the value of the static `data` global that will be available
    ///   to the policy.
    /// - `entrypoint`: the rule that will be evaluated to create the result of the
    ///   policy.
    /// - `async_host_fns`: a list of built-in function names to make available to
    ///   the policy and the number of arguments that the function takes. When
    ///   evaluated in the policy these will suspend the VM and give the host the
    ///   opportunity to make any requests or do any processing and provide the result
    ///   to the VM before resuming execution.
    pub fn new(
        policy: &str,
        data: Value,
        entrypoint: &str,
        async_host_fns: &[&str],
    ) -> Result<Self> {
        // First compile the module into a compiled policy
        let compiled_policy = regorus::compile_policy_with_entrypoint(
            Value::new_object(),
            &[PolicyModule {
                id: "policy.rego".into(),
                content: policy.into(),
            }],
            entrypoint.into(),
        )?;

        // Next compile the policy to a program
        let mut host_fns = Vec::with_capacity(async_host_fns.len());
        host_fns.extend(async_host_fns.iter().map(|x| (*x, 1usize)));
        let program = Compiler::compile_from_policy_with_host_await(
            &compiled_policy,
            &[entrypoint],
            &host_fns,
        )?;

        // Finally create the VM and load the program
        let mut vm = RegoVM::new();
        vm.load_program(program);
        vm.set_data(data.clone())?;
        vm.set_execution_mode(regorus::rvm::vm::ExecutionMode::Suspendable);

        Ok(Self { data, vm })
    }

    /// Start evaluating a policy. The provided input will be set as the `input`
    /// global in the policy.
    pub fn start(&mut self, input: Value) -> Result<PolicyVmOutput> {
        self.vm.set_input(input);
        self.vm.execute()?;
        self.vm.execution_state().try_into()
    }

    /// Resume VM execution with the result of a host function call, after the
    /// VM has been suspended and returned a [`PolicyVmOutput::HostCall`].
    pub fn resume(&mut self, host_function_result: Value) -> Result<PolicyVmOutput> {
        self.vm.resume(Some(host_function_result))?;
        self.vm.execution_state().try_into()
    }
}

impl TryFrom<&ExecutionState> for PolicyVmOutput {
    type Error = anyhow::Error;

    /// Return a [`PolicyVmOutput`] based on the [`RegoVM`]'s execution state.
    fn try_from(state: &ExecutionState) -> Result<Self, Self::Error> {
        match state {
            // The engine has been suspended to trigger an async host function.
            ExecutionState::Suspended {
                reason:
                    SuspendReason::HostAwait {
                        argument,
                        identifier,
                        ..
                    },
                ..
            } => Ok(PolicyVmOutput::HostCall {
                fn_name: identifier
                    .as_string()
                    .context("Invalid policy host function identifier: expected string")?
                    .to_string(),
                arg: argument.clone(),
            }),
            // The engine has completed with the result of the policy evaluation
            ExecutionState::Completed { result } => Ok(PolicyVmOutput::Completed(result.clone())),
            // We shouldn't really be able to get into any state
            state => anyhow::bail!("Unexpected policy execution state: {state:?}"),
        }
    }
}
