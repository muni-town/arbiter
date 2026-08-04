//! Core policy engine.
//!
//! This module is responsible for executing the Rego policies that power the
//! arbiter. It is relatively low-level, providing a state machine for Rego
//! execution with custom host functions, but no arbiter-specific functionality.

use std::time::Duration;

use anyhow::{Context, Result};
use regorus::{
    PolicyModule, Value,
    languages::rego::compiler::Compiler,
    rvm::{
        RegoVM,
        vm::{ExecutionState, SuspendReason},
    },
    utils::limits::ExecutionTimerConfig,
};

/// A thin wrapper around a [Rego][`regorus`] [VM][`RegoVM`] that makes it
/// simpler to compile a policy and evaluate it while also responding to custom
/// async builtins.
#[derive(Debug)]
pub struct PolicyVm {
    data: Value,
    /// Wall-clock budget per evaluation (`None` disables the limit).
    time_limit: Option<Duration>,
    vm: RegoVM,
}

/// Default wall-clock budget for a single policy evaluation.
///
/// The limit is enforced cooperatively by the [`RegoVM`]'s execution timer: it
/// ticks once per VM instruction and only counts wall-clock time spent *inside*
/// the policy evaluator. Time spent in async host functions (e.g. `xrpc` and
/// `policy` calls) is suspended out, so the budget bounds the work the untrusted
/// policy can perform, not host latency. A tight infinite loop will burn this
/// budget and be aborted with a time-limit error.
const DEFAULT_EXECUTION_TIME_LIMIT: Duration = Duration::from_millis(100);

/// Build an [`ExecutionTimerConfig`] from a wall-clock budget, checking the
/// clock every 1 VM instruction so a tight loop is caught as soon as the budget
/// is exceeded.
fn execution_timer_config(limit: Duration) -> ExecutionTimerConfig {
    ExecutionTimerConfig {
        limit,
        check_interval: std::num::NonZeroU32::new(1).expect("1 is non-zero"),
    }
}

impl Clone for PolicyVm {
    /// Clone the policy and data, but create a new, fresh VM execution context.
    fn clone(&self) -> Self {
        // Clone the program and data
        let program = self.vm.get_program().clone();

        // Create a new VM using the same program and data
        let mut vm = RegoVM::new();
        vm.load_program(program);
        // `set_data` only fails via `check_rule_data_conflicts`, a pure check of
        // the program's rule tree against `data`. Here both the program (cloned
        // from `self.vm`) and the data (`self.data`, already accepted by `new`)
        // are byte-for-byte the same pair that `new` successfully installed, so
        // the conflict check is guaranteed to pass again. The unwrap is
        // infallible given the invariant that this `PolicyVm` was successfully
        // constructed.
        vm.set_data(self.data.clone())
            .expect("clone preserves the program+data pair that new() already validated");
        vm.set_execution_mode(regorus::rvm::vm::ExecutionMode::Suspendable);
        vm.set_execution_timer_config(self.time_limit.map(execution_timer_config));

        Self {
            data: self.data.clone(),
            time_limit: self.time_limit,
            vm,
        }
    }
}

pub enum PolicyVmOutput {
    /// The policy has called a host function.
    ///
    HostCall { fn_name: String, arg: Value },
    /// The policy has completed and returned a value
    Completed(Value),
}

impl PolicyVm {
    /// Create a new policy VM with the default execution time limit.
    ///
    /// See [`Self::with_time_limit`] for configuring (or disabling) the budget.
    pub fn new(
        policy: &str,
        data: Value,
        entrypoint: &str,
        async_host_fns: &[&str],
    ) -> Result<Self> {
        Self::with_time_limit(
            policy,
            data,
            entrypoint,
            async_host_fns,
            Some(DEFAULT_EXECUTION_TIME_LIMIT),
        )
    }

    /// Create a new policy VM with a configurable execution time limit.
    ///
    /// - `policy`: the Rego policy source code to create the VM for.
    /// - `data`: the value of the static `data` global that will be available
    ///   to the policy.
    /// - `entrypoint`: the rule that will be evaluated to create the result of the
    ///   policy.
    /// - `async_host_fns`: a list of built-in function names to make available to
    ///   the policy. Each function is registered as taking exactly one argument;
    ///   when evaluated in the policy the VM suspends and gives the host the
    ///   opportunity to make any requests or do any processing and provide the
    ///   result to the VM before resuming execution. Host functions that need a
    ///   different arity are not currently supported.
    /// - `time_limit`: the maximum wall-clock budget per evaluation, enforced
    ///   cooperatively by the [`RegoVM`]. Only time the VM spends executing policy
    ///   instructions counts against it; time spent in async host functions does
    ///   not. Passing `None` disables the limit.
    pub fn with_time_limit(
        policy: &str,
        data: Value,
        entrypoint: &str,
        async_host_fns: &[&str],
        time_limit: Option<Duration>,
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
        vm.set_execution_timer_config(time_limit.map(execution_timer_config));

        Ok(Self {
            data,
            time_limit,
            vm,
        })
    }

    /// Start evaluating a policy. The provided input will be set as the `input`
    /// global in the policy.
    ///
    /// A `PolicyVm` may be started again after a previous [`PolicyVmOutput::Completed`]
    /// (the VM is re-driven with the new `input`). It must not be re-started
    /// while a [`PolicyVmOutput::HostCall`] is outstanding — such a call must be
    /// resolved with [`Self::resume`] first.
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
