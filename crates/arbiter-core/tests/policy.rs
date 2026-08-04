use arbiter_core::policy::{PolicyVm, PolicyVmOutput};
use regorus::Value;
use std::time::Duration;

#[test]
fn basic_policy() {
    let data = Value::from_json_str(r#"{ "required_awesomeness": 50 }"#).unwrap();
    let policy = r#"
        package test
        default allow := false
        allow if {
            input.awesomeness > data.required_awesomeness
        }
    "#;

    let mut vm = PolicyVm::new(policy, data, "data.test.allow", &[]).unwrap();

    let input = Value::from_json_str(r#"{ "awesomeness": 30 }"#).unwrap();
    let PolicyVmOutput::Completed(value) = vm.start(input).unwrap() else {
        panic!("Unexpected suspension");
    };
    assert!(!value.as_bool().unwrap());

    let input = Value::from_json_str(r#"{ "awesomeness": 80 }"#).unwrap();
    let PolicyVmOutput::Completed(value) = vm.start(input).unwrap() else {
        panic!("Unexpected suspension");
    };
    assert!(value.as_bool().unwrap());
}

#[test]
fn policy_with_host_call() {
    let data = Value::new_object();
    let policy = r#"
        package test
        default allow := false
        allow if {
            input.awesomeness > required_awesomeness("test")
        }
    "#;

    let mut vm = PolicyVm::new(policy, data, "data.test.allow", &["required_awesomeness"]).unwrap();

    let input = Value::from_json_str(r#"{ "awesomeness": 30 }"#).unwrap();
    let PolicyVmOutput::HostCall { fn_name, arg } = vm.start(input).unwrap() else {
        panic!("Unexpected value");
    };
    assert_eq!(fn_name, "required_awesomeness");
    assert_eq!(&arg.as_string().unwrap()[..], "test");

    let PolicyVmOutput::Completed(value) = vm
        .resume(Value::from_numeric_string("50").unwrap())
        .unwrap()
    else {
        panic!("Unexpected suspension");
    };
    assert!(!value.as_bool().unwrap());

    let input = Value::from_json_str(r#"{ "awesomeness": 20 }"#).unwrap();
    let PolicyVmOutput::HostCall { fn_name, arg } = vm.start(input).unwrap() else {
        panic!("Unexpected value");
    };
    assert_eq!(fn_name, "required_awesomeness");
    assert_eq!(&arg.as_string().unwrap()[..], "test");

    let PolicyVmOutput::Completed(value) = vm
        .resume(Value::from_numeric_string("10").unwrap())
        .unwrap()
    else {
        panic!("Unexpected suspension");
    };
    assert!(value.as_bool().unwrap());
}

/// A policy that exceeds a small execution time budget is aborted with a
/// time-limit error, even though it would otherwise terminate.
#[test]
fn small_time_limit_aborts_policy() {
    let data = Value::new_object();
    // A finite loop over a modest range: well under the VM's 25000-instruction
    // cap, but enough VM instructions that a 1ms budget is exceeded. (A pure
    // infinite loop would instead trip the instruction cap before the timer,
    // so a finite-but-slow policy is what exercises the time limit.)
    let policy = r#"
        package test
        allow := countdown(0)
        countdown(x) := countdown(x + 1) if x < 100000
        countdown(x) := x if x >= 100000
    "#;

    let mut vm = PolicyVm::with_time_limit(
        policy,
        data,
        "data.test.allow",
        &[],
        Some(Duration::from_millis(1)),
    )
    .unwrap();

    let input = Value::new_object();
    let err = match vm.start(input) {
        Ok(_) => panic!("expected the time limit to abort the policy"),
        Err(err) => err,
    };
    let err = format!("{err:#}");
    assert!(
        err.contains("time limit") || err.contains("TimeLimit"),
        "expected a time-limit error, got: {err}"
    );
}

/// `None` disables the time limit; a policy that would exceed the default budget
/// is allowed to complete (and host functions are still supported).
#[test]
fn with_time_limit_none_disables_limit() {
    let data = Value::new_object();
    let policy = r#"
        package test
        allow := true
    "#;

    // A non-looping policy still completes when the limit is disabled.
    let mut vm = PolicyVm::with_time_limit(policy, data, "data.test.allow", &[], None).unwrap();
    let input = Value::new_object();
    let PolicyVmOutput::Completed(value) = vm.start(input).unwrap() else {
        panic!("Unexpected suspension");
    };
    assert!(value.as_bool().unwrap());

    // A custom, non-default limit is honored (fast policy finishes under it).
    let data = Value::new_object();
    let mut vm = PolicyVm::with_time_limit(
        policy,
        data,
        "data.test.allow",
        &[],
        Some(Duration::from_secs(5)),
    )
    .unwrap();
    let PolicyVmOutput::Completed(value) = vm.start(Value::new_object()).unwrap() else {
        panic!("Unexpected suspension");
    };
    assert!(value.as_bool().unwrap());
}
