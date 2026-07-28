use arbiter_core::policy::{PolicyVm, PolicyVmOutput};
use regorus::Value;

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
