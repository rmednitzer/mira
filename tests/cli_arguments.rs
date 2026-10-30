//! Argument encoding is rejected before collector or retained-demo dispatch.
#![cfg(unix)]

use std::{
    ffi::OsString,
    os::unix::{ffi::OsStringExt, process::CommandExt},
    process::Command,
};

#[test]
fn non_utf8_arguments_are_usage_errors_without_output_or_panic() {
    let invalid = OsString::from_vec(vec![0xff, 0xfe]);
    for arguments in [
        vec![invalid.clone()],
        vec![OsString::from("capture"), invalid.clone()],
        vec![OsString::from("service"), invalid.clone()],
        vec![
            OsString::from("investigate"),
            OsString::from("service-active"),
            invalid.clone(),
            OsString::from("--json"),
        ],
        vec![OsString::from("inspect"), invalid.clone()],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mira"))
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"MIRA: arguments must be valid UTF-8\n");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_mira"))
        .arg0(invalid)
        .arg("demo")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"MIRA: arguments must be valid UTF-8\n");
}
