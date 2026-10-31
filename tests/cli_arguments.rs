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

#[test]
fn option_shaped_capture_labels_are_rejected_before_collection() {
    // A forgotten label must not turn an option into the scope of another profile.
    for label in [
        "--pressure",
        "--timeline",
        "--bind-boot",
        "--json",
        "-",
        "-x",
        ".",
        ".hidden",
        "_x",
    ] {
        for arguments in [
            vec!["capture", label],
            vec!["capture", label, "--pressure"],
            vec!["capture", label, "--timeline"],
            vec!["capture", label, "--pressure", "--timeline"],
            vec!["capture", label, "--bind-boot"],
            vec!["capture", label, "--pressure", "--timeline", "--bind-boot"],
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_mira"))
                .args(&arguments)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2), "{arguments:?}");
            assert!(output.stdout.is_empty(), "{arguments:?}");
            assert_eq!(
                output.stderr, b"MIRA: invalid capture label\n",
                "{arguments:?}"
            );
        }
    }
}

#[test]
fn timeline_is_opt_in_and_order_fixed() {
    let run = |arguments: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_mira"))
            .args(arguments)
            .output()
            .unwrap()
    };
    for (arguments, version) in [
        (vec!["capture", "cli-fixture"], 1),
        (vec!["capture", "cli-fixture", "--pressure"], 1),
        (vec!["capture", "cli-fixture", "--timeline"], 2),
        (
            vec!["capture", "cli-fixture", "--pressure", "--timeline"],
            2,
        ),
        (vec!["capture", "cli-fixture", "--bind-boot"], 2),
        (
            vec!["capture", "cli-fixture", "--timeline", "--bind-boot"],
            2,
        ),
        (
            vec![
                "capture",
                "cli-fixture",
                "--pressure",
                "--timeline",
                "--bind-boot",
            ],
            2,
        ),
    ] {
        let output = run(&arguments);
        assert!(matches!(output.status.code(), Some(0 | 1)), "{arguments:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.starts_with(&format!("{{\"capture_version\":{version},")),
            "{arguments:?}"
        );
        assert_eq!(
            stdout.contains("\"timeline\":["),
            version == 2,
            "{arguments:?}"
        );
        // The boot ID is read only when --bind-boot is given.
        let bound = arguments.contains(&"--bind-boot");
        assert_eq!(
            stdout.contains("\"binding\":\"not_requested\""),
            version == 2 && !bound,
            "{arguments:?}"
        );
    }
    for arguments in [
        vec!["capture", "cli-fixture", "--timeline", "--pressure"],
        vec!["capture", "cli-fixture", "--timeline", "--timeline"],
        vec!["capture", "cli-fixture", "--pressure", "--pressure"],
        vec!["capture", "cli-fixture", "--timeline", "--json"],
        vec!["capture", "cli-fixture", "--bind-boot", "--timeline"],
        vec!["capture", "cli-fixture", "--bind-boot", "--pressure"],
        vec!["capture", "cli-fixture", "--bind-boot", "--bind-boot"],
    ] {
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
    }
}
