#![cfg(target_os = "linux")]
use orc_execution::*;
use std::{collections::BTreeMap, fs, process::Command};

fn execute(
    command: ExecutionCommand,
    output: u64,
    seconds: u64,
) -> (RunnerResult, Vec<u8>, Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    private_dir(directory.path()).unwrap();
    let uid = unsafe { libc::getuid() };
    assert_ne!(uid, 0, "run Linux execution tests as an ordinary user");
    let spec = ExecutionSpec {
        task_id: "test-runner".into(),
        execution_uid: uid,
        command,
        cwd: directory.path().to_owned(),
        env: BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            (
                "HOME".into(),
                directory.path().to_string_lossy().into_owned(),
            ),
        ]),
        stdin: vec![],
        deadline_unix_ms: unix_ms() + seconds * 1000,
        output_limit_bytes: output,
    };
    let resolved = resolve_spec(spec).unwrap();
    write_new_json(&directory.path().join("spec.json"), &resolved).unwrap();
    write_new_json(&directory.path().join("gate.json"), &resolved.digest).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_orc-runner"))
        .arg("supervise")
        .arg("--directory")
        .arg(directory.path())
        .status()
        .unwrap();
    assert!(status.success());
    let result = read_json(&directory.path().join("result.json"), MAX_SPEC).unwrap();
    let stdout = fs::read(directory.path().join("stdout")).unwrap();
    let stderr = fs::read(directory.path().join("stderr")).unwrap();
    (result, stdout, stderr)
}
#[test]
fn argv_has_no_shell_expansion() {
    let (result, stdout, _) = execute(
        ExecutionCommand::Argv {
            program: "/usr/bin/printf".into(),
            args: vec!["%s\n".into(), "$HOME | cat > no-file".into()],
        },
        4096,
        10,
    );
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(stdout, b"$HOME | cat > no-file\n");
}
#[test]
fn explicit_script_runs_approved_memfd_bytes() {
    let (result, stdout, _) = execute(
        ExecutionCommand::Script {
            interpreter: "/usr/bin/dash".into(),
            interpreter_args: vec![],
            source: "printf 'approved script\\n'".into(),
            source_path: None,
            args: vec![],
        },
        4096,
        10,
    );
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(stdout, b"approved script\n");
}
#[test]
fn output_budget_is_shared_and_truncation_visible() {
    let (result,stdout,stderr)=execute(ExecutionCommand::Script{interpreter:"/usr/bin/dash".into(),interpreter_args:vec![],source:"i=0; while [ $i -lt 2000 ]; do printf abcdefghijklmnopqrstuvwxyz; printf abcdefghijklmnopqrstuvwxyz >&2; i=$((i+1)); done".into(),source_path:None,args:vec![]},1024,10);
    assert!(result.output_truncated);
    assert_eq!(stdout.len() + stderr.len(), 1024);
}
#[test]
fn deadline_does_not_report_normal_exit() {
    let (result, _, _) = execute(
        ExecutionCommand::Script {
            interpreter: "/usr/bin/dash".into(),
            interpreter_args: vec![],
            source: "while :; do sleep 1; done".into(),
            source_path: None,
            args: vec![],
        },
        1024,
        1,
    );
    assert_eq!(result.reason, "deadline");
    assert_eq!(result.exit_code, None);
}
#[test]
fn stdin_reaches_eof_and_environment_is_not_inherited() {
    let (result, stdout, _) = execute(
        ExecutionCommand::Script {
            interpreter: "/usr/bin/dash".into(),
            interpreter_args: vec![],
            source: "cat; printf '%s' \"${ORC_TEST_SECRET-unset}\"".into(),
            source_path: None,
            args: vec![],
        },
        4096,
        10,
    );
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(stdout, b"unset");
}
