#![cfg(target_os = "linux")]
use orc_backend_host_linux::{HostBackend, HostConfig};
use orc_execution::*;
use std::{collections::BTreeMap, fs, path::Path, time::Duration};

fn spec(root: &Path, task: &str, command: ExecutionCommand) -> ResolvedSpec {
    resolve_spec(ExecutionSpec {
        task_id: task.into(),
        execution_uid: unsafe { libc::getuid() },
        command,
        cwd: root.into(),
        env: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
        stdin: vec![],
        deadline_unix_ms: unix_ms() + 30_000,
        output_limit_bytes: 4096,
    })
    .unwrap()
}
async fn exited(backend: &HostBackend, instance: &InstanceRef) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if backend.inspect(instance).await.unwrap().state == RuntimeState::Exited {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("original systemd unit must reach a proven terminal state");
}

/// Explicitly invoked by the Linux CI service fixture; never treats a missing
/// user manager, runner, or non-root session as a passing integration test.
#[tokio::test]
#[ignore = "requires real systemd user manager and ORC_TEST_RUNNER_PATH"]
async fn real_systemd_prepare_launch_tree_stop_and_stop_before_launch() {
    let uid = unsafe { libc::getuid() };
    assert_ne!(uid, 0);
    let runner = fs::canonicalize(
        std::env::var_os("ORC_TEST_RUNNER_PATH")
            .expect("set ORC_TEST_RUNNER_PATH to a built Linux orc-runner"),
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("tasks");
    private_dir(&state).unwrap();
    let backend = HostBackend::new(HostConfig {
        state_dir: state,
        runner_path: runner,
        execution_uid: uid,
    });
    assert!(backend.probe().await.unwrap().available);

    let resolved = spec(
        root.path(),
        "systemd-literal",
        ExecutionCommand::Argv {
            program: "/usr/bin/printf".into(),
            args: vec!["%s\n".into(), "$HOME | cat > not-a-command".into()],
        },
    );
    let permit = LaunchPermit::after_durable_authorization(
        resolved.spec.task_id.clone(),
        resolved.digest.clone(),
    );
    let prepared = backend.prepare(resolved).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !prepared.instance.directory.join("started.json").exists(),
        "prepare cannot execute the user entry"
    );
    assert!(!prepared.instance.directory.join("stdout").exists());
    let instance = backend.start(prepared, permit).await.unwrap();
    exited(&backend, &instance).await;
    assert_eq!(
        fs::read(instance.directory.join("stdout")).unwrap(),
        b"$HOME | cat > not-a-command\n"
    );
    assert!(!root.path().join("not-a-command").exists());
    backend.cleanup(&instance).await.unwrap();

    let resolved = spec(
        root.path(),
        "systemd-tree",
        ExecutionCommand::Script {
            interpreter: "/usr/bin/dash".into(),
            interpreter_args: vec![],
            source: "sleep 60 & printf '%s' \"$!\" > child.pid; wait".into(),
            source_path: None,
            args: vec![],
        },
    );
    let permit = LaunchPermit::after_durable_authorization(
        resolved.spec.task_id.clone(),
        resolved.digest.clone(),
    );
    let instance = backend
        .start(backend.prepare(resolved).await.unwrap(), permit)
        .await
        .unwrap();
    let child: u32 = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(pid) = fs::read_to_string(root.path().join("child.pid"))
                .ok()
                .and_then(|text| text.parse().ok())
            {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        backend
            .stop(&instance, StopReason::Cancelled)
            .await
            .unwrap()
            .confirmed
    );
    exited(&backend, &instance).await;
    if let Ok(stat) = fs::read_to_string(format!("/proc/{child}/stat")) {
        assert_eq!(
            stat.rsplit_once(") ").unwrap().1.split_whitespace().next(),
            Some("Z"),
            "child must not remain runnable"
        );
    }
    backend.cleanup(&instance).await.unwrap();

    let marker = root.path().join("forbidden-start");
    let resolved = spec(
        root.path(),
        "systemd-stop-before-start",
        ExecutionCommand::Argv {
            program: "/usr/bin/touch".into(),
            args: vec![marker.to_string_lossy().into_owned()],
        },
    );
    let permit = LaunchPermit::after_durable_authorization(
        resolved.spec.task_id.clone(),
        resolved.digest.clone(),
    );
    let prepared = backend.prepare(resolved).await.unwrap();
    let instance = prepared.instance.clone();
    assert!(
        backend
            .stop(&instance, StopReason::SupervisorLost)
            .await
            .unwrap()
            .confirmed
    );
    assert!(backend.start(prepared, permit).await.is_err());
    assert!(!marker.exists());
    backend.cleanup(&instance).await.unwrap();
}
