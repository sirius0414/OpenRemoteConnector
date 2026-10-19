use orc_workspace::ManagedWorkspace;
use std::{
    process::{Command, Stdio},
    thread,
    time::Duration,
};

#[test]
fn editor_keeps_lock_if_the_cli_crashes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("managed");
    let workspace = ManagedWorkspace::create(&path, "workspace").unwrap();
    let mut cli = Command::new(env!("CARGO_BIN_EXE_orc"))
        .arg("workspace")
        .arg("edit")
        .arg("--path")
        .arg(&path)
        .arg("--")
        .arg("/bin/sleep")
        .arg("0.5")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut acquired = false;
    for _ in 0..100 {
        if workspace.lock().is_err() {
            acquired = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(acquired, "editor did not acquire workspace lock");
    // Give exec a chance to inherit the descriptor, then kill only our CLI child.
    thread::sleep(Duration::from_millis(50));
    cli.kill().unwrap();
    cli.wait().unwrap();
    assert!(
        workspace.lock().is_err(),
        "CLI death must not release a still-running editor's lock"
    );
    let mut released = false;
    for _ in 0..200 {
        if workspace.lock().is_ok() {
            released = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        released,
        "foreground editor should release its inherited lock when it exits"
    );
}
