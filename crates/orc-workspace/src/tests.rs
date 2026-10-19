use super::*;
use tempfile::tempdir;
fn fixture() -> (tempfile::TempDir, ManagedWorkspace, ObjectStore, PathBuf) {
    let dir = tempdir().unwrap();
    let root = dir.path().join("workspace");
    let managed = ManagedWorkspace::create(&root, "ws").unwrap();
    let objects = ObjectStore::open(dir.path().join("objects")).unwrap();
    (dir, managed, objects, root)
}
#[test]
fn snapshot_excludes_secrets_links_and_non_text() {
    let (_dir, _managed, objects, root) = fixture();
    fs::write(root.join("ok.txt"), "hello").unwrap();
    fs::write(root.join(".env"), "SECRET=never-export").unwrap();
    fs::write(root.join("binary"), [0, 255]).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", root.join("escape")).unwrap();
    fs::hard_link(root.join("ok.txt"), root.join("hard.txt")).unwrap();
    let snapshot = Snapshot::export(&root, "ws", &objects, &Limits::default(), 1).unwrap();
    assert!(snapshot.files.is_empty());
    assert!(snapshot.exclusions.iter().any(|e| e.path == ".env"));
    assert!(snapshot.exclusions.iter().any(|e| e.path == "escape"));
    assert!(snapshot.exclusions.iter().any(|e| e.path == "hard.txt"));
}
#[test]
fn approved_snapshot_bytes_do_not_follow_host_changes() {
    let (_dir, _managed, objects, root) = fixture();
    fs::write(root.join("text.txt"), "before").unwrap();
    let snapshot = Snapshot::export(&root, "ws", &objects, &Limits::default(), 1).unwrap();
    fs::write(root.join("text.txt"), "after").unwrap();
    assert_eq!(
        snapshot.read("text.txt", &objects, 0, 64).unwrap(),
        b"before"
    );
    assert!(snapshot.read("../outside", &objects, 0, 64).is_err());
    assert!(snapshot.read("text.txt", &objects, 0, 65537).is_err());
}
#[test]
fn apply_checks_whole_baseline_before_consuming_approval() {
    let (dir, managed, objects, root) = fixture();
    fs::write(root.join("a.txt"), "old").unwrap();
    let baseline = Snapshot::export(&root, "ws", &objects, &Limits::default(), 1).unwrap();
    let output = dir.path().join("output");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("a.txt"), "new").unwrap();
    let artifacts = Snapshot::export(output, "ws", &objects, &Limits::artifacts(), 2).unwrap();
    let changes = ChangeSet::between("ws", &baseline, &artifacts).unwrap();
    fs::write(root.join("a.txt"), "external edit").unwrap();
    let mut consumed = false;
    assert!(matches!(
        managed.apply(&changes, &objects, &changes.change_set_id, |stage| {
            if matches!(stage, ApplyCheck::ConsumeApproval) {
                consumed = true
            }
            Ok(())
        }),
        Err(WorkspaceError::Conflict(_))
    ));
    assert!(!consumed);
    assert_eq!(
        fs::read_to_string(root.join("a.txt")).unwrap(),
        "external edit"
    );
}
#[test]
fn apply_is_exact_and_never_replays_a_consumed_batch() {
    let (dir, managed, objects, root) = fixture();
    fs::write(root.join("a.txt"), "old").unwrap();
    fs::write(root.join("deleted.txt"), "remove").unwrap();
    let baseline = Snapshot::export(&root, "ws", &objects, &Limits::default(), 1).unwrap();
    let output = dir.path().join("output");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("a.txt"), "new").unwrap();
    fs::write(output.join("created.txt"), "created").unwrap();
    let artifacts = Snapshot::export(output, "ws", &objects, &Limits::artifacts(), 2).unwrap();
    let changes = ChangeSet::between("ws", &baseline, &artifacts).unwrap();
    let mut consumed = 0;
    let report = managed
        .apply(&changes, &objects, &changes.change_set_id, |stage| {
            if matches!(stage, ApplyCheck::ConsumeApproval) {
                consumed += 1
            }
            Ok(())
        })
        .unwrap();
    assert!(
        report
            .results
            .iter()
            .all(|r| r.state == ApplyState::Applied)
    );
    assert_eq!(consumed, 1);
    assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "new");
    assert!(!root.join("deleted.txt").exists());
    assert!(matches!(
        managed.apply(&changes, &objects, &changes.change_set_id, |_| Ok(())),
        Err(WorkspaceError::AlreadyAttempted)
    ));
}
#[test]
fn revoke_mid_apply_reports_partial_results() {
    let (dir, managed, objects, root) = fixture();
    fs::write(root.join("a.txt"), "old").unwrap();
    fs::write(root.join("b.txt"), "old").unwrap();
    let baseline = Snapshot::export(&root, "ws", &objects, &Limits::default(), 1).unwrap();
    let output = dir.path().join("output");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("a.txt"), "new").unwrap();
    fs::write(output.join("b.txt"), "new").unwrap();
    let artifacts = Snapshot::export(output, "ws", &objects, &Limits::artifacts(), 2).unwrap();
    let changes = ChangeSet::between("ws", &baseline, &artifacts).unwrap();
    let report = managed
        .apply(
            &changes,
            &objects,
            &changes.change_set_id,
            |stage| match stage {
                ApplyCheck::BeforeFile("b.txt") => Err(WorkspaceError::Revoked),
                _ => Ok(()),
            },
        )
        .unwrap();
    assert_eq!(report.results[0].state, ApplyState::Applied);
    assert_eq!(report.results[1].state, ApplyState::NotApplied);
    assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "new");
    assert_eq!(fs::read_to_string(root.join("b.txt")).unwrap(), "old");
    assert_eq!(
        managed.reconcile(&changes).unwrap().results[0].state,
        ApplyState::Applied
    );
}
#[test]
fn unregistered_or_busy_workspaces_cannot_apply() {
    let (dir, managed, objects, root) = fixture();
    assert!(matches!(
        ManagedWorkspace::open(dir.path()),
        Err(WorkspaceError::NotExclusive)
    ));
    let _lock = managed.lock().unwrap();
    let other = ManagedWorkspace::open(root).unwrap();
    assert!(matches!(other.lock(), Err(WorkspaceError::NotExclusive)));
    assert!(matches!(
        other.export(&objects, &Limits::default(), 1),
        Err(WorkspaceError::NotExclusive)
    ));
}
#[test]
fn text_and_object_capacity_are_enforced() {
    let dir = tempdir().unwrap();
    let objects = ObjectStore::with_capacity(dir.path().join("objects"), 4).unwrap();
    objects.put_text(b"abcd", 4).unwrap();
    assert!(matches!(
        objects.put_text(b"other", 8),
        Err(WorkspaceError::QuotaExceeded)
    ));
    assert!(matches!(
        objects.put_text(b"\0", 4),
        Err(WorkspaceError::UnsupportedFile)
    ));
}
#[test]
fn changed_approved_manifest_is_rejected() {
    let (_dir, _managed, objects, root) = fixture();
    fs::write(root.join("a.txt"), "hello").unwrap();
    let mut snapshot = Snapshot::export(root, "ws", &objects, &Limits::default(), 1).unwrap();
    snapshot.files.get_mut("a.txt").unwrap().digest = "0".repeat(64);
    assert!(snapshot.verify().is_err());
}
#[test]
fn parent_symlink_cannot_escape_during_baseline_check() {
    let (dir, managed, objects, root) = fixture();
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("sub/a.txt"), "old").unwrap();
    let baseline = Snapshot::export(&root, "ws", &objects, &Limits::default(), 1).unwrap();
    let output = dir.path().join("output");
    fs::create_dir_all(output.join("sub")).unwrap();
    fs::write(output.join("sub/a.txt"), "new").unwrap();
    let artifacts = Snapshot::export(&output, "ws", &objects, &Limits::artifacts(), 2).unwrap();
    let changes = ChangeSet::between("ws", &baseline, &artifacts).unwrap();
    fs::remove_file(root.join("sub/a.txt")).unwrap();
    fs::remove_dir(root.join("sub")).unwrap();
    std::os::unix::fs::symlink(output.join("sub"), root.join("sub")).unwrap();
    assert!(
        managed
            .apply::<()>(&changes, &objects, &changes.change_set_id, |_| panic!(
                "must reject before approval"
            ))
            .is_err()
    );
    assert_eq!(fs::read_to_string(output.join("sub/a.txt")).unwrap(), "new");
}

#[test]
fn cloned_editor_descriptor_retains_exclusivity_after_parent_guard_drops() {
    let dir = tempdir().unwrap();
    let workspace = ManagedWorkspace::create(dir.path().join("managed"), "workspace").unwrap();
    let guard = workspace.lock().unwrap();
    let editor = guard.clone_editor_lock().unwrap();
    drop(guard);
    assert!(matches!(
        workspace.lock(),
        Err(WorkspaceError::NotExclusive)
    ));
    drop(editor);
    assert!(workspace.lock().is_ok());
}

#[test]
fn authorization_guard_lives_through_actual_file_mutation() {
    struct Guard {
        path: PathBuf,
        released: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            assert_eq!(fs::read(&self.path).unwrap(), b"new");
            self.released
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let (dir, managed, objects, root) = fixture();
    fs::write(root.join("a.txt"), b"old").unwrap();
    let baseline = managed.export(&objects, &Limits::default(), 1).unwrap();
    let output = dir.path().join("output");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("a.txt"), b"new").unwrap();
    let artifacts = Snapshot::export(output, "ws", &objects, &Limits::artifacts(), 2).unwrap();
    let changes = ChangeSet::between("ws", &baseline, &artifacts).unwrap();
    let released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let report = managed
        .apply(
            &changes,
            &objects,
            &changes.change_set_id,
            |stage| match stage {
                ApplyCheck::ConsumeApproval => Ok(None),
                ApplyCheck::BeforeFile(path) => Ok(Some(Guard {
                    path: root.join(path),
                    released: released.clone(),
                })),
            },
        )
        .unwrap();
    assert_eq!(report.results[0].state, ApplyState::Applied);
    assert!(released.load(std::sync::atomic::Ordering::SeqCst));
}
