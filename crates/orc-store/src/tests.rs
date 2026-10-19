use super::*;
use tempfile::tempdir;

fn grant() -> StoredGrant {
    StoredGrant {
        grant_id: "grant".into(),
        principal_id: "alice".into(),
        device_id: "device".into(),
        revision: 1,
        expires_at: 1000,
        status: "active".into(),
        payload: serde_json::json!({"policy":"approval"}),
    }
}
fn submission() -> SubmissionRecord {
    SubmissionRecord {
        key: SubmissionKey {
            principal_id: "alice".into(),
            device_id: "device".into(),
            submission_id: "submission".into(),
        },
        request_digest: "digest".into(),
        task_id: "task".into(),
        grant_id: "grant".into(),
        created_at: 100,
    }
}
fn task() -> StoredTask {
    StoredTask {
        task_id: "task".into(),
        principal_id: "alice".into(),
        device_id: "device".into(),
        grant_id: "grant".into(),
        effective_digest: "effective".into(),
        execution_state: "pending_approval".into(),
        stop_state: "none".into(),
        finish_reason: None,
        exit_code: None,
        revision: 0,
        created_at: 100,
        updated_at: 100,
        payload: serde_json::json!({"script":"secret-script-body"}),
    }
}
fn approval() -> StoredApproval {
    StoredApproval {
        approval_id: "approval".into(),
        grant_id: "grant".into(),
        effective_digest: "effective".into(),
        grant_revision: 1,
        policy_revision: 1,
        expires_at: 500,
        status: "pending".into(),
        consumed_by: None,
    }
}
async fn fixture() -> (tempfile::TempDir, Store) {
    let dir = tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.put_grant(grant()).await.unwrap();
    (dir, store)
}
fn reopen(dir: &Path) -> Store {
    for _ in 0..100 {
        match Store::open(dir) {
            Ok(store) => return store,
            Err(StoreError::SecurityState(s)) if s.contains("already in use") => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(e) => panic!("{e}"),
        }
    }
    panic!("store did not close")
}

#[tokio::test]
async fn retry_is_idempotent_but_changed_body_conflicts() {
    let (_dir, store) = fixture().await;
    assert!(
        store
            .accept_submission(submission(), task())
            .await
            .unwrap()
            .created
    );
    assert!(
        !store
            .accept_submission(submission(), task())
            .await
            .unwrap()
            .created
    );
    let mut changed = submission();
    changed.request_digest = "other".into();
    assert!(matches!(
        store.accept_submission(changed, task()).await,
        Err(StoreError::SubmissionConflict)
    ));
    assert_eq!(store.list_tasks(None).await.unwrap().len(), 1);
}
#[tokio::test]
async fn approval_is_content_bound_and_single_use() {
    let (_dir, store) = fixture().await;
    store.accept_submission(submission(), task()).await.unwrap();
    store.create_approval(approval()).await.unwrap();
    store.decide_approval("approval", true, 101).await.unwrap();
    assert!(matches!(
        store
            .consume_approval("approval", "changed", 1, 1, "task", 102)
            .await,
        Err(StoreError::ApprovalInvalid)
    ));
    store
        .consume_approval("approval", "effective", 1, 1, "task", 102)
        .await
        .unwrap();
    assert!(matches!(
        store
            .consume_approval("approval", "effective", 1, 1, "task", 102)
            .await,
        Err(StoreError::ApprovalInvalid)
    ));
}
#[tokio::test]
async fn revoke_invalidates_pending_work_and_prevents_new_acceptance() {
    let (_dir, store) = fixture().await;
    store.accept_submission(submission(), task()).await.unwrap();
    store.create_approval(approval()).await.unwrap();
    let stopped = store.revoke_grant("grant", 101).await.unwrap();
    assert_eq!(stopped[0].execution_state, "not_started");
    assert_eq!(stopped[0].stop_state, "confirmed");
    assert!(store.decide_approval("approval", true, 102).await.is_err());
    let mut next = submission();
    next.key.submission_id = "next".into();
    next.task_id = "next".into();
    let mut next_task = task();
    next_task.task_id = "next".into();
    assert!(matches!(
        store.accept_submission(next, next_task).await,
        Err(StoreError::GrantInactive)
    ));
}
#[tokio::test]
async fn restore_old_database_keeps_revocations_and_consumption() {
    let (dir, store) = fixture().await;
    let backup = dir.path().join("backup.sqlite3");
    store.accept_submission(submission(), task()).await.unwrap();
    store.create_approval(approval()).await.unwrap();
    store.decide_approval("approval", true, 101).await.unwrap();
    store.backup(&backup).await.unwrap();
    store
        .consume_approval("approval", "effective", 1, 1, "task", 102)
        .await
        .unwrap();
    store.revoke_grant("grant", 103).await.unwrap();
    drop(store);
    let closed = reopen(dir.path());
    drop(closed);
    std::thread::sleep(Duration::from_millis(20));
    fs::copy(backup, dir.path().join("state.sqlite3")).unwrap();
    let restored = reopen(dir.path());
    assert_eq!(
        restored.get_grant("grant").await.unwrap().unwrap().status,
        "revoked"
    );
    assert_eq!(
        restored
            .get_approval("approval")
            .await
            .unwrap()
            .unwrap()
            .status,
        "consumed"
    );
    assert_eq!(
        restored
            .get_task("task")
            .await
            .unwrap()
            .unwrap()
            .execution_state,
        "not_started"
    );
}
#[tokio::test]
async fn journal_does_not_contain_task_body() {
    let (dir, store) = fixture().await;
    store.accept_submission(submission(), task()).await.unwrap();
    let journal = fs::read_to_string(dir.path().join("security-journal.jsonl")).unwrap();
    assert!(!journal.contains("secret-script-body"));
}
#[tokio::test]
async fn journal_tampering_fails_closed() {
    let (dir, store) = fixture().await;
    drop(store);
    std::thread::sleep(Duration::from_millis(20));
    OpenOptions::new()
        .append(true)
        .open(dir.path().join("security-journal.jsonl"))
        .unwrap()
        .write_all(b"{\"partial\":")
        .unwrap();
    assert!(matches!(
        Store::open(dir.path()),
        Err(StoreError::SecurityState(_))
    ));
}
#[tokio::test]
async fn compare_and_swap_and_terminal_state_do_not_restart_tasks() {
    let (_dir, store) = fixture().await;
    store.accept_submission(submission(), task()).await.unwrap();
    let mut next = task();
    next.execution_state = "accepted".into();
    let next = store.update_task(next, 0).await.unwrap();
    assert!(matches!(
        store.update_task(next.clone(), 0).await,
        Err(StoreError::RevisionConflict)
    ));
    let mut ended = next;
    ended.execution_state = "not_started".into();
    ended.stop_state = "confirmed".into();
    let mut ended = store.update_task(ended, 1).await.unwrap();
    ended.execution_state = "starting".into();
    assert!(matches!(
        store.update_task(ended, 2).await,
        Err(StoreError::RevisionConflict)
    ));
}
#[tokio::test]
async fn accepted_after_backup_restores_only_unknown_tombstone() {
    let (dir, store) = fixture().await;
    let backup = dir.path().join("backup.sqlite3");
    store.backup(&backup).await.unwrap();
    store.accept_submission(submission(), task()).await.unwrap();
    drop(store);
    std::thread::sleep(Duration::from_millis(20));
    fs::copy(backup, dir.path().join("state.sqlite3")).unwrap();
    let store = reopen(dir.path());
    let recovered = store.accept_submission(submission(), task()).await.unwrap();
    assert!(!recovered.created);
    assert_eq!(recovered.task.execution_state, "unknown");
    assert!(recovered.task.payload.is_null());
}

#[tokio::test]
async fn change_approval_is_bound_to_durable_change_record() {
    let (_dir, store) = fixture().await;
    store.create_approval(approval()).await.unwrap();
    store.decide_approval("approval", true, 101).await.unwrap();
    assert!(matches!(
        store
            .consume_change_approval("approval", "effective", 1, 1, "change", 102)
            .await,
        Err(StoreError::NotFound)
    ));
    store.put_record("changes","change",serde_json::json!({"change_set_id":"change","approval_id":"approval","grant_id":"grant","effective_digest":"effective","grant_revision":1,"policy_revision":1})).await.unwrap();
    store
        .consume_change_approval("approval", "effective", 1, 1, "change", 102)
        .await
        .unwrap();
    assert!(matches!(
        store
            .consume_change_approval("approval", "effective", 1, 1, "change", 103)
            .await,
        Err(StoreError::ApprovalInvalid)
    ));
}

#[tokio::test]
async fn pending_task_and_approval_commit_together() {
    let (_dir, store) = fixture().await;
    store
        .accept_submission_with_approval(submission(), task(), Some(approval()))
        .await
        .unwrap();
    assert!(store.get_task("task").await.unwrap().is_some());
    assert_eq!(
        store
            .get_approval("approval")
            .await
            .unwrap()
            .unwrap()
            .status,
        "pending"
    );
    let before = store.security_sequence().await.unwrap();
    let retried = store
        .accept_submission_with_approval(submission(), task(), Some(approval()))
        .await
        .unwrap();
    assert!(!retried.created);
    assert_eq!(store.security_sequence().await.unwrap(), before);
}

#[tokio::test]
async fn invitation_redemption_is_atomic_and_replay_safe() {
    let (dir, store) = fixture().await;
    store.put_record("enrollment_invitation", "nonce", serde_json::json!({"invitation_digest":"digest","expires_at":500,"consumed":false,"name":"device"})).await.unwrap();
    let backup = dir.path().join("before-redemption.sqlite3");
    store.backup(&backup).await.unwrap();
    let device = serde_json::json!({"device_id":"new-device","status":"trusted_ungranted"});
    assert!(
        store
            .redeem_invitation("nonce", "wrong", "new-device", device.clone(), 101)
            .await
            .is_err()
    );
    assert!(
        store
            .get_record("device", "new-device")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .redeem_invitation("nonce", "digest", "new-device", device.clone(), 500)
            .await
            .is_err()
    );
    store
        .redeem_invitation("nonce", "digest", "new-device", device.clone(), 101)
        .await
        .unwrap();
    assert!(
        store
            .redeem_invitation("nonce", "digest", "new-device", device.clone(), 102)
            .await
            .is_err()
    );
    drop(store);
    std::thread::sleep(Duration::from_millis(20));
    fs::copy(backup, dir.path().join("state.sqlite3")).unwrap();
    let store = reopen(dir.path());
    assert_eq!(
        store.get_record("device", "new-device").await.unwrap(),
        Some(device.clone())
    );
    assert!(
        store
            .redeem_invitation("nonce", "digest", "new-device", device, 103)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn expired_body_cannot_return_from_an_old_database() {
    let (dir, store) = fixture().await;
    store.accept_submission(submission(), task()).await.unwrap();
    assert!(store.expire_task_body("task", 86500).await.is_err());
    let mut ended = task();
    ended.execution_state = "not_started".into();
    ended.stop_state = "confirmed".into();
    store.update_task(ended, 0).await.unwrap();
    assert!(store.expire_task_body("task", 86499).await.is_err());
    let backup = dir.path().join("before-expiry.sqlite3");
    store.backup(&backup).await.unwrap();
    store.expire_task_body("task", 86500).await.unwrap();
    let sequence = store.security_sequence().await.unwrap();
    store.expire_task_body("task", 86501).await.unwrap();
    assert_eq!(sequence, store.security_sequence().await.unwrap());
    drop(store);
    std::thread::sleep(Duration::from_millis(20));
    fs::copy(backup, dir.path().join("state.sqlite3")).unwrap();
    let store = reopen(dir.path());
    let task = store.get_task("task").await.unwrap().unwrap();
    assert!(task.payload.is_null());
    assert_eq!(task.revision, 2);
    assert!(
        store
            .get_submission(submission().key)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn task_creation_time_cannot_extend_retention() {
    let (_dir, store) = fixture().await;
    store.accept_submission(submission(), task()).await.unwrap();
    let mut changed = task();
    changed.created_at += 86400;
    changed.execution_state = "accepted".into();
    assert!(matches!(
        store.update_task(changed, 0).await,
        Err(StoreError::RevisionConflict)
    ));
    assert_eq!(
        store.get_task("task").await.unwrap().unwrap().created_at,
        100
    );
}

#[test]
fn audit_budget_prunes_seven_day_metadata_without_touching_security_history() {
    let dir = tempdir().unwrap();
    let mut db = Database::open_with_limits(
        dir.path(),
        StorageLimits {
            audit: 160,
            ..Default::default()
        },
    )
    .unwrap();
    db.handle(Operation::PutGrant(grant())).unwrap();
    let sequence = db.sequence;
    let event = |timestamp| AuditEvent {
        timestamp,
        principal_id: Some("alice".into()),
        device_id: None,
        task_id: None,
        action: "task.get".into(),
        outcome: "success".into(),
    };
    db.handle(Operation::Audit(event(10))).unwrap();
    assert!(matches!(
        db.handle(Operation::Audit(event(11))),
        Err(StoreError::QuotaExceeded)
    ));
    db.handle(Operation::Audit(event(10 + AUDIT_RETENTION_SECONDS + 1)))
        .unwrap();
    let (count, oldest): (u64, u64) = db
        .connection
        .query_row(
            "SELECT count(*),min(timestamp) FROM audit_events",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(oldest, 10 + AUDIT_RETENTION_SECONDS + 1);
    assert_eq!(sequence, db.sequence);
    let used: u64 = db
        .connection
        .query_row(
            "SELECT value FROM metadata WHERE key='audit_bytes'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(used, 84);
    assert!(db.grant("grant").unwrap().is_some());
}
#[test]
fn database_capacity_rejects_new_work_but_keeps_revocation_reserve_and_retries() {
    let dir = tempdir().unwrap();
    let mut db = Database::open_with_limits(
        dir.path(),
        StorageLimits {
            database_hard: 512 * 1024,
            database_high_water: 256 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    db.handle(Operation::PutGrant(grant())).unwrap();
    db.handle(Operation::Accept(submission(), task(), None))
        .unwrap();
    db.connection
        .execute_batch("CREATE TABLE fill(body BLOB); INSERT INTO fill VALUES(zeroblob(262144));")
        .unwrap();
    assert!(db.require_headroom().is_err());
    let retry = db
        .handle(Operation::Accept(submission(), task(), None))
        .unwrap();
    assert_eq!(retry["created"], false);
    let mut next = submission();
    next.key.submission_id = "new".into();
    next.task_id = "next".into();
    let mut next_task = task();
    next_task.task_id = "next".into();
    assert!(matches!(
        db.handle(Operation::Accept(next, next_task, None)),
        Err(StoreError::QuotaExceeded)
    ));
    db.handle(Operation::Revoke("grant".into(), 101)).unwrap();
    assert_eq!(db.grant("grant").unwrap().unwrap().status, "revoked");
    assert!(
        db.connection
            .execute("INSERT INTO fill VALUES(zeroblob(1048576))", [])
            .is_err()
    );
    let pages: u64 = db
        .connection
        .pragma_query_value(None, "max_page_count", |r| r.get(0))
        .unwrap();
    let page_size: u64 = db
        .connection
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .unwrap();
    assert_eq!(pages * page_size, 512 * 1024);
}
#[test]
fn security_journal_high_water_reserves_room_for_revocation() {
    let dir = tempdir().unwrap();
    let mut db = Database::open(dir.path()).unwrap();
    db.handle(Operation::PutGrant(grant())).unwrap();
    db.limits.journal_high_water = db.journal.metadata().unwrap().len();
    assert!(matches!(
        db.handle(Operation::PutRecord(
            "snapshot".into(),
            "new".into(),
            serde_json::json!({})
        )),
        Err(StoreError::QuotaExceeded)
    ));
    db.handle(Operation::Revoke("grant".into(), 101)).unwrap();
    assert_eq!(db.grant("grant").unwrap().unwrap().status, "revoked");
}
