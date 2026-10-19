//! 串行持久化存储，以及独立保留的安全事实 journal。
//!
//! `Store` 是异步队列句柄，`Database` 仅由专用线程使用；控制队列优先于普通请求，
//! 为撤销、停止状态和恢复保留处理机会及容量。SQL 不在调用者的异步任务上执行。
//! 安全事件按 journal 写入并同步 → SQLite 事务 → 更新内存序号的顺序提交。
//! 恢复旧数据库时必须保留 `security-journal.jsonl`；重放只恢复安全事实，不能执行命令。
//! journal 缺失或损坏时拒绝恢复；任务正文不写入任务事件的 journal 副本。

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

const JOURNAL_LIMIT: u64 = 256 * 1024 * 1024;
const RECORD_LIMIT: usize = 256 * 1024;
#[derive(Clone, Copy)]
struct StorageLimits {
    database_hard: u64,
    database_high_water: u64,
    journal_hard: u64,
    journal_high_water: u64,
    audit: u64,
}
impl Default for StorageLimits {
    fn default() -> Self {
        Self {
            database_hard: 256 * 1024 * 1024,
            database_high_water: 192 * 1024 * 1024,
            journal_hard: JOURNAL_LIMIT,
            journal_high_water: 192 * 1024 * 1024,
            audit: 128 * 1024 * 1024,
        }
    }
}
const AUDIT_RETENTION_SECONDS: u64 = 7 * 86400;

// Only trusted service code selects record kinds; callers cannot request a reserve bypass.
fn control_record(kind: &str) -> bool {
    matches!(
        kind,
        "oauth"
            | "config"
            | "trust"
            | "maintenance"
            | "service_revoked"
            | "revocation_delivery"
            | "service_metadata"
            | "transport_metadata"
            | "revoked_principal"
            | "cancel_operation"
            | "runtime"
            | "collection_complete"
            | "collection_error"
            | "cleanup_error"
            | "apply_result"
    )
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("database operation failed: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("stored data is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("SECURITY_STATE_INVALID: {0}")]
    SecurityState(String),
    #[error("SUBMISSION_CONFLICT")]
    SubmissionConflict,
    #[error("REVISION_CONFLICT")]
    RevisionConflict,
    #[error("APPROVAL_INVALID")]
    ApprovalInvalid,
    #[error("GRANT_REVOKED_OR_EXPIRED")]
    GrantInactive,
    #[error("NOT_FOUND")]
    NotFound,
    #[error("QUOTA_EXCEEDED")]
    QuotaExceeded,
    #[error("STORAGE_UNAVAILABLE")]
    Unavailable,
}
pub type Result<T> = std::result::Result<T, StoreError>;

/// 去重范围是主体 × 设备 × submission_id；不能只按客户端生成的 ID 全局去重。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionKey {
    pub principal_id: String,
    pub device_id: String,
    pub submission_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionRecord {
    pub key: SubmissionKey,
    pub request_digest: String,
    pub task_id: String,
    pub grant_id: String,
    pub created_at: u64,
}
/// 持久任务状态；revision 用于 CAS 更新，payload 是接受时固定的任务正文。
/// 运行实例另存 runtime 记录，避免状态推进顺便改变已批准的命令内容。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredTask {
    pub task_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub grant_id: String,
    pub effective_digest: String,
    pub execution_state: String,
    pub stop_state: String,
    pub finish_reason: Option<String>,
    pub exit_code: Option<i32>,
    pub revision: u64,
    pub created_at: u64,
    pub updated_at: u64,
    /// Protected body reference or immutable effective specification. Never audited.
    #[serde(default)]
    pub payload: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredGrant {
    pub grant_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub revision: u64,
    pub expires_at: u64,
    pub status: String,
    pub payload: Value,
}
/// 一次性审批，绑定有效内容摘要及 grant/policy 版本，不能移用到其他内容。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredApproval {
    pub approval_id: String,
    pub grant_id: String,
    pub effective_digest: String,
    pub grant_revision: u64,
    pub policy_revision: u64,
    pub expires_at: u64,
    /// pending, approved, rejected, consumed, or invalidated.
    pub status: String,
    pub consumed_by: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptOutcome {
    pub created: bool,
    pub submission: SubmissionRecord,
    pub task: StoredTask,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: u64,
    pub principal_id: Option<String>,
    pub device_id: Option<String>,
    pub task_id: Option<String>,
    pub action: String,
    pub outcome: String,
}

/// 有界异步存储接口；入队完成后丢弃响应接收者不会撤销数据库操作。
#[derive(Clone)]
pub struct Store {
    normal: mpsc::Sender<Job>,
    control: mpsc::Sender<Job>,
}
struct Job {
    operation: Operation,
    reply: oneshot::Sender<Result<Value>>,
}
enum Operation {
    PutRecord(String, String, Value),
    GetRecord(String, String),
    ListRecords(String),
    PutGrant(StoredGrant),
    GetGrant(String),
    ListGrants,
    Revoke(String, u64),
    Accept(SubmissionRecord, StoredTask, Option<Box<StoredApproval>>),
    Submission(SubmissionKey),
    Task(String),
    Tasks(Option<String>),
    UpdateTask(StoredTask, u64),
    Approval(StoredApproval),
    GetApproval(String),
    ListApprovals,
    DecideApproval(String, bool, u64),
    ConsumeApproval {
        id: String,
        digest: String,
        grant_revision: u64,
        policy_revision: u64,
        task_id: String,
        now: u64,
        changes: bool,
    },
    Audit(AuditEvent),
    Backup(PathBuf),
    Sequence,
    RedeemInvitation {
        nonce: String,
        digest: String,
        device_id: String,
        device: Value,
        now: u64,
    },
    ExpireTaskBody(String, u64),
}

impl Store {
    /// Starts a dedicated database thread. All clones share the same bounded queues.
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self> {
        let state_dir = state_dir.as_ref().to_path_buf();
        let (normal, mut normal_rx) = mpsc::channel::<Job>(64);
        let (control, mut control_rx) = mpsc::channel::<Job>(16);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("orc-sqlite".into())
            .spawn(move || {
                let mut db = match Database::open(&state_dir) {
                    Ok(db) => db,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.into()));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                runtime.block_on(async move {
                    loop {
                        let job = tokio::select! { biased;
                            Some(job) = control_rx.recv() => job,
                            Some(job) = normal_rx.recv() => job,
                            else => break,
                        };
                        // Dropping an HTTP response never cancels an accepted database operation.
                        let result = db.handle(job.operation);
                        let _ = job.reply.send(result);
                    }
                });
            })?;
        ready_rx.recv().map_err(|_| StoreError::Unavailable)??;
        Ok(Self { normal, control })
    }
    async fn call<T: DeserializeOwned>(&self, operation: Operation, control: bool) -> Result<T> {
        let (reply, rx) = oneshot::channel();
        let sender = if control { &self.control } else { &self.normal };
        sender
            .send(Job { operation, reply })
            .await
            .map_err(|_| StoreError::Unavailable)?;
        let value = rx.await.map_err(|_| StoreError::Unavailable)??;
        Ok(serde_json::from_value(value)?)
    }
    pub async fn put_record(&self, kind: &str, id: &str, body: Value) -> Result<()> {
        self.call(
            Operation::PutRecord(kind.into(), id.into(), body),
            control_record(kind),
        )
        .await
    }
    pub async fn get_record(&self, kind: &str, id: &str) -> Result<Option<Value>> {
        self.call(Operation::GetRecord(kind.into(), id.into()), false)
            .await
    }
    pub async fn list_records(&self, kind: &str) -> Result<Vec<Value>> {
        self.call(Operation::ListRecords(kind.into()), false).await
    }
    pub async fn put_grant(&self, grant: StoredGrant) -> Result<()> {
        self.call(Operation::PutGrant(grant), true).await
    }
    pub async fn get_grant(&self, id: &str) -> Result<Option<StoredGrant>> {
        self.call(Operation::GetGrant(id.into()), false).await
    }
    pub async fn list_grants(&self) -> Result<Vec<StoredGrant>> {
        self.call(Operation::ListGrants, false).await
    }
    pub async fn revoke_grant(&self, id: &str, now: u64) -> Result<Vec<StoredTask>> {
        self.call(Operation::Revoke(id.into(), now), true).await
    }
    pub async fn accept_submission(
        &self,
        submission: SubmissionRecord,
        task: StoredTask,
    ) -> Result<AcceptOutcome> {
        self.accept_submission_with_approval(submission, task, None)
            .await
    }
    /// 一次提交去重记录、任务及可选待审批记录；重复请求返回已有任务。
    /// 这一步仅确认接受，不消费审批、不启动外部进程。
    pub async fn accept_submission_with_approval(
        &self,
        submission: SubmissionRecord,
        task: StoredTask,
        approval: Option<StoredApproval>,
    ) -> Result<AcceptOutcome> {
        self.call(
            Operation::Accept(submission, task, approval.map(Box::new)),
            false,
        )
        .await
    }
    pub async fn get_submission(&self, key: SubmissionKey) -> Result<Option<SubmissionRecord>> {
        self.call(Operation::Submission(key), false).await
    }
    pub async fn get_task(&self, id: &str) -> Result<Option<StoredTask>> {
        self.call(Operation::Task(id.into()), false).await
    }
    pub async fn list_tasks(&self, principal_id: Option<&str>) -> Result<Vec<StoredTask>> {
        self.call(Operation::Tasks(principal_id.map(str::to_owned)), false)
            .await
    }
    /// 以 expected_revision 做 CAS；身份、有效摘要、原始正文和创建时间不可随状态更新改变。
    pub async fn update_task(
        &self,
        task: StoredTask,
        expected_revision: u64,
    ) -> Result<StoredTask> {
        self.call(Operation::UpdateTask(task, expected_revision), true)
            .await
    }
    pub async fn create_approval(&self, approval: StoredApproval) -> Result<()> {
        self.call(Operation::Approval(approval), false).await
    }
    pub async fn get_approval(&self, id: &str) -> Result<Option<StoredApproval>> {
        self.call(Operation::GetApproval(id.into()), false).await
    }
    pub async fn list_approvals(&self) -> Result<Vec<StoredApproval>> {
        self.call(Operation::ListApprovals, false).await
    }
    pub async fn decide_approval(
        &self,
        id: &str,
        approve: bool,
        now: u64,
    ) -> Result<StoredApproval> {
        self.call(Operation::DecideApproval(id.into(), approve, now), true)
            .await
    }
    /// 启动前单次消费审批；同时核对摘要、版本、期限及关联任务。
    #[allow(clippy::too_many_arguments)]
    pub async fn consume_approval(
        &self,
        id: &str,
        digest: &str,
        grant_revision: u64,
        policy_revision: u64,
        task_id: &str,
        now: u64,
    ) -> Result<StoredApproval> {
        self.call(
            Operation::ConsumeApproval {
                id: id.into(),
                digest: digest.into(),
                grant_revision,
                policy_revision,
                task_id: task_id.into(),
                now,
                changes: false,
            },
            true,
        )
        .await
    }
    /// Consume an approval bound to a durable change-set record, not a task.
    #[allow(clippy::too_many_arguments)]
    pub async fn consume_change_approval(
        &self,
        id: &str,
        digest: &str,
        grant_revision: u64,
        policy_revision: u64,
        change_set_id: &str,
        now: u64,
    ) -> Result<StoredApproval> {
        self.call(
            Operation::ConsumeApproval {
                id: id.into(),
                digest: digest.into(),
                grant_revision,
                policy_revision,
                task_id: change_set_id.into(),
                now,
                changes: true,
            },
            true,
        )
        .await
    }
    pub async fn audit(&self, event: AuditEvent) -> Result<()> {
        self.call(Operation::Audit(event), false).await
    }
    /// 仅备份 SQLite；恢复时还需保留当前安全 journal，不能用旧备份覆盖它。
    pub async fn backup(&self, destination: impl AsRef<Path>) -> Result<()> {
        self.call(Operation::Backup(destination.as_ref().to_owned()), false)
            .await
    }
    /// 将邀请消费与设备登记写成同一个安全事件，避免只完成一半后可重复兑换。
    pub async fn redeem_invitation(
        &self,
        nonce: &str,
        expected_digest: &str,
        device_id: &str,
        device: Value,
        now: u64,
    ) -> Result<()> {
        self.call(
            Operation::RedeemInvitation {
                nonce: nonce.into(),
                digest: expected_digest.into(),
                device_id: device_id.into(),
                device,
                now,
            },
            true,
        )
        .await
    }
    pub async fn expire_task_body(&self, task_id: &str, now: u64) -> Result<()> {
        self.call(Operation::ExpireTaskBody(task_id.into(), now), false)
            .await
    }
    pub async fn security_sequence(&self) -> Result<u64> {
        self.call(Operation::Sequence, true).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum SecurityEvent {
    Record {
        kind: String,
        id: String,
        body: Value,
    },
    Grant {
        grant: StoredGrant,
    },
    Accepted {
        submission: SubmissionRecord,
        task: StoredTask,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approval: Option<Box<StoredApproval>>,
    },
    Task {
        task: StoredTask,
    },
    Approval {
        approval: StoredApproval,
    },
    Revoke {
        grant_id: String,
        now: u64,
    },
    InvitationRedeemed {
        nonce: String,
        invitation: Value,
        device_id: String,
        device: Value,
    },
    TaskBodyExpired {
        task_id: String,
        now: u64,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEntry {
    sequence: u64,
    previous: String,
    event: SecurityEvent,
    hash: String,
}
struct Database {
    connection: Connection,
    journal: File,
    sequence: u64,
    last_hash: String,
    failed: bool,
    _lock: File,
    limits: StorageLimits,
}

fn hash(sequence: u64, previous: &str, event: &SecurityEvent) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(sequence, previous, event))?)
    ))
}
fn encode<T: Serialize>(value: T) -> Result<Value> {
    Ok(serde_json::to_value(value)?)
}
fn body<T: Serialize>(value: &T) -> Result<String> {
    let result = serde_json::to_string(value)?;
    if result.len() > RECORD_LIMIT {
        return Err(StoreError::QuotaExceeded);
    }
    Ok(result)
}
fn private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    if fs::symlink_metadata(dir)?.file_type().is_symlink() {
        return Err(StoreError::SecurityState(
            "state directory is a symlink".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn private_file(path: &Path, append: bool) -> Result<File> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && (!meta.is_file() || meta.file_type().is_symlink())
    {
        return Err(StoreError::SecurityState(
            "state file is not a regular file".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).append(append);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}
impl Database {
    fn open(dir: &Path) -> Result<Self> {
        Self::open_with_limits(dir, StorageLimits::default())
    }
    fn open_with_limits(dir: &Path, limits: StorageLimits) -> Result<Self> {
        private_dir(dir)?;
        let lock = private_file(&dir.join("store.lock"), false)?;
        lock.try_lock()
            .map_err(|_| StoreError::SecurityState("state directory is already in use".into()))?;
        let db_path = dir.join("state.sqlite3");
        let existed = db_path.exists();
        private_file(&db_path, false)?;
        let connection = Connection::open(&db_path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )?;
        let page_size: u64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
        let pages: u64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
        if pages.saturating_mul(page_size) > limits.database_hard {
            return Err(StoreError::QuotaExceeded);
        }
        connection.pragma_update(None, "max_page_count", limits.database_hard / page_size)?;
        connection
            .execute_batch("PRAGMA wal_autocheckpoint=256; PRAGMA journal_size_limit=4194304;")?;
        let schema: u64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if schema > 1 {
            return Err(StoreError::SecurityState(
                "unsupported database schema".into(),
            ));
        }
        connection.execute_batch(include_str!("../migrations/001_initial.sql"))?;
        let high_water: u64 = connection.query_row(
            "SELECT value FROM metadata WHERE key='security_sequence'",
            [],
            |row| row.get(0),
        )?;
        let journal_path = dir.join("security-journal.jsonl");
        if existed && high_water > 0 && !journal_path.exists() {
            return Err(StoreError::SecurityState(
                "security journal is missing".into(),
            ));
        }
        let journal = private_file(&journal_path, true)?;
        if journal.metadata()?.len() > limits.journal_hard {
            return Err(StoreError::QuotaExceeded);
        }
        let mut sequence = 0u64;
        let mut previous = "0".repeat(64);
        let mut reader = BufReader::new(journal.try_clone()?);
        let mut line = Vec::new();
        while reader.read_until(b'\n', &mut line)? > 0 {
            if line.last() != Some(&b'\n') {
                return Err(StoreError::SecurityState("partial journal entry".into()));
            }
            let entry: JournalEntry = serde_json::from_slice(&line)
                .map_err(|_| StoreError::SecurityState("invalid journal entry".into()))?;
            if entry.sequence != sequence + 1
                || entry.previous != previous
                || hash(entry.sequence, &entry.previous, &entry.event)? != entry.hash
            {
                return Err(StoreError::SecurityState(
                    "security journal chain is invalid".into(),
                ));
            }
            // 数据库备份可能落后 journal；只补齐缺失安全事实，恢复模式会剥夺任务启动资格。
            if entry.sequence > high_water {
                connection.execute_batch("BEGIN IMMEDIATE")?;
                let applied = apply_event(&connection, &entry.event, true).and_then(|()| {
                    connection.execute(
                        "UPDATE metadata SET value=?1 WHERE key='security_sequence'",
                        [entry.sequence],
                    )?;
                    Ok(())
                });
                if let Err(error) = applied {
                    let _ = connection.execute_batch("ROLLBACK");
                    return Err(error);
                }
                connection.execute_batch("COMMIT")?;
            }
            sequence = entry.sequence;
            previous = entry.hash;
            line.clear();
        }
        if high_water > sequence {
            return Err(StoreError::SecurityState(
                "database is ahead of security journal".into(),
            ));
        }
        File::open(dir)?.sync_all()?;
        Ok(Self {
            connection,
            journal,
            sequence,
            last_hash: previous,
            failed: false,
            _lock: lock,
            limits,
        })
    }
    /// 先同步 journal，再应用 SQLite 事务；任何中途错误都要求重新打开存储恢复。
    /// 不能简单重试 SQL 或继续用旧内存序号，否则可能再次接受已消费的权限。
    fn commit(&mut self, event: SecurityEvent) -> Result<()> {
        if self.failed {
            return Err(StoreError::SecurityState(
                "recovery required after durable write failure".into(),
            ));
        }
        let next = self
            .sequence
            .checked_add(1)
            .ok_or(StoreError::QuotaExceeded)?;
        // SQLite 保留受保护任务正文；长期 journal 只留摘要与状态，避免恢复时还原敏感正文。
        let mut journal_event = event.clone();
        match &mut journal_event {
            SecurityEvent::Accepted { task, .. } | SecurityEvent::Task { task } => {
                task.payload = Value::Null
            }
            _ => {}
        }
        let digest = hash(next, &self.last_hash, &journal_event)?;
        let entry = JournalEntry {
            sequence: next,
            previous: self.last_hash.clone(),
            event: journal_event,
            hash: digest.clone(),
        };
        let mut encoded = serde_json::to_vec(&entry)?;
        encoded.push(b'\n');
        if self.journal.metadata()?.len() + encoded.len() as u64 > self.limits.journal_hard {
            return Err(StoreError::QuotaExceeded);
        }
        // Any error from here requires reopening and journal recovery before new writes.
        self.failed = true;
        self.journal.write_all(&encoded)?;
        self.journal.sync_all()?;
        self.connection.execute_batch("BEGIN IMMEDIATE")?;
        let result = apply_event(&self.connection, &event, false).and_then(|()| {
            self.connection.execute(
                "UPDATE metadata SET value=?1 WHERE key='security_sequence'",
                [next],
            )?;
            Ok(())
        });
        if let Err(error) = result {
            let _ = self.connection.execute_batch("ROLLBACK");
            return Err(error);
        }
        self.connection.execute_batch("COMMIT")?;
        self.sequence = next;
        self.last_hash = digest;
        self.failed = false;
        Ok(())
    }
    /// 普通新增工作在高水位处被拒绝，为控制操作保留到硬上限之间的空间。
    fn require_headroom(&self) -> Result<()> {
        let pages: u64 = self
            .connection
            .pragma_query_value(None, "page_count", |row| row.get(0))?;
        let size: u64 = self
            .connection
            .pragma_query_value(None, "page_size", |row| row.get(0))?;
        if pages.saturating_mul(size) >= self.limits.database_high_water
            || self.journal.metadata()?.len() >= self.limits.journal_high_water
        {
            return Err(StoreError::QuotaExceeded);
        }
        Ok(())
    }
    fn handle(&mut self, operation: Operation) -> Result<Value> {
        if self.failed {
            return Err(StoreError::SecurityState("reopen store to recover".into()));
        }
        match operation {
            Operation::PutRecord(kind, id, value) => {
                if !control_record(&kind) {
                    self.require_headroom()?;
                }
                body(&value)?;
                self.commit(SecurityEvent::Record {
                    kind,
                    id,
                    body: value,
                })?;
                encode(())
            }
            Operation::GetRecord(kind, id) => {
                let value: Option<Value> = load(
                    &self.connection,
                    "SELECT body FROM records WHERE kind=?1 AND id=?2",
                    params![kind, id],
                )?;
                encode(value)
            }
            Operation::ListRecords(kind) => encode(list::<Value>(
                &self.connection,
                "SELECT body FROM records WHERE kind=?1 ORDER BY id",
                [kind],
            )?),
            Operation::PutGrant(grant) => {
                self.require_headroom()?;
                if let Some(old) = self.grant(&grant.grant_id)?
                    && (grant.revision <= old.revision
                        || old.principal_id != grant.principal_id
                        || old.device_id != grant.device_id
                        || old.status == "revoked")
                {
                    return Err(StoreError::RevisionConflict);
                }
                self.commit(SecurityEvent::Grant { grant })?;
                encode(())
            }
            Operation::GetGrant(id) => encode(self.grant(&id)?),
            Operation::ListGrants => encode(list::<StoredGrant>(
                &self.connection,
                "SELECT body FROM grants ORDER BY id",
                [],
            )?),
            Operation::Revoke(id, now) => {
                self.grant(&id)?.ok_or(StoreError::NotFound)?;
                self.commit(SecurityEvent::Revoke {
                    grant_id: id.clone(),
                    now,
                })?;
                encode(list::<StoredTask>(
                    &self.connection,
                    "SELECT body FROM tasks WHERE grant_id=?1 ORDER BY id",
                    [id],
                )?)
            }
            Operation::Accept(submission, task, approval) => {
                // 必须先查已有接受记录再检查容量和新任务约束，保证重试仍返回原决定。
                if let Some(existing) = self.submission(&submission.key)? {
                    if existing.request_digest != submission.request_digest {
                        return Err(StoreError::SubmissionConflict);
                    }
                    let task = self.task(&existing.task_id)?.ok_or_else(|| {
                        StoreError::SecurityState("submission has no task".into())
                    })?;
                    return encode(AcceptOutcome {
                        created: false,
                        submission: existing,
                        task,
                    });
                }
                self.require_headroom()?;
                let grant = self
                    .grant(&submission.grant_id)?
                    .ok_or(StoreError::GrantInactive)?;
                if grant.status != "active"
                    || grant.expires_at <= submission.created_at
                    || grant.principal_id != submission.key.principal_id
                    || grant.device_id != submission.key.device_id
                {
                    return Err(StoreError::GrantInactive);
                }
                if task.task_id != submission.task_id
                    || task.principal_id != submission.key.principal_id
                    || task.device_id != submission.key.device_id
                    || task.grant_id != submission.grant_id
                    || task.revision != 0
                    || !matches!(
                        task.execution_state.as_str(),
                        "accepted" | "pending_approval"
                    )
                {
                    return Err(StoreError::SecurityState(
                        "inconsistent accepted task".into(),
                    ));
                }
                if let Some(approval) = &approval {
                    if self.approval(&approval.approval_id)?.is_some()
                        || task.execution_state != "pending_approval"
                        || approval.status != "pending"
                        || approval.consumed_by.is_some()
                        || approval.grant_id != task.grant_id
                        || approval.effective_digest != task.effective_digest
                        || approval.expires_at <= submission.created_at
                    {
                        return Err(StoreError::ApprovalInvalid);
                    }
                    self.check_approval_grant(approval, submission.created_at)?;
                }
                self.commit(SecurityEvent::Accepted {
                    submission: submission.clone(),
                    task: task.clone(),
                    approval,
                })?;
                encode(AcceptOutcome {
                    created: true,
                    submission,
                    task,
                })
            }
            Operation::Submission(key) => encode(self.submission(&key)?),
            Operation::Task(id) => encode(self.task(&id)?),
            Operation::Tasks(principal) => match principal {
                Some(id) => encode(list::<StoredTask>(
                    &self.connection,
                    "SELECT body FROM tasks WHERE principal_id=?1 ORDER BY id",
                    [id],
                )?),
                None => encode(list::<StoredTask>(
                    &self.connection,
                    "SELECT body FROM tasks ORDER BY id",
                    [],
                )?),
            },
            Operation::UpdateTask(mut task, expected) => {
                let old = self.task(&task.task_id)?.ok_or(StoreError::NotFound)?;
                if old.revision != expected
                    || old.principal_id != task.principal_id
                    || old.device_id != task.device_id
                    || old.grant_id != task.grant_id
                    || old.effective_digest != task.effective_digest
                    || old.payload != task.payload
                    || old.created_at != task.created_at
                {
                    return Err(StoreError::RevisionConflict);
                }
                validate_transition(&old, &task)?;
                task.revision = expected.checked_add(1).ok_or(StoreError::QuotaExceeded)?;
                self.commit(SecurityEvent::Task { task: task.clone() })?;
                encode(task)
            }
            Operation::Approval(approval) => {
                self.require_headroom()?;
                if self.approval(&approval.approval_id)?.is_some()
                    || approval.status != "pending"
                    || approval.consumed_by.is_some()
                {
                    return Err(StoreError::ApprovalInvalid);
                }
                self.check_approval_grant(&approval, 0)?;
                self.commit(SecurityEvent::Approval { approval })?;
                encode(())
            }
            Operation::GetApproval(id) => encode(self.approval(&id)?),
            Operation::ListApprovals => encode(list::<StoredApproval>(
                &self.connection,
                "SELECT body FROM approvals ORDER BY id",
                [],
            )?),
            Operation::DecideApproval(id, approve, now) => {
                if approve {
                    self.require_headroom()?;
                }
                let mut approval = self.approval(&id)?.ok_or(StoreError::NotFound)?;
                if approval.status != "pending" || approval.expires_at <= now {
                    return Err(StoreError::ApprovalInvalid);
                }
                self.check_approval_grant(&approval, now)?;
                approval.status = if approve { "approved" } else { "rejected" }.into();
                self.commit(SecurityEvent::Approval {
                    approval: approval.clone(),
                })?;
                encode(approval)
            }
            Operation::ConsumeApproval {
                id,
                digest,
                grant_revision,
                policy_revision,
                task_id,
                now,
                changes,
            } => {
                self.require_headroom()?;
                let mut approval = self.approval(&id)?.ok_or(StoreError::NotFound)?;
                if approval.status != "approved"
                    || approval.consumed_by.is_some()
                    || approval.effective_digest != digest
                    || approval.grant_revision != grant_revision
                    || approval.policy_revision != policy_revision
                    || approval.expires_at <= now
                {
                    return Err(StoreError::ApprovalInvalid);
                }
                self.check_approval_grant(&approval, now)?;
                if changes {
                    let record: Value = load(
                        &self.connection,
                        "SELECT body FROM records WHERE kind='changes' AND id=?1",
                        [&task_id],
                    )?
                    .ok_or(StoreError::NotFound)?;
                    if record["change_set_id"] != task_id
                        || record["approval_id"] != id
                        || record["grant_id"] != approval.grant_id
                        || record["effective_digest"] != approval.effective_digest
                        || record["grant_revision"].as_u64() != Some(grant_revision)
                        || record["policy_revision"].as_u64() != Some(policy_revision)
                    {
                        return Err(StoreError::ApprovalInvalid);
                    }
                } else {
                    let task = self.task(&task_id)?.ok_or(StoreError::NotFound)?;
                    if task.grant_id != approval.grant_id
                        || task.effective_digest != approval.effective_digest
                    {
                        return Err(StoreError::ApprovalInvalid);
                    }
                }
                approval.status = "consumed".into();
                approval.consumed_by = Some(task_id);
                self.commit(SecurityEvent::Approval {
                    approval: approval.clone(),
                })?;
                encode(approval)
            }
            Operation::Audit(event) => {
                let ids = [
                    event.principal_id.as_deref(),
                    event.device_id.as_deref(),
                    event.task_id.as_deref(),
                ];
                if event.action.is_empty()
                    || event.action.len() > 128
                    || event.outcome.len() > 128
                    || event
                        .action
                        .chars()
                        .chain(event.outcome.chars())
                        .any(char::is_control)
                    || ids
                        .iter()
                        .flatten()
                        .any(|s| s.len() > 256 || s.chars().any(char::is_control))
                {
                    return Err(StoreError::QuotaExceeded);
                }
                self.connection.execute(
                    "DELETE FROM audit_events WHERE timestamp<?1",
                    [event.timestamp.saturating_sub(AUDIT_RETENTION_SECONDS)],
                )?;
                self.require_headroom()?;
                let used: u64 = self.connection.query_row(
                    "SELECT value FROM metadata WHERE key='audit_bytes'",
                    [],
                    |row| row.get(0),
                )?;
                let incoming = 64
                    + event.action.len() as u64
                    + event.outcome.len() as u64
                    + ids.iter().flatten().map(|v| v.len() as u64).sum::<u64>();
                if used.saturating_add(incoming) > self.limits.audit {
                    return Err(StoreError::QuotaExceeded);
                }
                self.connection.execute("INSERT INTO audit_events(timestamp,principal_id,device_id,task_id,action,outcome) VALUES (?1,?2,?3,?4,?5,?6)",params![event.timestamp,event.principal_id,event.device_id,event.task_id,event.action,event.outcome])?;
                encode(())
            }
            Operation::Backup(destination) => {
                if destination.exists() {
                    return Err(StoreError::SecurityState(
                        "backup destination already exists".into(),
                    ));
                }
                private_file(&destination, false)?;
                let mut backup = Connection::open(&destination)?;
                rusqlite::backup::Backup::new(&self.connection, &mut backup)?.run_to_completion(
                    128,
                    Duration::from_millis(1),
                    None,
                )?;
                File::open(&destination)?.sync_all()?;
                encode(())
            }
            Operation::RedeemInvitation {
                nonce,
                digest,
                device_id,
                device,
                now,
            } => {
                self.require_headroom()?;
                let mut invitation: Value = load(
                    &self.connection,
                    "SELECT body FROM records WHERE kind='enrollment_invitation' AND id=?1",
                    [&nonce],
                )?
                .ok_or(StoreError::NotFound)?;
                let existing: Option<Value> = load(
                    &self.connection,
                    "SELECT body FROM records WHERE kind='device' AND id=?1",
                    [&device_id],
                )?;
                if invitation["invitation_digest"] != digest
                    || invitation["consumed"] != false
                    || invitation["expires_at"]
                        .as_u64()
                        .is_none_or(|expiry| expiry <= now)
                    || existing.is_some()
                    || device["device_id"] != device_id
                {
                    return Err(StoreError::ApprovalInvalid);
                }
                invitation["consumed"] = Value::Bool(true);
                self.commit(SecurityEvent::InvitationRedeemed {
                    nonce,
                    invitation,
                    device_id,
                    device,
                })?;
                encode(())
            }
            Operation::ExpireTaskBody(task_id, now) => {
                let task = self.task(&task_id)?.ok_or(StoreError::NotFound)?;
                if !matches!(task.execution_state.as_str(), "exited" | "not_started")
                    || !matches!(task.stop_state.as_str(), "confirmed" | "none")
                    || task.created_at.saturating_add(86400) > now
                {
                    return Err(StoreError::RevisionConflict);
                }
                if !task.payload.is_null() {
                    self.commit(SecurityEvent::TaskBodyExpired { task_id, now })?;
                }
                encode(())
            }
            Operation::Sequence => encode(self.sequence),
        }
    }
    fn grant(&self, id: &str) -> Result<Option<StoredGrant>> {
        load(
            &self.connection,
            "SELECT body FROM grants WHERE id=?1",
            [id],
        )
    }
    fn task(&self, id: &str) -> Result<Option<StoredTask>> {
        load(&self.connection, "SELECT body FROM tasks WHERE id=?1", [id])
    }
    fn approval(&self, id: &str) -> Result<Option<StoredApproval>> {
        load(
            &self.connection,
            "SELECT body FROM approvals WHERE id=?1",
            [id],
        )
    }
    fn submission(&self, key: &SubmissionKey) -> Result<Option<SubmissionRecord>> {
        load(
            &self.connection,
            "SELECT body FROM submissions WHERE principal_id=?1 AND device_id=?2 AND submission_id=?3",
            params![key.principal_id, key.device_id, key.submission_id],
        )
    }
    fn check_approval_grant(&self, approval: &StoredApproval, now: u64) -> Result<()> {
        let grant = self
            .grant(&approval.grant_id)?
            .ok_or(StoreError::GrantInactive)?;
        if grant.status != "active"
            || grant.revision != approval.grant_revision
            || grant.expires_at <= now
            || approval.expires_at > grant.expires_at
        {
            return Err(StoreError::GrantInactive);
        }
        Ok(())
    }
}
fn load<T: DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    parameters: impl rusqlite::Params,
) -> Result<Option<T>> {
    let value: Option<String> = connection
        .query_row(sql, parameters, |row| row.get(0))
        .optional()?;
    value
        .map(|s| serde_json::from_str(&s).map_err(StoreError::from))
        .transpose()
}
fn list<T: DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    parameters: impl rusqlite::Params,
) -> Result<Vec<T>> {
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map(parameters, |row| row.get::<_, String>(0))?;
    rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
}
fn write_task(connection: &Connection, task: &StoredTask) -> Result<()> {
    connection.execute("INSERT INTO tasks VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,body=excluded.body",params![task.task_id,task.principal_id,task.device_id,task.grant_id,task.revision,body(task)?])?;
    Ok(())
}
/// 同一事件用于正常提交与恢复；恢复中的任务只还原事实，绝不重新获得启动资格。
fn apply_event(connection: &Connection, event: &SecurityEvent, recovery: bool) -> Result<()> {
    match event {
        SecurityEvent::TaskBodyExpired { task_id, now } => {
            let mut task: StoredTask =
                load(connection, "SELECT body FROM tasks WHERE id=?1", [task_id])?
                    .ok_or(StoreError::NotFound)?;
            task.payload = Value::Null;
            task.revision += 1;
            task.updated_at = *now;
            write_task(connection, &task)?;
        }
        SecurityEvent::InvitationRedeemed {
            nonce,
            invitation,
            device_id,
            device,
        } => {
            connection.execute("INSERT INTO records VALUES ('enrollment_invitation',?1,?2) ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body",params![nonce,body(invitation)?])?;
            connection.execute("INSERT INTO records VALUES ('device',?1,?2) ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body",params![device_id,body(device)?])?;
        }
        SecurityEvent::Record {
            kind,
            id,
            body: value,
        } => {
            connection.execute("INSERT INTO records VALUES (?1,?2,?3) ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body",params![kind,id,body(value)?])?;
        }
        SecurityEvent::Grant { grant } => {
            connection.execute("INSERT INTO grants VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,status=excluded.status,expires_at=excluded.expires_at,body=excluded.body",params![grant.grant_id,grant.principal_id,grant.device_id,grant.revision,grant.status,grant.expires_at,body(grant)?])?;
            // Any semantic revision invalidates prior unconsumed approvals.
            let approvals = list::<StoredApproval>(
                connection,
                "SELECT body FROM approvals WHERE grant_id=?1",
                [&grant.grant_id],
            )?;
            for mut approval in approvals {
                if approval.grant_revision != grant.revision
                    && matches!(approval.status.as_str(), "pending" | "approved")
                {
                    approval.status = "invalidated".into();
                    write_approval(connection, &approval)?;
                }
            }
        }
        SecurityEvent::Accepted {
            submission,
            task,
            approval,
        } => {
            connection.execute(
                "INSERT OR IGNORE INTO submissions VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    submission.key.principal_id,
                    submission.key.device_id,
                    submission.key.submission_id,
                    submission.request_digest,
                    submission.task_id,
                    body(submission)?
                ],
            )?;
            let mut restored = task.clone();
            if recovery {
                restored.execution_state = "unknown".into();
                restored.stop_state = "unknown".into();
            }
            write_task(connection, &restored)?;
            if let Some(approval) = approval {
                write_approval(connection, approval)?;
            }
        }
        SecurityEvent::Task { task } => {
            let mut restored = task.clone();
            if recovery
                && let Some(existing) = load::<StoredTask>(
                    connection,
                    "SELECT body FROM tasks WHERE id=?1",
                    [&task.task_id],
                )?
            {
                restored.payload = existing.payload;
            }
            if recovery
                && matches!(
                    restored.execution_state.as_str(),
                    "accepted" | "starting" | "running" | "pending_approval"
                )
            {
                restored.execution_state = "unknown".into();
                restored.stop_state = "unknown".into();
            }
            write_task(connection, &restored)?;
        }
        SecurityEvent::Approval { approval } => write_approval(connection, approval)?,
        SecurityEvent::Revoke { grant_id, now } => {
            if let Some(mut grant) = load::<StoredGrant>(
                connection,
                "SELECT body FROM grants WHERE id=?1",
                [grant_id],
            )? {
                if grant.status != "revoked" {
                    grant.status = "revoked".into();
                    grant.revision += 1;
                }
                connection.execute(
                    "UPDATE grants SET status='revoked',revision=?1,body=?2 WHERE id=?3",
                    params![grant.revision, body(&grant)?, grant_id],
                )?;
            }
            for mut approval in list::<StoredApproval>(
                connection,
                "SELECT body FROM approvals WHERE grant_id=?1",
                [grant_id],
            )? {
                if matches!(approval.status.as_str(), "pending" | "approved") {
                    approval.status = "invalidated".into();
                    write_approval(connection, &approval)?;
                }
            }
            for mut task in list::<StoredTask>(
                connection,
                "SELECT body FROM tasks WHERE grant_id=?1",
                [grant_id],
            )? {
                if !matches!(task.execution_state.as_str(), "exited" | "not_started") {
                    task.stop_state = "requested".into();
                    task.finish_reason = Some("grant_revoked".into());
                    task.updated_at = *now;
                    task.revision += 1;
                    if matches!(
                        task.execution_state.as_str(),
                        "accepted" | "pending_approval"
                    ) {
                        task.execution_state = "not_started".into();
                        task.stop_state = "confirmed".into();
                    }
                    write_task(connection, &task)?;
                }
            }
        }
    }
    Ok(())
}
fn write_approval(connection: &Connection, approval: &StoredApproval) -> Result<()> {
    connection.execute("INSERT INTO approvals VALUES (?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET status=excluded.status,body=excluded.body",params![approval.approval_id,approval.grant_id,approval.status,body(approval)?])?;
    Ok(())
}
fn validate_transition(old: &StoredTask, new: &StoredTask) -> Result<()> {
    let valid = old.execution_state == new.execution_state
        || matches!(
            (old.execution_state.as_str(), new.execution_state.as_str()),
            ("pending_approval", "accepted" | "not_started" | "unknown")
                | ("accepted", "starting" | "not_started" | "unknown")
                | ("starting", "running" | "exited" | "not_started" | "unknown")
                | ("running", "exited" | "unknown")
                | ("unknown", "exited" | "not_started")
        );
    if !valid
        || !matches!(
            new.stop_state.as_str(),
            "none" | "requested" | "confirmed" | "failed" | "unknown"
        )
        || (new.exit_code.is_some() && new.execution_state != "exited")
        || (old.stop_state == "confirmed" && new.stop_state != "confirmed")
    {
        return Err(StoreError::RevisionConflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
