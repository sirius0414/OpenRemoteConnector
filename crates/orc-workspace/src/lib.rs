//! 文本快照、内容寻址对象，以及受管工作区中的精确内容回写。
//!
//! 阅读顺序：ObjectStore → Snapshot/Scan → ChangeSet → ManagedWorkspace::apply。
//! 快照冻结获准字节；回写先校验整个基线，再消费审批，逐文件获取授权并记录结果。
//! 通过目录 FD 遍历并拒绝链接；Linux 另用 openat2 限制 BENEATH/NO_SYMLINKS/NO_XDEV。
//! 工作区锁只协调 ORC 和遵守约定的编辑器，不能约束同 UID 的任意程序。
//! 单文件替换不代表跨文件事务；失败或撤销后的部分结果必须保留供人工核对。

use rustix::fs::{AtFlags, Dir, Mode, OFlags, renameat, unlinkat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("workspace I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("workspace data invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("INVALID_PATH")]
    InvalidPath,
    #[error("UNSUPPORTED_FILE_TYPE")]
    UnsupportedFile,
    #[error("QUOTA_EXCEEDED")]
    QuotaExceeded,
    #[error("SOURCE_CHANGED")]
    SourceChanged,
    #[error("OBJECT_CORRUPT")]
    ObjectCorrupt,
    #[error("WORKSPACE_NOT_EXCLUSIVE")]
    NotExclusive,
    #[error("WORKSPACE_IDENTITY_CHANGED")]
    IdentityChanged,
    #[error("BASELINE_CONFLICT: {0}")]
    Conflict(String),
    #[error("APPROVAL_INVALID")]
    ApprovalInvalid,
    #[error("APPLY_ALREADY_ATTEMPTED")]
    AlreadyAttempted,
    #[error("AUTHORIZATION_REVOKED")]
    Revoked,
}
pub type Result<T> = std::result::Result<T, WorkspaceError>;
fn io_error(error: rustix::io::Errno) -> WorkspaceError {
    WorkspaceError::Io(error.into())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_read_bytes: usize,
    pub max_depth: usize,
    pub max_entries: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_files: 2_000,
            max_file_bytes: 8 * 1024 * 1024,
            max_total_bytes: 128 * 1024 * 1024,
            max_read_bytes: 64 * 1024,
            max_depth: 32,
            max_entries: 8_000,
        }
    }
}
impl Limits {
    pub fn artifacts() -> Self {
        Self {
            max_files: 1_000,
            max_total_bytes: 64 * 1024 * 1024,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRef {
    pub digest: String,
    pub size: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub device: u64,
    pub inode: u64,
}
impl DirectoryIdentity {
    fn of(meta: &Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludedFile {
    pub path: String,
    pub reason: String,
}
/// 不可变路径到内容摘要的清单；读取来自对象库，不再次读取可变的宿主源文件。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub snapshot_id: String,
    pub workspace_id: String,
    pub source: DirectoryIdentity,
    pub created_at: u64,
    pub files: BTreeMap<String, BlobRef>,
    pub exclusions: Vec<ExcludedFile>,
    pub total_bytes: u64,
}

/// 以 SHA-256 命名的有界文本对象库；读取时复核摘要，调用方负责授权与留存引用。
#[derive(Clone)]
pub struct ObjectStore {
    directory: PathBuf,
    capacity: u64,
}
impl ObjectStore {
    pub fn open(directory: impl AsRef<Path>) -> Result<Self> {
        Self::with_capacity(directory, 512 * 1024 * 1024)
    }
    pub fn with_capacity(directory: impl AsRef<Path>, capacity: u64) -> Result<Self> {
        let directory = directory.as_ref().to_owned();
        fs::create_dir_all(&directory)?;
        let root = open_root(&directory)?;
        set_private(&root, 0o700)?;
        Ok(Self {
            directory,
            capacity,
        })
    }
    pub fn put_text(&self, text: &[u8], max_bytes: u64) -> Result<BlobRef> {
        check_text(text, max_bytes)?;
        let object = BlobRef {
            digest: digest(text),
            size: text.len() as u64,
        };
        let root = open_root(&self.directory)?;
        let lock = open_file_at(&root, "objects.lock", OFlags::RDWR | OFlags::CREATE, 0o600)?;
        lock.lock()?;
        if let Ok(existing) = self.read_all(&object, max_bytes)
            && existing == text
        {
            return Ok(object);
        }
        let mut used = 0u64;
        let mut count = 0usize;
        for entry in Dir::read_from(&root).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." || name == b"objects.lock" {
                continue;
            }
            count += 1;
            if count > 100_000 {
                return Err(WorkspaceError::QuotaExceeded);
            }
            let filename = std::str::from_utf8(name).map_err(|_| WorkspaceError::ObjectCorrupt)?;
            let file = open_file_at(&root, filename, OFlags::RDONLY, 0)?;
            used = used
                .checked_add(file.metadata()?.len())
                .ok_or(WorkspaceError::QuotaExceeded)?;
        }
        if used
            .checked_add(object.size)
            .ok_or(WorkspaceError::QuotaExceeded)?
            > self.capacity
        {
            return Err(WorkspaceError::QuotaExceeded);
        }
        let temporary = format!(".tmp-{}", uuid::Uuid::new_v4());
        let mut file = open_file_at(
            &root,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            0o600,
        )?;
        if let Err(error) = file.write_all(text).and_then(|()| file.sync_all()) {
            let _ = unlinkat(&root, &temporary, AtFlags::empty());
            return Err(error.into());
        }
        // No-overwrite link gives publication a single winner; object names are hashes.
        let publication =
            rustix::fs::linkat(&root, &temporary, &root, &object.digest, AtFlags::empty());
        let _ = unlinkat(&root, &temporary, AtFlags::empty());
        match publication {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {
                self.read_all(&object, max_bytes)?;
            }
            Err(error) => return Err(io_error(error)),
        }
        root.sync_all()?;
        Ok(object)
    }
    pub fn read(&self, object: &BlobRef, offset: u64, limit: usize) -> Result<Vec<u8>> {
        if limit > 64 * 1024 || offset > object.size {
            return Err(WorkspaceError::QuotaExceeded);
        }
        let bytes = self.read_all(object, 8 * 1024 * 1024)?;
        let start = usize::try_from(offset).map_err(|_| WorkspaceError::QuotaExceeded)?;
        Ok(bytes[start..bytes.len().min(start.saturating_add(limit))].to_vec())
    }
    pub fn read_all(&self, object: &BlobRef, max_bytes: u64) -> Result<Vec<u8>> {
        if !valid_digest(&object.digest) || object.size > max_bytes {
            return Err(WorkspaceError::ObjectCorrupt);
        }
        let root = open_root(&self.directory)?;
        let file = open_file_at(&root, &object.digest, OFlags::RDONLY, 0)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 || meta.len() != object.size {
            return Err(WorkspaceError::ObjectCorrupt);
        }
        let bytes = read_bounded(file, max_bytes)?;
        if bytes.len() as u64 != object.size || digest(&bytes) != object.digest {
            return Err(WorkspaceError::ObjectCorrupt);
        }
        check_text(&bytes, max_bytes)?;
        Ok(bytes)
    }
}

impl Snapshot {
    /// Export creates an immutable candidate. Caller must obtain owner approval
    /// and bind its snapshot ID to a grant before exposing it to an Agent.
    pub fn export(
        source: impl AsRef<Path>,
        workspace_id: &str,
        objects: &ObjectStore,
        limits: &Limits,
        now: u64,
    ) -> Result<Self> {
        if workspace_id.is_empty() {
            return Err(WorkspaceError::InvalidPath);
        }
        let root = open_root(source.as_ref())?;
        Self::export_root(&root, workspace_id, objects, limits, now)
    }
    fn export_root(
        root: &File,
        workspace_id: &str,
        objects: &ObjectStore,
        limits: &Limits,
        now: u64,
    ) -> Result<Self> {
        let identity = DirectoryIdentity::of(&root.metadata()?);
        let mut scan = Scan {
            objects,
            limits,
            root_device: identity.device,
            files: BTreeMap::new(),
            exclusions: Vec::new(),
            total: 0,
            visited: 0,
            normalized: BTreeSet::new(),
        };
        scan.walk(root, "", 0)?;
        let snapshot_id = digest(&serde_json::to_vec(&(
            workspace_id,
            &identity,
            &scan.files,
        ))?);
        Ok(Self {
            snapshot_id,
            workspace_id: workspace_id.into(),
            source: identity,
            created_at: now,
            files: scan.files,
            exclusions: scan.exclusions,
            total_bytes: scan.total,
        })
    }
    pub fn read(
        &self,
        path: &str,
        objects: &ObjectStore,
        offset: u64,
        limit: usize,
    ) -> Result<Vec<u8>> {
        validate_path(path)?;
        let object = self.files.get(path).ok_or(WorkspaceError::InvalidPath)?;
        objects.read(object, offset, limit)
    }
    pub fn verify(&self) -> Result<()> {
        if self.snapshot_id
            != digest(&serde_json::to_vec(&(
                &self.workspace_id,
                &self.source,
                &self.files,
            ))?)
        {
            return Err(WorkspaceError::ObjectCorrupt);
        }
        Ok(())
    }
}
struct Scan<'a> {
    objects: &'a ObjectStore,
    limits: &'a Limits,
    root_device: u64,
    files: BTreeMap<String, BlobRef>,
    exclusions: Vec<ExcludedFile>,
    total: u64,
    visited: usize,
    normalized: BTreeSet<String>,
}
impl Scan<'_> {
    fn exclude(&mut self, path: String, reason: &str) {
        self.exclusions.push(ExcludedFile {
            path,
            reason: reason.into(),
        });
    }
    /// 通过已打开的目录 FD 扫描；同时限制访问条目数与有效文件数，排除项也计入扫描预算。
    fn walk(&mut self, directory: &File, prefix: &str, depth: usize) -> Result<()> {
        if depth > self.limits.max_depth {
            return Err(WorkspaceError::QuotaExceeded);
        }
        let mut names = Vec::new();
        for entry in Dir::read_from(directory).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            self.visited += 1;
            if self.visited > self.limits.max_entries {
                return Err(WorkspaceError::QuotaExceeded);
            }
            match std::str::from_utf8(bytes) {
                Ok(name) => names.push(name.to_owned()),
                Err(_) => self.exclude(
                    bytes.iter().map(|b| format!("\\x{b:02x}")).collect(),
                    "non_utf8_name_unsupported",
                ),
            }
        }
        names.sort();
        for name in names {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if validate_path(&path).is_err() {
                self.exclude(path.escape_default().to_string(), "ambiguous_path");
                continue;
            }
            if excluded(&name) {
                self.exclude(path, "private_or_control_file");
                continue;
            }
            let normalized: String = path.nfc().collect();
            if !self.normalized.insert(normalized) {
                return Err(WorkspaceError::InvalidPath);
            }
            let stat = rustix::fs::statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io_error)?;
            let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
            if kind == rustix::fs::FileType::Directory {
                let child = open_file_at(directory, &name, OFlags::RDONLY | OFlags::DIRECTORY, 0)?;
                if child.metadata()?.dev() != self.root_device {
                    self.exclude(path, "mount_boundary");
                    continue;
                }
                self.walk(&child, &path, depth + 1)?;
                continue;
            }
            if kind != rustix::fs::FileType::RegularFile {
                self.exclude(path, "link_or_special_file");
                continue;
            }
            let file = open_file_at(directory, &name, OFlags::RDONLY, 0)?;
            let before = file.metadata()?;
            if !before.is_file() || before.dev() != self.root_device || before.nlink() != 1 {
                self.exclude(path, "mount_or_hard_link");
                continue;
            }
            if before.len() > self.limits.max_file_bytes {
                return Err(WorkspaceError::QuotaExceeded);
            }
            let bytes = read_bounded(&file, self.limits.max_file_bytes)?;
            let after = file.metadata()?;
            if !same_file(&before, &after) || bytes.len() as u64 != after.len() {
                return Err(WorkspaceError::SourceChanged);
            }
            if check_text(&bytes, self.limits.max_file_bytes).is_err() {
                self.exclude(path, "non_text_file");
                continue;
            }
            if self.files.len() >= self.limits.max_files
                || self.total + bytes.len() as u64 > self.limits.max_total_bytes
            {
                return Err(WorkspaceError::QuotaExceeded);
            }
            let object = self.objects.put_text(&bytes, self.limits.max_file_bytes)?;
            self.total += object.size;
            self.files.insert(path, object);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub path: String,
    pub before: Option<BlobRef>,
    pub after: Option<BlobRef>,
}
/// 绑定工作区身份和逐文件 before/after 的差异；摘要覆盖整批内容供本地审批。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSet {
    pub change_set_id: String,
    pub workspace_id: String,
    pub target: DirectoryIdentity,
    pub baseline_snapshot_id: String,
    pub artifact_snapshot_id: String,
    pub changes: Vec<Change>,
}
impl ChangeSet {
    pub fn between(workspace_id: &str, baseline: &Snapshot, artifacts: &Snapshot) -> Result<Self> {
        baseline.verify()?;
        artifacts.verify()?;
        if baseline.workspace_id != workspace_id || artifacts.workspace_id != workspace_id {
            return Err(WorkspaceError::InvalidPath);
        }
        let names: BTreeSet<_> = baseline
            .files
            .keys()
            .chain(artifacts.files.keys())
            .collect();
        let changes = names
            .into_iter()
            .filter_map(|name| {
                let before = baseline.files.get(name).cloned();
                let after = artifacts.files.get(name).cloned();
                (before != after).then(|| Change {
                    path: name.clone(),
                    before,
                    after,
                })
            })
            .collect();
        let mut result = Self {
            change_set_id: String::new(),
            workspace_id: workspace_id.into(),
            target: baseline.source.clone(),
            baseline_snapshot_id: baseline.snapshot_id.clone(),
            artifact_snapshot_id: artifacts.snapshot_id.clone(),
            changes,
        };
        result.change_set_id = result.calculate_digest()?;
        Ok(result)
    }
    pub fn calculate_digest(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(&(
            &self.workspace_id,
            &self.target,
            &self.baseline_snapshot_id,
            &self.artifact_snapshot_id,
            &self.changes,
        ))?))
    }
    pub fn verify(&self) -> Result<()> {
        if self.calculate_digest()? != self.change_set_id
            || !valid_digest(&self.change_set_id)
            || self.changes.len() > 2_000
        {
            return Err(WorkspaceError::ApprovalInvalid);
        }
        let mut paths = BTreeSet::new();
        for change in &self.changes {
            validate_path(&change.path)?;
            if change.path.split('/').any(excluded)
                || !paths.insert(&change.path)
                || change.before == change.after
            {
                return Err(WorkspaceError::InvalidPath);
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyState {
    Applied,
    NotApplied,
    Conflict,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileApplyResult {
    pub path: String,
    pub state: ApplyState,
    pub reason: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyReport {
    pub change_set_id: String,
    pub results: Vec<FileApplyResult>,
}
#[derive(Debug, Clone, Copy)]
pub enum ApplyCheck<'a> {
    ConsumeApproval,
    BeforeFile(&'a str),
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedMarker {
    version: u32,
    workspace_id: String,
    identity: DirectoryIdentity,
}
pub struct ManagedWorkspace {
    root: File,
    marker: ManagedMarker,
}
pub struct WorkspaceGuard {
    lock: File,
}
impl WorkspaceGuard {
    /// Clone the locked open file description for an owner-launched editor.
    /// The editor must inherit this descriptor across exec. Closing the parent
    /// alone then cannot release exclusivity while a child still holds it.
    /// Do not explicitly unlock this file: close each holder when it finishes.
    pub fn clone_editor_lock(&self) -> Result<File> {
        Ok(self.lock.try_clone()?)
    }
}
impl ManagedWorkspace {
    /// A fresh private directory establishes the managed-writer convention.
    /// Import existing projects by exporting/copying into this workspace. No
    /// boolean flag can upgrade an arbitrary active project to exclusive mode.
    pub fn create(root: impl AsRef<Path>, workspace_id: &str) -> Result<Self> {
        if workspace_id.is_empty() {
            return Err(WorkspaceError::InvalidPath);
        }
        fs::create_dir(root.as_ref())?;
        let root = open_root(root.as_ref())?;
        set_private(&root, 0o700)?;
        let marker = ManagedMarker {
            version: 1,
            workspace_id: workspace_id.into(),
            identity: DirectoryIdentity::of(&root.metadata()?),
        };
        let mut file = open_file_at(
            &root,
            ".orc-workspace.json",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            0o600,
        )?;
        file.write_all(&serde_json::to_vec(&marker)?)?;
        file.sync_all()?;
        root.sync_all()?;
        Ok(Self { root, marker })
    }
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = open_root(root.as_ref())?;
        let file = open_file_at(&root, ".orc-workspace.json", OFlags::RDONLY, 0)
            .map_err(|_| WorkspaceError::NotExclusive)?;
        let marker: ManagedMarker = serde_json::from_slice(&read_bounded(file, 4096)?)?;
        if marker.version != 1 || marker.identity != DirectoryIdentity::of(&root.metadata()?) {
            return Err(WorkspaceError::IdentityChanged);
        }
        Ok(Self { root, marker })
    }
    pub fn export(&self, objects: &ObjectStore, limits: &Limits, now: u64) -> Result<Snapshot> {
        let _guard = self.lock()?;
        if DirectoryIdentity::of(&self.root.metadata()?) != self.marker.identity {
            return Err(WorkspaceError::IdentityChanged);
        }
        Snapshot::export_root(&self.root, &self.marker.workspace_id, objects, limits, now)
    }
    pub fn workspace_id(&self) -> &str {
        &self.marker.workspace_id
    }
    pub fn lock(&self) -> Result<WorkspaceGuard> {
        let lock = open_file_at(
            &self.root,
            ".orc-workspace.lock",
            OFlags::RDWR | OFlags::CREATE,
            0o600,
        )?;
        lock.try_lock().map_err(|_| WorkspaceError::NotExclusive)?;
        Ok(WorkspaceGuard { lock })
    }
    /// 在工作区排他锁下校验全量基线和对象，消费一次审批，再逐文件检查授权并修改。
    /// authorize 返回的 guard 保持到该文件落盘及结果记录完成；中途失败只报告部分结果。
    /// 已经创建批次 journal 的尝试不能重放，应使用 reconcile 核对当前内容。
    pub fn apply<G>(
        &self,
        changes: &ChangeSet,
        objects: &ObjectStore,
        approval_digest: &str,
        mut authorize: impl FnMut(ApplyCheck<'_>) -> Result<G>,
    ) -> Result<ApplyReport> {
        changes.verify()?;
        if approval_digest != changes.change_set_id {
            return Err(WorkspaceError::ApprovalInvalid);
        }
        if changes.workspace_id != self.marker.workspace_id
            || changes.target != self.marker.identity
            || DirectoryIdentity::of(&self.root.metadata()?) != self.marker.identity
        {
            return Err(WorkspaceError::IdentityChanged);
        }
        let _guard = self.lock()?;
        let journal_name = format!(".orc-apply-{}.jsonl", changes.change_set_id);
        match open_file_at(&self.root, &journal_name, OFlags::RDONLY, 0) {
            Ok(_) => return Err(WorkspaceError::AlreadyAttempted),
            Err(WorkspaceError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // Check every baseline and new object before approval is consumed.
        for change in &changes.changes {
            self.check_baseline(change)?;
            if let Some(after) = &change.after {
                objects.read_all(after, 8 * 1024 * 1024)?;
            }
        }
        let mut prepared = Vec::new();
        for change in &changes.changes {
            let (parent, leaf) = parent_and_leaf(&self.root, &change.path)?;
            let temporary = if let Some(after) = &change.after {
                let name = format!(".orc-tmp-{}", uuid::Uuid::new_v4());
                let mut file = open_file_at(
                    &parent,
                    &name,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
                    0o600,
                )?;
                let bytes = objects.read_all(after, 8 * 1024 * 1024)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                Some(name)
            } else {
                None
            };
            prepared.push(Prepared {
                parent,
                leaf,
                temporary,
            });
        }
        // 批次 journal 是永久防重放标记；创建后即使审批消费失败，也必须核对结果而非重复写入。
        let mut journal = open_file_at(
            &self.root,
            &journal_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            0o600,
        )?;
        write_journal(
            &mut journal,
            &serde_json::json!({"change_set_id":changes.change_set_id,"phase":"prepared"}),
        )?;
        self.root.sync_all()?;
        // Consumption itself has no host write; each file obtains a fresh guard.
        drop(authorize(ApplyCheck::ConsumeApproval)?);
        let mut report = ApplyReport {
            change_set_id: changes.change_set_id.clone(),
            results: changes
                .changes
                .iter()
                .map(|change| FileApplyResult {
                    path: change.path.clone(),
                    state: ApplyState::NotApplied,
                    reason: None,
                })
                .collect(),
        };
        for (index, (change, prepared)) in
            changes.changes.iter().zip(prepared.iter_mut()).enumerate()
        {
            // Retain the caller's authority lock through baseline validation,
            // the filesystem mutation, fsync, and recording this file's result.
            let _authority_guard = match authorize(ApplyCheck::BeforeFile(&change.path)) {
                Ok(guard) => guard,
                Err(error) => {
                    report.results[index].reason = Some(error.to_string());
                    write_journal(&mut journal, &report.results[index])?;
                    break;
                }
            };
            if let Err(error) = self.check_baseline(change) {
                report.results[index].reason = Some(error.to_string());
                if matches!(error, WorkspaceError::Conflict(_)) {
                    report.results[index].state = ApplyState::Conflict;
                }
                write_journal(&mut journal, &report.results[index])?;
                break;
            }
            write_journal(
                &mut journal,
                &serde_json::json!({"path":change.path,"phase":"applying","before":change.before,"after":change.after}),
            )?;
            let result = match (&change.before, &change.after, &prepared.temporary) {
                (None, Some(_), Some(temporary)) => rustix::fs::linkat(
                    &prepared.parent,
                    temporary,
                    &prepared.parent,
                    &prepared.leaf,
                    AtFlags::empty(),
                ),
                (Some(_), Some(_), Some(temporary)) => renameat(
                    &prepared.parent,
                    temporary,
                    &prepared.parent,
                    &prepared.leaf,
                ),
                (Some(_), None, None) => {
                    unlinkat(&prepared.parent, &prepared.leaf, AtFlags::empty())
                }
                _ => return Err(WorkspaceError::InvalidPath),
            };
            match result {
                Ok(()) => {
                    if let Some(temporary) = prepared.temporary.take() {
                        let _ = unlinkat(&prepared.parent, &temporary, AtFlags::empty());
                    }
                    if let Err(error) = prepared.parent.sync_all() {
                        report.results[index].state = ApplyState::Unknown;
                        report.results[index].reason = Some(error.to_string());
                        write_journal(&mut journal, &report.results[index])?;
                        break;
                    }
                    report.results[index].state = ApplyState::Applied;
                    write_journal(&mut journal, &report.results[index])?;
                }
                Err(error) => {
                    report.results[index].reason = Some(error.to_string());
                    write_journal(&mut journal, &report.results[index])?;
                    break;
                }
            }
        }
        write_journal(&mut journal, &report)?;
        Ok(report)
    }
    /// Reconcile a crashed application without retrying or consuming approval again.
    pub fn reconcile(&self, changes: &ChangeSet) -> Result<ApplyReport> {
        changes.verify()?;
        let _guard = self.lock()?;
        if changes.workspace_id != self.marker.workspace_id
            || changes.target != self.marker.identity
        {
            return Err(WorkspaceError::IdentityChanged);
        }
        let name = format!(".orc-apply-{}.jsonl", changes.change_set_id);
        open_file_at(&self.root, &name, OFlags::RDONLY, 0)?;
        let mut results = Vec::new();
        for change in &changes.changes {
            let current = self.current_blob(&change.path)?;
            let state = if current == change.after {
                ApplyState::Applied
            } else if current == change.before {
                ApplyState::NotApplied
            } else {
                ApplyState::Unknown
            };
            results.push(FileApplyResult {
                path: change.path.clone(),
                state,
                reason: None,
            });
        }
        Ok(ApplyReport {
            change_set_id: changes.change_set_id.clone(),
            results,
        })
    }
    fn current_blob(&self, path: &str) -> Result<Option<BlobRef>> {
        match open_relative(&self.root, path) {
            Ok(file) => {
                let before = file.metadata()?;
                if !before.is_file() || before.nlink() != 1 {
                    return Err(WorkspaceError::UnsupportedFile);
                }
                let bytes = read_bounded(&file, 8 * 1024 * 1024)?;
                if !same_file(&before, &file.metadata()?) {
                    return Err(WorkspaceError::SourceChanged);
                }
                Ok(Some(BlobRef {
                    digest: digest(&bytes),
                    size: bytes.len() as u64,
                }))
            }
            Err(WorkspaceError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn check_baseline(&self, change: &Change) -> Result<()> {
        if self.current_blob(&change.path)? != change.before {
            return Err(WorkspaceError::Conflict(change.path.clone()));
        }
        Ok(())
    }
}
struct Prepared {
    parent: File,
    leaf: String,
    temporary: Option<String>,
}
impl Drop for Prepared {
    fn drop(&mut self) {
        if let Some(temporary) = &self.temporary {
            let _ = unlinkat(&self.parent, temporary, AtFlags::empty());
        }
    }
}
fn write_journal(file: &mut File, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn check_text(bytes: &[u8], max_bytes: u64) -> Result<()> {
    if bytes.len() as u64 > max_bytes {
        return Err(WorkspaceError::QuotaExceeded);
    }
    if bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
        return Err(WorkspaceError::UnsupportedFile);
    }
    Ok(())
}
fn read_bounded(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(WorkspaceError::QuotaExceeded);
    }
    Ok(bytes)
}
fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
        && b.nlink() == 1
        && b.is_file()
}
fn excluded(name: &str) -> bool {
    name == ".git"
        || name == ".ssh"
        || name == ".aws"
        || name == ".gnupg"
        || name == ".codex"
        || name == ".env"
        || name.starts_with(".env.")
        || name.starts_with(".orc-")
        || name.ends_with(".pem")
        || name.ends_with(".key")
        || matches!(
            name,
            "credentials" | "credentials.json" | "id_rsa" | "id_ed25519"
        )
}
fn validate_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains("//")
        || path.chars().any(|c| {
            c.is_control()
                || c == '\\'
                || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
        })
    {
        return Err(WorkspaceError::InvalidPath);
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == ".." || part.len() > 255)
        || Path::new(path)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(WorkspaceError::InvalidPath);
    }
    Ok(())
}
fn open_root(path: &Path) -> Result<File> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(io_error)?;
    Ok(fd.into())
}
fn open_file_at(root: &File, name: &str, flags: OFlags, mode: u32) -> Result<File> {
    #[cfg(target_os = "linux")]
    let fd = rustix::fs::openat2(
        root,
        name,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::from_raw_mode(mode as _),
        rustix::fs::ResolveFlags::BENEATH
            | rustix::fs::ResolveFlags::NO_SYMLINKS
            | rustix::fs::ResolveFlags::NO_XDEV,
    )
    .map_err(io_error)?;
    #[cfg(not(target_os = "linux"))]
    let fd = rustix::fs::openat(
        root,
        name,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::from_raw_mode(mode as _),
    )
    .map_err(io_error)?;
    Ok(fd.into())
}
/// 逐级固定父目录 FD 后返回叶名；后续 rename/unlink 相对此 FD 操作，不重新拼接绝对路径。
fn parent_and_leaf(root: &File, path: &str) -> Result<(File, String)> {
    validate_path(path)?;
    let mut parts = path.split('/').collect::<Vec<_>>();
    let leaf = parts.pop().ok_or(WorkspaceError::InvalidPath)?.to_owned();
    let mut directory = root.try_clone()?;
    let root_device = root.metadata()?.dev();
    for part in parts {
        directory = open_file_at(&directory, part, OFlags::RDONLY | OFlags::DIRECTORY, 0)?;
        if directory.metadata()?.dev() != root_device {
            return Err(WorkspaceError::InvalidPath);
        }
    }
    Ok((directory, leaf))
}
fn open_relative(root: &File, path: &str) -> Result<File> {
    validate_path(path)?;
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{ResolveFlags, openat2};
        let fd = openat2(
            root,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .map_err(io_error)?;
        Ok(fd.into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (parent, leaf) = parent_and_leaf(root, path)?;
        open_file_at(&parent, &leaf, OFlags::RDONLY, 0)
    }
}
fn set_private(file: &File, mode: u32) -> Result<()> {
    rustix::fs::fchmod(file, Mode::from_raw_mode(mode as _)).map_err(io_error)
}

#[cfg(test)]
mod tests;
