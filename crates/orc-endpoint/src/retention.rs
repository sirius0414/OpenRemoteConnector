use super::*;
use std::collections::BTreeSet;

impl Endpoint {
    /// Remove expired bodies while retaining submission/security tombstones.
    /// Active tasks pin their input snapshots until their stop is confirmed.
    pub(crate) async fn cleanup_expired(&self) -> std::result::Result<Value, AnyError> {
        let _body_lock = self.body_lock.lock().await;
        let tasks = self.store.list_tasks(None).await?;
        let referenced: BTreeSet<String> = tasks
            .iter()
            .filter(|t| {
                !matches!(t.execution_state.as_str(), "exited" | "not_started")
                    || !matches!(t.stop_state.as_str(), "none" | "confirmed")
            })
            .filter_map(|t| serde_json::from_value::<TaskBody>(t.payload.clone()).ok())
            .filter_map(|b| b.request.context.snapshot_id.map(|s| s.0))
            .collect();
        let mut protected = BTreeSet::new();
        for record in self.store.list_records("snapshot").await? {
            let snapshot: Snapshot = serde_json::from_value(record)?;
            snapshot.verify()?;
            if now() < snapshot.created_at.saturating_add(86400)
                || referenced.contains(&snapshot.snapshot_id)
            {
                protected.extend(snapshot.files.values().map(|b| b.digest.clone()));
            } else {
                let input = self
                    .config
                    .state_dir
                    .join("inputs")
                    .join(&snapshot.snapshot_id);
                if input.exists() {
                    let mut remaining = 10_000;
                    remove_private_tree(&input, &mut remaining)?;
                }
            }
        }
        for record in self.store.list_records("changes").await? {
            if let Some(id) = record["approval_id"].as_str()
                && let Some(approval) = self.store.get_approval(id).await?
                && approval.expires_at > now()
                && matches!(approval.status.as_str(), "pending" | "approved")
            {
                let changes: orc_workspace::ChangeSet =
                    serde_json::from_value(record["changes"].clone())?;
                for change in changes.changes {
                    if let Some(blob) = change.before {
                        protected.insert(blob.digest);
                    }
                    if let Some(blob) = change.after {
                        protected.insert(blob.digest);
                    }
                }
            }
        }
        let mut deleted_bytes = 0_u64;
        let mut expired = 0;
        for task in tasks {
            let final_state = matches!(task.execution_state.as_str(), "exited" | "not_started")
                && matches!(task.stop_state.as_str(), "none" | "confirmed");
            let is_expired = final_state && now() >= task.created_at.saturating_add(86400);
            if let Some(record) = self
                .store
                .get_record("task_artifacts", &task.task_id)
                .await?
            {
                let snapshot: Snapshot = serde_json::from_value(record)?;
                if !is_expired {
                    protected.extend(snapshot.files.values().map(|b| b.digest.clone()));
                }
            }
            if !is_expired {
                continue;
            }
            if let Some(record) = self.store.get_record("runtime", &task.task_id).await? {
                let instance: InstanceRef = serde_json::from_value(record)?;
                if instance.task_id != task.task_id
                    || instance.directory != self.config.state_dir.join("tasks").join(&task.task_id)
                {
                    return Err("RETENTION_INSTANCE_IDENTITY_MISMATCH".into());
                }
                // Only fixed ORC body files; runtime and stop evidence remain.
                for name in [
                    "stdout",
                    "stderr",
                    "spec.json",
                    "request.json",
                    "output.frames",
                    "output.errors",
                    "stdout.collecting",
                    "stderr.collecting",
                    "collector.frames",
                    "collector.stderr",
                ] {
                    let target = instance.directory.join(name);
                    if let Ok(metadata) = std::fs::symlink_metadata(&target) {
                        if metadata.file_type().is_symlink() || !metadata.is_file() {
                            return Err("RETENTION_UNSAFE_FILE".into());
                        }
                        deleted_bytes += metadata.len();
                        std::fs::remove_file(target)?;
                    }
                }
                let artifacts = instance.directory.join("artifacts");
                if let Ok(metadata) = std::fs::symlink_metadata(&artifacts) {
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        return Err("RETENTION_UNSAFE_DIRECTORY".into());
                    }
                    for item in std::fs::read_dir(artifacts)?.take(1001) {
                        let item = item?;
                        let name = item.file_name();
                        let name = name.to_str().ok_or("RETENTION_INVALID_NAME")?;
                        let meta = item.metadata()?;
                        if !hash_name(name) || !item.file_type()?.is_file() {
                            return Err("RETENTION_UNSAFE_ARTIFACT".into());
                        }
                        deleted_bytes += meta.len();
                        std::fs::remove_file(item.path())?;
                    }
                }
            }
            self.store.expire_task_body(&task.task_id, now()).await?;
            expired += 1;
        }
        let object_root = self.config.state_dir.join("objects");
        for item in std::fs::read_dir(object_root)?.take(100001) {
            let item = item?;
            let name = item.file_name();
            let Some(name) = name.to_str() else { continue };
            if !hash_name(name) || protected.contains(name) {
                continue;
            }
            let meta = item.metadata()?;
            // A grace period protects objects created by an in-progress snapshot or collector.
            let age = meta.modified()?.elapsed().unwrap_or_default();
            if age < Duration::from_secs(86400) || !item.file_type()?.is_file() {
                continue;
            }
            deleted_bytes += meta.len();
            std::fs::remove_file(item.path())?;
        }
        Ok(
            json!({"expired_tasks":expired,"deleted_bytes":deleted_bytes,"submission_tombstones_retained":true,"agent_copies_deleted":false}),
        )
    }
}
fn hash_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

// Input directories are made read-only for execution. Remove only this bounded,
// ORC-owned tree and never follow a link into an owner project or another task.
fn remove_private_tree(path: &Path, remaining: &mut usize) -> std::result::Result<(), AnyError> {
    *remaining = remaining
        .checked_sub(1)
        .ok_or("RETENTION_DIRECTORY_LIMIT")?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err("RETENTION_UNSAFE_DIRECTORY".into());
    }
    if metadata.is_dir() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        for item in std::fs::read_dir(path)? {
            remove_private_tree(&item?.path(), remaining)?;
        }
        std::fs::remove_dir(path)?;
    } else if metadata.is_file() {
        std::fs::remove_file(path)?;
    } else {
        return Err("RETENTION_UNSAFE_FILE".into());
    }
    Ok(())
}
