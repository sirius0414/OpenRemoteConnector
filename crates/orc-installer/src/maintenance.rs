//! Maintenance swaps programs only. State databases and security journals never
//! move backwards. Live preparation is performed by the authoritative services.
use super::*;
use orc_admin::Request;
use std::time::Duration;
use tokio::process::Command;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Upgrade,
    Rollback,
    Uninstall,
}
pub struct Package<'a> {
    pub bundle: &'a Path,
    pub manifest: &'a [u8],
    pub signature: &'a str,
    pub public_key: &'a str,
}

fn components(role: Role) -> Vec<&'static str> {
    let mut result = vec![];
    if role.includes_mcp() {
        result.push("mcp")
    }
    if role.includes_endpoint() {
        result.push("endpoint")
    }
    result
}
fn units(role: Role) -> Vec<&'static str> {
    let mut result = components(role);
    if role.includes_endpoint() {
        result.push("watchdog")
    }
    result
}
fn require_platform() -> Result<()> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(
            "maintenance requires the supported Linux host; no services were changed".into(),
        );
    }
    Ok(())
}
fn config(root: &Path, component: &str) -> Result<Value> {
    let path = root.join(component).join("config.json");
    check_private_file(&path)?;
    let bytes = fs::read(path)?;
    if bytes.len() > 256 * 1024 {
        return Err("config too large".into());
    }
    Ok(orc_protocol::strict_decode(&bytes)?)
}
async fn rpc(root: &Path, component: &str, method: &str) -> Result<Value> {
    let config = config(root, component)?;
    let socket = config["admin_socket"]
        .as_str()
        .ok_or("admin socket absent")?;
    let response = orc_admin::call(
        Path::new(socket),
        Request {
            method: method.into(),
            params: json!({"cancel":false}),
        },
    )
    .await?;
    if let Some(error) = response.error {
        return Err(format!(
            "{component}: {error}; maintenance remains paused; inspect tasks and retry"
        )
        .into());
    }
    response
        .result
        .ok_or_else(|| "invalid maintenance response".into())
}
fn validate_prepared(value: &Value) -> Result<()> {
    if value["maintenance"] != true
        || value["active_tasks"].as_u64() != Some(0)
        || value["unresolved_tasks"].as_u64() != Some(0)
    {
        return Err(
            "tasks are active or stopping is unconfirmed; no binary switch is allowed".into(),
        );
    }
    if value["state_schema"].as_u64() != Some(1) {
        return Err("unsupported live security-state schema".into());
    }
    let backup = value["backup_path"]
        .as_str()
        .ok_or("maintenance backup evidence missing")?;
    let meta = fs::symlink_metadata(backup)?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.uid() != orc_admin::current_uid()
        || meta.mode() & 0o077 != 0
    {
        return Err("maintenance backup is not a private regular file".into());
    }
    Ok(())
}
fn validate_uninstall_prepared(value: &Value) -> Result<()> {
    if value["revocation_applied"] != true {
        return Err("uninstall requires durable access revocation before removing programs".into());
    }
    validate_prepared(value)
}
async fn revoke_offline_endpoint(store: &orc_store::Store) -> Result<()> {
    store
        .put_record("config", "trust_revoked", json!(true))
        .await?;
    store.put_record("config", "paused", json!(true)).await?;
    store
        .put_record("config", "maintenance", json!(true))
        .await?;
    for grant in store.list_grants().await? {
        if grant.status != "revoked" {
            store
                .revoke_grant(&grant.grant_id, orc_transport::now())
                .await?;
        }
    }
    Ok(())
}
async fn systemctl(arguments: &[&str]) -> Result<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(20),
        Command::new("/usr/bin/systemctl")
            .arg("--user")
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env(
                "XDG_RUNTIME_DIR",
                format!("/run/user/{}", orc_admin::current_uid()),
            )
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    if !output.status.success() {
        return Err(format!(
            "systemctl {} failed; services/programs may remain in maintenance",
            arguments.first().unwrap_or(&"operation")
        )
        .into());
    }
    if output.stdout.len() > 64 * 1024 {
        return Err("systemctl response exceeded limit".into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
async fn owned_unit(root: &Path, component: &str) -> Result<PathBuf> {
    let unit = format!("orc-{component}.service");
    let fragment = systemctl(&["show", &unit, "--property=FragmentPath", "--value"]).await?;
    let path = PathBuf::from(fragment);
    if !path.is_absolute() {
        return Err("selected role has no installed systemd user unit".into());
    }
    let expected = fs::read(root.join("systemd").join(&unit))?;
    let actual = fs::read(&path)?;
    if expected.len() > 64 * 1024 || actual != expected {
        return Err("systemd unit does not match this ORC installation; refusing to operate on another service".into());
    }
    Ok(path)
}
fn stage(
    root: &Path,
    role: Role,
    package: &Package<'_>,
    manifest: &ReleaseManifest,
) -> Result<PathBuf> {
    let releases = root.join("releases");
    orc_admin::secure_dir(&releases)?;
    let destination = releases.join(format!("{}-{}", manifest.version, role.name()));
    if destination.exists() {
        let metadata = fs::symlink_metadata(&destination)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("release directory must not be a link".into());
        }
        for name in role.binaries() {
            let entry = manifest
                .files
                .iter()
                .find(|f| f.name == name)
                .ok_or("binary absent")?;
            verify_binary(&destination.join(name), entry)?;
        }
        return Ok(destination);
    }
    let temporary = releases.join(format!(".staging-{}", uuid::Uuid::new_v4()));
    orc_admin::secure_dir(&temporary)?;
    let result: Result<()> = (|| {
        for name in role.binaries() {
            let entry = manifest
                .files
                .iter()
                .find(|f| f.name == name)
                .ok_or("binary absent")?;
            let bytes = verify_binary(&package.bundle.join(name), entry)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(temporary.join(name))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temporary.join("release-manifest.json"))?;
        file.write_all(package.manifest)?;
        file.sync_all()?;
        File::open(&temporary)?.sync_all()?;
        fs::rename(&temporary, &destination)?;
        File::open(&releases)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result?;
    Ok(destination)
}
#[derive(Serialize, Deserialize)]
struct LinkChange {
    name: String,
    previous: Option<PathBuf>,
    next: Option<PathBuf>,
}
fn link_plan(root: &Path, role: Role, destination: Option<&Path>) -> Result<Vec<LinkChange>> {
    let bin = root.join("bin");
    orc_admin::secure_dir(&bin)?;
    let releases = root.join("releases");
    let mut changes = vec![];
    for name in role.binaries() {
        // Keep the shared management command when one product role remains.
        if destination.is_none() && name == "orc" && role != Role::Complete {
            continue;
        }
        let path = bin.join(name);
        let previous = match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.file_type().is_symlink() {
                    return Err("managed binary is not an ORC version link; migrate the source installation explicitly before version switching".into());
                }
                let target = fs::read_link(&path)?;
                if !target.is_absolute()
                    || target.parent().and_then(Path::parent) != Some(releases.as_path())
                    || target.parent().is_none_or(|p| {
                        !fs::symlink_metadata(p)
                            .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
                    })
                    || target.file_name().and_then(|s| s.to_str()) != Some(name)
                {
                    return Err("binary link does not belong to this ORC installation".into());
                }
                Some(target)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        changes.push(LinkChange {
            name: name.into(),
            previous,
            next: destination.map(|d| d.join(name)),
        });
    }
    Ok(changes)
}
fn apply_links(root: &Path, changes: &[LinkChange], restore: bool) -> Result<()> {
    let bin = root.join("bin");
    for change in changes {
        let target = if restore {
            change.previous.as_ref()
        } else {
            change.next.as_ref()
        };
        let link = bin.join(&change.name);
        match target {
            Some(target) => {
                let temporary = bin.join(format!(".switch-{}", uuid::Uuid::new_v4()));
                std::os::unix::fs::symlink(target, &temporary)?;
                if let Err(error) = fs::rename(&temporary, &link) {
                    let _ = fs::remove_file(temporary);
                    return Err(error.into());
                }
            }
            None => match fs::remove_file(link) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            },
        }
    }
    File::open(&bin)?.sync_all()?;
    Ok(())
}
fn event(journal: &mut File, value: Value) -> Result<()> {
    serde_json::to_writer(&mut *journal, &value)?;
    journal.write_all(b"\n")?;
    journal.sync_all()?;
    Ok(())
}

/// Upgrade/rollback both require a freshly verified package with state schema 1.
/// Rollback changes executable links, not databases, grants, or consumed approvals.
/// Offline mode currently supports endpoint-only maintenance: the exclusive
/// store lock and terminal task evidence are required. An offline MCP cannot
/// confirm remote tasks, so it must use live preparation.
pub async fn maintain(
    root: &Path,
    role: Role,
    operation: Operation,
    package: Option<Package<'_>>,
    offline: bool,
) -> Result<Value> {
    require_platform()?;
    if !root.is_absolute() {
        return Err("maintenance root must be absolute".into());
    }
    orc_admin::secure_dir(root)?;
    let canonical_root = fs::canonicalize(root)?;
    let root = canonical_root.as_path();
    let lock_path = root.join("maintenance.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_path)?;
    lock.try_lock()
        .map_err(|_| "another maintenance operation is in progress")?;
    let verified = match operation {
        Operation::Uninstall => None,
        _ => {
            let package = package.as_ref().ok_or("signed package required")?;
            Some(verify_release(
                package.manifest,
                package.signature,
                package.public_key,
                package.bundle,
                role,
            )?)
        }
    };
    let destination = match (&package, &verified) {
        (Some(package), Some(manifest)) => Some(stage(root, role, package, manifest)?),
        _ => None,
    };
    let changes = link_plan(root, role, destination.as_deref())?;
    let mut unit_paths = vec![];
    let manage_units = !offline || matches!(operation, Operation::Uninstall);
    let mut backups = vec![];
    let mut offline_store = None;
    if offline {
        if role != Role::Endpoint {
            return Err("offline MCP maintenance cannot prove remote termination; prepare the live MCP first".into());
        }
        if matches!(operation, Operation::Uninstall) {
            for component in units(role) {
                unit_paths.push((component, owned_unit(root, component).await?));
            }
        }
        let c = config(root, "endpoint")?;
        let socket = Path::new(c["admin_socket"].as_str().ok_or("admin socket absent")?);
        if tokio::net::UnixStream::connect(socket).await.is_ok() {
            return Err("endpoint is still online; use live maintenance".into());
        }
        let state = PathBuf::from(c["state_dir"].as_str().ok_or("state directory absent")?);
        let store = orc_store::Store::open(&state)?;
        if store.list_tasks(None).await?.iter().any(|t| {
            !matches!(t.execution_state.as_str(), "exited" | "not_started")
                || !matches!(t.stop_state.as_str(), "none" | "confirmed")
        }) {
            return Err("active or unresolved endpoint tasks block offline maintenance".into());
        }
        if matches!(operation, Operation::Uninstall) {
            revoke_offline_endpoint(&store).await?;
        }
        let backup = state.join(format!(
            "maintenance-backup-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        store.backup(&backup).await?;
        backups.push(json!({"role":"endpoint","backup_path":backup}));
        offline_store = Some(store);
    } else {
        for component in units(role) {
            unit_paths.push((component, owned_unit(root, component).await?));
        }
        for component in components(role) {
            let method = if matches!(operation, Operation::Uninstall) {
                "uninstall.prepare"
            } else {
                "maintenance.prepare"
            };
            let prepared = rpc(root, component, method).await?;
            if matches!(operation, Operation::Uninstall) {
                validate_uninstall_prepared(&prepared)?;
            } else {
                validate_prepared(&prepared)?;
            }
            backups.push(json!({"role":component,"evidence":prepared}));
        }
    }
    let journal_dir = root.join("maintenance");
    orc_admin::secure_dir(&journal_dir)?;
    let operation_id = uuid::Uuid::new_v4().to_string();
    let journal_path = journal_dir.join(format!("{operation_id}.jsonl"));
    let mut journal = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&journal_path)?;
    event(
        &mut journal,
        json!({"phase":"prepared","operation":operation,"role":role,"links":changes,"backups":backups,"security_state":"retained_in_place"}),
    )?;
    File::open(&journal_dir)?.sync_all()?;
    if manage_units {
        for component in units(role) {
            let unit = format!("orc-{component}.service");
            systemctl(&["stop", &unit]).await?;
            if systemctl(&["show", &unit, "--property=ActiveState", "--value"]).await? != "inactive"
            {
                return Err(
                    format!("{unit} stop unconfirmed; see {}", journal_path.display()).into(),
                );
            }
        }
    }
    event(&mut journal, json!({"phase":"services_stopped"}))?;
    if let Err(error) = apply_links(root, &changes, false) {
        let restored = apply_links(root, &changes, true).is_ok();
        event(
            &mut journal,
            json!({"phase":"switch_failed","old_links_restored":restored}),
        )?;
        return Err(error);
    }
    event(
        &mut journal,
        json!({"phase":"programs_switched","state_schema":1}),
    )?;
    match operation {
        Operation::Uninstall => {
            if manage_units {
                for (component, path) in unit_paths {
                    let unit = format!("orc-{component}.service");
                    systemctl(&["disable", &unit]).await?;
                    fs::remove_file(path)?;
                }
                systemctl(&["daemon-reload"]).await?;
            }
        }
        Operation::Upgrade | Operation::Rollback => {
            if !offline {
                systemctl(&["daemon-reload"]).await?;
                // Start watchdog before the endpoint can accept work.
                let mut start = units(role);
                start.sort_by_key(|c| if *c == "watchdog" { 0 } else { 1 });
                for component in start {
                    systemctl(&["start", &format!("orc-{component}.service")]).await?;
                }
                for component in components(role) {
                    let mut resumed = false;
                    for _ in 0..20 {
                        if let Ok(value) = rpc(root, component, "maintenance.resume").await
                            && value.get("maintenance") == Some(&json!(false))
                        {
                            resumed = true;
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    if !resumed {
                        return Err(format!("{component} restart/resume unconfirmed; inspect {}, state and security journal were retained",journal_path.display()).into());
                    }
                }
            }
        }
    }
    event(&mut journal, json!({"phase":"complete"}))?;
    drop(offline_store);
    Ok(
        json!({"operation":operation,"role":role,"completed":true,"revocation_applied":matches!(operation,Operation::Uninstall),"services_started":!offline&&!matches!(operation,Operation::Uninstall),"security_state":"retained_in_place","backups":backups,"maintenance_journal":journal_path,"retained":[root.join("mcp/state"),root.join("endpoint/state"),root.join("releases")],"user_projects_deleted":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn program_switch_and_rollback_preserve_security_journal() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("orc");
        orc_admin::secure_dir(&root).unwrap();
        orc_admin::secure_dir(&root.join("bin")).unwrap();
        fs::create_dir_all(root.join("releases/old-endpoint")).unwrap();
        fs::create_dir_all(root.join("releases/new-endpoint")).unwrap();
        fs::create_dir_all(root.join("endpoint/state")).unwrap();
        let security = root.join("endpoint/state/security-journal.jsonl");
        fs::write(&security, b"current-revocations-and-consumption").unwrap();
        for name in Role::Endpoint.binaries() {
            let old = root.join("releases/old-endpoint").join(name);
            fs::write(&old, b"old").unwrap();
            fs::write(root.join("releases/new-endpoint").join(name), b"new").unwrap();
            std::os::unix::fs::symlink(old, root.join("bin").join(name)).unwrap();
        }
        let changes = link_plan(
            &root,
            Role::Endpoint,
            Some(&root.join("releases/new-endpoint")),
        )
        .unwrap();
        apply_links(&root, &changes, false).unwrap();
        assert_eq!(fs::read(root.join("bin/orc-endpoint")).unwrap(), b"new");
        apply_links(&root, &changes, true).unwrap();
        assert_eq!(fs::read(root.join("bin/orc-endpoint")).unwrap(), b"old");
        assert_eq!(
            fs::read(security).unwrap(),
            b"current-revocations-and-consumption"
        );
    }
    #[test]
    fn outside_binary_links_are_never_removed() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("orc");
        orc_admin::secure_dir(&root).unwrap();
        orc_admin::secure_dir(&root.join("bin")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/true", root.join("bin/orc-endpoint")).unwrap();
        assert!(link_plan(&root, Role::Endpoint, None).is_err());
        assert!(fs::symlink_metadata(root.join("bin/orc-endpoint")).is_ok());
    }
    #[test]
    fn active_or_unknown_stop_evidence_cannot_pass_preparation() {
        assert!(
            validate_prepared(&json!({"maintenance":true,"active_tasks":1,"unresolved_tasks":0}))
                .is_err()
        );
        assert!(
            validate_prepared(&json!({"maintenance":true,"active_tasks":0,"unresolved_tasks":1}))
                .is_err()
        );
        assert!(
            validate_prepared(&json!({"maintenance":false,"active_tasks":0,"unresolved_tasks":0}))
                .is_err()
        );
    }
}

#[cfg(test)]
mod uninstall_tests {
    use super::*;
    #[test]
    fn uninstall_requires_explicit_revocation_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let backup = dir.path().join("backup");
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&backup)
            .unwrap();
        file.sync_all().unwrap();
        let mut evidence = json!({"maintenance":true,"active_tasks":0,"unresolved_tasks":0,"state_schema":1,"backup_path":backup});
        assert!(validate_prepared(&evidence).is_ok());
        assert!(validate_uninstall_prepared(&evidence).is_err());
        evidence["revocation_applied"] = json!(true);
        assert!(validate_uninstall_prepared(&evidence).is_ok());
    }
    #[tokio::test]
    async fn offline_uninstall_retires_all_grants_and_trust_before_backup() {
        let dir = tempfile::tempdir().unwrap();
        let store = orc_store::Store::open(dir.path()).unwrap();
        store
            .put_grant(orc_store::StoredGrant {
                grant_id: "grant".into(),
                principal_id: "owner".into(),
                device_id: "device".into(),
                revision: 1,
                expires_at: orc_transport::now() + 3600,
                status: "active".into(),
                payload: json!({}),
            })
            .await
            .unwrap();
        revoke_offline_endpoint(&store).await.unwrap();
        assert_eq!(
            store.get_grant("grant").await.unwrap().unwrap().status,
            "revoked"
        );
        assert_eq!(
            store.get_record("config", "trust_revoked").await.unwrap(),
            Some(json!(true))
        );
        assert_eq!(
            store.get_record("config", "paused").await.unwrap(),
            Some(json!(true))
        );
        let backup = dir.path().join("post-revocation.sqlite3");
        store.backup(&backup).await.unwrap();
        assert!(backup.is_file());
    }
}
