//! 角色初始化、离线发行包验证和首次安装。
//!
//! setup 只生成私有目录、身份和配置，不自动建立对端信任或执行 grant。
//! verify_release 使用所有者独立提供的公钥验证原始 manifest 字节及所选二进制摘要。
//! install_release 支持初装和相同版本重复安装；运行中角色的版本切换交给 maintenance。
//! 不运行远程脚本、安装钩子或隐式提权操作。

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use orc_transport::IdentityFile;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Mcp,
    Endpoint,
    Complete,
}
impl Role {
    pub fn includes_mcp(self) -> bool {
        matches!(self, Self::Mcp | Self::Complete)
    }
    pub fn includes_endpoint(self) -> bool {
        matches!(self, Self::Endpoint | Self::Complete)
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::Endpoint => "endpoint",
            Self::Complete => "complete",
        }
    }
    pub fn binaries(self) -> Vec<&'static str> {
        let mut names = vec!["orc"];
        if self.includes_mcp() {
            names.push("orc-mcp");
        }
        if self.includes_endpoint() {
            names.extend(["orc-endpoint", "orc-runner", "orc-watchdog"]);
        }
        names
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseFile {
    pub name: String,
    pub sha256: String,
    pub size: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub state_schema: u32,
    pub version: String,
    pub target: String,
    pub toolchain: String,
    pub cargo_lock_sha256: String,
    pub files: Vec<ReleaseFile>,
}
#[derive(Serialize)]
pub struct SetupReport {
    pub role: Role,
    pub root: PathBuf,
    pub created: Vec<PathBuf>,
    pub preserved: Vec<PathBuf>,
    pub identities: Value,
    pub services_started: bool,
    pub remote_verified: bool,
    pub next_steps: Vec<String>,
}
#[derive(Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}
#[derive(Serialize)]
pub struct DoctorReport {
    pub checks: Vec<Check>,
    pub remote_verified: bool,
    pub cloud_client_verified: bool,
}

/// 幂等生成所选角色的私有布局；已有身份和配置保留，缺证书/授权时仍不可执行。
pub fn setup(root: &Path, role: Role, public_url: &str) -> Result<SetupReport> {
    if !root.is_absolute() {
        return Err("setup root must be an absolute path".into());
    }
    if !(public_url.starts_with("https://")
        || public_url.starts_with("http://127.0.0.1:")
        || public_url.starts_with("http://localhost:"))
        || !public_url.ends_with("/mcp")
    {
        return Err("public URL must be HTTPS /mcp or explicit loopback HTTP /mcp".into());
    }
    orc_admin::secure_dir(root)?;
    let mut report = SetupReport {
        role,
        root: root.into(),
        created: vec![],
        preserved: vec![],
        identities: json!({}),
        services_started: false,
        remote_verified: false,
        next_steps: vec![],
    };
    if role.includes_mcp() {
        let base = root.join("mcp");
        prepare_component(&base)?;
        let identity = ensure_identity(&base.join("identity.json"), &mut report)?;
        report.identities["mcp"] =
            json!({"mcp_id":identity.id("mcp")?,"public_key":identity.public_key()?});
        let config = json!({"state_dir":base.join("state"),"admin_socket":base.join("run/admin.sock"),"identity_file":base.join("identity.json"),"http_bind":"127.0.0.1:8787","public_url":public_url,"device_bind":"127.0.0.1:8788","device_tls":{"certificate":base.join("tls/server.pem"),"key":base.join("tls/server-key.pem"),"ca":base.join("tls/ca.pem")},"owner_id":uuid::Uuid::new_v4().to_string(),"auth_domain_id":uuid::Uuid::new_v4().to_string()});
        save_if_absent(
            &base.join("config.json"),
            &serde_json::to_vec_pretty(&config)?,
            &mut report,
        )?;
        write_unit(root, "mcp", &base.join("config.json"), &mut report)?;
        report.next_steps.push(format!("Provide trusted CA/server PEM files under {}. The device listener defaults to loopback; configure a reachable TLS bind address for remote endpoints.",base.join("tls").display()));
    }
    if role.includes_endpoint() {
        let base = root.join("endpoint");
        prepare_component(&base)?;
        let identity = ensure_identity(&base.join("identity.json"), &mut report)?;
        report.identities["endpoint"] =
            json!({"device_id":identity.id("dev")?,"public_key":identity.public_key()?});
        // A deliberately untrusted draft: fill peer identity and TLS from an
        // owner-verified enrollment before the endpoint is allowed to connect.
        let config = json!({"state_dir":base.join("state"),"admin_socket":base.join("run/admin.sock"),"identity_file":base.join("identity.json"),"execution_uid":orc_admin::current_uid(),"mcp_address":"127.0.0.1:8788","mcp_server_name":"localhost","mcp_id":"UNCONFIGURED","mcp_public_key":"UNCONFIGURED","mcp_certificate_digest":"UNCONFIGURED","tls":{"certificate":base.join("tls/client.pem"),"key":base.join("tls/client-key.pem"),"ca":base.join("tls/ca.pem")},"runner_path":root.join("bin/orc-runner"),"host_context_id":"host-default","host_profile_id":"linux-host-v1","host_environment_digest":"UNCONFIGURED","environment":{"PATH":"/usr/local/bin:/usr/bin:/bin","LANG":"C.UTF-8"},"gvisor":null,"continue_on_disconnect":false});
        save_if_absent(
            &base.join("config.json"),
            &serde_json::to_vec_pretty(&config)?,
            &mut report,
        )?;
        write_unit(root, "endpoint", &base.join("config.json"), &mut report)?;
        let watchdog = json!({"state_dir":base.join("state/tasks"),"runner_path":root.join("bin/orc-runner"),"execution_uid":orc_admin::current_uid(),"gvisor":null});
        save_if_absent(
            &base.join("watchdog-config.json"),
            &serde_json::to_vec_pretty(&watchdog)?,
            &mut report,
        )?;
        write_unit(
            root,
            "watchdog",
            &base.join("watchdog-config.json"),
            &mut report,
        )?;
        report.next_steps.push("Complete endpoint peer identity, client TLS certificate, fixed execution account, host contexts and verified environment configuration before starting it; no grants have been created.".into());
    }
    report.next_steps.push("Install verified offline binaries with `orc install`; inspect the generated systemd units, then use systemctl --user to enable only configured roles. Linger is never enabled automatically.".into());
    report.next_steps.push("For remote/cloud access, provide your own reachable HTTPS endpoint, domain/certificate and optional server. Their costs belong to the deployment owner; installation does not verify cloud reachability.".into());
    Ok(report)
}
fn prepare_component(base: &Path) -> Result<()> {
    for dir in [
        base.to_path_buf(),
        base.join("state"),
        base.join("run"),
        base.join("tls"),
    ] {
        orc_admin::secure_dir(&dir)?;
    }
    Ok(())
}
fn ensure_identity(path: &Path, report: &mut SetupReport) -> Result<IdentityFile> {
    if path.exists() {
        check_private_file(path)?;
        report.preserved.push(path.into());
        IdentityFile::load(path)
    } else {
        let identity = IdentityFile::create(path)?;
        report.created.push(path.into());
        Ok(identity)
    }
}
fn save_if_absent(path: &Path, bytes: &[u8], report: &mut SetupReport) -> Result<()> {
    if path.exists() {
        check_private_file(path)?;
        report.preserved.push(path.into());
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    report.created.push(path.into());
    Ok(())
}
fn write_unit(root: &Path, component: &str, config: &Path, report: &mut SetupReport) -> Result<()> {
    let directory = root.join("systemd");
    orc_admin::secure_dir(&directory)?;
    let binary = root.join("bin").join(format!("orc-{component}"));
    let unit = format!(
        "[Unit]\nDescription=OpenRemoteConnector {component}\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart={} --config {}\nRestart=on-failure\nRestartSec=3\nUMask=0077\n\n[Install]\nWantedBy=default.target\n",
        systemd_quote(&binary)?,
        systemd_quote(config)?
    );
    save_if_absent(
        &directory.join(format!("orc-{component}.service")),
        unit.as_bytes(),
        report,
    )
}
fn systemd_quote(path: &Path) -> Result<String> {
    let s = path.to_str().ok_or("non-UTF8 unit path unsupported")?;
    if s.chars().any(char::is_control) {
        return Err("control character in unit path".into());
    }
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}
fn check_private_file(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.uid() != orc_admin::current_uid()
        || meta.mode() & 0o077 != 0
    {
        return Err("private file ownership/permissions invalid".into());
    }
    Ok(())
}
fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn safe_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 128
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        && segment != "."
        && segment != ".."
}

/// Signature is over the exact manifest bytes, using an independently verified
/// release public key. Neither the bundle nor the manifest selects its own key.
pub fn verify_release(
    manifest_bytes: &[u8],
    signature_base64: &str,
    public_key_base64: &str,
    bundle: &Path,
    role: Role,
) -> Result<ReleaseManifest> {
    if manifest_bytes.len() > 64 * 1024 {
        return Err("manifest exceeds limit".into());
    }
    let raw: [u8; 32] = STANDARD
        .decode(public_key_base64.trim())?
        .try_into()
        .map_err(|_| "invalid release key")?;
    let key = VerifyingKey::from_bytes(&raw)?;
    let signature = Signature::from_slice(&STANDARD.decode(signature_base64.trim())?)?;
    key.verify(manifest_bytes, &signature)?;
    let manifest: ReleaseManifest = orc_protocol::strict_decode(manifest_bytes)?;
    if manifest.state_schema != 1 {
        return Err(
            "unsupported release state schema; current security journal must remain readable"
                .into(),
        );
    }
    if !safe_segment(&manifest.version)
        || manifest.target != "x86_64-unknown-linux-gnu"
        || manifest.files.len() > 16
    {
        return Err("unsupported release manifest".into());
    }
    let allowed: BTreeSet<_> = [
        "orc",
        "orc-mcp",
        "orc-endpoint",
        "orc-runner",
        "orc-watchdog",
    ]
    .into_iter()
    .collect();
    let mut seen = BTreeSet::new();
    for file in &manifest.files {
        if !allowed.contains(file.name.as_str())
            || !seen.insert(&file.name)
            || file.size > 128 * 1024 * 1024
        {
            return Err("invalid release file".into());
        }
    }
    for name in role.binaries() {
        let entry = manifest
            .files
            .iter()
            .find(|f| f.name == name)
            .ok_or("selected role missing binary")?;
        verify_binary(&bundle.join(name), entry)?;
    }
    Ok(manifest)
}
fn verify_binary(path: &Path, entry: &ReleaseFile) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.len() != entry.size
    {
        return Err("release file type/size mismatch".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let before = file.metadata()?;
    let mut bytes = Vec::new();
    file.take(entry.size + 1).read_to_end(&mut bytes)?;
    if before.ino() != metadata.ino()
        || before.dev() != metadata.dev()
        || bytes.len() as u64 != entry.size
        || sha256(&bytes) != entry.sha256
    {
        return Err("release checksum mismatch".into());
    }
    Ok(bytes)
}
/// 验证所选二进制后安装；已运行角色的不同版本切换必须走维护暂停流程。
pub fn install_release(
    root: &Path,
    bundle: &Path,
    manifest_bytes: &[u8],
    signature: &str,
    public_key: &str,
    role: Role,
) -> Result<Value> {
    let manifest = verify_release(manifest_bytes, signature, public_key, bundle, role)?;
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err("P0 installation requires Ubuntu 24.04 x86_64; release verification is available on this host".into());
    }
    if !root.is_absolute() {
        return Err("installation root must be absolute".into());
    }
    orc_admin::secure_dir(root)?;
    let canonical_root = fs::canonicalize(root)?;
    let root = canonical_root.as_path();
    let releases = root.join("releases");
    let bin = root.join("bin");
    orc_admin::secure_dir(&releases)?;
    orc_admin::secure_dir(&bin)?;
    let release_name = format!("{}-{}", manifest.version, role.name());
    let destination = releases.join(&release_name);
    if destination.exists() {
        for name in role.binaries() {
            let entry = manifest
                .files
                .iter()
                .find(|f| f.name == name)
                .ok_or("missing binary")?;
            verify_binary(&destination.join(name), entry)?;
        }
    } else {
        let staging = releases.join(format!(".staging-{}", uuid::Uuid::new_v4()));
        orc_admin::secure_dir(&staging)?;
        let result: Result<()> = (|| {
            for name in role.binaries() {
                let entry = manifest
                    .files
                    .iter()
                    .find(|f| f.name == name)
                    .ok_or("missing binary")?;
                let bytes = verify_binary(&bundle.join(name), entry)?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o700)
                    .open(staging.join(name))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(staging.join("release-manifest.json"))?;
            file.write_all(manifest_bytes)?;
            file.sync_all()?;
            File::open(&staging)?.sync_all()?;
            fs::rename(&staging, &destination)?;
            File::open(&releases)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result?;
    }
    // Updating a running role requires maintenance/drain coordination. Initial
    // installs and exact idempotent repeats are allowed; updates fail closed.
    for name in role.binaries() {
        let link = bin.join(name);
        if let Ok(meta) = fs::symlink_metadata(&link)
            && (!meta.file_type().is_symlink() || fs::read_link(&link)? != destination.join(name))
        {
            return Err("role already installed at another version; pause/drain and use a validated upgrade flow".into());
        }
    }
    for name in role.binaries() {
        let link = bin.join(name);
        if !link.exists() {
            std::os::unix::fs::symlink(destination.join(name), link)?;
        }
    }
    File::open(&bin)?.sync_all()?;
    Ok(
        json!({"installed":true,"role":role,"version":manifest.version,"binaries":role.binaries(),"services_started":false,"remote_verified":false}),
    )
}

/// 报告本机可观察的配置和依赖状态；本地成功不能证明公网入口或真实客户端可达。
pub fn doctor(root: &Path) -> Result<DoctorReport> {
    let mut checks = vec![
        Check {
            name: "platform".into(),
            passed: cfg!(all(target_os = "linux", target_arch = "x86_64")),
            detail: format!(
                "{} {}; P0 target is Ubuntu 24.04 x86_64",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        },
        Check {
            name: "ordinary_execution_uid".into(),
            passed: orc_admin::current_uid() != 0,
            detail: format!(
                "uid={}; endpoints must use a fixed ordinary account",
                orc_admin::current_uid()
            ),
        },
    ];
    #[cfg(target_os = "linux")]
    {
        let release = fs::read_to_string("/etc/os-release").unwrap_or_default();
        checks.push(Check {
            name: "ubuntu_baseline".into(),
            passed: release.lines().any(|l| l == "ID=ubuntu")
                && release.lines().any(|l| l == "VERSION_ID=\"24.04\""),
            detail: "Requires independent runtime acceptance on the exact kernel/runtime versions"
                .into(),
        });
        let controllers =
            fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").unwrap_or_default();
        checks.push(Check{name:"cgroup_v2".into(),passed:["cpu","memory","pids"].iter().all(|v|controllers.split_whitespace().any(|c|c==*v)),detail:"Controller availability alone does not prove per-user delegation or effective limits".into()});
    }
    let mut configured_roles = 0;
    for component in ["mcp", "endpoint"] {
        let config_path = root.join(component).join("config.json");
        if !config_path.exists() {
            continue;
        }
        configured_roles += 1;
        let config: Value = orc_protocol::strict_decode(&fs::read(&config_path)?)?;
        let identity_path = config["identity_file"].as_str().map(Path::new);
        let identity_ok = identity_path
            .is_some_and(|p| check_private_file(p).is_ok() && IdentityFile::load(p).is_ok());
        checks.push(Check {
            name: format!("{component}.identity"),
            passed: identity_ok,
            detail: "Private identity must retain its original value across upgrades".into(),
        });
        let tls = config.get(if component == "mcp" {
            "device_tls"
        } else {
            "tls"
        });
        let tls_ok = tls.is_some_and(|v| {
            ["certificate", "key", "ca"]
                .iter()
                .all(|field| v[*field].as_str().is_some_and(|s| Path::new(s).is_file()))
        });
        checks.push(Check{name:format!("{component}.tls_files"),passed:tls_ok,detail:"Presence only; authenticated handshakes and expected peer identity still require validation".into()});
        if component == "endpoint" {
            checks.push(Check {
                name: "endpoint.peer_identity".into(),
                passed: config["mcp_id"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("mcp_"))
                    && config["mcp_public_key"]
                        .as_str()
                        .is_some_and(|s| orc_transport::verifying_key(s).is_ok()),
                detail: "Owner must verify MCP fingerprint through a trusted channel".into(),
            });
        }
        checks.push(Check{name:format!("{component}.admin_socket"),passed:config["admin_socket"].as_str().is_some_and(|s|Path::new(s).exists()),detail:"Use local status RPC to confirm service health; file presence is not connectivity proof".into()});
    }
    if configured_roles == 0 {
        checks.push(Check {
            name: "configuration".into(),
            passed: false,
            detail: "No role configuration found; run orc setup".into(),
        });
    }
    Ok(DoctorReport {
        checks,
        remote_verified: false,
        cloud_client_verified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::tempdir;
    #[test]
    fn repeated_setup_preserves_identity_and_configuration() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("orc");
        setup(&root, Role::Mcp, "http://127.0.0.1:8787/mcp").unwrap();
        let before = fs::read(root.join("mcp/identity.json")).unwrap();
        let config = fs::read(root.join("mcp/config.json")).unwrap();
        let result = setup(&root, Role::Mcp, "https://example.test/mcp").unwrap();
        assert_eq!(fs::read(root.join("mcp/identity.json")).unwrap(), before);
        assert_eq!(fs::read(root.join("mcp/config.json")).unwrap(), config);
        assert!(!result.services_started);
        assert!(!root.join("endpoint").exists());
    }
    #[test]
    fn signature_and_every_selected_binary_are_verified() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("orc"), b"cli").unwrap();
        fs::write(dir.path().join("orc-mcp"), b"service").unwrap();
        let manifest = ReleaseManifest {
            state_schema: 1,
            version: "0.1.0".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            toolchain: "1.99.1".into(),
            cargo_lock_sha256: "0".repeat(64),
            files: vec![
                ReleaseFile {
                    name: "orc".into(),
                    size: 3,
                    sha256: sha256(b"cli"),
                },
                ReleaseFile {
                    name: "orc-mcp".into(),
                    size: 7,
                    sha256: sha256(b"service"),
                },
            ],
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let key = SigningKey::from_bytes(&[42; 32]);
        let signature = STANDARD.encode(key.sign(&bytes).to_bytes());
        let public = STANDARD.encode(key.verifying_key().as_bytes());
        assert!(verify_release(&bytes, &signature, &public, dir.path(), Role::Mcp).is_ok());
        let mut future = manifest.clone();
        future.state_schema = 2;
        let future_bytes = serde_json::to_vec(&future).unwrap();
        let future_signature = STANDARD.encode(key.sign(&future_bytes).to_bytes());
        assert!(
            verify_release(
                &future_bytes,
                &future_signature,
                &public,
                dir.path(),
                Role::Mcp
            )
            .is_err()
        );
        assert!(verify_release(&bytes, &signature, &public, dir.path(), Role::Complete).is_err());
        fs::write(dir.path().join("orc-mcp"), b"changed").unwrap();
        assert!(verify_release(&bytes, &signature, &public, dir.path(), Role::Mcp).is_err());
        let bad = STANDARD.encode(SigningKey::from_bytes(&[43; 32]).verifying_key().as_bytes());
        assert!(verify_release(&bytes, &signature, &bad, dir.path(), Role::Mcp).is_err());
    }
}

pub mod maintenance;
