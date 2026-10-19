//! 所有者 CLI 的信任切换：协调服务端权威状态和本地配置文件。
//!
//! 先写好私有候选配置，调用 endpoint 的 trust.set 成功后才替换生效配置。
//! 若持久信任已提交但文件激活失败，保留候选文件供恢复，不能假装两处更新具有原子性。

use super::{private_identity, rpc};
use orc_transport::{AnyError, Invitation};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    expected_mcp_id: String,
    expected_mcp_public_key: String,
    mcp_certificate_digest: String,
    mcp_address: String,
    mcp_server_name: String,
}
fn private_bytes(path: &Path) -> Result<Vec<u8>, AnyError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != orc_admin::current_uid()
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || meta.len() > 256 * 1024
    {
        return Err(
            "trust input must be a private, bounded, ordinary file owned by this UID".into(),
        );
    }
    let mut bytes = vec![];
    file.take(256 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 256 * 1024 {
        return Err("trust input exceeds limit".into());
    }
    Ok(bytes)
}
/// 准备候选配置并请求终端提交信任；提交成功后才原子替换配置文件，要求重启激活。
pub async fn set(
    config_path: &Path,
    invitation_path: &Path,
    peer_path: &Path,
    socket: Option<&Path>,
) -> Result<Value, AnyError> {
    let original = private_bytes(config_path)?;
    let mut config: Value = orc_protocol::strict_decode(&original)?;
    let peer: Peer = orc_protocol::strict_decode(&private_bytes(peer_path)?)?;
    let invitation: Invitation = orc_protocol::strict_decode(&private_bytes(invitation_path)?)?;
    if peer.mcp_address.is_empty()
        || peer.mcp_address.len() > 256
        || peer.mcp_address.chars().any(char::is_control)
        || peer.mcp_server_name.is_empty()
        || peer.mcp_server_name.len() > 253
        || peer
            .mcp_server_name
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '/')
    {
        return Err("invalid peer network address or TLS name".into());
    }
    if !peer
        .mcp_certificate_digest
        .strip_prefix("sha256:")
        .is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
    {
        return Err("invalid peer certificate digest".into());
    }
    let identity = private_identity(Path::new(
        config["identity_file"]
            .as_str()
            .ok_or("identity file absent")?,
    ))?;
    invitation.verify(
        &peer.expected_mcp_id,
        &peer.expected_mcp_public_key,
        &identity.id("dev")?,
        orc_transport::now(),
    )?;
    let certificate = Path::new(
        config["tls"]["certificate"]
            .as_str()
            .ok_or("client certificate absent")?,
    );
    if invitation.request.certificate_digest != orc_transport::certificate_file_digest(certificate)?
    {
        return Err("invitation certificate does not match this endpoint".into());
    }
    let configured_socket = std::path::PathBuf::from(
        config["admin_socket"]
            .as_str()
            .ok_or("admin socket absent")?,
    );
    if socket.is_some_and(|s| s != configured_socket) {
        return Err("selected socket does not match the endpoint configuration".into());
    }
    config["mcp_id"] = json!(peer.expected_mcp_id);
    config["mcp_public_key"] = json!(peer.expected_mcp_public_key);
    config["mcp_certificate_digest"] = json!(peer.mcp_certificate_digest);
    config["mcp_address"] = json!(peer.mcp_address);
    config["mcp_server_name"] = json!(peer.mcp_server_name);
    let directory = config_path.parent().ok_or("configuration parent absent")?;
    let pending = directory.join(format!(".trust-config-{}.json", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending)?;
    file.write_all(&serde_json::to_vec_pretty(&config)?)?;
    file.sync_all()?;
    File::open(directory)?.sync_all()?;
    if private_bytes(config_path)? != original {
        let _ = fs::remove_file(&pending);
        return Err("configuration changed while preparing peer trust".into());
    }
    let result=rpc(Some(&configured_socket),"trust.set",json!({"invitation":invitation,"expected_mcp_id":peer.expected_mcp_id,"expected_mcp_public_key":peer.expected_mcp_public_key,"mcp_certificate_digest":peer.mcp_certificate_digest})).await;
    let mut result = match result {
        Ok(value) => value,
        Err(error) => {
            let _ = fs::remove_file(&pending);
            return Err(error);
        }
    };
    if private_bytes(config_path)? != original {
        return Err(format!("trust stored but configuration changed concurrently; reconcile private prepared configuration {} before restart",pending.display()).into());
    }
    fs::rename(&pending,config_path).map_err(|error|format!("trust stored; configuration activation failed ({error}); recover from {} before restart",pending.display()))?;
    File::open(directory)?.sync_all()?;
    result["config_updated"] = json!(true);
    result["needs_restart"] = json!(true);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    fn save(path: &Path, value: &Value) {
        fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[tokio::test]
    async fn configuration_changes_only_after_authoritative_trust_commit() {
        for reject in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let identity_path = dir.path().join("identity.json");
            let identity = orc_transport::IdentityFile::create(&identity_path).unwrap();
            let mcp = orc_transport::IdentityFile::create(&dir.path().join("mcp.json")).unwrap();
            let certificate = dir.path().join("certificate.pem");
            fs::write(
                &certificate,
                b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
            )
            .unwrap();
            let request = orc_transport::EnrollmentRequest::create(
                &identity,
                orc_transport::certificate_file_digest(&certificate).unwrap(),
                orc_transport::now(),
            )
            .unwrap();
            let invite = Invitation::issue(&mcp, request, orc_transport::now()).unwrap();
            let invitation_path = dir.path().join("invite.json");
            save(&invitation_path, &json!(invite));
            let socket = dir.path().join("owner.sock");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
            let config_path = dir.path().join("config.json");
            let original = json!({"admin_socket":socket,"identity_file":identity_path,"tls":{"certificate":certificate},"mcp_id":"old","execution_uid":orc_admin::current_uid(),"state_dir":"preserved"});
            save(&config_path, &original);
            let peer_path = dir.path().join("peer.json");
            save(
                &peer_path,
                &json!({"expected_mcp_id":mcp.id("mcp").unwrap(),"expected_mcp_public_key":mcp.public_key().unwrap(),"mcp_certificate_digest":format!("sha256:{}","a".repeat(64)),"mcp_address":"new.example:8788","mcp_server_name":"new.example"}),
            );
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                let request: orc_admin::Request = serde_json::from_str(&line).unwrap();
                assert_eq!(request.method, "trust.set");
                let response = if reject {
                    orc_admin::Response::error("STOP_NOT_CONFIRMED")
                } else {
                    orc_admin::Response::ok(json!({"needs_restart":true}))
                };
                let mut bytes = serde_json::to_vec(&response).unwrap();
                bytes.push(b'\n');
                reader.get_mut().write_all(&bytes).await.unwrap();
            });
            let result = set(&config_path, &invitation_path, &peer_path, None).await;
            server.await.unwrap();
            let actual: Value = serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
            if reject {
                assert!(result.is_err());
                assert_eq!(actual, original);
            } else {
                assert_eq!(result.unwrap()["needs_restart"], true);
                assert_eq!(actual["mcp_id"], mcp.id("mcp").unwrap());
                assert_eq!(actual["state_dir"], "preserved");
                assert_eq!(actual["execution_uid"], original["execution_uid"]);
            }
        }
    }
}
