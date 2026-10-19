//! 设备出站连接共用的身份、mTLS、握手和有界 WebSocket 帧。
//!
//! TLS 认证证书，应用层签名证明 ORC 身份密钥；调用方还要核对登记的证书指纹。
//! Hello 携带设备随机数，Sync 绑定该随机数、连接代数和撤销集合，Ready 回签整个同步摘要。
//! 服务端验证 Ready 后才发布连接，终端必须持久处理 Sync 中的撤销后才发送 Ready。
//! 普通业务请求另外使用 orc-protocol 的签名信封，连接建立不等于执行授权。

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use orc_protocol::{Hello, SignedEnvelope};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};

pub type AnyError = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, AnyError>;
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub ca: PathBuf,
}
/// 本机 Ed25519 私钥文件；只输出公钥和派生 ID，加载时检查文件归属及权限。
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFile {
    pub secret_key: String,
}
impl IdentityFile {
    pub fn create(path: &Path) -> Result<Self> {
        let mut key = [0; 32];
        getrandom::fill(&mut key).map_err(|_| "random source unavailable")?;
        let identity = Self {
            secret_key: STANDARD.encode(key),
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let mut f = options.open(path)?;
        f.write_all(&serde_json::to_vec(&identity)?)?;
        f.sync_all()?;
        Ok(identity)
    }
    pub fn load(path: &Path) -> Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.len() > 1024 {
            return Err("identity must be a bounded regular file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.mode() & 0o077 != 0 {
                return Err("identity file must not be accessible by other accounts".into());
            }
        }
        use std::io::Read;
        let mut bytes = Vec::new();
        file.take(1025).read_to_end(&mut bytes)?;
        let identity: Self = orc_protocol::strict_decode(&bytes)?;
        identity.signing_key()?;
        Ok(identity)
    }
    pub fn signing_key(&self) -> Result<SigningKey> {
        let raw: [u8; 32] = STANDARD
            .decode(&self.secret_key)?
            .try_into()
            .map_err(|_| "invalid identity key")?;
        Ok(SigningKey::from_bytes(&raw))
    }
    pub fn id(&self, prefix: &str) -> Result<String> {
        Ok(key_id(prefix, &self.signing_key()?.verifying_key()))
    }
    pub fn public_key(&self) -> Result<String> {
        Ok(STANDARD.encode(self.signing_key()?.verifying_key().as_bytes()))
    }
}
pub fn key_id(prefix: &str, key: &VerifyingKey) -> String {
    format!("{}_{:x}", prefix, Sha256::digest(key.as_bytes()))
}
pub fn verifying_key(s: &str) -> Result<VerifyingKey> {
    let raw: [u8; 32] = STANDARD
        .decode(s)?
        .try_into()
        .map_err(|_| "invalid public key")?;
    Ok(VerifyingKey::from_bytes(&raw)?)
}
pub fn capabilities() -> BTreeSet<String> {
    [
        "state-v1",
        "policy-v1",
        "strict-task-v1",
        "durable-submission-v1",
        "stop-evidence-v1",
        "bounded-read-v1",
        "snapshot-v1",
        "artifacts-v1",
        "changes-v1",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}
pub fn hello() -> Hello {
    Hello {
        protocol_major: 1,
        protocol_minor: 0,
        software_version: env!("CARGO_PKG_VERSION").into(),
        state_schema: 1,
        boot_id: uuid::Uuid::new_v4().to_string(),
        capabilities: capabilities(),
    }
}
/// 设备通道上的严格消息类型；握手、请求响应、心跳和撤销各自有独立语义。
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frame {
    Hello {
        device_id: String,
        public_key: String,
        hello: Hello,
        nonce: String,
    },
    Sync {
        mcp_id: String,
        public_key: String,
        epoch: u64,
        service_revision: u64,
        revoked_principals: Vec<String>,
        hello: Hello,
        device_nonce: String,
        challenge: String,
        signature: String,
    },
    Ready {
        epoch: u64,
        signature: String,
    },
    Request {
        id: String,
        envelope: SignedEnvelope,
    },
    Response {
        id: String,
        result: Option<Value>,
        error: Option<String>,
    },
    Ping {
        sequence: u64,
    },
    Pong {
        sequence: u64,
    },
    Revoke {
        principal_id: String,
        revision: u64,
    },
    RevokeAck {
        principal_id: String,
        revision: u64,
    },
    MaintenanceProbe {
        id: String,
    },
}

fn random_nonce() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| "random source unavailable")?;
    Ok(STANDARD.encode(bytes))
}
fn valid_nonce(nonce: &str) -> bool {
    STANDARD.decode(nonce).is_ok_and(|bytes| bytes.len() == 32)
}
fn sign(identity: &IdentityFile, payload: &Value) -> Result<String> {
    Ok(STANDARD.encode(
        identity
            .signing_key()?
            .sign(&orc_protocol::canonical_bytes(payload)?)
            .to_bytes(),
    ))
}
fn verify(public_key: &str, payload: &Value, signature: &str) -> Result<()> {
    let raw = STANDARD.decode(signature)?;
    let sig = Signature::from_slice(&raw)?;
    verifying_key(public_key)?.verify_strict(&orc_protocol::canonical_bytes(payload)?, &sig)?;
    Ok(())
}

pub fn hello_frame(identity: &IdentityFile) -> Result<Frame> {
    Ok(Frame::Hello {
        device_id: identity.id("dev")?,
        public_key: identity.public_key()?,
        hello: hello(),
        nonce: random_nonce()?,
    })
}
fn sync_payload(frame: &Frame) -> Result<Value> {
    let Frame::Sync {
        mcp_id,
        public_key,
        epoch,
        service_revision,
        revoked_principals,
        hello,
        device_nonce,
        challenge,
        ..
    } = frame
    else {
        return Err("SYNC_REQUIRED".into());
    };
    Ok(
        json!({"purpose":"orc-device-sync-v1","mcp_id":mcp_id,"public_key":public_key,"epoch":epoch,"service_revision":service_revision,"revoked_principals":revoked_principals,"hello":hello,"device_nonce":device_nonce,"challenge":challenge}),
    )
}
/// 签名完整同步上下文并回显设备 nonce，防止旧 Sync 被用于新连接。
pub fn sync_frame(
    identity: &IdentityFile,
    hello_frame: &Frame,
    epoch: u64,
    service_revision: u64,
    revoked_principals: Vec<String>,
) -> Result<Frame> {
    let Frame::Hello { nonce, .. } = hello_frame else {
        return Err("HELLO_REQUIRED".into());
    };
    if !valid_nonce(nonce) {
        return Err("INVALID_HANDSHAKE_NONCE".into());
    }
    let mut frame = Frame::Sync {
        mcp_id: identity.id("mcp")?,
        public_key: identity.public_key()?,
        epoch,
        service_revision,
        revoked_principals,
        hello: hello(),
        device_nonce: nonce.clone(),
        challenge: random_nonce()?,
        signature: String::new(),
    };
    let proof = sign(identity, &sync_payload(&frame)?)?;
    if let Frame::Sync { signature, .. } = &mut frame {
        *signature = proof
    }
    Ok(frame)
}
pub fn verify_sync(
    frame: &Frame,
    expected_mcp_id: &str,
    expected_public_key: &str,
    expected_device_nonce: &str,
) -> Result<()> {
    let Frame::Sync {
        mcp_id,
        public_key,
        hello,
        device_nonce,
        challenge,
        signature,
        ..
    } = frame
    else {
        return Err("SYNC_REQUIRED".into());
    };
    if mcp_id != expected_mcp_id
        || public_key != expected_public_key
        || key_id("mcp", &verifying_key(public_key)?) != *mcp_id
        || device_nonce != expected_device_nonce
        || !valid_nonce(challenge)
        || !valid_nonce(device_nonce)
    {
        return Err("MCP_IDENTITY_MISMATCH".into());
    }
    hello.validate(&BTreeSet::from(["state-v1".into()]))?;
    verify(expected_public_key, &sync_payload(frame)?, signature)
}
fn ready_payload(sync: &Frame) -> Result<Value> {
    let Frame::Sync {
        mcp_id,
        epoch,
        device_nonce,
        challenge,
        ..
    } = sync
    else {
        return Err("SYNC_REQUIRED".into());
    };
    Ok(
        json!({"purpose":"orc-device-ready-v1","mcp_id":mcp_id,"epoch":epoch,"device_nonce":device_nonce,"challenge":challenge,"sync_digest":orc_protocol::canonical_digest(&sync_payload(sync)?)?}),
    )
}
/// 回签 Sync 摘要；调用方必须已持久应用撤销，构造签名本身不执行该持久化。
pub fn ready_frame(identity: &IdentityFile, sync: &Frame) -> Result<Frame> {
    let Frame::Sync { epoch, .. } = sync else {
        return Err("SYNC_REQUIRED".into());
    };
    Ok(Frame::Ready {
        epoch: *epoch,
        signature: sign(identity, &ready_payload(sync)?)?,
    })
}
/// 验证当前握手的设备持钥证明；epoch 与同步摘要都必须匹配，不能只验证签名格式。
pub fn verify_ready(ready: &Frame, sync: &Frame, expected_device_public_key: &str) -> Result<()> {
    let Frame::Ready { epoch, signature } = ready else {
        return Err("READY_REQUIRED".into());
    };
    let Frame::Sync {
        epoch: expected, ..
    } = sync
    else {
        return Err("SYNC_REQUIRED".into());
    };
    if epoch != expected {
        return Err("CONNECTION_EPOCH_MISMATCH".into());
    }
    verify(expected_device_public_key, &ready_payload(sync)?, signature)
}
pub fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(256 * 1024))
        .max_frame_size(Some(256 * 1024))
        .max_write_buffer_size(512 * 1024)
        .write_buffer_size(0)
}
pub async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
    frame: &Frame,
) -> Result<()> {
    let bytes = serde_json::to_string(frame)?;
    if bytes.len() > 256 * 1024 {
        return Err("QUOTA_EXCEEDED".into());
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ws.send(Message::Text(bytes.into())),
    )
    .await??;
    Ok(())
}
pub async fn receive<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
) -> Result<Frame> {
    loop {
        match ws.next().await.ok_or("CONTROL_LOST")?? {
            Message::Text(text) => {
                return orc_protocol::strict_decode(text.as_bytes()).map_err(Into::into);
            }
            Message::Close(_) => return Err("CONTROL_LOST".into()),
            Message::Ping(bytes) => {
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    ws.send(Message::Pong(bytes)),
                )
                .await??
            }
            Message::Pong(_) => {}
            _ => return Err("INVALID_FRAME".into()),
        }
    }
}
pub fn tls_server(files: &TlsFiles) -> Result<Arc<rustls::ServerConfig>> {
    let (certs, key, roots) = read_tls(files)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()?;
    Ok(Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?,
    ))
}
pub fn tls_client(files: &TlsFiles) -> Result<Arc<rustls::ClientConfig>> {
    let (certs, key, roots) = read_tls(files)?;
    Ok(Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)?,
    ))
}
type TlsParts = (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
    rustls::RootCertStore,
);
fn read_tls(files: &TlsFiles) -> Result<TlsParts> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(
        &files.certificate,
    )?))
    .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(&files.key)?))?
        .ok_or("TLS key missing")?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(&files.ca)?)) {
        roots.add(cert?)?;
    }
    Ok((certs, key, roots))
}
pub fn certificate_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
pub fn certificate_file_digest(path: &Path) -> Result<String> {
    let first = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(path)?))
        .next()
        .ok_or("missing certificate")??;
    Ok(certificate_digest(first.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_keys_are_private_and_handshake_proves_both_keys() {
        let dir = tempfile::tempdir().unwrap();
        let device = IdentityFile::create(&dir.path().join("device.json")).unwrap();
        let server = IdentityFile::create(&dir.path().join("server.json")).unwrap();
        let impostor = IdentityFile::create(&dir.path().join("impostor.json")).unwrap();
        assert!(IdentityFile::create(&dir.path().join("device.json")).is_err());
        let loaded = IdentityFile::load(&dir.path().join("device.json")).unwrap();
        assert_eq!(loaded.id("dev").unwrap(), device.id("dev").unwrap());
        let hello = hello_frame(&device).unwrap();
        let nonce = match &hello {
            Frame::Hello { nonce, .. } => nonce,
            _ => unreachable!(),
        };
        let sync = sync_frame(&server, &hello, 42, 7, vec!["revoked-principal".into()]).unwrap();
        verify_sync(
            &sync,
            &server.id("mcp").unwrap(),
            &server.public_key().unwrap(),
            nonce,
        )
        .unwrap();
        assert!(
            verify_sync(
                &sync,
                &server.id("mcp").unwrap(),
                &server.public_key().unwrap(),
                "wrong-session"
            )
            .is_err()
        );
        assert!(
            verify_sync(
                &sync,
                &impostor.id("mcp").unwrap(),
                &impostor.public_key().unwrap(),
                nonce
            )
            .is_err()
        );
        let ready = ready_frame(&device, &sync).unwrap();
        verify_ready(&ready, &sync, &device.public_key().unwrap()).unwrap();
        assert!(verify_ready(&ready, &sync, &impostor.public_key().unwrap()).is_err());
        let another_sync = sync_frame(&server, &hello, 42, 7, vec![]).unwrap();
        assert!(verify_ready(&ready, &another_sync, &device.public_key().unwrap()).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.path().join("device.json"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert!(IdentityFile::load(&dir.path().join("device.json")).is_err());
        }
    }
    #[test]
    fn handshake_mutations_are_detected() {
        let dir = tempfile::tempdir().unwrap();
        let device = IdentityFile::create(&dir.path().join("device.json")).unwrap();
        let server = IdentityFile::create(&dir.path().join("server.json")).unwrap();
        let hello = hello_frame(&device).unwrap();
        let nonce = match &hello {
            Frame::Hello { nonce, .. } => nonce,
            _ => unreachable!(),
        };
        let mut sync = sync_frame(&server, &hello, 42, 7, vec!["revoked".into()]).unwrap();
        if let Frame::Sync {
            revoked_principals, ..
        } = &mut sync
        {
            revoked_principals.clear();
        }
        assert!(
            verify_sync(
                &sync,
                &server.id("mcp").unwrap(),
                &server.public_key().unwrap(),
                nonce
            )
            .is_err()
        );
    }
    #[test]
    fn strict_frames_reject_unknown_capabilities_and_identity_override_fields() {
        assert!(
            orc_protocol::strict_decode::<Frame>(
                br#"{"type":"ping","sequence":1,"principal":"admin"}"#
            )
            .is_err()
        );
        let mut hello = hello();
        hello.protocol_major = 2;
        assert!(hello.validate(&BTreeSet::new()).is_err());
    }
}

mod enrollment;
pub use enrollment::{EnrollmentProof, EnrollmentRequest, Invitation};
