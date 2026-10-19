//! 生成可交给所有者中转的公开登记请求和设备证明。
//!
//! 私钥从受保护文件读取，不放入命令行参数或输出；邀请验证与服务端兑换仍是独立步骤。

use orc_transport::{AnyError, EnrollmentProof, EnrollmentRequest, IdentityFile, Invitation, now};
use serde_json::{Value, json};
use std::{io::Read, path::Path};

pub fn request(identity: &Path, certificate: &Path) -> Result<Value, AnyError> {
    let identity = IdentityFile::load(identity)?;
    let metadata = std::fs::symlink_metadata(certificate)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        return Err("INVALID_CERTIFICATE_FILE".into());
    }
    let request = EnrollmentRequest::create(
        &identity,
        orc_transport::certificate_file_digest(certificate)?,
        now(),
    )?;
    Ok(serde_json::to_value(request)?)
}
pub fn proof(identity: &Path, invitation: &Path) -> Result<Value, AnyError> {
    let identity = IdentityFile::load(identity)?;
    let meta = std::fs::symlink_metadata(invitation)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 64 * 1024 {
        return Err("INVALID_INVITATION_FILE".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("INVITATION_FILE_MUST_BE_PRIVATE".into());
        }
    }
    let mut bytes = Vec::new();
    std::fs::File::open(invitation)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let invitation: Invitation = orc_protocol::strict_decode(&bytes)?;
    let proof = EnrollmentProof::create(&identity, &invitation, now())?;
    Ok(json!({"invitation":invitation,"proof":proof}))
}
