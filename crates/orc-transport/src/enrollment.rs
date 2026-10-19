//! Owner-mediated, expiring enrollment. These public objects contain no secret
//! keys. An invitation proves identity; it grants no device execution action.
use super::{IdentityFile, Result, key_id, random_nonce, sign, valid_nonce, verify, verifying_key};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const LIFETIME: u64 = 600;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub version: u32,
    pub device_id: String,
    pub device_public_key: String,
    pub certificate_digest: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}
impl EnrollmentRequest {
    pub fn create(identity: &IdentityFile, certificate_digest: String, now: u64) -> Result<Self> {
        let mut request = Self {
            version: 1,
            device_id: identity.id("dev")?,
            device_public_key: identity.public_key()?,
            certificate_digest,
            nonce: random_nonce()?,
            issued_at: now,
            expires_at: now.checked_add(LIFETIME).ok_or("CLOCK_INVALID")?,
            signature: String::new(),
        };
        request.signature = sign(identity, &request.payload())?;
        request.verify(now)?;
        Ok(request)
    }
    fn payload(&self) -> Value {
        json!({"purpose":"orc-enrollment-request-v1","version":self.version,"device_id":self.device_id,"device_public_key":self.device_public_key,"certificate_digest":self.certificate_digest,"nonce":self.nonce,"issued_at":self.issued_at,"expires_at":self.expires_at})
    }
    pub fn verify(&self, now: u64) -> Result<()> {
        if self.version != 1
            || key_id("dev", &verifying_key(&self.device_public_key)?) != self.device_id
            || !valid_nonce(&self.nonce)
        {
            return Err("INVALID_ENROLLMENT_IDENTITY".into());
        }
        validate_window(self.issued_at, self.expires_at, now)?;
        if !self
            .certificate_digest
            .strip_prefix("sha256:")
            .is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
        {
            return Err("INVALID_CERTIFICATE_DIGEST".into());
        }
        verify(&self.device_public_key, &self.payload(), &self.signature)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub version: u32,
    pub mcp_id: String,
    pub mcp_public_key: String,
    pub request: EnrollmentRequest,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}
impl Invitation {
    pub fn issue(identity: &IdentityFile, request: EnrollmentRequest, now: u64) -> Result<Self> {
        request.verify(now)?;
        let expires_at = request
            .expires_at
            .min(now.checked_add(LIFETIME).ok_or("CLOCK_INVALID")?);
        let mut invitation = Self {
            version: 1,
            mcp_id: identity.id("mcp")?,
            mcp_public_key: identity.public_key()?,
            request,
            nonce: random_nonce()?,
            issued_at: now,
            expires_at,
            signature: String::new(),
        };
        invitation.signature = sign(identity, &invitation.payload())?;
        Ok(invitation)
    }
    fn payload(&self) -> Value {
        json!({"purpose":"orc-enrollment-invitation-v1","version":self.version,"mcp_id":self.mcp_id,"mcp_public_key":self.mcp_public_key,"request":self.request,"nonce":self.nonce,"issued_at":self.issued_at,"expires_at":self.expires_at})
    }
    pub fn verify(
        &self,
        expected_mcp_id: &str,
        expected_mcp_public_key: &str,
        expected_device_id: &str,
        now: u64,
    ) -> Result<()> {
        self.request.verify(now)?;
        validate_window(self.issued_at, self.expires_at, now)?;
        if self.version != 1
            || self.mcp_id != expected_mcp_id
            || self.mcp_public_key != expected_mcp_public_key
            || self.request.device_id != expected_device_id
            || self.expires_at > self.request.expires_at
            || key_id("mcp", &verifying_key(&self.mcp_public_key)?) != self.mcp_id
            || !valid_nonce(&self.nonce)
        {
            return Err("INVITATION_IDENTITY_MISMATCH".into());
        }
        verify(expected_mcp_public_key, &self.payload(), &self.signature)
    }
    pub fn digest(&self) -> Result<String> {
        Ok(orc_protocol::canonical_digest(self)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentProof {
    pub invitation_digest: String,
    pub device_id: String,
    pub signature: String,
}
impl EnrollmentProof {
    /// This signs enrollment only. The caller must still compare the invitation's
    /// MCP fingerprint through an independent trusted owner channel before trust.
    pub fn create(identity: &IdentityFile, invitation: &Invitation, now: u64) -> Result<Self> {
        invitation.verify(
            &invitation.mcp_id,
            &invitation.mcp_public_key,
            &identity.id("dev")?,
            now,
        )?;
        let mut proof = Self {
            invitation_digest: invitation.digest()?,
            device_id: identity.id("dev")?,
            signature: String::new(),
        };
        proof.signature = sign(identity, &proof.payload())?;
        Ok(proof)
    }
    fn payload(&self) -> Value {
        json!({"purpose":"orc-enrollment-redemption-v1","invitation_digest":self.invitation_digest,"device_id":self.device_id})
    }
    pub fn verify(&self, invitation: &Invitation) -> Result<()> {
        if self.invitation_digest != invitation.digest()?
            || self.device_id != invitation.request.device_id
        {
            return Err("ENROLLMENT_PROOF_MISMATCH".into());
        }
        verify(
            &invitation.request.device_public_key,
            &self.payload(),
            &self.signature,
        )
    }
}
fn validate_window(issued: u64, expires: u64, now: u64) -> Result<()> {
    if issued > now.saturating_add(60)
        || expires <= now
        || expires <= issued
        || expires > issued.saturating_add(LIFETIME)
    {
        return Err("ENROLLMENT_EXPIRED".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signatures_bind_both_identities_certificate_and_invitation() {
        let dir = tempfile::tempdir().unwrap();
        let mcp = IdentityFile::create(&dir.path().join("mcp")).unwrap();
        let device = IdentityFile::create(&dir.path().join("device")).unwrap();
        let other = IdentityFile::create(&dir.path().join("other")).unwrap();
        let request =
            EnrollmentRequest::create(&device, format!("sha256:{}", "a".repeat(64)), 100).unwrap();
        request.verify(101).unwrap();
        let invite = Invitation::issue(&mcp, request.clone(), 101).unwrap();
        invite
            .verify(
                &mcp.id("mcp").unwrap(),
                &mcp.public_key().unwrap(),
                &device.id("dev").unwrap(),
                102,
            )
            .unwrap();
        let proof = EnrollmentProof::create(&device, &invite, 102).unwrap();
        proof.verify(&invite).unwrap();
        assert!(EnrollmentProof::create(&other, &invite, 102).is_err());
        assert!(
            invite
                .verify(
                    &other.id("mcp").unwrap(),
                    &other.public_key().unwrap(),
                    &device.id("dev").unwrap(),
                    102
                )
                .is_err()
        );
        let another = Invitation::issue(&mcp, request.clone(), 102).unwrap();
        assert!(proof.verify(&another).is_err());
        let mut changed = request;
        changed.certificate_digest = format!("sha256:{}", "b".repeat(64));
        assert!(changed.verify(102).is_err());
        assert!(
            invite
                .verify(
                    &mcp.id("mcp").unwrap(),
                    &mcp.public_key().unwrap(),
                    &device.id("dev").unwrap(),
                    701
                )
                .is_err()
        );
    }
}
