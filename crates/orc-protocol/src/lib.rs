//! Strict wire parsing, deterministic integer-only canonical JSON, and signed
//! delegation envelopes. Schema validation is independent of MCP presentation.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use orc_domain::{DeviceId, Error, ErrorCode, McpId, Principal, Result, SubmissionId};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

pub const PROTOCOL_MAJOR: u32 = 1;
pub const PROTOCOL_MINOR: u32 = 0;
pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;
pub const DELIVERY_LIFETIME_SECONDS: u64 = 30;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Reject duplicate keys recursively before converting to the target type.
/// JSON numbers are integer units; floating/exponent notation is not accepted.
pub fn strict_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::new(
            ErrorCode::QuotaExceeded,
            "request exceeds 256 KiB",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer).map_err(|_| {
        Error::new(
            ErrorCode::InvalidRequest,
            "invalid JSON: duplicate keys, noninteger numbers or malformed content",
        )
    })?;
    deserializer
        .end()
        .map_err(|_| Error::new(ErrorCode::InvalidRequest, "trailing JSON content"))?;
    serde_json::from_value(value.0).map_err(|_| {
        Error::new(
            ErrorCode::InvalidRequest,
            "request contains unknown, missing or invalid fields",
        )
    })
}

struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("strict JSON without duplicate keys or floating point numbers")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                if v.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(E::custom("integer exceeds canonical range"));
                }
                Ok(StrictValue(Value::Number(v.into())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                if v > MAX_SAFE_INTEGER {
                    return Err(E::custom("integer exceeds canonical range"));
                }
                Ok(StrictValue(Value::Number(v.into())))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Self::Value, E> {
                Err(E::custom("floating point values are forbidden"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::String(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::String(v)))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                    values.insert(key, map.next_value::<StrictValue>()?.0);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

/// RFC 8785 compatible encoding for the protocol's restricted value domain:
/// Unicode strings and exact integers in ±(2^53-1), with UTF-16 key ordering.
/// This deliberately rejects floats instead of claiming general JCS support.
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)
        .map_err(|_| Error::new(ErrorCode::InvalidRequest, "value cannot be serialized"))?;
    let mut output = Vec::new();
    encode_value(&value, &mut output)?;
    Ok(output)
}

pub fn canonical_digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(canonical_bytes(value)?)
    ))
}

fn encode_value(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::String(value) => serde_json::to_writer(output, value)
            .map_err(|_| Error::new(ErrorCode::Internal, "canonical string encoding failed"))?,
        Value::Number(n) => {
            let valid = n.as_u64().is_some_and(|v| v <= MAX_SAFE_INTEGER)
                || n.as_i64()
                    .is_some_and(|v| v.unsigned_abs() <= MAX_SAFE_INTEGER);
            if !valid {
                return Err(Error::new(
                    ErrorCode::InvalidRequest,
                    "canonical protocol numbers must be exact safe integers",
                ));
            }
            output.extend_from_slice(n.to_string().as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                encode_value(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            output.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).map_err(|_| {
                    Error::new(ErrorCode::Internal, "canonical key encoding failed")
                })?;
                output.push(b':');
                encode_value(&values[*key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub protocol_major: u32,
    pub protocol_minor: u32,
    pub software_version: String,
    pub state_schema: u32,
    pub boot_id: String,
    pub capabilities: BTreeSet<String>,
}

impl Hello {
    pub fn validate(&self, required: &BTreeSet<String>) -> Result<()> {
        if self.protocol_major != PROTOCOL_MAJOR
            || self.state_schema != 1
            || self.boot_id.is_empty()
        {
            return Err(Error::new(
                ErrorCode::IncompatibleContract,
                "unsupported protocol, state schema or missing boot identity",
            ));
        }
        check_capabilities(required, &self.capabilities)
    }
}

pub fn check_capabilities(required: &BTreeSet<String>, available: &BTreeSet<String>) -> Result<()> {
    if !required.is_subset(available) {
        return Err(Error::new(
            ErrorCode::CapabilityUnavailable,
            "required execution contract is unavailable",
        ));
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub protocol_major: u32,
    pub mcp_id: McpId,
    pub device_id: DeviceId,
    pub principal: Principal,
    pub connection_epoch: u64,
    pub operation: String,
    pub submission_id: Option<SubmissionId>,
    pub request_digest: String,
    pub request: Value,
    pub service_policy_revision: u64,
    pub required_capabilities: BTreeSet<String>,
    pub sent_at: u64,
    pub delivery_expires_at: u64,
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("device_id", &self.device_id)
            .field("operation", &self.operation)
            .field("submission_id", &self.submission_id)
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    pub payload: Envelope,
    pub signature: String,
}

/// Current trusted channel facts, never copied from the incoming envelope.
pub struct EnvelopeContext<'a> {
    pub mcp_id: &'a McpId,
    pub device_id: &'a DeviceId,
    pub connection_epoch: u64,
    pub service_policy_revision: u64,
    pub capabilities: &'a BTreeSet<String>,
    pub now: u64,
}

impl SignedEnvelope {
    pub fn sign(payload: Envelope, key: &SigningKey) -> Result<Self> {
        if canonical_digest(&payload.request)? != payload.request_digest {
            return Err(Error::new(
                ErrorCode::InvalidRequest,
                "request digest does not match payload",
            ));
        }
        let signature = hex_encode(&key.sign(&canonical_bytes(&payload)?).to_bytes());
        Ok(Self { payload, signature })
    }

    pub fn verify(&self, key: &VerifyingKey, context: &EnvelopeContext<'_>) -> Result<()> {
        let raw = hex_decode(&self.signature)?;
        let signature = Signature::from_slice(&raw)
            .map_err(|_| Error::new(ErrorCode::AccessDenied, "invalid delegation signature"))?;
        key.verify_strict(&canonical_bytes(&self.payload)?, &signature)
            .map_err(|_| {
                Error::new(
                    ErrorCode::AccessDenied,
                    "delegation signature did not verify",
                )
            })?;
        let p = &self.payload;
        p.principal.validate()?;
        if p.protocol_major != PROTOCOL_MAJOR {
            return Err(Error::new(
                ErrorCode::IncompatibleContract,
                "unsupported delegation protocol",
            ));
        }
        if &p.mcp_id != context.mcp_id
            || &p.device_id != context.device_id
            || p.principal.mcp_id != p.mcp_id
            || p.connection_epoch != context.connection_epoch
            || p.service_policy_revision != context.service_policy_revision
        {
            return Err(Error::new(
                ErrorCode::AccessDenied,
                "delegation identity, target or authorization epoch mismatch",
            ));
        }
        if p.sent_at > context.now.saturating_add(5)
            || p.delivery_expires_at <= context.now
            || p.delivery_expires_at <= p.sent_at
            || p.delivery_expires_at > p.sent_at.saturating_add(DELIVERY_LIFETIME_SECONDS)
        {
            return Err(Error::new(
                ErrorCode::SubmissionExpired,
                "delegation delivery window expired or invalid",
            ));
        }
        if canonical_digest(&p.request)? != p.request_digest {
            return Err(Error::new(
                ErrorCode::AccessDenied,
                "delegated request was changed",
            ));
        }
        let trusted_required = operation_capabilities(&p.operation)?;
        let required: BTreeSet<_> = p
            .required_capabilities
            .union(&trusted_required)
            .cloned()
            .collect();
        check_capabilities(&required, context.capabilities)?;
        if p.operation == "orc_task_submit" {
            let request: orc_domain::TaskRequest = serde_json::from_value(p.request.clone())
                .map_err(|_| {
                    Error::new(
                        ErrorCode::InvalidRequest,
                        "invalid task schema in delegation",
                    )
                })?;
            request.validate()?;
            if p.submission_id.as_ref() != Some(&request.submission_id)
                || request.device_id != p.device_id
            {
                return Err(Error::new(
                    ErrorCode::AccessDenied,
                    "submission or target differs from delegation",
                ));
            }
        }
        Ok(())
    }
}

/// Capabilities are attached by trusted local schema. A request cannot omit a
/// mandatory safety capability to negotiate a less restrictive operation.
pub fn operation_capabilities(operation: &str) -> Result<BTreeSet<String>> {
    let names: &[&str] = match operation {
        "orc_device_inspect" | "orc_task_get" | "orc_task_list" | "orc_submission_get" => {
            &["state-v1"]
        }
        "orc_policy_preview" => &["policy-v1", "strict-task-v1"],
        "orc_task_submit" => &["strict-task-v1", "durable-submission-v1", "policy-v1"],
        "orc_task_cancel" => &["stop-evidence-v1"],
        "orc_snapshot_list" | "orc_snapshot_read" => &["snapshot-v1", "bounded-read-v1"],
        "orc_task_output_read" => &["bounded-read-v1"],
        "orc_artifacts_list" | "orc_artifact_read" => &["artifacts-v1", "bounded-read-v1"],
        "orc_changes_propose" | "orc_changes_get" => &["changes-v1", "durable-submission-v1"],
        _ => {
            return Err(Error::new(
                ErrorCode::IncompatibleContract,
                "unknown delegated operation",
            ));
        }
    };
    Ok(names.iter().map(|name| (*name).to_owned()).collect())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub transfer_id: String,
    pub sequence: u64,
    pub length: usize,
    pub digest: String,
    pub bytes: Vec<u8>,
}
impl Chunk {
    pub fn validate(&self, expected_sequence: u64) -> Result<()> {
        if self.transfer_id.is_empty()
            || self.sequence != expected_sequence
            || self.length != self.bytes.len()
            || self.length > MAX_CHUNK_BYTES
        {
            return Err(Error::new(
                ErrorCode::InvalidRequest,
                "invalid or out-of-order transfer chunk",
            ));
        }
        if self.digest != format!("sha256:{:x}", Sha256::digest(&self.bytes)) {
            return Err(Error::new(
                ErrorCode::InvalidRequest,
                "transfer chunk digest mismatch",
            ));
        }
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if value.len() != 128 || !value.is_ascii() {
        return Err(Error::new(
            ErrorCode::AccessDenied,
            "invalid signature encoding",
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16)
                .map_err(|_| Error::new(ErrorCode::AccessDenied, "invalid signature encoding"))
        })
        .collect()
}

#[cfg(test)]
mod tests;
