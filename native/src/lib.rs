#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::arithmetic_side_effects)]

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[cfg(feature = "dynamodb-claims")]
pub mod dynamodb_claims;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyCode {
    Parse,
    DuplicateKey,
    UnknownField,
    MissingField,
    BodyTooLarge,
    Version,
    Type,
    Decision,
    Algorithm,
    NonCanonicalHex,
    NonCanonicalUuid,
    NonCanonicalNumber,
    Nonce,
    UnknownKid,
    RevokedKid,
    KeyBinding,
    KeyRole,
    Signature,
    IssuedFuture,
    Expired,
    TimeOrder,
    ValidityTooLong,
    TimestampRange,
    Audience,
    ActionHash,
    Release,
    Approver,
    ApprovalBinding,
}
impl VerifyCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "E001_PARSE",
            Self::DuplicateKey => "E002_DUPLICATE_KEY",
            Self::UnknownField => "E003_UNKNOWN_FIELD",
            Self::MissingField => "E004_MISSING_FIELD",
            Self::BodyTooLarge => "E005_BODY_TOO_LARGE",
            Self::Version => "E006_VERSION",
            Self::Type => "E007_TYPE",
            Self::Decision => "E008_DECISION",
            Self::Algorithm => "E009_ALGORITHM",
            Self::NonCanonicalHex => "E010_NONCANONICAL_HEX",
            Self::NonCanonicalUuid => "E011_NONCANONICAL_UUID",
            Self::NonCanonicalNumber => "E012_NONCANONICAL_NUMBER",
            Self::Nonce => "E013_NONCE",
            Self::UnknownKid => "E014_UNKNOWN_KID",
            Self::RevokedKid => "E015_REVOKED_KID",
            Self::KeyBinding => "E016_KEY_BINDING",
            Self::KeyRole => "E017_KEY_ROLE",
            Self::Signature => "E018_SIGNATURE",
            Self::IssuedFuture => "E019_ISSUED_FUTURE",
            Self::Expired => "E020_EXPIRED",
            Self::TimeOrder => "E021_TIME_ORDER",
            Self::ValidityTooLong => "E022_VALIDITY_TOO_LONG",
            Self::TimestampRange => "E023_TIMESTAMP_RANGE",
            Self::Audience => "E024_AUDIENCE",
            Self::ActionHash => "E025_ACTION_HASH",
            Self::Release => "E030_RELEASE",
            Self::Approver => "E031_APPROVER",
            Self::ApprovalBinding => "E032_APPROVAL_BINDING",
        }
    }
}

impl std::fmt::Display for VerifyCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for VerifyCode {}

#[derive(Clone)]
pub struct TrustedKey {
    pub public_key: [u8; 32],
    pub role: KeyRole,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    Decision,
    Approval,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringDocument {
    keys: Vec<KeyringEntry>,
    #[serde(rename = "revokedKids", default)]
    revoked_kids: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringEntry {
    kid: String,
    role: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}
pub struct LoadedKeyring {
    pub keys: HashMap<String, TrustedKey>,
    pub revoked: HashSet<String>,
}
pub fn load_keyring_file(path: impl AsRef<Path>) -> Result<LoadedKeyring, String> {
    let raw = fs::read(path).map_err(|e| format!("keyring read: {e}"))?;
    reject_duplicate_json(&raw).map_err(|e| e.as_str().to_owned())?;
    let doc: KeyringDocument =
        serde_json::from_slice(&raw).map_err(|e| format!("keyring parse: {e}"))?;
    let mut keys = HashMap::new();
    for e in doc.keys {
        if !lower_hex(&e.kid, 64) {
            return Err("keyring kid must be 64 lowercase hex characters".into());
        }
        let b = B64
            .decode(e.public_key.as_bytes())
            .map_err(|_| "keyring publicKey is not canonical base64")?;
        if B64.encode(&b) != e.public_key {
            return Err("keyring publicKey is not canonical base64".into());
        }
        let arr = <[u8; 32]>::try_from(b).map_err(|_| "keyring publicKey must be 32 bytes")?;
        let vk =
            VerifyingKey::from_bytes(&arr).map_err(|_| "keyring publicKey is invalid Ed25519")?;
        if hex::encode(Sha256::digest(vk.to_bytes())) != e.kid {
            return Err("keyring kid does not match SHA-256(public key)".into());
        }
        let role = match e.role.as_str() {
            "decision" => KeyRole::Decision,
            "approval" => KeyRole::Approval,
            _ => return Err("keyring role must be decision or approval".into()),
        };
        if keys
            .insert(
                e.kid,
                TrustedKey {
                    public_key: arr,
                    role,
                },
            )
            .is_some()
        {
            return Err("duplicate kid in keyring".into());
        }
    }
    let mut revoked = HashSet::new();
    for kid in doc.revoked_kids {
        if !lower_hex(&kid, 64) {
            return Err("revoked kid must be 64 lowercase hex characters".into());
        }
        if !revoked.insert(kid) {
            return Err("duplicate revoked kid".into());
        }
    }
    Ok(LoadedKeyring { keys, revoked })
}
pub fn load_signing_key_file(path: impl AsRef<Path>) -> Result<SigningKey, String> {
    let path = path.as_ref();
    let meta = fs::metadata(path).map_err(|e| format!("signing key metadata: {e}"))?;
    if !meta.is_file() {
        return Err("signing key path must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("signing key file must not be group/world accessible".into());
        }
    }
    let mut raw = fs::read(path).map_err(|e| format!("signing key read: {e}"))?;
    if raw.len() != 32 {
        raw.zeroize();
        return Err("signing key must be exactly 32 raw bytes".into());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw);
    raw.zeroize();
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}
#[cfg(unix)]
pub fn disable_core_dumps() -> Result<(), String> {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) };
    if rc == 0 {
        Ok(())
    } else {
        Err("failed to disable core dumps".into())
    }
}
#[cfg(not(unix))]
pub fn disable_core_dumps() -> Result<(), String> {
    Err("qualified runtime requires Unix core-dump controls".into())
}

pub struct VerifyContext<'a> {
    pub keys: &'a HashMap<String, TrustedKey>,
    pub revoked: &'a HashSet<String>,
    pub expected_audience: &'a str,
    pub expected_release: &'a str,
    pub now: u64,
    pub skew: u64,
    pub max_validity: u64,
    pub max_body: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    #[serde(rename = "decisionEnvelope")]
    decision_envelope: Envelope,
    #[serde(rename = "canonicalAction")]
    canonical_action: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    #[serde(rename = "type")]
    typ: String,
    version: String,
    algorithm: String,
    decision: String,
    kid: String,
    #[serde(rename = "releaseId")]
    release_id: String,
    audience: String,
    #[serde(rename = "profileHash")]
    profile_hash: String,
    #[serde(rename = "canonicalActionHash")]
    canonical_action_hash: String,
    nonce: String,
    #[serde(rename = "envelopeId")]
    envelope_id: String,
    #[serde(rename = "issuedAt")]
    issued_at: Value,
    #[serde(rename = "expiresAt")]
    expires_at: Value,
    signature: String,
}

struct NoDuplicateJson;
impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = NoDuplicateJson;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("valid JSON without duplicate object keys")
            }
            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(NoDuplicateJson)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(NoDuplicateJson)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(NoDuplicateJson)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(NoDuplicateJson)
            }
            fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
                Ok(NoDuplicateJson)
            }
            fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
                Ok(NoDuplicateJson)
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(NoDuplicateJson)
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(NoDuplicateJson)
            }
            fn visit_some<D>(self, d: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                Deserialize::deserialize(d)
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                while seq.next_element::<NoDuplicateJson>()?.is_some() {}
                Ok(NoDuplicateJson)
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                while let Some(k) = map.next_key::<String>()? {
                    if !seen.insert(k) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    let _: NoDuplicateJson = map.next_value()?;
                }
                Ok(NoDuplicateJson)
            }
        }
        deserializer.deserialize_any(V)
    }
}
pub fn reject_duplicate_json(raw: &[u8]) -> Result<(), VerifyCode> {
    serde_json::from_slice::<NoDuplicateJson>(raw)
        .map(|_| ())
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                VerifyCode::DuplicateKey
            } else {
                VerifyCode::Parse
            }
        })
}
fn canonical_json_u64(v: &Value) -> Result<u64, VerifyCode> {
    let s = v.as_str().ok_or(VerifyCode::NonCanonicalNumber)?;
    canonical_u64(s)
}
fn canonical_u64(s: &str) -> Result<u64, VerifyCode> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(VerifyCode::NonCanonicalNumber);
    }
    let value = s.parse::<u64>().map_err(|_| VerifyCode::TimestampRange)?;
    if value > 9_007_199_254_740_991 {
        return Err(VerifyCode::TimestampRange);
    }
    Ok(value)
}

fn lower_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn put_field(out: &mut Vec<u8>, b: &[u8]) -> Result<(), VerifyCode> {
    let len = u32::try_from(b.len()).map_err(|_| VerifyCode::BodyTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionKind {
    Retain,
    Gate,
}
impl DecisionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retain => "RETAIN",
            Self::Gate => "GATE",
        }
    }
}
#[derive(Clone)]
pub struct DecisionSigningFields<'a> {
    pub decision: DecisionKind,
    pub release_id: &'a str,
    pub audience: &'a str,
    pub kid: &'a str,
    pub profile_hash: &'a str,
    pub action_hash: &'a str,
    pub nonce: &'a str,
    pub envelope_id: &'a Uuid,
    pub issued_at: u64,
    pub expires_at: u64,
}
pub fn decision_signing_bytes(f: &DecisionSigningFields<'_>) -> Result<Vec<u8>, VerifyCode> {
    let mut o = Vec::new();
    for v in [
        b"zdx-decision-v2".as_slice(),
        b"decision",
        f.decision.as_str().as_bytes(),
        f.release_id.as_bytes(),
        f.audience.as_bytes(),
        f.kid.as_bytes(),
        f.profile_hash.as_bytes(),
        f.action_hash.as_bytes(),
        f.nonce.as_bytes(),
        f.envelope_id.as_bytes(),
    ] {
        put_field(&mut o, v)?;
    }
    o.extend_from_slice(&f.issued_at.to_be_bytes());
    o.extend_from_slice(&f.expires_at.to_be_bytes());
    Ok(o)
}
pub fn canonical_action_hash(v: &Value) -> Result<String, VerifyCode> {
    let b = serde_jcs::to_vec(v).map_err(|_| VerifyCode::ActionHash)?;
    Ok(hex::encode(Sha256::digest(b)))
}
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedDecision {
    pub decision: DecisionKind,
    pub envelope_id: String,
    pub kid: String,
    pub profile_hash: String,
    pub action_hash: String,
    pub release_id: String,
    pub audience: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub canonical_action: Value,
}

pub fn verify_decision(
    raw: &[u8],
    ctx: &VerifyContext<'_>,
) -> Result<VerifiedDecision, VerifyCode> {
    if raw.len() > ctx.max_body {
        return Err(VerifyCode::BodyTooLarge);
    }
    reject_duplicate_json(raw)?;
    let root: Root = serde_json::from_slice(raw).map_err(|e| {
        let m = e.to_string();
        if m.contains("duplicate field") {
            VerifyCode::DuplicateKey
        } else if m.contains("unknown field") {
            VerifyCode::UnknownField
        } else if m.contains("missing field") {
            VerifyCode::MissingField
        } else {
            VerifyCode::Parse
        }
    })?;
    let e = root.decision_envelope;
    if e.version != "2" {
        return Err(VerifyCode::Version);
    }
    if e.typ != "decision" {
        return Err(VerifyCode::Type);
    }
    let decision = match e.decision.as_str() {
        "RETAIN" => DecisionKind::Retain,
        "GATE" => DecisionKind::Gate,
        _ => return Err(VerifyCode::Decision),
    };
    if e.algorithm != "Ed25519" {
        return Err(VerifyCode::Algorithm);
    }
    if !lower_hex(&e.kid, 64)
        || !lower_hex(&e.profile_hash, 64)
        || !lower_hex(&e.canonical_action_hash, 64)
    {
        return Err(VerifyCode::NonCanonicalHex);
    }
    if !e.nonce.is_ascii() || !(16..=128).contains(&e.nonce.len()) {
        return Err(VerifyCode::Nonce);
    }
    let id = Uuid::parse_str(&e.envelope_id).map_err(|_| VerifyCode::NonCanonicalUuid)?;
    if id.hyphenated().to_string() != e.envelope_id {
        return Err(VerifyCode::NonCanonicalUuid);
    }
    let issued = canonical_json_u64(&e.issued_at)?;
    let expires = canonical_json_u64(&e.expires_at)?;
    let future = ctx.now.saturating_add(ctx.skew);
    if issued > future {
        return Err(VerifyCode::IssuedFuture);
    }
    if expires <= issued {
        return Err(VerifyCode::TimeOrder);
    }
    if ctx.now >= expires {
        return Err(VerifyCode::Expired);
    }
    let validity = expires.checked_sub(issued).ok_or(VerifyCode::TimeOrder)?;
    if validity > ctx.max_validity {
        return Err(VerifyCode::ValidityTooLong);
    }
    if e.audience != ctx.expected_audience {
        return Err(VerifyCode::Audience);
    }
    if e.release_id != ctx.expected_release {
        return Err(VerifyCode::Release);
    }
    if ctx.revoked.contains(&e.kid) {
        return Err(VerifyCode::RevokedKid);
    }
    let tk = ctx.keys.get(&e.kid).ok_or(VerifyCode::UnknownKid)?;
    if tk.role != KeyRole::Decision {
        return Err(VerifyCode::KeyRole);
    }
    let vk = VerifyingKey::from_bytes(&tk.public_key).map_err(|_| VerifyCode::KeyBinding)?;
    if hex::encode(Sha256::digest(vk.to_bytes())) != e.kid {
        return Err(VerifyCode::KeyBinding);
    }
    let sig_bytes = B64
        .decode(e.signature.as_bytes())
        .map_err(|_| VerifyCode::Signature)?;
    if B64.encode(&sig_bytes) != e.signature {
        return Err(VerifyCode::Signature);
    }
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| VerifyCode::Signature)?;
    vk.verify_strict(
        &decision_signing_bytes(&DecisionSigningFields {
            decision,
            release_id: &e.release_id,
            audience: &e.audience,
            kid: &e.kid,
            profile_hash: &e.profile_hash,
            action_hash: &e.canonical_action_hash,
            nonce: &e.nonce,
            envelope_id: &id,
            issued_at: issued,
            expires_at: expires,
        })?,
        &sig,
    )
    .map_err(|_| VerifyCode::Signature)?;
    if canonical_action_hash(&root.canonical_action)? != e.canonical_action_hash {
        return Err(VerifyCode::ActionHash);
    }
    Ok(VerifiedDecision {
        decision,
        envelope_id: e.envelope_id,
        kid: e.kid,
        profile_hash: e.profile_hash,
        action_hash: e.canonical_action_hash,
        release_id: e.release_id,
        audience: e.audience,
        issued_at: issued,
        expires_at: expires,
        canonical_action: root.canonical_action,
    })
}

pub fn verify_envelope(raw: &[u8], ctx: &VerifyContext<'_>) -> Result<String, VerifyCode> {
    let d = verify_decision(raw, ctx)?;
    if d.decision != DecisionKind::Retain {
        return Err(VerifyCode::Decision);
    }
    Ok(d.envelope_id)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalRoot {
    #[serde(rename = "approvalArtifact")]
    approval_artifact: ApprovalArtifact,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalArtifact {
    #[serde(rename = "type")]
    typ: String,
    version: String,
    algorithm: String,
    decision: String,
    kid: String,
    #[serde(rename = "releaseId")]
    release_id: String,
    audience: String,
    #[serde(rename = "profileHash")]
    profile_hash: String,
    #[serde(rename = "canonicalActionHash")]
    canonical_action_hash: String,
    #[serde(rename = "decisionEnvelopeId")]
    decision_envelope_id: String,
    #[serde(rename = "approvalId")]
    approval_id: String,
    approver: String,
    #[serde(rename = "issuedAt")]
    issued_at: Value,
    #[serde(rename = "expiresAt")]
    expires_at: Value,
    signature: String,
}
#[derive(Clone)]
pub struct ApprovalSigningFields<'a> {
    pub release_id: &'a str,
    pub audience: &'a str,
    pub kid: &'a str,
    pub profile_hash: &'a str,
    pub action_hash: &'a str,
    pub decision_envelope_id: &'a Uuid,
    pub approval_id: &'a Uuid,
    pub approver: &'a str,
    pub issued_at: u64,
    pub expires_at: u64,
}
pub fn approval_signing_bytes(f: &ApprovalSigningFields<'_>) -> Result<Vec<u8>, VerifyCode> {
    let mut o = Vec::new();
    for v in [
        b"zdx-approval-v1".as_slice(),
        b"approval",
        b"APPROVE",
        f.release_id.as_bytes(),
        f.audience.as_bytes(),
        f.kid.as_bytes(),
        f.profile_hash.as_bytes(),
        f.action_hash.as_bytes(),
        f.decision_envelope_id.as_bytes(),
        f.approval_id.as_bytes(),
        f.approver.as_bytes(),
    ] {
        put_field(&mut o, v)?
    }
    o.extend_from_slice(&f.issued_at.to_be_bytes());
    o.extend_from_slice(&f.expires_at.to_be_bytes());
    Ok(o)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedApproval {
    pub approval_id: String,
    pub approver: String,
    pub kid: String,
    pub expires_at: u64,
}
pub fn verify_approval(
    raw: &[u8],
    decision: &VerifiedDecision,
    ctx: &VerifyContext<'_>,
) -> Result<VerifiedApproval, VerifyCode> {
    if raw.len() > ctx.max_body {
        return Err(VerifyCode::BodyTooLarge);
    }
    reject_duplicate_json(raw)?;
    let root: ApprovalRoot = serde_json::from_slice(raw).map_err(|e| {
        let m = e.to_string();
        if m.contains("duplicate field") {
            VerifyCode::DuplicateKey
        } else if m.contains("unknown field") {
            VerifyCode::UnknownField
        } else if m.contains("missing field") {
            VerifyCode::MissingField
        } else {
            VerifyCode::Parse
        }
    })?;
    let a = root.approval_artifact;
    if a.version != "1" {
        return Err(VerifyCode::Version);
    }
    if a.typ != "approval" {
        return Err(VerifyCode::Type);
    }
    if a.decision != "APPROVE" {
        return Err(VerifyCode::Decision);
    }
    if a.algorithm != "Ed25519" {
        return Err(VerifyCode::Algorithm);
    }
    if !lower_hex(&a.kid, 64)
        || !lower_hex(&a.profile_hash, 64)
        || !lower_hex(&a.canonical_action_hash, 64)
    {
        return Err(VerifyCode::NonCanonicalHex);
    }
    if a.approver.is_empty() || a.approver.len() > 128 || !a.approver.is_ascii() {
        return Err(VerifyCode::Approver);
    }
    let decision_id =
        Uuid::parse_str(&a.decision_envelope_id).map_err(|_| VerifyCode::NonCanonicalUuid)?;
    if decision_id.hyphenated().to_string() != a.decision_envelope_id {
        return Err(VerifyCode::NonCanonicalUuid);
    }
    let approval_id = Uuid::parse_str(&a.approval_id).map_err(|_| VerifyCode::NonCanonicalUuid)?;
    if approval_id.hyphenated().to_string() != a.approval_id {
        return Err(VerifyCode::NonCanonicalUuid);
    }
    let issued = canonical_json_u64(&a.issued_at)?;
    let expires = canonical_json_u64(&a.expires_at)?;
    if issued > ctx.now.saturating_add(ctx.skew) {
        return Err(VerifyCode::IssuedFuture);
    }
    if expires <= issued {
        return Err(VerifyCode::TimeOrder);
    }
    if ctx.now >= expires {
        return Err(VerifyCode::Expired);
    }
    if expires.checked_sub(issued).ok_or(VerifyCode::TimeOrder)? > ctx.max_validity {
        return Err(VerifyCode::ValidityTooLong);
    }
    if a.release_id != ctx.expected_release {
        return Err(VerifyCode::Release);
    }
    if a.audience != ctx.expected_audience {
        return Err(VerifyCode::Audience);
    }
    if a.decision_envelope_id != decision.envelope_id
        || a.profile_hash != decision.profile_hash
        || a.canonical_action_hash != decision.action_hash
        || a.release_id != decision.release_id
        || a.audience != decision.audience
        || expires > decision.expires_at
    {
        return Err(VerifyCode::ApprovalBinding);
    }
    if ctx.revoked.contains(&a.kid) {
        return Err(VerifyCode::RevokedKid);
    }
    let tk = ctx.keys.get(&a.kid).ok_or(VerifyCode::UnknownKid)?;
    if tk.role != KeyRole::Approval {
        return Err(VerifyCode::KeyRole);
    }
    let vk = VerifyingKey::from_bytes(&tk.public_key).map_err(|_| VerifyCode::KeyBinding)?;
    if hex::encode(Sha256::digest(vk.to_bytes())) != a.kid {
        return Err(VerifyCode::KeyBinding);
    }
    let sig_bytes = B64
        .decode(a.signature.as_bytes())
        .map_err(|_| VerifyCode::Signature)?;
    if B64.encode(&sig_bytes) != a.signature {
        return Err(VerifyCode::Signature);
    }
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| VerifyCode::Signature)?;
    let fields = ApprovalSigningFields {
        release_id: &a.release_id,
        audience: &a.audience,
        kid: &a.kid,
        profile_hash: &a.profile_hash,
        action_hash: &a.canonical_action_hash,
        decision_envelope_id: &decision_id,
        approval_id: &approval_id,
        approver: &a.approver,
        issued_at: issued,
        expires_at: expires,
    };
    vk.verify_strict(&approval_signing_bytes(&fields)?, &sig)
        .map_err(|_| VerifyCode::Signature)?;
    Ok(VerifiedApproval {
        approval_id: a.approval_id,
        approver: a.approver,
        kid: a.kid,
        expires_at: expires,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimCode {
    Replay,
    StoreUnavailable,
    InvalidId,
}
impl ClaimCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "E026_REPLAY",
            Self::StoreUnavailable => "E027_STORE_UNAVAILABLE",
            Self::InvalidId => "E028_CLAIM_CONFLICT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimStatus {
    Claimed,
    Executed,
    Failed,
    Unknown,
}

#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRecord {
    #[serde(rename = "envelopeId")]
    envelope_id: String,
    kid: String,
    #[serde(rename = "canonicalActionHash")]
    canonical_action_hash: String,
    #[serde(rename = "issuedAt")]
    issued_at: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(rename = "claimedAt")]
    claimed_at: String,
    #[serde(rename = "approvalId", skip_serializing_if = "Option::is_none")]
    approval_id: Option<String>,
    state: String,
    #[serde(rename = "outcomeAt", skip_serializing_if = "Option::is_none")]
    outcome_at: Option<String>,
    #[serde(rename = "failureReason", skip_serializing_if = "Option::is_none")]
    failure_reason: Option<String>,
}

pub struct ClaimInput<'a> {
    pub envelope_id: &'a str,
    pub kid: &'a str,
    pub action_hash: &'a str,
    pub issued: u64,
    pub expires: u64,
    pub now: u64,
    pub approval_id: Option<&'a str>,
}
pub struct FileClaimStore {
    root: PathBuf,
    execution_timeout: u64,
}
impl FileClaimStore {
    pub fn new(root: impl AsRef<Path>, execution_timeout: u64) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            execution_timeout,
        }
    }
    fn path(&self, envelope_id: &str) -> Result<PathBuf, ClaimCode> {
        let id = Uuid::parse_str(envelope_id).map_err(|_| ClaimCode::InvalidId)?;
        if id.hyphenated().to_string() != envelope_id {
            return Err(ClaimCode::InvalidId);
        }
        Ok(self.root.join(format!("{envelope_id}.json")))
    }
    pub fn claim(&self, input: &ClaimInput<'_>) -> Result<(), ClaimCode> {
        if let Some(a) = input.approval_id {
            let u = Uuid::parse_str(a).map_err(|_| ClaimCode::InvalidId)?;
            if u.hyphenated().to_string() != a {
                return Err(ClaimCode::InvalidId);
            }
        }
        fs::create_dir_all(&self.root).map_err(|_| ClaimCode::StoreUnavailable)?;
        if let Some(a) = input.approval_id {
            let approval_path = self.root.join(format!("approval-{a}.used"));
            let mut marker = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(approval_path)
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        ClaimCode::Replay
                    } else {
                        ClaimCode::StoreUnavailable
                    }
                })?;
            marker
                .write_all(input.envelope_id.as_bytes())
                .map_err(|_| ClaimCode::StoreUnavailable)?;
            marker.sync_all().map_err(|_| ClaimCode::StoreUnavailable)?;
        }
        let path = self.path(input.envelope_id)?;
        let rec = ClaimRecord {
            envelope_id: input.envelope_id.to_owned(),
            kid: input.kid.to_owned(),
            canonical_action_hash: input.action_hash.to_owned(),
            issued_at: input.issued.to_string(),
            expires_at: input.expires.to_string(),
            claimed_at: input.now.to_string(),
            approval_id: input.approval_id.map(str::to_owned),
            state: "claimed".to_owned(),
            outcome_at: None,
            failure_reason: None,
        };
        let bytes = serde_json::to_vec(&rec).map_err(|_| ClaimCode::StoreUnavailable)?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    ClaimCode::Replay
                } else {
                    ClaimCode::StoreUnavailable
                }
            })?;
        f.write_all(&bytes)
            .map_err(|_| ClaimCode::StoreUnavailable)?;
        f.sync_all().map_err(|_| ClaimCode::StoreUnavailable)
    }
    pub fn complete(
        &self,
        envelope_id: &str,
        executed: bool,
        now: u64,
        reason: Option<&str>,
    ) -> Result<(), ClaimCode> {
        let path = self.path(envelope_id)?;
        let raw = fs::read(&path).map_err(|_| ClaimCode::StoreUnavailable)?;
        let mut rec: ClaimRecord =
            serde_json::from_slice(&raw).map_err(|_| ClaimCode::StoreUnavailable)?;
        if rec.state != "claimed" {
            return Err(ClaimCode::Replay);
        }
        rec.state = if executed {
            "executed".to_owned()
        } else {
            "failed".to_owned()
        };
        rec.outcome_at = Some(now.to_string());
        rec.failure_reason = reason.map(str::to_owned);
        let bytes = serde_json::to_vec(&rec).map_err(|_| ClaimCode::StoreUnavailable)?;
        let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|_| ClaimCode::StoreUnavailable)?;
        f.write_all(&bytes)
            .map_err(|_| ClaimCode::StoreUnavailable)?;
        f.sync_all().map_err(|_| ClaimCode::StoreUnavailable)?;
        fs::rename(&tmp, &path).map_err(|_| ClaimCode::StoreUnavailable)
    }
    pub fn status(&self, envelope_id: &str, now: u64) -> Result<ClaimStatus, ClaimCode> {
        let path = self.path(envelope_id)?;
        let raw = fs::read(path).map_err(|_| ClaimCode::StoreUnavailable)?;
        let rec: ClaimRecord =
            serde_json::from_slice(&raw).map_err(|_| ClaimCode::StoreUnavailable)?;
        match rec.state.as_str() {
            "executed" => Ok(ClaimStatus::Executed),
            "failed" => Ok(ClaimStatus::Failed),
            "claimed" => {
                let claimed =
                    canonical_u64(&rec.claimed_at).map_err(|_| ClaimCode::StoreUnavailable)?;
                let deadline = claimed.saturating_add(self.execution_timeout);
                if now > deadline {
                    Ok(ClaimStatus::Unknown)
                } else {
                    Ok(ClaimStatus::Claimed)
                }
            }
            _ => Err(ClaimCode::StoreUnavailable),
        }
    }
}

pub const COMPILED_RELEASE_ID: &str = match option_env!("AXIOMATIC_COMPILED_RELEASE_ID") {
    Some(v) => v,
    None => "dev-unqualified",
};

pub const VALIDATED_BASELINE_HASH: &str =
    "0cc36375922e4040f1dd3a321d5b18beb67f5e31fe3630363ca94303dd8d9ae6";

fn sha_text(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn canonical_profile(profile: &Value) -> Result<String, String> {
    let mut m = serde_json::Map::new();
    for k in ["schemaVersion", "name", "origin", "policy"] {
        m.insert(k.to_owned(), profile.get(k).cloned().unwrap_or(Value::Null));
    }
    serde_json::to_string(&Value::Object(m)).map_err(|e| format!("profile serialize: {e}"))
}

pub fn validate_profile(profile: &Value) -> Result<(String, String), String> {
    if profile.get("schemaVersion").and_then(Value::as_str) != Some("1.0") {
        return Err("unsupported schemaVersion".into());
    }
    let origin = profile
        .get("origin")
        .and_then(Value::as_str)
        .ok_or_else(|| "invalid origin".to_owned())?;
    if origin != "zdx-validated" && origin != "customer-modified" {
        return Err("invalid origin".into());
    }
    let policy = profile
        .get("policy")
        .ok_or_else(|| "policy required".to_owned())?;
    for k in [
        "allowedCommands",
        "allowedTools",
        "mutatingTools",
        "nonMutatingCommands",
    ] {
        if !policy.get(k).is_some_and(Value::is_array) {
            return Err(format!("policy.{k} must be an array"));
        }
    }
    let array = |k: &str| -> &[Value] {
        policy
            .get(k)
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    };
    if array("mutatingTools")
        .iter()
        .any(|x| !array("allowedTools").contains(x))
    {
        return Err("mutatingTools must be a subset of allowedTools".into());