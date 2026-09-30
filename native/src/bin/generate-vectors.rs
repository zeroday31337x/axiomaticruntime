#![allow(clippy::too_many_arguments, clippy::vec_init_then_push)]
use axiomatic_runtime_native::{
    ApprovalSigningFields, DecisionKind, DecisionSigningFields, approval_signing_bytes,
    canonical_action_hash, decision_signing_bytes,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use uuid::Uuid;

const NOW: u64 = 1_700_000_000;
const RELEASE: &str = "zdx-axiomatic-1.0.0-test";
const AUDIENCE: &str = "zdx-executor";
const NONCE: &str = "abcdefghijklmnop";
const EID: &str = "123e4567-e89b-12d3-a456-426614174000";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn kid(k: &SigningKey) -> String {
    hex::encode(Sha256::digest(k.verifying_key().to_bytes()))
}
fn action() -> Value {
    json!({"kind":"tool","tool":"safe_tool","args":{"x":1}})
}
fn sign_body(
    k: &SigningKey,
    decision: DecisionKind,
    release: &str,
    audience: &str,
    profile_hash: &str,
    action_hash: &str,
    nonce: &str,
    eid: &Uuid,
    issued: u64,
    expires: u64,
) -> Result<Value, String> {
    let k_id = kid(k);
    let fields = DecisionSigningFields {
        decision,
        release_id: release,
        audience,
        kid: &k_id,
        profile_hash,
        action_hash,
        nonce,
        envelope_id: eid,
        issued_at: issued,
        expires_at: expires,
    };
    let sig = k.sign(&decision_signing_bytes(&fields).map_err(|e| e.to_string())?);
    Ok(json!({"decisionEnvelope":{
        "type":"decision","version":"2","algorithm":"Ed25519","decision":decision.as_str(),
        "kid":k_id,"releaseId":release,"audience":audience,"profileHash":profile_hash,
        "canonicalActionHash":action_hash,"nonce":nonce,"envelopeId":eid.hyphenated().to_string(),
        "issuedAt":issued.to_string(),"expiresAt":expires.to_string(),"signature":B64.encode(sig.to_bytes())
    },"canonicalAction":action()}))
}
fn put(out: &mut Vec<u8>, b: &[u8]) -> Result<(), String> {
    let n = u32::try_from(b.len()).map_err(|_| "field too long")?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}
fn wrong_domain_bytes(f: &DecisionSigningFields<'_>) -> Result<Vec<u8>, String> {
    let mut o = Vec::new();
    for v in [
        b"zdx-decision-v2-wrong".as_slice(),
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
        put(&mut o, v)?
    }
    o.extend_from_slice(&f.issued_at.to_be_bytes());
    o.extend_from_slice(&f.expires_at.to_be_bytes());
    Ok(o)
}
fn sign_approval(
    k: &SigningKey,
    release: &str,
    audience: &str,
    profile_hash: &str,
    action_hash: &str,
    decision_eid: &Uuid,
    approval_id: &Uuid,
    approver: &str,
    issued: u64,
    expires: u64,
) -> Result<Value, String> {
    let k_id = kid(k);
    let fields = ApprovalSigningFields {
        release_id: release,
        audience,
        kid: &k_id,
        profile_hash,
        action_hash,
        decision_envelope_id: decision_eid,
        approval_id,
        approver,
        issued_at: issued,
        expires_at: expires,
    };
    let sig = k.sign(&approval_signing_bytes(&fields).map_err(|e| e.to_string())?);
    Ok(json!({"approvalArtifact":{
        "type":"approval","version":"1","algorithm":"Ed25519","decision":"APPROVE","kid":k_id,
        "releaseId":release,"audience":audience,"profileHash":profile_hash,"canonicalActionHash":action_hash,
        "decisionEnvelopeId":decision_eid.hyphenated().to_string(),"approvalId":approval_id.hyphenated().to_string(),
        "approver":approver,"issuedAt":issued.to_string(),"expiresAt":expires.to_string(),
        "signature":B64.encode(sig.to_bytes())
    }}))
}
fn approval_vector(
    id: &str,
    expected: &str,
    decision_body: String,
    approval_body: String,
) -> Value {
    json!({"id":id,"kind":"approval","expected":expected,"decisionBody":decision_body,"approvalBody":approval_body})
}

fn vector(id: &str, expected: &str, body: String) -> Value {
    json!({"id":id,"kind":"decision","expected":expected,"body":body})
}
fn set(v: &Value, path: &str, value: Value) -> Value {
    let mut x = v.clone();
    if let Some(e) = x.get_mut("decisionEnvelope").and_then(Value::as_object_mut) {
        e.insert(path.to_owned(), value);
    }
    x
}
fn remove(v: &Value, path: &str) -> Value {
    let mut x = v.clone();
    if let Some(e) = x.get_mut("decisionEnvelope").and_then(Value::as_object_mut) {
        e.remove(path);
    }
    x
}
fn main() -> Result<(), String> {
    let decision_key = key(1);
    let approval_key = key(2);
    let unknown_key = key(3);
    let revoked_key = key(4);
    let profile = "a".repeat(64);
    let ah = canonical_action_hash(&action()).map_err(|e| e.to_string())?;
    let eid = Uuid::parse_str(EID).map_err(|e| e.to_string())?;
    let base = sign_body(
        &decision_key,
        DecisionKind::Retain,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        NONCE,
        &eid,
        NOW - 5,
        NOW + 30,
    )?;
    let mut vs = Vec::new();
    vs.push(vector("valid-retain", "VALID", base.to_string()));
    vs.push(vector(
        "v1-hmac",
        "E006_VERSION",
        set(
            &set(&base, "version", json!("1")),
            "algorithm",
            json!("HMAC-SHA256"),
        )
        .to_string(),
    ));
    vs.push(vector(
        "unknown-version",
        "E006_VERSION",
        set(&base, "version", json!("9")).to_string(),
    ));
    vs.push(vector(
        "wrong-type",
        "E007_TYPE",
        set(&base, "type", json!("approval")).to_string(),
    ));
    vs.push(vector(
        "wrong-decision",
        "E008_DECISION",
        set(&base, "decision", json!("ALLOW")).to_string(),
    ));
    vs.push(vector(
        "wrong-algorithm",
        "E009_ALGORITHM",
        set(&base, "algorithm", json!("Ed448")).to_string(),
    ));
    let mut unknown = base.clone();
    unknown
        .as_object_mut()
        .ok_or("root")?
        .insert("extra".into(), json!(1));
    vs.push(vector(
        "unknown-root-field",
        "E003_UNKNOWN_FIELD",
        unknown.to_string(),
    ));
    vs.push(vector(
        "removed-notBefore-enforced",
        "E003_UNKNOWN_FIELD",
        {
            let mut x = base.clone();
            x.get_mut("decisionEnvelope")
                .and_then(Value::as_object_mut)
                .ok_or("env")?
                .insert("notBefore".into(), json!("1699999995"));
            x.to_string()
        },
    ));
    vs.push(vector(
        "missing-signature",
        "E004_MISSING_FIELD",
        remove(&base, "signature").to_string(),
    ));
    let dup = base.to_string().replacen(
        "\"type\":\"decision\"",
        "\"type\":\"decision\",\"type\":\"decision\"",
        1,
    );
    vs.push(vector("duplicate-type-key", "E002_DUPLICATE_KEY", dup));
    let dup_action = base.to_string().replacen(r#""x":1"#, r#""x":1,"x":2"#, 1);
    vs.push(vector(
        "duplicate-canonical-action-key",
        "E002_DUPLICATE_KEY",
        dup_action,
    ));
    let oversized = format!("{{\"pad\":\"{}\"}}", "A".repeat(1_048_700));
    vs.push(vector("oversized-body", "E005_BODY_TOO_LARGE", oversized));
    vs.push(vector(
        "uppercase-kid",
        "E010_NONCANONICAL_HEX",
        set(&base, "kid", json!(kid(&decision_key).to_uppercase())).to_string(),
    ));
    vs.push(vector(
        "uppercase-uuid",
        "E011_NONCANONICAL_UUID",
        set(&base, "envelopeId", json!(EID.to_uppercase())).to_string(),
    ));
    vs.push(vector(
        "nonhyphenated-uuid",
        "E011_NONCANONICAL_UUID",
        set(&base, "envelopeId", json!(EID.replace("-", ""))).to_string(),
    ));
    vs.push(vector(
        "nonce-short",
        "E013_NONCE",
        set(&base, "nonce", json!("short")).to_string(),
    ));
    vs.push(vector(
        "nonce-long",
        "E013_NONCE",
        set(&base, "nonce", json!("x".repeat(129))).to_string(),
    ));
    vs.push(vector(
        "nonce-nonascii",
        "E013_NONCE",
        set(&base, "nonce", json!("abcdefghijklmnøp")).to_string(),
    ));
    vs.push(vector(
        "timestamp-float",
        "E012_NONCANONICAL_NUMBER",
        set(&base, "issuedAt", json!(1.0)).to_string(),
    ));
    vs.push(vector(
        "timestamp-exponent",
        "E012_NONCANONICAL_NUMBER",
        base.to_string()
            .replacen("\"issuedAt\":\"1699999995\"", "\"issuedAt\":1e3", 1),
    ));
    vs.push(vector(
        "timestamp-negative-zero",
        "E012_NONCANONICAL_NUMBER",
        base.to_string()
            .replacen("\"issuedAt\":\"1699999995\"", "\"issuedAt\":-0", 1),
    ));
    vs.push(vector(
        "timestamp-plus-one",
        "E001_PARSE",
        base.to_string()
            .replacen("\"issuedAt\":\"1699999995\"", "\"issuedAt\":+1", 1),
    ));
    vs.push(vector(
        "timestamp-leading-zero",
        "E012_NONCANONICAL_NUMBER",
        set(&base, "issuedAt", json!("01699999995")).to_string(),
    ));
    vs.push(vector(
        "timestamp-above-2pow53",
        "E023_TIMESTAMP_RANGE",
        set(&base, "issuedAt", json!("9007199254740992")).to_string(),
    ));
    let unk = sign_body(
        &unknown_key,
        DecisionKind::Retain,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        NONCE,
        &eid,
        NOW - 5,
        NOW + 30,
    )?;
    vs.push(vector("unknown-kid", "E014_UNKNOWN_KID", unk.to_string()));
    let rev = sign_body(
        &revoked_key,
        DecisionKind::Retain,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        NONCE,
        &eid,
        NOW - 5,
        NOW + 30,
    )?;
    vs.push(vector("revoked-kid", "E015_REVOKED_KID", rev.to_string()));
    let role = sign_body(
        &approval_key,
        DecisionKind::Retain,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        NONCE,
        &eid,
        NOW - 5,
        NOW + 30,
    )?;
    vs.push(vector(
        "approval-role-key-for-decision",
        "E017_KEY_ROLE",
        role.to_string(),
    ));
    vs.push(vector(
        "mutate-release",
        "E030_RELEASE",
        set(&base, "releaseId", json!("other-release")).to_string(),
    ));
    vs.push(vector(
        "mutate-kid",
        "E014_UNKNOWN_KID",
        set(&base, "kid", json!("b".repeat(64))).to_string(),
    ));
    vs.push(vector(
        "mutate-profile-hash",
        "E018_SIGNATURE",
        set(&base, "profileHash", json!("b".repeat(64))).to_string(),
    ));
    vs.push(vector(
        "mutate-action-hash",
        "E018_SIGNATURE",
        set(&base, "canonicalActionHash", json!("b".repeat(64))).to_string(),
    ));
    vs.push(vector(
        "mutate-nonce",
        "E018_SIGNATURE",
        set(&base, "nonce", json!("abcdefghijklmnopq")).to_string(),
    ));
    vs.push(vector(
        "mutate-envelope-id",
        "E018_SIGNATURE",
        set(
            &base,
            "envelopeId",
            json!("123e4567-e89b-12d3-a456-426614174001"),
        )
        .to_string(),
    ));
    vs.push(vector(
        "mutate-issuedAt",
        "E018_SIGNATURE",
        set(&base, "issuedAt", json!((NOW - 4).to_string())).to_string(),
    ));
    vs.push(vector(
        "mutate-expiresAt",
        "E018_SIGNATURE",
        set(&base, "expiresAt", json!((NOW + 29).to_string())).to_string(),
    ));
    vs.push(vector(
        "mutate-audience",
        "E024_AUDIENCE",
        set(&base, "audience", json!("other-audience")).to_string(),
    ));
    let mut wrong_key = base.clone();
    let fields = DecisionSigningFields {
        decision: DecisionKind::Retain,
        release_id: RELEASE,
        audience: AUDIENCE,
        kid: &kid(&decision_key),
        profile_hash: &profile,
        action_hash: &ah,
        nonce: NONCE,
        envelope_id: &eid,
        issued_at: NOW - 5,
        expires_at: NOW + 30,
    };
    let badsig = unknown_key.sign(&decision_signing_bytes(&fields).map_err(|e| e.to_string())?);
    wrong_key
        .get_mut("decisionEnvelope")
        .and_then(Value::as_object_mut)
        .ok_or("env")?
        .insert("signature".into(), json!(B64.encode(badsig.to_bytes())));
    vs.push(vector(
        "wrong-signing-key",
        "E018_SIGNATURE",
        wrong_key.to_string(),
    ));
    let mut wrong_domain = base.clone();
    let dsig = decision_key.sign(&wrong_domain_bytes(&fields)?);
    wrong_domain
        .get_mut("decisionEnvelope")
        .and_then(Value::as_object_mut)
        .ok_or("env")?
        .insert("signature".into(), json!(B64.encode(dsig.to_bytes())));
    vs.push(vector(
        "wrong-domain",
        "E018_SIGNATURE",
        wrong_domain.to_string(),
    ));
    let sig = base
        .pointer("/decisionEnvelope/signature")
        .and_then(Value::as_str)
        .ok_or("sig")?;
    let mut sb = B64.decode(sig).map_err(|e| e.to_string())?;
    sb.truncate(63);
    vs.push(vector(
        "truncated-signature",
        "E018_SIGNATURE",
        set(&base, "signature", json!(B64.encode(&sb))).to_string(),
    ));
    let mut sx = B64.decode(sig).map_err(|e| e.to_string())?;
    sx.push(0);
    vs.push(vector(
        "extended-signature",
        "E018_SIGNATURE",
        set(&base, "signature", json!(B64.encode(&sx))).to_string(),
    ));
    let future = sign_body(
        &decision_key,
        DecisionKind::Retain,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        NONCE,
        &eid,
        NOW + 6,
        NOW + 30,
    )?;
    vs.push(vector(
        "issued-beyond-skew",
        "E019_ISSUED_FUTURE",
        future.to_string(),
    ));
    let expired = sign_body(
        &decision_key,
        DecisionKind::Retain,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        NONCE,
        &eid,
        NOW - 60,
        NOW,
    )?;
    vs.push(vector("expired", "E020_EXPIRED", expired.to_string()));
    let equal = sign_body(
        &decision_key,
        DecisionKind::Retain,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        NONCE,
        &eid,
        NOW,
        NOW,
    )?;
    vs.push(vector(
        "expires-equals-issued",
        "E021_TIME_ORDER",
        equal.to_string(),
    ));
    let reversed = sign_body(
        &decision_key,
        DecisionKind::Retain,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        NONCE,
        &eid,
        NOW,
        NOW - 1,
    )?;
    vs.push(vector(
        "expires-before-issued",
        "E021_TIME_ORDER",
        reversed.to_string(),
    ));
    let long = sign_body(
        &decision_key,
        DecisionKind::Retain,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        NONCE,
        &eid,
        NOW,
        NOW + 61,
    )?;
    vs.push(vector(
        "validity-over-max",
        "E022_VALIDITY_TOO_LONG",
        long.to_string(),
    ));
    let wrong_aud = sign_body(
        &decision_key,
        DecisionKind::Retain,
        RELEASE,
        "other-audience",
        &profile,
        &ah,
        NONCE,
        &eid,
        NOW - 5,
        NOW + 30,
    )?;
    vs.push(vector(
        "audience-mismatch",
        "E024_AUDIENCE",
        wrong_aud.to_string(),
    ));
    let mut changed_action = base.clone();
    changed_action["canonicalAction"]["args"]["x"] = json!(2);
    vs.push(vector(
        "action-byte-diff",
        "E025_ACTION_HASH",
        changed_action.to_string(),
    ));

    let gate_eid =
        Uuid::parse_str("123e4567-e89b-12d3-a456-426614174100").map_err(|e| e.to_string())?;
    let gate = sign_body(
        &decision_key,
        DecisionKind::Gate,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        NONCE,
        &gate_eid,
        NOW - 5,
        NOW + 30,
    )?;
    let approval_id =
        Uuid::parse_str("123e4567-e89b-12d3-a456-426614174101").map_err(|e| e.to_string())?;
    let valid_approval = sign_approval(
        &approval_key,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        &gate_eid,
        &approval_id,
        "operator-1",
        NOW,
        NOW + 20,
    )?;
    let mut avs = Vec::new();
    avs.push(approval_vector(
        "valid-gate-approval",
        "VALID",
        gate.to_string(),
        valid_approval.to_string(),
    ));
    let wrong_role = sign_approval(
        &decision_key,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        &gate_eid,
        &approval_id,
        "operator-1",
        NOW,
        NOW + 20,
    )?;
    avs.push(approval_vector(
        "decision-role-key-for-approval",
        "E017_KEY_ROLE",
        gate.to_string(),
        wrong_role.to_string(),
    ));
    let unknown_ap = sign_approval(
        &unknown_key,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        &gate_eid,
        &approval_id,
        "operator-1",
        NOW,
        NOW + 20,
    )?;
    avs.push(approval_vector(
        "unknown-approval-kid",
        "E014_UNKNOWN_KID",
        gate.to_string(),
        unknown_ap.to_string(),
    ));
    let revoked_ap = sign_approval(
        &revoked_key,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        &gate_eid,
        &approval_id,
        "operator-1",
        NOW,
        NOW + 20,
    )?;
    avs.push(approval_vector(
        "revoked-approval-kid",
        "E015_REVOKED_KID",
        gate.to_string(),
        revoked_ap.to_string(),
    ));
    let mut x = valid_approval.clone();
    x["approvalArtifact"]["decisionEnvelopeId"] = json!("123e4567-e89b-12d3-a456-426614174102");
    avs.push(approval_vector(
        "approval-wrong-envelope-binding",
        "E032_APPROVAL_BINDING",
        gate.to_string(),
        x.to_string(),
    ));
    let mut x = valid_approval.clone();
    x["approvalArtifact"]["profileHash"] = json!("b".repeat(64));
    avs.push(approval_vector(
        "approval-wrong-profile-binding",
        "E032_APPROVAL_BINDING",
        gate.to_string(),
        x.to_string(),
    ));
    let mut x = valid_approval.clone();
    x["approvalArtifact"]["canonicalActionHash"] = json!("b".repeat(64));
    avs.push(approval_vector(
        "approval-wrong-action-binding",
        "E032_APPROVAL_BINDING",
        gate.to_string(),
        x.to_string(),
    ));
    let mut x = valid_approval.clone();
    x["approvalArtifact"]["releaseId"] = json!("other-release");
    avs.push(approval_vector(
        "approval-release-mismatch",
        "E030_RELEASE",
        gate.to_string(),
        x.to_string(),
    ));
    let mut x = valid_approval.clone();
    x["approvalArtifact"]["audience"] = json!("other-audience");
    avs.push(approval_vector(
        "approval-audience-mismatch",
        "E024_AUDIENCE",
        gate.to_string(),
        x.to_string(),
    ));
    let mut x = valid_approval.clone();
    x["approvalArtifact"]["approver"] = json!("");
    avs.push(approval_vector(
        "approval-empty-approver",
        "E031_APPROVER",
        gate.to_string(),
        x.to_string(),
    ));
    let mut x = valid_approval.clone();
    x["approvalArtifact"]["approver"] = json!("opérator");
    avs.push(approval_vector(
        "approval-nonascii-approver",
        "E031_APPROVER",
        gate.to_string(),
        x.to_string(),
    ));
    let expired_ap = sign_approval(
        &approval_key,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        &gate_eid,
        &approval_id,
        "operator-1",
        NOW - 30,
        NOW,
    )?;
    avs.push(approval_vector(
        "approval-expired",
        "E020_EXPIRED",
        gate.to_string(),
        expired_ap.to_string(),
    ));
    let future_ap = sign_approval(
        &approval_key,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        &gate_eid,
        &approval_id,
        "operator-1",
        NOW + 6,
        NOW + 20,
    )?;
    avs.push(approval_vector(
        "approval-issued-beyond-skew",
        "E019_ISSUED_FUTURE",
        gate.to_string(),
        future_ap.to_string(),
    ));
    let long_ap = sign_approval(
        &approval_key,
        RELEASE,
        AUDIENCE,
        &profile,
        &ah,
        &gate_eid,
        &approval_id,
        "operator-1",
        NOW - 31,
        NOW + 30,
    )?;
    avs.push(approval_vector(
        "approval-validity-over-max",
        "E022_VALIDITY_TOO_LONG",
        gate.to_string(),
        long_ap.to_string(),
    ));
    let mut x = valid_approval.clone();
    x.get_mut("approvalArtifact")
        .and_then(Value::as_object_mut)
        .ok_or("approval")?
        .insert("extra".into(), json!(1));
    avs.push(approval_vector(
        "approval-unknown-field",
        "E003_UNKNOWN_FIELD",
        gate.to_string(),
        x.to_string(),
    ));
    let dup_ap = valid_approval.to_string().replacen(
        r#""type":"approval""#,
        r#""type":"approval","type":"approval""#,
        1,
    );
    avs.push(approval_vector(
        "approval-duplicate-key",
        "E002_DUPLICATE_KEY",
        gate.to_string(),
        dup_ap,
    ));
    let asig = valid_approval
        .pointer("/approvalArtifact/signature")
        .and_then(Value::as_str)
        .ok_or("approval sig")?;
    let mut trunc = B64.decode(asig).map_err(|e| e.to_string())?;
    trunc.truncate(63);
    let mut x = valid_approval.clone();
    x["approvalArtifact"]["signature"] = json!(B64.encode(trunc));
    avs.push(approval_vector(
        "approval-truncated-signature",
        "E018_SIGNATURE",
        gate.to_string(),
        x.to_string(),
    ));

    let out = json!({
        "schemaVersion":"1",
        "context":{"now":NOW,"skew":5,"maxValidity":60,"release":RELEASE,"audience":AUDIENCE},
        "keys":{
            "decision":{"kid":kid(&decision_key),"publicKey":B64.encode(decision_key.verifying_key().to_bytes())},
            "approval":{"kid":kid(&approval_key),"publicKey":B64.encode(approval_key.verifying_key().to_bytes())},
            "revoked":{"kid":kid(&revoked_key),"publicKey":B64.encode(revoked_key.verifying_key().to_bytes())}
        },
        "vectors":vs,
        "approvalVectors":avs
    });
    let path = PathBuf::from("artifacts/envelope-v2-vectors.json");
    fs::create_dir_all(path.parent().ok_or("artifact parent")?).map_err(|e| e.to_string())?;
    fs::write(
        &path,
        serde_json::to_vec_pretty(&out).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!("{}", path.display());
    Ok(())
}