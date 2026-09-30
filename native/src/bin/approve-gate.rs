use axiomatic_runtime_native::{
    ApprovalSigningFields, COMPILED_RELEASE_ID, DecisionKind, KeyRole, VerifyContext,
    approval_signing_bytes, disable_core_dumps, load_keyring_file, load_signing_key_file,
    verify_decision,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::Signer;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{env, fs};

fn now() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock error".to_owned())
        .map(|d| d.as_secs())
}
fn run() -> Result<(), String> {
    disable_core_dumps()?;
    let decision_path = env::args()
        .nth(1)
        .ok_or("usage: approve-gate <gate-decision.json>")?;
    let keyring = load_keyring_file(
        env::var("AXIOMATIC_TRUSTED_KEYS_FILE")
            .map_err(|_| "AXIOMATIC_TRUSTED_KEYS_FILE required")?,
    )?;
    let audience = env::var("AXIOMATIC_AUDIENCE").map_err(|_| "AXIOMATIC_AUDIENCE required")?;
    let release = COMPILED_RELEASE_ID.to_owned();
    let n = now()?;
    let ctx = VerifyContext {
        keys: &keyring.keys,
        revoked: &keyring.revoked,
        expected_audience: &audience,
        expected_release: &release,
        now: n,
        skew: 5,
        max_validity: 60,
        max_body: 1_048_576,
    };
    let decision = verify_decision(&fs::read(decision_path).map_err(|e| e.to_string())?, &ctx)
        .map_err(|e| format!("gate verification failed: {}", e.as_str()))?;
    if decision.decision != DecisionKind::Gate {
        return Err("approval can only be issued for GATE".into());
    }
    let key = load_signing_key_file(
        env::var("AXIOMATIC_APPROVAL_KEY_FILE")
            .map_err(|_| "AXIOMATIC_APPROVAL_KEY_FILE required")?,
    )?;
    let kid = hex::encode(Sha256::digest(key.verifying_key().to_bytes()));
    let trusted = keyring
        .keys
        .get(&kid)
        .ok_or("approval signing key is not in trusted keyring")?;
    if trusted.role != KeyRole::Approval {
        return Err("approval signing key is not tagged approval".into());
    }
    let approver =
        env::var("AXIOMATIC_APPROVER_ID").map_err(|_| "AXIOMATIC_APPROVER_ID required")?;
    if approver.is_empty() || approver.len() > 128 || !approver.is_ascii() {
        return Err("invalid approver identity".into());
    }
    let ttl = env::var("AXIOMATIC_APPROVAL_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30)
        .clamp(1, 60);
    let wanted = n.saturating_add(ttl);
    let expires = wanted.min(decision.expires_at);
    if expires <= n {
        return Err("decision envelope expires before approval can be issued".into());
    }
    let decision_id =
        uuid::Uuid::parse_str(&decision.envelope_id).map_err(|_| "invalid decision envelope id")?;
    let approval_id = uuid::Uuid::new_v4();
    let fields = ApprovalSigningFields {
        release_id: &release,
        audience: &audience,
        kid: &kid,
        profile_hash: &decision.profile_hash,
        action_hash: &decision.action_hash,
        decision_envelope_id: &decision_id,
        approval_id: &approval_id,
        approver: &approver,
        issued_at: n,
        expires_at: expires,
    };
    let sig = key.sign(&approval_signing_bytes(&fields).map_err(|e| e.as_str().to_owned())?);
    println!(
        "{}",
        json!({"approvalArtifact":{
            "type":"approval","version":"1","algorithm":"Ed25519","decision":"APPROVE",
            "kid":kid,"releaseId":release,"audience":audience,"profileHash":decision.profile_hash,
            "canonicalActionHash":decision.action_hash,"decisionEnvelopeId":decision.envelope_id,
            "approvalId":approval_id.hyphenated().to_string(),"approver":approver,
            "issuedAt":n.to_string(),"expiresAt":expires.to_string(),"signature":B64.encode(sig.to_bytes())
        }})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}