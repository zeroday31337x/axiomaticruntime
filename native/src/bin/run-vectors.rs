use axiomatic_runtime_native::{
    KeyRole, TrustedKey, VerifyContext, verify_approval, verify_decision,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    env, fs,
};

#[derive(Deserialize)]
struct Corpus {
    context: Context,
    keys: Keys,
    vectors: Vec<Vector>,
    #[serde(rename = "approvalVectors")]
    approval_vectors: Vec<ApprovalVector>,
}
#[derive(Deserialize)]
struct Context {
    now: u64,
    skew: u64,
    #[serde(rename = "maxValidity")]
    max_validity: u64,
    release: String,
    audience: String,
}
#[derive(Deserialize)]
struct Keys {
    decision: Key,
    approval: Key,
    revoked: Key,
}
#[derive(Deserialize)]
struct Key {
    kid: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}
#[derive(Deserialize)]
struct Vector {
    id: String,
    expected: String,
    body: String,
}
#[derive(Deserialize)]
struct ApprovalVector {
    id: String,
    expected: String,
    #[serde(rename = "decisionBody")]
    decision_body: String,
    #[serde(rename = "approvalBody")]
    approval_body: String,
}
fn decode(k: &Key, role: KeyRole) -> Result<TrustedKey, String> {
    let b = B64.decode(&k.public_key).map_err(|e| e.to_string())?;
    let arr = <[u8; 32]>::try_from(b).map_err(|_| "bad public key length")?;
    Ok(TrustedKey {
        public_key: arr,
        role,
    })
}
fn run() -> Result<(), String> {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "artifacts/envelope-v2-vectors.json".to_owned());
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    let c: Corpus = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let mut keys = HashMap::new();
    keys.insert(
        c.keys.decision.kid.clone(),
        decode(&c.keys.decision, KeyRole::Decision)?,
    );
    keys.insert(
        c.keys.approval.kid.clone(),
        decode(&c.keys.approval, KeyRole::Approval)?,
    );
    keys.insert(
        c.keys.revoked.kid.clone(),
        decode(&c.keys.revoked, KeyRole::Decision)?,
    );
    let mut revoked = HashSet::new();
    revoked.insert(c.keys.revoked.kid.clone());
    let ctx = VerifyContext {
        keys: &keys,
        revoked: &revoked,
        expected_audience: &c.context.audience,
        expected_release: &c.context.release,
        now: c.context.now,
        skew: c.context.skew,
        max_validity: c.context.max_validity,
        max_body: 1_048_576,
    };
    let mut failures = Vec::new();
    for v in &c.vectors {
        let got = match verify_decision(v.body.as_bytes(), &ctx) {
            Ok(_) => "VALID".to_owned(),
            Err(e) => e.as_str().to_owned(),
        };
        if got != v.expected {
            failures.push(format!("{} expected={} got={}", v.id, v.expected, got))
        }
    }
    for v in &c.approval_vectors {
        let got = match verify_decision(v.decision_body.as_bytes(), &ctx) {
            Ok(d) => match verify_approval(v.approval_body.as_bytes(), &d, &ctx) {
                Ok(_) => "VALID".to_owned(),
                Err(e) => e.as_str().to_owned(),
            },
            Err(e) => format!("DECISION:{}", e.as_str()),
        };
        if got != v.expected {
            failures.push(format!("{} expected={} got={}", v.id, v.expected, got))
        }
    }
    println!(
        "vectors={} approval_vectors={} failures={}",
        c.vectors.len(),
        c.approval_vectors.len(),
        failures.len()
    );
    for f in &failures {
        println!("{f}")
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err("vector conformance failure".into())
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}