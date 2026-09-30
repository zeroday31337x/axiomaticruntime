use axiomatic_runtime_native::{
    KeyRole, TrustedKey, VerifyContext, evaluate_policy, verify_approval, verify_decision,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    env,
    fs::File,
    io::{BufRead, BufReader},
};

#[derive(Deserialize)]
struct HeaderLine {
    kind: String,
    context: Context,
    keys: HashMap<String, KeyEntry>,
    #[serde(rename = "revokedKids")]
    revoked_kids: Vec<String>,
    #[serde(rename = "declaredCounts")]
    declared_counts: HashMap<String, usize>,
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
struct KeyEntry {
    kid: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    role: String,
}

fn trusted(k: &KeyEntry) -> Result<TrustedKey, String> {
    let bytes = B64
        .decode(k.public_key.as_bytes())
        .map_err(|e| e.to_string())?;
    let public_key = <[u8; 32]>::try_from(bytes).map_err(|_| "public key length")?;
    let role = match k.role.as_str() {
        "decision" => KeyRole::Decision,
        "approval" => KeyRole::Approval,
        _ => return Err("invalid role".into()),
    };
    Ok(TrustedKey { public_key, role })
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}

fn run() -> Result<(), String> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: run-fresh-qualification <corpus.ndjson>")?;
    let f = File::open(path).map_err(|e| e.to_string())?;
    let mut lines = BufReader::new(f).lines();
    let first = lines
        .next()
        .ok_or("empty corpus")?
        .map_err(|e| e.to_string())?;
    let header: HeaderLine = serde_json::from_str(&first).map_err(|e| e.to_string())?;
    if header.kind != "header" {
        return Err("first line is not header".into());
    }
    let mut keys = HashMap::new();
    for e in header.keys.values() {
        keys.insert(e.kid.clone(), trusted(e)?);
    }
    let revoked: HashSet<String> = header.revoked_kids.into_iter().collect();
    let ctx = VerifyContext {
        keys: &keys,
        revoked: &revoked,
        expected_audience: &header.context.audience,
        expected_release: &header.context.release,
        now: header.context.now,
        skew: header.context.skew,
        max_validity: header.context.max_validity,
        max_body: 1_048_576,
    };
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut failures = Vec::new();
    let mut total = 0usize;
    for (idx, line) in lines.enumerate() {
        let raw = line.map_err(|e| e.to_string())?;
        let v: Value =
            serde_json::from_str(&raw).map_err(|e| format!("outer JSON line {}: {e}", idx + 2))?;
        let kind = v.get("kind").and_then(Value::as_str).ok_or("case kind")?;
        let family = v
            .get("family")
            .and_then(Value::as_str)
            .ok_or("case family")?;
        let expected = v
            .get("expected")
            .and_then(Value::as_str)
            .ok_or("case expected")?;
        let key = format!("{kind}:{family}");
        *counts.entry(key.clone()).or_insert(0) += 1;
        total = total.saturating_add(1);
        let got = match kind {
            "eval" => {
                let input = v.get("input").ok_or("eval input")?;
                let out = evaluate_policy(input);
                let d = out
                    .get("decision")
                    .and_then(Value::as_str)
                    .unwrap_or("MISSING");
                let action_ok = match d {
                    "RETAIN" | "GATE" => out.get("canonicalAction").is_some(),
                    "PRUNE" => out.get("canonicalAction").is_none(),
                    _ => false,
                };
                if !action_ok {
                    failures.push(format!(
                        "line {} {key}: canonicalAction invariant failed",
                        idx + 2
                    ));
                }
                d.to_owned()
            }
            "decision" => {
                let body = v
                    .get("body")
                    .and_then(Value::as_str)
                    .ok_or("decision body")?;
                match verify_decision(body.as_bytes(), &ctx) {
                    Ok(_) => "VALID".to_owned(),
                    Err(e) => e.as_str().to_owned(),
                }
            }
            "approval" => {
                let db = v
                    .get("decisionBody")
                    .and_then(Value::as_str)
                    .ok_or("decisionBody")?;
                let ab = v
                    .get("approvalBody")
                    .and_then(Value::as_str)
                    .ok_or("approvalBody")?;
                match verify_decision(db.as_bytes(), &ctx) {
                    Ok(d) => match verify_approval(ab.as_bytes(), &d, &ctx) {
                        Ok(_) => "VALID".to_owned(),
                        Err(e) => e.as_str().to_owned(),
                    },
                    Err(e) => format!("DECISION:{}", e.as_str()),
                }
            }
            _ => return Err(format!("unknown kind {kind}")),
        };
        if got != expected {
            failures.push(format!(
                "line {} {key}: expected={expected} got={got}",
                idx + 2
            ));
        }
        if failures.len() >= 100 {
            break;
        }
    }
    for (kind, expected_total) in &header.declared_counts {
        let actual: usize = counts
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{kind}:")))
            .map(|(_, v)| *v)
            .sum();
        if actual != *expected_total {
            failures.push(format!(
                "declared count {kind}: expected {expected_total}, got {actual}"
            ));
        }
    }
    for (family, count) in &counts {
        if *count < 100 {
            failures.push(format!("family {family} has only {count} cases"));
        }
    }
    println!(
        "cases={} families={} failures={}",
        total,
        counts.len(),
        failures.len()
    );
    for f in failures.iter().take(100) {
        println!("{f}");
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err("fresh qualification failed".into())
    }
}