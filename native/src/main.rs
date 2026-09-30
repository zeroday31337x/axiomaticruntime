mod license;
use axiomatic_runtime_native::{
    COMPILED_RELEASE_ID, DecisionKind, DecisionSigningFields, canonical_action_hash,
    decision_signing_bytes, disable_core_dumps, evaluate_policy, load_signing_key_file,
    validate_profile,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::{
    env, fs,
    io::{self, BufRead, Read},
    net::TcpListener,
};
use subtle::ConstantTimeEq;
use tiny_http::{Header, Method, Response, Server, StatusCode};
struct SignDecisionConfig<'a> {
    profile_hash: &'a str,
    key: &'a SigningKey,
    nonce: &'a str,
    now: u64,
    ttl: u64,
    release: &'a str,
    audience: &'a str,
}

fn sign_decision(mut v: Value, cfg: &SignDecisionConfig<'_>) -> Result<Value, String> {
    let decision = match v.get("decision").and_then(Value::as_str) {
        Some("RETAIN") => DecisionKind::Retain,
        Some("GATE") => DecisionKind::Gate,
        _ => return Ok(v),
    };
    let action = v
        .get("canonicalAction")
        .cloned()
        .ok_or("signed decision missing canonicalAction")?;
    let action_hash = canonical_action_hash(&action).map_err(|e| e.as_str().to_owned())?;
    let exp = cfg.now.saturating_add(cfg.ttl);
    let envelope_id = uuid::Uuid::new_v4();
    let kid = hex::encode(Sha256::digest(cfg.key.verifying_key().to_bytes()));
    let payload = decision_signing_bytes(&DecisionSigningFields {
        decision,
        release_id: cfg.release,
        audience: cfg.audience,
        kid: &kid,
        profile_hash: cfg.profile_hash,
        action_hash: &action_hash,
        nonce: cfg.nonce,
        envelope_id: &envelope_id,
        issued_at: cfg.now,
        expires_at: exp,
    })
    .map_err(|e| e.as_str().to_owned())?;
    let sig = cfg.key.sign(&payload);
    let env = json!({
        "type":"decision","version":"2","algorithm":"Ed25519","decision":decision.as_str(),
        "kid":kid,"releaseId":cfg.release,"audience":cfg.audience,"profileHash":cfg.profile_hash,
        "canonicalActionHash":action_hash,"nonce":cfg.nonce,"envelopeId":envelope_id.hyphenated().to_string(),
        "issuedAt":cfg.now.to_string(),"expiresAt":exp.to_string(),"signature":B64.encode(sig.to_bytes())
    });
    v.as_object_mut()
        .ok_or("decision response is not an object")?
        .insert("decisionEnvelope".into(), env);
    Ok(v)
}
fn evaluate_http(input: &Value, profile: &Value) -> Value {
    let v = json!({"proposal":input.get("proposal").cloned().unwrap_or(Value::Null),"explicitAction":false,"profile":profile});
    evaluate_policy(&v)
}
fn auth(got: Option<&str>, token: &str) -> bool {
    let Some(v) = got.and_then(|x| x.strip_prefix("Bearer ")) else {
        return false;
    };
    v.len() == token.len() && bool::from(v.as_bytes().ct_eq(token.as_bytes()))
}
fn serve() {
    if let Err(e) = disable_core_dumps() {
        eprintln!("startup security failed: {e}");
        std::process::exit(1)
    }
    let signing_key = env::var("AXIOMATIC_ED25519_KEY_FILE")
        .map_err(|_| "AXIOMATIC_ED25519_KEY_FILE is required".to_owned())
        .and_then(load_signing_key_file)
        .unwrap_or_else(|e| {
            eprintln!("startup signing-key validation failed: {e}");
            std::process::exit(1)
        });
    let release = COMPILED_RELEASE_ID.to_owned();
    let audience = env::var("AXIOMATIC_AUDIENCE").unwrap_or_else(|_| {
        eprintln!("AXIOMATIC_AUDIENCE is required");
        std::process::exit(1)
    });
    let decision_ttl = env::var("AXIOMATIC_DECISION_TTL_SECONDS")
        .ok()
        .and_then(|x| x.parse::<u64>().ok())
        .unwrap_or(30)
        .clamp(1, 60);
    let license_lease = license::checkout().unwrap_or_else(|e| {
        eprintln!("license validation failed: {e}");
        std::process::exit(1)
    });
    #[cfg(feature = "marketplace")]
    {
        if let Err(e) = license_lease.start_heartbeat() {
            eprintln!("license validation failed: {e}");
            std::process::exit(1)
        }
        if let Err(e) = license_lease.install_shutdown_handler() {
            eprintln!("license validation failed: {e}");
            std::process::exit(1)
        }
    }
    #[cfg(not(feature = "marketplace"))]
    let _license_lease = license_lease;
    let token = env::var("AXIOMATIC_RUNTIME_TOKEN").unwrap_or_else(|_| {
        eprintln!("AXIOMATIC_RUNTIME_TOKEN must be set to at least 32 bytes");
        std::process::exit(1)
    });
    if token.len() < 32 {
        eprintln!("AXIOMATIC_RUNTIME_TOKEN must be set to at least 32 bytes");
        std::process::exit(1)
    }
    let path = env::var("AXIOMATIC_PROFILE").unwrap_or("./profiles/zdx-validated-v1.json".into());
    let profile: Value = serde_json::from_str(&fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("profile validation failed: {e}");
        std::process::exit(1)
    }))
    .unwrap_or_else(|e| {
        eprintln!("profile validation failed: {e}");
        std::process::exit(1)
    });
    let (class, h) = validate_profile(&profile).unwrap_or_else(|e| {
        eprintln!("profile validation failed: {e}");
        std::process::exit(1)
    });
    eprintln!("profile {class} {h}");
    let port = env::var("PORT").unwrap_or("8080".into());
    let server =
        Server::from_listener(TcpListener::bind(format!("0.0.0.0:{port}")).unwrap(), None).unwrap();
    let replay_on = env::var("AXIOMATIC_REPLAY_PROTECTION")
        .map(|x| x != "off")
        .unwrap_or(true);
    let replay_cap = env::var("AXIOMATIC_REPLAY_CACHE_SIZE")
        .ok()
        .and_then(|x| x.parse::<usize>().ok())
        .unwrap_or(100000)
        .clamp(1000, 1000000);
    let mut seen: HashMap<String, u64> = HashMap::new();
    let mut order: VecDeque<(String, u64)> = VecDeque::new();
    for mut rq in server.incoming_requests() {
        let hdr = Header::from_bytes("content-type", "application/json").unwrap();
        if rq.method() == &Method::Get && rq.url() == "/health" {
            let _ = rq.respond(
                Response::from_string(json!({"ok":true,"version":"1.0.0"}).to_string())
                    .with_header(hdr),
            );
            continue;
        }
        if rq.method() != &Method::Post || rq.url() != "/v1/evaluate" {
            let _ = rq.respond(
                Response::from_string(json!({"error":"not_found"}).to_string())
                    .with_status_code(StatusCode(404))
                    .with_header(hdr),
            );
            continue;
        }
        let a = rq
            .headers()
            .iter()
            .find(|x| x.field.equiv("Authorization"))
            .map(|x| x.value.as_str());
        if !auth(a, &token) {
            let _ = rq.respond(
                Response::from_string(json!({"error":"unauthorized"}).to_string())
                    .with_status_code(StatusCode(401))
                    .with_header(hdr),
            );
            continue;
        }
        if rq.body_length().map(|n| n > 1048576).unwrap_or(false) {
            let _ = rq.respond(
                Response::from_string(json!({"error":"body_too_large"}).to_string())
                    .with_status_code(StatusCode(413))
                    .with_header(hdr),
            );
            continue;
        }
        let mut body = String::new();
        if rq
            .as_reader()
            .take(1048577)
            .read_to_string(&mut body)
            .is_err()
            || body.len() > 1048576
        {
            let _ = rq.respond(
                Response::from_string(json!({"error":"body_too_large"}).to_string())
                    .with_status_code(StatusCode(413))
                    .with_header(hdr),
            );
            continue;
        }
        let input: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => {
                let _ = rq.respond(
                    Response::from_string(json!({"error":"invalid_json"}).to_string())
                        .with_status_code(StatusCode(400))
                        .with_header(hdr),
                );
                continue;
            }
        };
        let nonce = match input.get("nonce").and_then(Value::as_str) {
            Some(n) if n.is_ascii() && n.len() >= 16 && n.len() <= 128 => n,
            _ => {
                let _ = rq.respond(
                    Response::from_string(json!({"error":"nonce_required"}).to_string())
                        .with_status_code(StatusCode(400))
                        .with_header(hdr),
                );
                continue;
            }
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if replay_on {
            while let Some((n, e)) = order.front().cloned() {
                if e >= now && seen.len() < replay_cap {
                    break;
                }
                order.pop_front();
                if seen.get(&n) == Some(&e) {
                    seen.remove(&n);
                }
            }
            if seen.contains_key(nonce) {
                let _ = rq.respond(
                    Response::from_string(json!({"error":"replay_detected"}).to_string())
                        .with_status_code(StatusCode(409))
                        .with_header(hdr),
                );
                continue;
            }
            let ttl = env::var("AXIOMATIC_DECISION_TTL_SECONDS")
                .ok()
                .and_then(|x| x.parse::<u64>().ok())
                .unwrap_or(30)
                .clamp(1, 60);
            let exp = now.saturating_add(ttl);
            seen.insert(nonce.to_string(), exp);
            order.push_back((nonce.to_string(), exp));
        }
        let decision = evaluate_http(&input, &profile);
        let signing = SignDecisionConfig {
            profile_hash: &h,
            key: &signing_key,
            nonce,
            now,
            ttl: decision_ttl,
            release: &release,
            audience: &audience,
        };
        let decision = match sign_decision(decision, &signing) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("decision signing failed: {e}");
                json!({"decision":"PRUNE","reason":"decision signing unavailable"})
            }
        };
        let _ = rq.respond(Response::from_string(decision.to_string()).with_header(hdr));
    }
}

fn main() {
    if env::args().any(|x| x == "serve") {
        serve();
        return;
    }
    for l in io::stdin().lock().lines() {
        let l = l.unwrap();
        let v: Value = match serde_json::from_str(&l) {
            Ok(v) => v,
            Err(_) => {
                println!("{}", json!({"error":"invalid json"}));
                continue;
            }
        };
        println!("{}", evaluate_policy(&v));
    }
}

#[cfg(test)]
mod tests {
    use super::evaluate_http;
    use serde_json::json;
    #[test]
    fn http_client_explicit_action_cannot_release_gate() {
        let profile = json!({
            "schemaVersion":"1.0","name":"gate-test","origin":"customer-modified",
            "policy":{"allowedCommands":[],"allowedTools":["danger"],"mutatingTools":["danger"],"nonMutatingCommands":[]}
        });
        let input = json!({"explicitAction":true,"proposal":{"kind":"tool","tool":"danger","args":{"x":1}}});
        let d = evaluate_http(&input, &profile);
        assert_eq!(
            d.get("decision").and_then(serde_json::Value::as_str),
            Some("GATE")
        );
        assert!(d.get("canonicalAction").is_some());
    }
}