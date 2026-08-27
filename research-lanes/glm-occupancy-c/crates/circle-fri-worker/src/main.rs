use circle_fri_worker::{encode_proof, prove_bytes, statement_coeffs};
use serde_json::{json, Value};
use std::io::{self, Read};

fn main() {
    let mut buf = String::new();
    let _ = io::stdin().read_to_string(&mut buf);
    let line = buf.lines().find(|l| !l.trim().is_empty()).unwrap_or("").trim();
    if line.is_empty() || line == "manifest" {
        println!("{}", manifest());
        return;
    }
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            println!("{}", json!({ "ok": false, "error": e.to_string() }));
            std::process::exit(1);
        }
    };
    match v.get("cmd").and_then(|c| c.as_str()).unwrap_or("") {
        "manifest" => println!("{}", manifest()),
        "coeffs" => {
            let hex = v.get("statementHex").and_then(|x| x.as_str()).unwrap_or("");
            let bytes = hex::decode(hex).unwrap_or_default();
            let coeffs = statement_coeffs(&bytes);
            println!(
                "{}",
                json!({
                    "ok": true,
                    "family": "circle-fri-m31",
                    "sound": false,
                    "coeffs": coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                })
            );
        }
        "prove" => {
            let hex = v.get("statementHex").and_then(|x| x.as_str()).unwrap_or("");
            let bytes = match hex::decode(hex) {
                Ok(b) if !b.is_empty() => b,
                _ => {
                    println!("{}", json!({ "ok": false, "error": "statementHex" }));
                    std::process::exit(1);
                }
            };
            let proof = prove_bytes(&bytes);
            let encoded = encode_proof(&proof);
            println!(
                "{}",
                json!({
                    "ok": true,
                    "family": "circle-fri-m31",
                    "sound": false,
                    "proofBytes": encoded.len(),
                    "proofHex": hex::encode(encoded),
                })
            );
        }
        other => {
            println!("{}", json!({ "ok": false, "error": format!("unknown cmd {other}") }));
            std::process::exit(1);
        }
    }
}

fn manifest() -> String {
    json!({
        "family": "circle-fri-m31",
        "role": "prove-worker",
        "sound": false,
        "params": { "n": 32, "queries": 8, "field": "M31" },
        "sameAs": "Toorik designs/fri fri-worker: heavy prove only, TS verifies",
    })
    .to_string()
}
