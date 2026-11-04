// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//! The canonical JSON oracle of spec §7.1 and §9: `canonical_json` 0.7.0's `to_string` over the value serde_json reads
//! (`float_roundtrip`, so a decimal is read as the nearest double, as revokt reads it). Same pipe protocol as `x509`:
//! one base64 JSON text per line in, one line per input out (`##` ends a batch, echoed and flushed):
//!
//! ```text
//! OK <base64 of the canonical JSON>
//! ERR <serde_json's or canonical_json's error>
//! PANIC <message>
//! ```
//!
//! `signed-payload` writes the content-signature payload of a Remote Settings changeset file (spec §7.1), without the
//! `Content-Signature:\0` prefix: the canonical JSON of `{"data": changes without tombstones sorted by id,
//! "last_modified": "<timestamp>"}`. `gen-numbers` writes number inputs for the pipe: random doubles in Rust's
//! shortest forms, random digit strings and exponents, and the integer range edges.

use std::fs;
use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde_json::{json, Value};

use crate::Rng;

fn failure(status: &str, error: &str) -> String {
    format!("{status}\t{}", error.replace(['\t', '\r', '\n'], " "))
}

fn describe(text: &[u8]) -> String {
    let value: Value = match serde_json::from_slice(text) {
        Ok(v) => v,
        Err(e) => return failure("ERR", &format!("serde_json: {e}")),
    };
    match canonical_json::to_string(&value) {
        Ok(s) => format!("OK\t{}", BASE64_STANDARD.encode(s)),
        Err(e) => failure("ERR", &format!("canonical_json: {e}")),
    }
}

fn verdict(text: &[u8]) -> String {
    match panic::catch_unwind(AssertUnwindSafe(|| describe(text))) {
        Ok(reply) => reply,
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic".to_string());
            failure("PANIC", &message)
        }
    }
}

pub fn run() -> Result<(), String> {
    panic::set_hook(Box::new(|_| {}));
    let mut input = io::stdin().lock();
    let mut out = io::BufWriter::new(io::stdout().lock());
    let mut raw = Vec::new();
    loop {
        raw.clear();
        if input
            .read_until(b'\n', &mut raw)
            .map_err(|e| e.to_string())?
            == 0
        {
            break;
        }
        let line = String::from_utf8_lossy(&raw);
        let line = line.trim();
        let reply = match line {
            "##" => "##".to_string(),
            // An empty line is the empty text, which is no JSON value.
            "" => verdict(b""),
            _ => match BASE64_STANDARD.decode(line) {
                Ok(text) => verdict(&text),
                Err(e) => failure("ERR", &format!("base64: {e}")),
            },
        };
        writeln!(out, "{reply}").map_err(|e| e.to_string())?;
        if line == "##" {
            out.flush().map_err(|e| e.to_string())?;
        }
    }
    out.flush().map_err(|e| e.to_string())
}

/// The payload Remote Settings signs for a changeset (`changes`, `timestamp`): Firefox's and application-services'
/// construction, tombstones (`"deleted": true`) dropped and records sorted by `id`.
fn payload(changeset: &Value) -> Result<Value, String> {
    let changes = changeset["changes"]
        .as_array()
        .ok_or("the changeset has no changes array")?;
    let timestamp = changeset["timestamp"]
        .as_u64()
        .ok_or("the changeset has no integer timestamp")?;
    let mut data: Vec<&Value> = changes
        .iter()
        .filter(|r| r["deleted"] != Value::Bool(true))
        .collect();
    for r in &data {
        r["id"].as_str().ok_or("a record has no string id")?;
    }
    data.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(json!({ "data": data, "last_modified": timestamp.to_string() }))
}

pub fn signed_payload(input: &str, output: &str) -> Result<(), String> {
    let bytes = fs::read(input).map_err(|e| format!("{input}: {e}"))?;
    let changeset: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("{input}: serde_json: {e}"))?;
    let text = canonical_json::to_string(&payload(&changeset)?)
        .map_err(|e| format!("{input}: canonical_json: {e}"))?;
    fs::write(output, text).map_err(|e| format!("{output}: {e}"))
}

/// `count` number inputs, `name<TAB>base64` per line: doubles from random bits in Rust's `{:e}` and `{:?}` forms, random
/// digit strings with a random fraction and exponent (long mantissas, halfway and out-of-range cases), and integers
/// around the `u64` and `i64` edges, where serde_json switches to a double.
pub fn gen_numbers(count: usize, seed: u64) -> Result<(), String> {
    let mut rng = Rng(seed);
    let mut out = io::BufWriter::new(io::stdout().lock());
    for i in 0..count {
        let text = match i % 4 {
            0 | 1 => {
                let mut v = f64::from_bits(rng.next());
                while !v.is_finite() {
                    v = f64::from_bits(rng.next());
                }
                if i % 4 == 0 {
                    format!("{v:e}")
                } else {
                    format!("{v:?}")
                }
            }
            2 => {
                let len = 1 + rng.below(30) as usize;
                let mut digits: String = (0..len)
                    .map(|_| char::from(b'0' + rng.below(10) as u8))
                    .collect();
                if digits.len() > 1 {
                    digits = digits.trim_start_matches('0').to_string();
                    if digits.is_empty() {
                        digits = "0".into();
                    }
                }
                let point = rng.below(digits.len() as u64 + 1) as usize;
                if point > 0 && point < digits.len() {
                    digits.insert(point, '.');
                }
                let sign = if rng.below(2) == 0 { "" } else { "-" };
                let exp = rng.below(700) as i64 - 350;
                format!("{sign}{digits}e{exp}")
            }
            _ => {
                let base: i128 = match rng.below(3) {
                    0 => u64::MAX as i128,
                    1 => i64::MIN as i128,
                    _ => i64::MAX as i128,
                };
                (base + rng.below(5) as i128 - 2).to_string()
            }
        };
        writeln!(out, "number-{i}\t{}", BASE64_STANDARD.encode(text)).map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(text: &str) -> String {
        verdict(text.as_bytes())
    }

    fn ok(text: &str) -> String {
        let r = reply(text);
        let b64 = r
            .strip_prefix("OK\t")
            .unwrap_or_else(|| panic!("{text}: {r}"));
        String::from_utf8(BASE64_STANDARD.decode(b64).unwrap()).unwrap()
    }

    #[test]
    fn canonical_forms() {
        assert_eq!(
            ok("{\"b\": 1, \"a\": [2.5, -0, \"é\"]}"),
            "{\"a\":[2.5E0,-0E0,\"\\u00e9\"],\"b\":1}"
        );
        assert_eq!(ok("1e21"), "1E21");
        assert_eq!(ok("18446744073709551616"), "1.8446744073709552E19");
    }

    #[test]
    fn serde_json_rejects_what_it_rejects() {
        for text in ["", "[1,]", "\"\\ud800\"", "01", "1e400", "{} x"] {
            assert!(reply(text).starts_with("ERR\t"), "{text}");
        }
        // serde_json keeps the last member of a duplicated key; revokt rejects the object (spec §7.1).
        assert_eq!(ok("{\"a\":1,\"a\":2}"), "{\"a\":2}");
    }

    #[test]
    fn float_roundtrip_reads_the_nearest_double() {
        // Without float_roundtrip serde_json reads this one ULP off.
        assert_eq!(ok("2.2250738585072011e-308"), "2.225073858507201E-308");
        assert_eq!(ok("9007199254740993"), "9007199254740993");
        assert_eq!(ok("9007199254740993.0"), "9.007199254740992E15");
    }

    #[test]
    fn the_payload_drops_tombstones_and_sorts_by_id() {
        let changeset = json!({"timestamp": 12, "changes": [
            {"id": "b", "last_modified": 12},
            {"id": "c", "last_modified": 11, "deleted": true},
            {"id": "a", "last_modified": 10},
        ]});
        assert_eq!(
            canonical_json::to_string(&payload(&changeset).unwrap()).unwrap(),
            "{\"data\":[{\"id\":\"a\",\"last_modified\":10},{\"id\":\"b\",\"last_modified\":12}],\"last_modified\":\"12\"}"
        );
    }
}
