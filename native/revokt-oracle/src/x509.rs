// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//! Oracle 3a of spec §9.2: `x509-parser` 0.18.1 on one certificate per input. It reads one base64 DER per line on
//! stdin and writes one tab-separated line per input line (§9.1's batched pipe protocol; `##` ends a batch, echoed and
//! flushed; an empty line is answered as an empty input):
//!
//! ```text
//! OK <serial> <spki> <subject> <issuer> <trailing> <tbs> <tbs-signature> <signature> <extensions>
//! ERR <error>
//! PANIC <error>
//! ```
//!
//! Every field but `trailing` (the count of bytes after the certificate) is lower-case hex. `extensions` is `;`-joined
//! `oid,critical,value,sct` with `oid` the OID's content octets as encoded, `critical` `0` or `1`, and `sct` `-` except
//! for the SCT-list extension: `E` when x509-parser reports a parse error for it, else its pairs as `+`-joined
//! `logid@timestamp`. `tbs` is the TBS TLV re-headed to a minimal length, `tbs-signature` its signature
//! AlgorithmIdentifier TLV and `signature` the `signatureValue` octets after the unused-bits octet (padding not
//! cleared), the parts of `canon`. Every value is what x509-parser reports, never revokt.

use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

/// The SCT-list extension's OID content, 1.3.6.1.4.1.11129.2.4.2.
const SCT_LIST: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn failure(status: &str, error: &str) -> String {
    format!("{status}\t{}", error.replace(['\t', '\r', '\n'], " "))
}

/// A DER header at `p`: (header length, content length), or None when it does not fit `b`.
fn header(b: &[u8], p: usize) -> Option<(usize, usize)> {
    let first = *b.get(p + 1)? as usize;
    if first < 0x80 {
        return Some((2, first));
    }
    let count = first & 0x7f;
    if count == 0 || count > 4 {
        return None;
    }
    let mut length = 0usize;
    for i in 0..count {
        length = (length << 8) | *b.get(p + 2 + i)? as usize;
    }
    Some((2 + count, length))
}

fn minimal_length(n: usize) -> Vec<u8> {
    match n {
        0..=0x7f => vec![n as u8],
        0x80..=0xff => vec![0x81, n as u8],
        0x100..=0xffff => vec![0x82, (n >> 8) as u8, n as u8],
        _ => vec![0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8],
    }
}

/// The TBS TLV under a minimal header, and the TBS `signature` AlgorithmIdentifier TLV (after `[0]` and the serial).
fn tbs_parts(tbs: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (h, length) = header(tbs, 0)?;
    let content = tbs.get(h..h + length)?;
    let mut reheaded = vec![tbs[0]];
    reheaded.extend(minimal_length(content.len()));
    reheaded.extend_from_slice(content);
    let mut p = 0;
    let skip = |p: &mut usize| -> Option<usize> {
        let (eh, el) = header(content, *p)?;
        let start = *p;
        *p += eh + el;
        Some(start)
    };
    if content.first() == Some(&0xa0) {
        skip(&mut p)?;
    }
    skip(&mut p)?;
    let start = skip(&mut p)?;
    Some((reheaded, content.get(start..p)?.to_vec()))
}

fn describe(der: &[u8]) -> String {
    let (rest, cert) = match X509Certificate::from_der(der) {
        Ok(parsed) => parsed,
        Err(e) => return failure("ERR", &format!("{e:?}")),
    };
    let tbs = &cert.tbs_certificate;
    let Some((reheaded, tbs_signature)) = tbs_parts(tbs.as_ref()) else {
        return failure("ERR", "TBS could not be sliced");
    };
    let extensions: Vec<String> = tbs
        .extensions()
        .iter()
        .map(|e| {
            let sct = if e.oid.as_bytes() != SCT_LIST {
                "-".to_string()
            } else {
                match e.parsed_extension() {
                    ParsedExtension::SCT(list) => list
                        .iter()
                        .map(|s| format!("{}@{}", hex(s.id.key_id), s.timestamp))
                        .collect::<Vec<_>>()
                        .join("+"),
                    _ => "E".to_string(),
                }
            };
            format!(
                "{},{},{},{}",
                hex(e.oid.as_bytes()),
                u8::from(e.critical),
                hex(e.value),
                sct
            )
        })
        .collect();
    [
        "OK".to_string(),
        hex(tbs.raw_serial()),
        hex(tbs.subject_pki.raw),
        hex(tbs.subject().as_raw()),
        hex(tbs.issuer().as_raw()),
        rest.len().to_string(),
        hex(&reheaded),
        hex(&tbs_signature),
        hex(&cert.signature_value.data),
        extensions.join(";"),
    ]
    .join("\t")
}

/// One reply per input; a panic anywhere in x509-parser is caught and reported, never fatal (spec §9.2).
fn verdict(der: &[u8]) -> String {
    match panic::catch_unwind(AssertUnwindSafe(|| describe(der))) {
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
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let line = line.trim();
        let reply = match line {
            "##" => "##".to_string(),
            "" => failure("ERR", "empty input"),
            _ => match BASE64_STANDARD.decode(line) {
                Ok(der) => verdict(&der),
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
