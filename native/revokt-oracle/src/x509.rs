// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//! Oracle 3a of spec §9.2: `x509-parser` 0.18.1 on one certificate per input. It reads one base64 DER per line on
//! stdin and writes one tab-separated line per input line (§9.1's batched pipe protocol; `##` ends a batch, echoed and
//! flushed; an empty line is answered as an empty input):
//!
//! ```text
//! OK <serial> <spki> <subject> <issuer> <trailing> <tbs> <tbs-signature> <signature> <extensions> <unused> <duplicate>
//! ERR <error>
//! PANIC <error>
//! ```
//!
//! Every field but `trailing` (the count of bytes after the certificate) is lower-case hex. `extensions` is `;`-joined
//! `oid,critical,value,sct` with `oid` the OID's content octets as encoded, `critical` `0` or `1`, and `sct` `-` except
//! for the SCT-list extension: `E` when x509-parser reports a parse error for it, else its pairs as `+`-joined
//! `logid@timestamp`. `tbs` is the TBS TLV re-headed to a minimal length, `tbs-signature` its signature
//! AlgorithmIdentifier TLV and `signature` the `signatureValue` octets after the unused-bits octet (padding not
//! cleared), the parts of `canon`; `unused` is the `signatureValue`'s unused-bits count, and `duplicate` is `1` when the
//! SCT-list extension occurs more than once (x509-parser's `DuplicateExtensions` for it). Element boundaries come from
//! asn1-rs's own headers. Every value is what x509-parser reports, never revokt.

use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};

use asn1_rs::{Any, Class, FromBer, Header, Length, Tag};
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

fn minimal_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let octets: Vec<u8> = n
        .to_be_bytes()
        .into_iter()
        .skip_while(|&b| b == 0)
        .collect();
    let mut out = vec![0x80 | octets.len() as u8];
    out.extend(octets);
    out
}

/// The identifier octets at the start of `b` (one, or the high-tag-number form).
fn identifier_length(b: &[u8]) -> usize {
    if b.first().is_none_or(|&t| t & 0x1f != 0x1f) {
        return 1;
    }
    1 + b[1..]
        .iter()
        .position(|&o| o & 0x80 == 0)
        .map_or(b.len() - 1, |i| i + 1)
}

/// The TBS slices 3a reports, each delimited by asn1-rs headers in the TBS bytes rather than taken from what
/// x509-parser consumed (which stops early inside malformed content): the TBS under a minimal header, the `signature`
/// AlgorithmIdentifier (after an optional context `[0]`, either form, and the serial), issuer, subject and SPKI TLVs.
struct TbsSlices {
    reheaded: Vec<u8>,
    algorithm: Vec<u8>,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    spki: Vec<u8>,
}

fn tbs_parts(tbs: &[u8]) -> Option<TbsSlices> {
    let (rest, header) = Header::from_ber(tbs).ok()?;
    let Length::Definite(n) = header.length() else {
        return None;
    };
    let content = rest.get(..n)?;
    let mut reheaded = tbs[..identifier_length(tbs)].to_vec();
    reheaded.extend(minimal_length(n));
    reheaded.extend_from_slice(content);
    let mut p = content;
    let (after, first) = Any::from_ber(p).ok()?;
    if first.header.class() == Class::ContextSpecific && first.header.tag() == Tag(0) {
        p = after;
    }
    // Each call returns the next element's whole TLV and advances past it.
    let mut next = || -> Option<Vec<u8>> {
        let (after, _) = Any::from_ber(p).ok()?;
        let element = p[..p.len() - after.len()].to_vec();
        p = after;
        Some(element)
    };
    next()?;
    let algorithm = next()?;
    let issuer = next()?;
    next()?;
    let subject = next()?;
    let spki = next()?;
    Some(TbsSlices {
        reheaded,
        algorithm,
        issuer,
        subject,
        spki,
    })
}

fn describe(der: &[u8]) -> String {
    let (rest, cert) = match X509Certificate::from_der(der) {
        Ok(parsed) => parsed,
        Err(e) => return failure("ERR", &format!("{e:?}")),
    };
    let tbs = &cert.tbs_certificate;
    let Some(slices) = tbs_parts(tbs.as_ref()) else {
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
        hex(&slices.spki),
        hex(&slices.subject),
        hex(&slices.issuer),
        rest.len().to_string(),
        hex(&slices.reheaded),
        hex(&slices.algorithm),
        hex(&cert.signature_value.data),
        extensions.join(";"),
        cert.signature_value.unused_bits.to_string(),
        u8::from(
            tbs.extensions()
                .iter()
                .filter(|e| e.oid.as_bytes() == SCT_LIST)
                .count()
                > 1,
        )
        .to_string(),
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
        // Bytes, not UTF-8 lines: an invalid line is answered, never fatal, so replies stay one per input.
        let line = String::from_utf8_lossy(&raw);
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

#[cfg(test)]
#[path = "test/x509.rs"]
mod tests;
