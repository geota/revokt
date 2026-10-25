// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//! Oracle 3b of spec §9.2, a minimal TLV locator written independently of revokt. It delimits `tbsCertificate`, the
//! outer `signatureAlgorithm` and `signatureValue` (definite only, revision 38), re-encodes an indefinite TBS or
//! algorithm as the JDK's `DerIndefLenConverter` does (the §9.2 unsigned-header rule), then walks the re-encoded TBS
//! ([`crate::walk`]). Same pipe protocol as `x509`:
//!
//! ```text
//! LOCATED <serial> <spki> <subject> <issuer> <tbs> <tbs-signature> <signature> <unused> <extensions> <stop>
//! CANON <tbs> <tbs-signature> <signature> <reason>
//! NOT_LOCATED <reason>
//! PANIC <reason>
//! ```
//!
//! `CANON` is the answer when the envelope is delimited but the TBS walk fails (`reason`). Byte fields are lower-case
//! hex. `tbs` is the re-encoded TBS under a minimal header, `tbs-signature` its signature AlgorithmIdentifier (after the
//! optional `[0]` and the serial) and `signature` the `signatureValue` content after its unused-bits octet (padding not
//! cleared): the parts of `canon(encoded)`. `unused` is that unused-bits octet in decimal
//! (`-` when the content is empty). `serial` is the INTEGER content, `spki`, `subject` and `issuer` the TLVs.
//! `extensions` is `;`-joined `oid,critical,value,sct`: the OID content, `1` when the flag octet is non-zero, the
//! `extnValue` content, and `sct` `-` except for the SCT-list extension, where it is `E` when the §9.2 SCT-list rule
//! fails the list, else the kept items' `logid@timestamp`, `+`-joined. `stop` is the identifier octet of the element that
//! ended the TBS tail read (§9.2 trailing-element rule), or `-`.

use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;

use crate::walk;

type Located<T> = Result<T, String>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn minimal_length(n: usize) -> Vec<u8> {
    let octets: Vec<u8> = n
        .to_be_bytes()
        .into_iter()
        .skip_while(|&o| o == 0)
        .collect();
    match n {
        0..=0x7f => vec![n as u8],
        _ => [vec![0x80 | octets.len() as u8], octets].concat(),
    }
}

/// A definite length at `b[p]` (the octet after the tag), in any form: short, or long with any count of length octets,
/// leading zeros allowed. Returns (offset of the content, length), the content within `limit`.
fn definite_length(b: &[u8], p: usize, limit: usize) -> Located<(usize, usize)> {
    let first = *b.get(p).filter(|_| p < limit).ok_or("missing length")?;
    let (start, length) = match first {
        0x00..=0x7f => (p + 1, first as usize),
        0x80 => return Err("indefinite length".into()),
        0xff => return Err("reserved length octet ff".into()),
        _ => {
            let count = (first & 0x7f) as usize;
            let octets = b
                .get(p + 1..p + 1 + count)
                .filter(|_| count < limit - p)
                .ok_or("length octets past the end")?;
            let mut length = 0usize;
            for &o in octets {
                length = length
                    .checked_mul(256)
                    .filter(|&n| n <= limit)
                    .ok_or("length past the end")?
                    | o as usize;
            }
            (p + 1 + count, length)
        }
    };
    if length > limit - start {
        return Err("element past the end".into());
    }
    Ok((start, length))
}

/// One step of the JDK converter's reading of indefinite content.
enum Token {
    /// A header with length octet `80` and this tag octet: a nested indefinite element opens.
    Open(u8),
    /// `00 00` at a tag position: the innermost open element closes.
    Close,
    /// A definite TLV, copied whole: its byte range.
    Copy(usize, usize),
}

/// Reads indefinite content from `p` to its end-of-contents as the converter does, one token per header met. Returns
/// the offset after the end-of-contents and the tokens before it.
fn read_indefinite(b: &[u8], p: usize, limit: usize) -> Located<(usize, Vec<Token>)> {
    let mut tokens = Vec::new();
    let mut depth = 0usize;
    let mut q = p;
    loop {
        let header = b
            .get(q..q + 2)
            .filter(|_| q + 2 <= limit)
            .ok_or("unterminated indefinite element")?;
        match header {
            [0, 0] if depth == 0 => return Ok((q + 2, tokens)),
            [0, 0] => {
                depth -= 1;
                tokens.push(Token::Close);
                q += 2;
            }
            [tag, 0x80] => {
                depth += 1;
                tokens.push(Token::Open(*tag));
                q += 2;
            }
            _ => {
                let end = converter_definite_end(b, q, limit)?;
                tokens.push(Token::Copy(q, end));
                q = end;
            }
        }
    }
}

/// The end of a definite TLV at `q` as the converter reads it: one tag octet, then a short form or `81`–`84` with a
/// minimal length; any other length octet, or a non-minimal length, is not located (§9.2).
fn converter_definite_end(b: &[u8], q: usize, limit: usize) -> Located<usize> {
    let first = b[q + 1];
    if !(first < 0x80 || (0x81..=0x84).contains(&first)) {
        return Err(format!(
            "length octet {first:02x} under an indefinite element"
        ));
    }
    let (start, length) = definite_length(b, q + 1, limit)?;
    if start - q - 2 != minimal_length(length).len() - 1 {
        return Err("non-minimal length under an indefinite element".into());
    }
    Ok(start + length)
}

/// The re-encoded content: walking the tokens backwards, every nested element's content is complete when its `Open`
/// is reached, so its minimal header is written then. The output is built reversed and turned round at the end.
fn reencode(b: &[u8], tokens: &[Token]) -> Vec<u8> {
    let mut reversed = Vec::new();
    let mut closes = Vec::new();
    for token in tokens.iter().rev() {
        match *token {
            Token::Close => closes.push(reversed.len()),
            Token::Copy(start, end) => reversed.extend(b[start..end].iter().rev()),
            Token::Open(tag) => {
                let content = reversed.len() - closes.pop().expect("an Open has its Close");
                reversed.extend(minimal_length(content).into_iter().rev());
                reversed.push(tag);
            }
        }
    }
    reversed.reverse();
    reversed
}

/// An unsigned envelope element at `p` with `tag`: definite in any form, or indefinite and re-encoded (the TBS and the
/// algorithm only; tag `03` is the `signatureValue`, which is not located indefinite). Returns (end, content as the
/// JDK verifies it).
fn unsigned(b: &[u8], p: usize, limit: usize, tag: u8) -> Located<(usize, Vec<u8>)> {
    if p + 1 >= limit || b[p] != tag {
        return Err(format!("expected tag {tag:02x}"));
    }
    if b[p + 1] == 0x80 {
        // Spec §9.2 revision 38: an indefinite signatureValue is not located (JDK 17 and later reject it).
        if tag == 0x03 {
            return Err("indefinite signatureValue".into());
        }
        let (end, tokens) = read_indefinite(b, p + 2, limit)?;
        return Ok((end, reencode(b, &tokens)));
    }
    let (start, length) = definite_length(b, p + 1, limit)?;
    Ok((start + length, b[start..start + length].to_vec()))
}

/// The TLV after the optional `[0]` and the serial in the re-encoded TBS content `b[p..limit]`: the signature
/// AlgorithmIdentifier.
fn tbs_signature(b: &[u8], mut p: usize, limit: usize) -> Located<&[u8]> {
    let skip = |p: &mut usize| -> Located<usize> {
        let begin = *p;
        let (start, length) = definite_length(b, begin + 1, limit)?;
        *p = start + length;
        Ok(begin)
    };
    if b.get(p) == Some(&0xa0) {
        skip(&mut p)?;
    }
    skip(&mut p)?;
    let begin = skip(&mut p)?;
    Ok(&b[begin..p])
}

fn describe(der: &[u8]) -> Located<String> {
    if der.first() != Some(&0x30) {
        return Err("not a SEQUENCE".into());
    }
    let (start, length) = definite_length(der, 1, der.len())?;
    if start + length != der.len() {
        return Err("bytes after Certificate".into());
    }
    let limit = der.len();
    let (tbs_end, tbs) = unsigned(der, start, limit, 0x30)?;
    let (algorithm_end, _) = unsigned(der, tbs_end, limit, 0x30)?;
    let (signature_end, signature) = unsigned(der, algorithm_end, limit, 0x03)?;
    if signature_end != limit {
        return Err("bytes after signatureValue".into());
    }
    let header = [vec![0x30], minimal_length(tbs.len())].concat();
    let reencoded = [header.as_slice(), &tbs].concat();
    let algorithm = tbs_signature(&reencoded, header.len(), reencoded.len())?;
    let canon = [
        hex(&reencoded),
        hex(algorithm),
        hex(signature.get(1..).unwrap_or(&[])),
    ]
    .join("\t");
    let fields = match walk::walk(&reencoded) {
        Ok(fields) => fields,
        Err(reason) => return Ok(format!("CANON\t{canon}\t{reason}")),
    };
    let unused = signature.first().map_or("-".to_string(), u8::to_string);
    let extensions: Vec<String> = fields
        .extensions
        .iter()
        .map(|e| {
            let sct = if !walk::is_sct_list(e.oid) {
                "-".to_string()
            } else {
                walk::sct_pairs(e.value).map_or("E".to_string(), |pairs| {
                    let items: Vec<String> = pairs
                        .iter()
                        .map(|(id, ts)| format!("{}@{ts}", hex(id)))
                        .collect();
                    items.join("+")
                })
            };
            format!(
                "{},{},{},{sct}",
                hex(e.oid),
                u8::from(e.critical),
                hex(e.value)
            )
        })
        .collect();
    let stop = fields.stop.map_or("-".to_string(), |t| format!("{t:02x}"));
    Ok([
        "LOCATED".to_string(),
        hex(fields.serial),
        hex(fields.spki),
        hex(fields.subject),
        hex(fields.issuer),
        canon,
        unused,
        extensions.join(";"),
        stop,
    ]
    .join("\t"))
}

fn verdict(der: &[u8]) -> String {
    match panic::catch_unwind(AssertUnwindSafe(|| describe(der))) {
        Ok(Ok(line)) => line,
        Ok(Err(reason)) => format!("NOT_LOCATED\t{}", reason.replace(['\t', '\r', '\n'], " ")),
        Err(_) => "PANIC\tlocator panic".to_string(),
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
            "" => "NOT_LOCATED\tempty input".to_string(),
            _ => match BASE64_STANDARD.decode(line) {
                Ok(der) => verdict(&der),
                Err(e) => format!("NOT_LOCATED\tbase64: {e}"),
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
#[path = "test/locate.rs"]
mod tests;
