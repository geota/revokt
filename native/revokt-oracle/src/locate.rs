// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//! Oracle 3b of spec §9.2, a minimal TLV locator written independently of revokt; this step builds `canon`. It
//! delimits `tbsCertificate`, the outer `signatureAlgorithm` and `signatureValue`, and re-encodes the indefinite ones as
//! the JDK's `DerIndefLenConverter` does (the §9.2 unsigned-header rule). Same pipe protocol as `x509`:
//!
//! ```text
//! CANON <tbs> <tbs-signature> <signature>
//! NOT_LOCATED <reason>
//! PANIC <reason>
//! ```
//!
//! Fields are lower-case hex: the re-encoded TBS under a minimal header, its signature AlgorithmIdentifier (after the
//! optional `[0]` and the serial), and the `signatureValue` content after its unused-bits octet, re-encoded when
//! indefinite (padding not cleared): the parts of `canon(encoded)`.

use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;

type Located<T> = Result<T, String>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn minimal_length(n: usize) -> Vec<u8> {
    match n {
        0..=0x7f => vec![n as u8],
        0x80..=0xff => vec![0x81, n as u8],
        0x100..=0xffff => vec![0x82, (n >> 8) as u8, n as u8],
        0x1_0000..=0xff_ffff => vec![0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8],
        _ => vec![
            0x84,
            (n >> 24) as u8,
            (n >> 16) as u8,
            (n >> 8) as u8,
            n as u8,
        ],
    }
}

/// A definite length at `b[p..]` (the octet after the tag): (offset of the content, length). `lenient` accepts any
/// count of length octets with leading zeros, as the unsigned headers allow; otherwise 1 to 4 octets.
fn definite_length(b: &[u8], p: usize, limit: usize, lenient: bool) -> Located<(usize, usize)> {
    let first = *b.get(p).filter(|_| p < limit).ok_or("missing length")? as usize;
    if first < 0x80 {
        return Ok((p + 1, first));
    }
    if first == 0x80 {
        return Err("indefinite length".into());
    }
    let count = first & 0x7f;
    if first == 0xff || (!lenient && count > 4) || count > limit - p - 1 {
        return Err(format!("length of {count} octets"));
    }
    let mut length = 0usize;
    for i in 0..count {
        length = length.checked_mul(256).ok_or("length overflow")? + b[p + 1 + i] as usize;
        if length > limit {
            return Err("length past the end".into());
        }
    }
    Ok((p + 1 + count, length))
}

/// The JDK converter's reading of an indefinite element whose content starts at `p`: one tag octet, then `80`, a short
/// form, or a minimal `81`–`84`; `00 00` at a tag position closes the innermost element; a definite element is copied
/// whole. Returns (end, re-encoded content). Iterative in two passes (the first sizes each element), so no input can
/// exhaust the stack or take quadratic time.
fn convert(b: &[u8], p: usize, limit: usize) -> Located<(usize, Vec<u8>)> {
    // Pass 1: delimit, and size each indefinite element's re-encoded content, in opening order.
    let mut sizes: Vec<usize> = vec![0];
    let mut open: Vec<usize> = vec![0];
    let mut q = p;
    while let Some(&top) = open.last() {
        if limit - q >= 2 && b[q] == 0 && b[q + 1] == 0 {
            q += 2;
            open.pop();
            if let Some(&parent) = open.last() {
                sizes[parent] += 1 + minimal_length(sizes[top]).len() + sizes[top];
            }
        } else if limit - q < 2 {
            return Err("unterminated indefinite element".into());
        } else if b[q + 1] == 0x80 {
            sizes.push(0);
            open.push(sizes.len() - 1);
            q += 2;
        } else {
            let end = definite_end(b, q, limit)?;
            sizes[top] += end - q;
            q = end;
        }
    }
    let end = q;
    // Pass 2: write each indefinite header as a minimal definite one; copy everything else.
    let mut out = Vec::with_capacity(sizes[0]);
    let mut next = 1;
    q = p;
    while q < end - 2 {
        if b[q] == 0 && b[q + 1] == 0 {
            q += 2;
        } else if b[q + 1] == 0x80 {
            out.push(b[q]);
            out.extend(minimal_length(sizes[next]));
            next += 1;
            q += 2;
        } else {
            let e = definite_end(b, q, limit)?;
            out.extend_from_slice(&b[q..e]);
            q = e;
        }
    }
    Ok((end, out))
}

/// The end of a definite element met by the converter: a short form, or a minimal `81`–`84`.
fn definite_end(b: &[u8], q: usize, limit: usize) -> Located<usize> {
    let first = b[q + 1] as usize;
    if first > 0x84 {
        return Err("length form the converter rejects".into());
    }
    let (start, length) = definite_length(b, q + 1, limit, false)?;
    if first > 0x80 && (length < 0x80 || b[q + 2] == 0) {
        return Err("non-minimal length under an indefinite element".into());
    }
    if length > limit - start {
        return Err("element past the end".into());
    }
    Ok(start + length)
}

/// An unsigned envelope element at `p` with `tag`: definite in any form, or indefinite and converted. Returns (end,
/// content as the JDK verifies it).
fn unsigned(b: &[u8], p: usize, limit: usize, tag: u8) -> Located<(usize, Vec<u8>)> {
    if p + 1 >= limit || b[p] != tag {
        return Err(format!("expected tag {tag:02x}"));
    }
    if b[p + 1] == 0x80 {
        return convert(b, p + 2, limit);
    }
    let (start, length) = definite_length(b, p + 1, limit, true)?;
    if length > limit - start {
        return Err("envelope element past the end".into());
    }
    Ok((start + length, b[start..start + length].to_vec()))
}

/// The TLV after the optional `[0]` and the serial in the re-encoded TBS content `b[p..limit]`: the signature
/// AlgorithmIdentifier.
fn tbs_signature(b: &[u8], mut p: usize, limit: usize) -> Located<&[u8]> {
    let next = |p: &mut usize| -> Located<(u8, usize)> {
        let tag = *b.get(*p).filter(|_| *p < limit).ok_or("TBS ends early")?;
        let (start, length) = definite_length(b, *p + 1, limit, false)?;
        if length > limit - start {
            return Err("TBS element past the end".into());
        }
        let begin = *p;
        *p = start + length;
        Ok((tag, begin))
    };
    if b.get(p) == Some(&0xa0) {
        next(&mut p)?;
    }
    next(&mut p)?;
    let (_, begin) = next(&mut p)?;
    Ok(&b[begin..p])
}

fn describe(der: &[u8]) -> Located<String> {
    let (start, length) = if der.first() == Some(&0x30) {
        definite_length(der, 1, der.len(), false)?
    } else {
        return Err("not a SEQUENCE".into());
    };
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
    let mut reencoded = vec![0x30];
    reencoded.extend(minimal_length(tbs.len()));
    reencoded.extend_from_slice(&tbs);
    let algorithm = tbs_signature(&reencoded, reencoded.len() - tbs.len(), reencoded.len())?;
    Ok(format!(
        "CANON\t{}\t{}\t{}",
        hex(&reencoded),
        hex(algorithm),
        hex(signature.get(1..).unwrap_or(&[]))
    ))
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
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
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
