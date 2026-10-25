// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//! The §9.2 unsigned-header rule as 3b implements it: each case re-encodes one indefinite element, or builds one
//! envelope, and asserts what 3b reports.
use super::*;

fn bytes(hex: &str) -> Vec<u8> {
    let digits: Vec<u8> = hex.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// The re-encoded content of the indefinite content `hex` (which ends with its `00 00`), or the reason it fails.
fn converted(hex: &str) -> Located<String> {
    let b = bytes(hex);
    let (end, tokens) = read_indefinite(&b, 0, b.len())?;
    assert_eq!(end, b.len(), "{hex}: the end-of-contents ends the input");
    Ok(super::hex(&reencode(&b, &tokens)))
}

#[test]
fn definite_children_are_copied_and_nested_headers_made_minimal() {
    assert_eq!(converted("02 01 05  00 00").unwrap(), "020105");
    assert_eq!(
        converted("30 80 02 01 05 00 00  00 00").unwrap(),
        "3003020105"
    );
    assert_eq!(
        converted("30 80 31 80 02 01 05 00 00 04 00 00 00  00 00").unwrap(),
        "300731030201050400"
    );
    // A primitive indefinite element whose content is a TLV chain, as `extnValue` in `04 80 … 00 00`.
    assert_eq!(
        converted("04 80 30 00 05 00 00 00  00 00").unwrap(),
        "040430000500"
    );
    // A nested element's re-encoded content of 128 octets takes a two-octet header.
    let long = format!("30 80 04 7e {} 00 00  00 00", "aa ".repeat(126));
    assert_eq!(
        converted(&long).unwrap(),
        format!("308180047e{}", "aa".repeat(126))
    );
}

#[test]
fn end_of_contents_inside_a_definite_child_is_content() {
    assert_eq!(
        converted("02 04 00 00 01 23  00 00").unwrap(),
        "020400000123"
    );
    assert_eq!(
        converted("30 80 04 02 00 00 00 00  00 00").unwrap(),
        "300404020000"
    );
}

#[test]
fn the_converter_rejects_other_length_forms() {
    for (hex, reason) in [
        ("02 81 05 aa aa aa aa aa  00 00", "non-minimal"),
        ("02 82 00 01 aa  00 00", "non-minimal"),
        ("02 85 00 00 00 00 01 aa  00 00", "length octet 85"),
        ("02 ff  00 00", "length octet ff"),
        ("30 80 02 01 05 00 00", "unterminated"),
        ("02 05 aa  00 00", "past the end"),
    ] {
        let reason_found = converted(hex).expect_err(hex);
        assert!(reason_found.contains(reason), "{hex}: {reason_found}");
    }
    assert!(converted(&format!("02 81 80 {} 00 00", "aa ".repeat(128))).is_ok());
}

#[test]
fn deep_nesting_needs_no_stack() {
    let depth = 200_000;
    let b = [[0x30, 0x80].repeat(depth), vec![0x00; 2 * (depth + 1)]].concat();
    let (end, tokens) = read_indefinite(&b, 0, b.len()).unwrap();
    assert_eq!(end, b.len());
    let out = reencode(&b, &tokens);
    assert_eq!(&out[out.len() - 2..], &[0x30, 0x00]);
}

fn certificate(tbs: &str, algorithm: &str, signature: &str) -> Vec<u8> {
    let body = [bytes(tbs), bytes(algorithm), bytes(signature)].concat();
    [vec![0x30], minimal_length(body.len()), body].concat()
}

const TBS: &str = "30 0d a0 03 02 01 02 02 01 07 30 03 06 01 2a";
const TBS_SIGNATURE: &str = "300306012a";

#[test]
fn the_envelope_takes_every_unsigned_header_form() {
    let definite = describe(&certificate(TBS, "30 03 06 01 2a", "03 02 00 aa")).unwrap();
    let expected = format!("CANON\t{}\t{TBS_SIGNATURE}\taa", TBS.replace(' ', ""));
    assert_eq!(definite, expected);
    let long5 = TBS.replacen("30 0d", "30 85 00 00 00 00 0d", 1);
    let indefinite = "30 80 a0 03 02 01 02 02 01 07 30 03 06 01 2a 00 00";
    for tbs in [long5.as_str(), indefinite] {
        assert_eq!(
            describe(&certificate(
                tbs,
                "30 80 06 01 2a 00 00",
                "03 82 00 02 00 aa"
            ))
            .unwrap(),
            expected
        );
    }
    // The Certificate header in any definite form.
    let body = [bytes(TBS), bytes("30 03 06 01 2a 03 02 00 aa")].concat();
    let long8 = [
        bytes("30 88 00 00 00 00 00 00 00"),
        vec![body.len() as u8],
        body,
    ]
    .concat();
    assert_eq!(describe(&long8).unwrap(), expected);
}

#[test]
fn the_tbs_signature_is_sliced_through_any_length_form() {
    let tbs = "30 17 a0 85 00 00 00 00 03 02 01 02 02 01 07 30 85 00 00 00 00 03 06 01 2a";
    let reply = describe(&certificate(tbs, "30 03 06 01 2a", "03 02 00 aa")).unwrap();
    assert_eq!(reply.split('\t').nth(2), Some("3085000000000306012a"));
}

#[test]
fn an_indefinite_signature_value_is_converted() {
    let reply = describe(&certificate(
        TBS,
        "30 03 06 01 2a",
        "03 80 00 80 04 01 aa 00 00 00 00",
    ))
    .unwrap();
    assert_eq!(reply.split('\t').nth(3), Some("030401aa"));
}

#[test]
fn what_is_not_located() {
    for (der, reason) in [
        (
            certificate(TBS, "30 03 06 01 2a", "03 02 00 aa 05 00"),
            "bytes after signatureValue",
        ),
        (
            [certificate(TBS, "30 03 06 01 2a", "03 02 00 aa"), vec![0]].concat(),
            "bytes after Certificate",
        ),
        (
            certificate("30 80 02 81 01 07 00 00", "30 03 06 01 2a", "03 02 00 aa"),
            "non-minimal",
        ),
        (
            certificate("31 00", "30 03 06 01 2a", "03 02 00 aa"),
            "expected tag 30",
        ),
    ] {
        let found = describe(&der).expect_err(reason);
        assert!(found.contains(reason), "{reason}: {found}");
    }
    assert_eq!(verdict(&[0x30, 0x80]), "NOT_LOCATED\tindefinite length");
}
