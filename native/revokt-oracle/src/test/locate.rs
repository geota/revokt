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

/// A TBS too short for the walk, so 3b answers `CANON` with the walk's reason.
const TBS: &str = "30 0d a0 03 02 01 02 02 01 07 30 03 06 01 2a";
const TBS_SIGNATURE: &str = "300306012a";

/// The `CANON` reply without the walk's reason.
fn canon(der: &[u8]) -> String {
    let reply = describe(der).unwrap();
    let f: Vec<&str> = reply.split('\t').collect();
    assert_eq!(f[0], "CANON", "{reply}");
    f[..4].join("\t")
}

#[test]
fn the_envelope_takes_every_unsigned_header_form() {
    let definite = canon(&certificate(TBS, "30 03 06 01 2a", "03 02 00 aa"));
    let expected = format!("CANON\t{}\t{TBS_SIGNATURE}\taa", TBS.replace(' ', ""));
    assert_eq!(definite, expected);
    let long5 = TBS.replacen("30 0d", "30 85 00 00 00 00 0d", 1);
    let indefinite = "30 80 a0 03 02 01 02 02 01 07 30 03 06 01 2a 00 00";
    for tbs in [long5.as_str(), indefinite] {
        assert_eq!(
            canon(&certificate(
                tbs,
                "30 80 06 01 2a 00 00",
                "03 82 00 02 00 aa"
            )),
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
    assert_eq!(canon(&long8), expected);
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

use crate::test_support as support;

/// The `LOCATED` reply's fields.
fn located(der: &[u8]) -> Vec<String> {
    let reply = describe(der).unwrap();
    let f: Vec<String> = reply.split('\t').map(str::to_string).collect();
    assert_eq!(f[0], "LOCATED", "{reply}");
    f
}

fn sct_fields(values: &[Vec<u8>]) -> Vec<String> {
    let extensions: Vec<Vec<u8>> = values.iter().map(|v| support::sct_extension(v)).collect();
    let f = located(&support::certificate(&extensions));
    f[9].split(';')
        .map(|e| e.rsplit(',').next().unwrap().to_string())
        .collect()
}

#[test]
fn the_shared_sct_cases_under_the_spec_rule() {
    for c in support::sct_cases() {
        // 3A_HEADER_LAX rows: §9.2 requires the inner identifier 0x04, so the list fails.
        let expected = if c.header_lax {
            vec!["E".to_string(); c.values.len()]
        } else {
            c.expected
        };
        assert_eq!(sct_fields(&c.values), expected, "{}", c.name);
    }
}

fn sct_list_extension(timestamp: u64) -> Vec<u8> {
    support::sct_extension(&support::tlv(
        0x04,
        &support::list(&[support::item(0, timestamp, &[])]),
    ))
}

#[test]
fn the_fields_are_sliced_from_the_tbs() {
    let f = located(&support::certificate(&[sct_list_extension(7)]));
    let name = "300c310a300806035504030c0161";
    assert_eq!(
        [f[1].as_str(), &f[2][..4], &f[3], &f[4]],
        ["0123", "3059", name, name]
    );
    assert_eq!(&f[6], "300a06082a8648ce3d040302");
    assert_eq!(&f[8], "0", "unused bits");
    let oid = hex(support::SCT_LIST_OID);
    assert!(f[9].starts_with(&format!("{oid},0,04")), "{}", f[9]);
    assert!(
        f[9].ends_with(&format!(",{}", support::pairs(&[7]))),
        "{}",
        f[9]
    );
    assert_eq!(&f[10], "-");
}

/// The extension count and the `stop` field for a TBS ending, after the SPKI, with `tail`.
fn read_tail(tail: &[u8]) -> (usize, String) {
    let f = located(&support::certificate_with_tail(tail));
    let count = if f[9].is_empty() {
        0
    } else {
        f[9].split(';').count()
    };
    (count, f[10].clone())
}

#[test]
fn the_trailing_element_rule() {
    let extensions = support::tlv(0xa3, &support::seq(&[sct_list_extension(1)]));
    let with = |before: &[u8], after: &[u8]| [before, &extensions, after].concat();
    let null = [0x05, 0x00];
    let cases: [(&str, Vec<u8>, (usize, &str)); 10] = [
        ("extensions", with(&[], &[]), (1, "-")),
        ("no tail", vec![], (0, "-")),
        ("bytes after [3]", with(&[], &null), (1, "-")),
        (
            "a multi-octet tag after [3]",
            with(&[], &[0x9f, 0x01, 0x02, 0x05, 0x00]),
            (1, "-"),
        ),
        (
            "an element between the SPKI and [3]",
            with(&null, &[]),
            (0, "05"),
        ),
        (
            "[2] before [1]",
            with(&[0x82, 0x00, 0x81, 0x00], &[]),
            (0, "81"),
        ),
        ("[1] twice", with(&[0x81, 0x00, 0x81, 0x00], &[]), (0, "81")),
        (
            "constructed [1] and [2]",
            with(&[0xa1, 0x00, 0xa2, 0x00], &[]),
            (1, "-"),
        ),
        ("two [3]", with(&[], &extensions), (1, "-")),
        (
            "an empty [3] SEQUENCE",
            support::tlv(0xa3, &support::seq(&[])),
            (0, "-"),
        ),
    ];
    for (name, tail, expected) in cases {
        let (count, stop) = read_tail(&tail);
        assert_eq!((count, stop.as_str()), expected, "{name}");
    }
}

#[test]
fn tag_number_3_other_than_a_constructed_context_3_ends_the_read() {
    // 3A_TBS_LAX rows: x509-parser reads these as extensions; §9.2 ignores them (revision 37).
    let list = support::seq(&[sct_list_extension(1)]);
    for tag in [0x83u8, 0x03, 0x23, 0x43, 0x63, 0xc3, 0xe3] {
        assert_eq!(
            read_tail(&support::tlv(tag, &list)),
            (0, format!("{tag:02x}")),
            "{tag:02x}"
        );
    }
}

#[test]
fn ignored_bytes_inside_3_and_an_extension() {
    let after_list = support::tlv(
        0xa3,
        &[support::seq(&[sct_list_extension(1)]), vec![0x05, 0x00]].concat(),
    );
    assert_eq!(read_tail(&after_list), (1, "-".to_string()));
    let oid = support::tlv(0x06, support::SCT_LIST_OID);
    let value = support::tlv(
        0x04,
        &support::tlv(0x04, &support::list(&[support::item(0, 1, &[])])),
    );
    let after_value = support::seq(&[oid.clone(), value.clone(), vec![0x05, 0x00]]);
    assert_eq!(
        read_tail(&support::tlv(0xa3, &support::seq(&[after_value]))),
        (1, "-".to_string())
    );
    let critical = support::seq(&[oid, vec![0x01, 0x01, 0xff], value]);
    let f = located(&support::certificate(&[critical]));
    assert!(f[9].contains(",1,"), "{}", f[9]);
}

#[test]
fn a_walk_that_fails_answers_canon_with_its_reason() {
    for (name, tail, reason) in [
        (
            "a stop element past the TBS",
            vec![0x05, 0x05, 0x00],
            "past its container",
        ),
        (
            "a multi-octet tag before [3]",
            vec![0x9f, 0x01, 0x00],
            "multi-octet tag",
        ),
        (
            "a two-octet critical flag",
            support::tlv(
                0xa3,
                &support::seq(&[support::seq(&[
                    support::tlv(0x06, support::SCT_LIST_OID),
                    vec![0x01, 0x02, 0x00, 0x00],
                    support::tlv(0x04, &[]),
                ])]),
            ),
            "critical",
        ),
        (
            "an indefinite length under a definite parent",
            vec![0xa3, 0x80, 0x30, 0x00, 0x00, 0x00],
            "length octet 80",
        ),
    ] {
        let reply = describe(&support::certificate_with_tail(&tail)).unwrap();
        assert!(
            reply.starts_with("CANON\t") && reply.contains(reason),
            "{name}: {reply}"
        );
    }
}
