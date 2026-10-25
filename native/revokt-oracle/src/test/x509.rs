// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//! Spec Appendix A: the probed SCT-list behaviour of x509-parser 0.18.1, one case per §9.2 sentence and per D7 SCT
//! entry (the shared table, also run against 3b), and 3a's TBS-signature slice.
use super::*;
use crate::test_support::*;

/// 3a's SCT field for each SCT-list extension of a certificate carrying `values`, and its duplicate flag.
fn reported(values: &[Vec<u8>]) -> (Vec<String>, String) {
    let reply = describe(&certificate(
        &values.iter().map(|v| sct_extension(v)).collect::<Vec<_>>(),
    ));
    let f: Vec<&str> = reply.split('\t').collect();
    assert_eq!(f[0], "OK", "{reply}");
    let scts = f[9]
        .split(';')
        .map(|e| e.rsplit(',').next().unwrap().to_string())
        .collect();
    (scts, f[11].to_string())
}

#[test]
fn the_shared_sct_cases() {
    for c in sct_cases() {
        assert_eq!(reported(&c.values).0, c.expected, "{}", c.name);
    }
}

#[test]
fn two_sct_extensions_are_reported_each_and_flagged() {
    let (scts, duplicate) =
        reported(&[tlv(0x04, &list(&[])), tlv(0x04, &list(&[item(0, 5, &[])]))]);
    assert_eq!(
        scts,
        vec!["E".to_string(), pairs(&[5])],
        "empty list first, covered SCT second"
    );
    assert_eq!(duplicate, "1");
    assert_eq!(reported(&[tlv(0x04, &list(&[item(0, 5, &[])]))]).1, "0");
}

#[test]
fn the_tbs_signature_slice_follows_asn1_headers() {
    let reply = describe(&certificate(&[]));
    let f: Vec<&str> = reply.split('\t').collect();
    assert_eq!(f[7], "300a06082a8648ce3d040302");
    assert_eq!(
        minimal_length(0x0100_0000),
        vec![0x84, 0x01, 0x00, 0x00, 0x00]
    );
}

/// The TBS `signature` slice follows asn1-rs headers, so each element is skipped as x509-parser reads it: a `[0]` in
/// any form, an identifier in high-tag-number form and a long-form length of any size.
#[test]
fn the_tbs_signature_slice_handles_every_header_form() {
    let algorithm = tlv(
        0x30,
        &tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
    );
    let serial = tlv(0x02, &[0x01, 0x23]);
    let version = tlv(0xa0, &tlv(0x02, &[2]));
    let long5 = [vec![0x30, 0x85, 0, 0, 0, 0, 0x0a], algorithm[2..].to_vec()].concat();
    let high = [vec![0x3f, 0x10], algorithm[1..].to_vec()].concat();
    let cases = [
        (
            "primitive [0]",
            vec![vec![0x80, 0x01, 0x02], serial.clone(), algorithm.clone()],
            &algorithm,
        ),
        (
            "bf 00",
            vec![
                [vec![0xbf, 0x00], version[1..].to_vec()].concat(),
                serial.clone(),
                algorithm.clone(),
            ],
            &algorithm,
        ),
        (
            "3f 10 algorithm",
            vec![version.clone(), serial.clone(), high.clone()],
            &high,
        ),
        (
            "1f 02 serial",
            vec![
                version.clone(),
                vec![0x1f, 0x02, 0x02, 0x01, 0x23],
                algorithm.clone(),
            ],
            &algorithm,
        ),
        (
            "serial 82",
            vec![
                version.clone(),
                vec![0x02, 0x82, 0x00, 0x02, 0x01, 0x23],
                algorithm.clone(),
            ],
            &algorithm,
        ),
        (
            "serial 42",
            vec![
                version.clone(),
                vec![0x42, 0x02, 0x01, 0x23],
                algorithm.clone(),
            ],
            &algorithm,
        ),
        (
            "algorithm 85",
            vec![version.clone(), serial.clone(), long5.clone()],
            &long5,
        ),
    ];
    for (name, elements, expected) in cases {
        let tbs = tlv(
            0x30,
            &[elements.concat(), tlv(0x30, &[]).repeat(4)].concat(),
        );
        let slice = tbs_parts(&tbs)
            .unwrap_or_else(|| panic!("{name}: not sliced"))
            .algorithm;
        assert_eq!(hex(&slice), hex(expected), "{name}");
    }
}

/// The issuer, subject and SPKI are each sliced whole from their own header (#43), not cut where x509-parser stopped:
/// name values tagged `1f` and `9f`, and an SPKI with an element after its BIT STRING, all of which x509-parser accepts.
#[test]
fn the_names_and_spki_are_sliced_from_their_headers() {
    let name = |value_tag: u8| {
        seq(&[tlv(
            0x31,
            &seq(&[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(value_tag, b"a")]),
        )])
    };
    let mut elements = tbs_elements();
    let well_formed_spki = elements[6].clone();
    let spki = tlv(0x30, &[&well_formed_spki[2..], &[0x05, 0x00][..]].concat());
    elements[3] = name(0x1f);
    elements[5] = name(0x9f);
    elements[6] = spki.clone();
    let reply = describe(&certificate_from(&elements));
    let f: Vec<&str> = reply.split('\t').collect();
    assert_eq!(f[0], "OK", "{reply}");
    assert_eq!(
        [f[2], f[3], f[4]],
        [hex(&spki), hex(&elements[5]), hex(&elements[3])]
            .each_ref()
            .map(String::as_str)
    );
}
