// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//! Spec Appendix A: the probed SCT-list behaviour of x509-parser 0.18.1, one case per §9.2 sentence and per D7 SCT
//! entry. Each case builds a certificate around one SCT-list extension value and asserts what 3a reports for it.
use super::*;

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(minimal_length(content.len()));
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn u16be(n: usize) -> Vec<u8> {
    vec![(n >> 8) as u8, n as u8]
}

/// One SCT item: version, a 32-octet log id, the timestamp, no extensions, hash and signature octets, an empty
/// signature, then `extra` octets inside the item.
fn item(version: u8, timestamp: u64, extra: &[u8]) -> Vec<u8> {
    let mut body = vec![version];
    body.extend([0x11; 32]);
    body.extend(timestamp.to_be_bytes());
    body.extend([0, 0, 4, 3, 0, 0]);
    body.extend_from_slice(extra);
    [u16be(body.len()), body].concat()
}

fn list(items: &[Vec<u8>]) -> Vec<u8> {
    let all = items.concat();
    [u16be(all.len()), all].concat()
}

fn certificate(extensions: &[Vec<u8>]) -> Vec<u8> {
    let ecdsa = tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
    let name = seq(&[tlv(
        0x31,
        &seq(&[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, b"a")]),
    )]);
    let point = [vec![0x00, 0x04], vec![0x01; 64]].concat();
    let spki = seq(&[
        seq(&[
            tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
            tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        ]),
        tlv(0x03, &point),
    ]);
    let tbs = seq(&[
        tlv(0xa0, &tlv(0x02, &[2])),
        tlv(0x02, &[0x01, 0x23]),
        seq(std::slice::from_ref(&ecdsa)),
        name.clone(),
        seq(&[tlv(0x17, b"260101000000Z"), tlv(0x17, b"270101000000Z")]),
        name,
        spki,
        tlv(0xa3, &seq(extensions)),
    ]);
    seq(&[tbs, seq(&[ecdsa]), tlv(0x03, &[0, 1, 2])])
}

fn sct_extension(value: &[u8]) -> Vec<u8> {
    seq(&[tlv(0x06, SCT_LIST), tlv(0x04, value)])
}

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

fn one(value: Vec<u8>) -> String {
    reported(&[value]).0.remove(0)
}

fn pairs(timestamps: &[u64]) -> String {
    timestamps
        .iter()
        .map(|t| format!("{}@{t}", "11".repeat(32)))
        .collect::<Vec<_>>()
        .join("+")
}

#[test]
fn a_well_formed_list_yields_its_pairs() {
    assert_eq!(
        one(tlv(0x04, &list(&[item(0, 1, &[]), item(0, 2, &[])]))),
        pairs(&[1, 2])
    );
}

#[test]
fn the_declared_list_length_bounds_the_items() {
    let items = [item(0, 1, &[]), item(0, 2, &[])].concat();
    let longer = [u16be(items.len() + 1), items.clone()].concat();
    assert_eq!(
        one(tlv(0x04, &longer)),
        "E",
        "declared longer than the content: the list fails"
    );
    let shorter = [u16be(items.len() / 2), items].concat();
    assert_eq!(
        one(tlv(0x04, &shorter)),
        pairs(&[1]),
        "declared shorter: the items that fit"
    );
}

#[test]
fn a_failing_first_item_fails_the_list_and_a_later_one_ends_it() {
    let bad = [u16be(3), vec![0, 0, 0]].concat();
    assert_eq!(
        one(tlv(0x04, &list(&[bad.clone(), item(0, 2, &[])]))),
        "E",
        "malformed first SCT"
    );
    assert_eq!(one(tlv(0x04, &list(&[]))), "E", "empty list");
    assert_eq!(
        one(tlv(0x04, &list(&[u16be(0)]))),
        "E",
        "first item of length 0"
    );
    assert_eq!(
        one(tlv(
            0x04,
            &list(&[item(0, 1, &[]), u16be(0), item(0, 3, &[])])
        )),
        pairs(&[1]),
        "later item of length 0"
    );
    let truncated = list(&[item(0, 1, &[]), item(0, 2, &[])]);
    let cut = [
        u16be(truncated.len() - 3),
        truncated[2..truncated.len() - 1].to_vec(),
    ]
    .concat();
    assert_eq!(
        one(tlv(0x04, &cut)),
        pairs(&[1]),
        "truncated last SCT: the items before it"
    );
}

#[test]
fn the_inner_length_forms() {
    let l = list(&[item(0, 1, &[])]);
    let long81 = [vec![0x04, 0x81, l.len() as u8], l.clone()].concat();
    assert_eq!(one(long81), pairs(&[1]), "81 nn with nn < 0x80");
    let long84 = [vec![0x04, 0x84, 0, 0, 0, l.len() as u8], l.clone()].concat();
    assert_eq!(one(long84), pairs(&[1]), "84 00 00 00 nn");
    assert_eq!(
        one([vec![0x04, 0x80], l.clone(), vec![0, 0]].concat()),
        "E",
        "inner length 80"
    );
    assert_eq!(one([vec![0x04, 0xff], l].concat()), "E", "inner length FF");
}

#[test]
fn the_inner_identifier() {
    let l = list(&[item(0, 1, &[])]);
    assert_eq!(
        one(tlv(0x44, &l)),
        pairs(&[1]),
        "0x44: 3a's wider acceptance (3A_HEADER_LAX)"
    );
    assert_eq!(
        one([vec![0x1f, 0x04, l.len() as u8], l.clone()].concat()),
        pairs(&[1]),
        "1F 04 (3A_HEADER_LAX)"
    );
    assert_eq!(
        one(tlv(0x24, &tlv(0x04, &l))),
        "E",
        "constructed inner OCTET STRING"
    );
    assert_eq!(one(tlv(0x30, &l)), "E", "0x30, not tag number 4");
}

#[test]
fn item_contents_and_ignored_bytes() {
    assert_eq!(
        one(tlv(0x04, &list(&[item(1, 1, &[])]))),
        pairs(&[1]),
        "non-zero SCT version"
    );
    assert_eq!(
        one(tlv(0x04, &list(&[item(0, 1, &[])]))),
        pairs(&[1]),
        "zero-length signature"
    );
    let after_inner = [tlv(0x04, &list(&[item(0, 1, &[])])), vec![0xaa]].concat();
    assert_eq!(
        one(after_inner),
        pairs(&[1]),
        "bytes after the inner OCTET STRING"
    );
    let after_region = [list(&[item(0, 1, &[])]), item(0, 9, &[])].concat();
    assert_eq!(
        one(tlv(0x04, &after_region)),
        pairs(&[1]),
        "an SCT hidden after the declared region"
    );
    assert_eq!(
        one(tlv(0x04, &list(&[item(0, 1, &[0xbb, 0xcc])]))),
        pairs(&[1]),
        "bytes after the signature"
    );
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
