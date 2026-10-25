// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//! Test builders shared by the 3a and 3b tests, and spec Appendix A's SCT-list cases: one per §9.2 sentence and per D7
//! SCT entry, with 3a's probed outcome. 3b expects the same outcome except on the `3A_HEADER_LAX` rows, where §9.2
//! fails the list.

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let n = content.len();
    let length = match n {
        0..=0x7f => vec![n as u8],
        0x80..=0xff => vec![0x81, n as u8],
        _ => vec![0x82, (n >> 8) as u8, n as u8],
    };
    [vec![tag], length, content.to_vec()].concat()
}

pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

pub fn u16be(n: usize) -> Vec<u8> {
    vec![(n >> 8) as u8, n as u8]
}

/// One SCT item: version, a 32-octet log id, the timestamp, no extensions, hash and signature octets, an empty
/// signature, then `extra` octets inside the item.
pub fn item(version: u8, timestamp: u64, extra: &[u8]) -> Vec<u8> {
    let mut body = vec![version];
    body.extend([0x11; 32]);
    body.extend(timestamp.to_be_bytes());
    body.extend([0, 0, 4, 3, 0, 0]);
    body.extend_from_slice(extra);
    [u16be(body.len()), body].concat()
}

pub fn list(items: &[Vec<u8>]) -> Vec<u8> {
    let all = items.concat();
    [u16be(all.len()), all].concat()
}

pub const SCT_LIST_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];

/// A v3 certificate whose TBS ends, after the SPKI, with `tail`.
pub fn certificate_with_tail(tail: &[u8]) -> Vec<u8> {
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
        tail.to_vec(),
    ]);
    seq(&[tbs, seq(&[ecdsa]), tlv(0x03, &[0, 1, 2])])
}

/// A v3 certificate carrying `extensions` in a `[3]`.
pub fn certificate(extensions: &[Vec<u8>]) -> Vec<u8> {
    certificate_with_tail(&tlv(0xa3, &seq(extensions)))
}

pub fn sct_extension(value: &[u8]) -> Vec<u8> {
    seq(&[tlv(0x06, SCT_LIST_OID), tlv(0x04, value)])
}

pub fn pairs(timestamps: &[u64]) -> String {
    let items: Vec<String> = timestamps
        .iter()
        .map(|t| format!("{}@{t}", "11".repeat(32)))
        .collect();
    items.join("+")
}

/// One Appendix A case: the SCT-list extension values of a certificate, and 3a's SCT field for each.
pub struct SctCase {
    pub name: &'static str,
    pub values: Vec<Vec<u8>>,
    pub expected: Vec<String>,
    pub header_lax: bool,
}

fn case(name: &'static str, value: Vec<u8>, expected: &str) -> SctCase {
    SctCase {
        name,
        values: vec![value],
        expected: vec![expected.to_string()],
        header_lax: false,
    }
}

pub fn sct_cases() -> Vec<SctCase> {
    let one = list(&[item(0, 1, &[])]);
    let two = [item(0, 1, &[]), item(0, 2, &[])].concat();
    let truncated = list(&[item(0, 1, &[]), item(0, 2, &[])]);
    let p1 = pairs(&[1]);
    let mut cases = vec![
        case(
            "a well-formed list",
            tlv(0x04, &list(&[item(0, 1, &[]), item(0, 2, &[])])),
            &pairs(&[1, 2]),
        ),
        case(
            "declared longer than the content",
            tlv(0x04, &[u16be(two.len() + 1), two.clone()].concat()),
            "E",
        ),
        case(
            "declared shorter: the items that fit",
            tlv(0x04, &[u16be(two.len() / 2), two].concat()),
            &p1,
        ),
        case(
            "malformed first SCT",
            tlv(
                0x04,
                &list(&[[u16be(3), vec![0; 3]].concat(), item(0, 2, &[])]),
            ),
            "E",
        ),
        case("empty list", tlv(0x04, &list(&[])), "E"),
        case("first item of length 0", tlv(0x04, &list(&[u16be(0)])), "E"),
        case(
            "later item of length 0",
            tlv(0x04, &list(&[item(0, 1, &[]), u16be(0), item(0, 3, &[])])),
            &p1,
        ),
        case(
            "truncated last SCT",
            tlv(
                0x04,
                &[
                    u16be(truncated.len() - 3),
                    truncated[2..truncated.len() - 1].to_vec(),
                ]
                .concat(),
            ),
            &p1,
        ),
        case(
            "81 nn with nn < 0x80",
            [vec![0x04, 0x81, one.len() as u8], one.clone()].concat(),
            &p1,
        ),
        case(
            "84 00 00 00 nn",
            [vec![0x04, 0x84, 0, 0, 0, one.len() as u8], one.clone()].concat(),
            &p1,
        ),
        case(
            "inner length 80",
            [vec![0x04, 0x80], one.clone(), vec![0, 0]].concat(),
            "E",
        ),
        case(
            "inner length FF",
            [vec![0x04, 0xff], one.clone()].concat(),
            "E",
        ),
        case(
            "constructed inner OCTET STRING",
            tlv(0x24, &tlv(0x04, &one)),
            "E",
        ),
        case("inner 0x30, not tag number 4", tlv(0x30, &one), "E"),
        case(
            "non-zero SCT version",
            tlv(0x04, &list(&[item(1, 1, &[])])),
            &p1,
        ),
        case("zero-length signature", tlv(0x04, &one), &p1),
        case(
            "bytes after the inner OCTET STRING",
            [tlv(0x04, &one), vec![0xaa]].concat(),
            &p1,
        ),
        case(
            "an SCT hidden after the declared region",
            tlv(0x04, &[one.clone(), item(0, 9, &[])].concat()),
            &p1,
        ),
        case(
            "bytes after the signature",
            tlv(0x04, &list(&[item(0, 1, &[0xbb, 0xcc])])),
            &p1,
        ),
    ];
    for (name, value) in [
        ("inner 0x44", tlv(0x44, &one)),
        (
            "inner 1F 04",
            [vec![0x1f, 0x04, one.len() as u8], one.clone()].concat(),
        ),
    ] {
        cases.push(SctCase {
            header_lax: true,
            ..case(name, value, &p1)
        });
    }
    cases.push(SctCase {
        name: "two SCT extensions, empty list first",
        values: vec![tlv(0x04, &list(&[])), tlv(0x04, &list(&[item(0, 5, &[])]))],
        expected: vec!["E".to_string(), pairs(&[5])],
        header_lax: false,
    });
    cases
}
