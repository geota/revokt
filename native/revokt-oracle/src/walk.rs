// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//! Oracle 3b's TBS walk (spec §9.2), written from the spec independently of revokt. It reads the re-encoded TBS
//! structurally strict, with `[0]` holding exactly its INTEGER and the tail under the trailing-element rule, slices the
//! fields, and applies the SCT-list rule to each SCT-list extension.

type Walked<T> = Result<T, String>;

/// The SCT-list extension's OID content, 1.3.6.1.4.1.11129.2.4.2.
const SCT_LIST: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];

/// One extension as the walk slices it.
pub struct Extension<'a> {
    pub oid: &'a [u8],
    pub critical: bool,
    pub value: &'a [u8],
}

/// The fields of one TBS. `stop` is the identifier octet of the element that ended the tail read, if one did.
pub struct Fields<'a> {
    pub serial: &'a [u8],
    pub spki: &'a [u8],
    pub subject: &'a [u8],
    pub issuer: &'a [u8],
    pub extensions: Vec<Extension<'a>>,
    pub stop: Option<u8>,
}

/// One TLV: the offsets of its first octet, its content and its end.
struct Element {
    start: usize,
    content: usize,
    end: usize,
}

/// A strict reader over `b[pos..limit]`: one-octet identifiers and definite lengths of up to four octets, non-minimal
/// forms accepted (§9.2 accepts non-minimal definite lengths for extraction).
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
    limit: usize,
}

impl<'a> Reader<'a> {
    fn peek(&self) -> Option<u8> {
        (self.pos < self.limit).then(|| self.b[self.pos])
    }

    fn next(&mut self) -> Walked<Element> {
        let start = self.pos;
        let tag = self.peek().ok_or("missing element")?;
        if tag & 0x1f == 0x1f {
            return Err(format!("multi-octet tag at {start}"));
        }
        let first = *self
            .b
            .get(start + 1)
            .filter(|_| start + 1 < self.limit)
            .ok_or("missing length")?;
        let count = match first {
            0x00..=0x7f => 0,
            0x81..=0x84 => (first & 0x7f) as usize,
            _ => return Err(format!("length octet {first:02x} at {start}")),
        };
        let content = start + 2 + count;
        if content > self.limit {
            return Err("length octets past the end".into());
        }
        let length = if count == 0 {
            first as usize
        } else {
            self.b[start + 2..content]
                .iter()
                .fold(0usize, |n, &o| n << 8 | o as usize)
        };
        if length > self.limit - content {
            return Err(format!("element at {start} past its container"));
        }
        self.pos = content + length;
        Ok(Element {
            start,
            content,
            end: self.pos,
        })
    }

    fn expect(&mut self, tag: u8, what: &str) -> Walked<Element> {
        if self.peek() != Some(tag) {
            return Err(format!("expected {what} ({tag:02x}) at {}", self.pos));
        }
        self.next()
    }

    fn inside(&self, e: &Element) -> Reader<'a> {
        Reader {
            b: self.b,
            pos: e.content,
            limit: e.end,
        }
    }

    fn tlv(&self, e: &Element) -> &'a [u8] {
        &self.b[e.start..e.end]
    }

    fn content(&self, e: &Element) -> &'a [u8] {
        &self.b[e.content..e.end]
    }
}

/// Walks the re-encoded TBS TLV `tbs`.
pub fn walk(tbs: &[u8]) -> Walked<Fields<'_>> {
    let mut outer = Reader {
        b: tbs,
        pos: 0,
        limit: tbs.len(),
    };
    let certificate_info = outer.expect(0x30, "tbsCertificate")?;
    let mut r = outer.inside(&certificate_info);
    if r.peek() == Some(0xa0) {
        let version = r.next()?;
        let mut inner = r.inside(&version);
        inner.expect(0x02, "version INTEGER")?;
        if inner.peek().is_some() {
            return Err("bytes after the version INTEGER".into());
        }
    }
    let serial = r.expect(0x02, "serialNumber")?;
    r.expect(0x30, "signature")?;
    let issuer = r.expect(0x30, "issuer")?;
    let validity = r.expect(0x30, "validity")?;
    let mut times = r.inside(&validity);
    for _ in 0..2 {
        match times.peek() {
            Some(0x17 | 0x18) => times.next()?,
            _ => return Err("validity holds two times".into()),
        };
    }
    if times.peek().is_some() {
        return Err("bytes after the validity times".into());
    }
    let subject = r.expect(0x30, "subject")?;
    let spki = r.expect(0x30, "subjectPublicKeyInfo")?;
    let (extensions, stop) = tail(&mut r)?;
    Ok(Fields {
        serial: r.content(&serial),
        spki: r.tlv(&spki),
        subject: r.tlv(&subject),
        issuer: r.tlv(&issuer),
        extensions,
        stop,
    })
}

/// The TBS tail under the trailing-element rule: `[1]` then `[2]`, each in either form, then a constructed `[3]`. The
/// first element that does not fit ends the read; it must be a well-formed TLV, and it and everything after it are
/// ignored unparsed. After `[3]`, and inside `[3]` after the Extensions SEQUENCE, the rest is ignored unparsed.
fn tail<'a>(r: &mut Reader<'a>) -> Walked<(Vec<Extension<'a>>, Option<u8>)> {
    for unique_id in [0x81, 0x82] {
        if r.peek().map(|t| t & !0x20) == Some(unique_id) {
            r.next()?;
        }
    }
    match r.peek() {
        None => return Ok((Vec::new(), None)),
        Some(0xa3) => {}
        Some(other) => {
            r.next()?;
            return Ok((Vec::new(), Some(other)));
        }
    }
    let wrapper = r.next()?;
    let list = r.inside(&wrapper).expect(0x30, "Extensions")?;
    let mut items = r.inside(&list);
    let mut out = Vec::new();
    while items.peek().is_some() {
        let extension = items.expect(0x30, "Extension")?;
        let mut e = items.inside(&extension);
        let oid = e.expect(0x06, "extnID")?;
        let critical = if e.peek() == Some(0x01) {
            let flag = e.next()?;
            match e.content(&flag) {
                [octet] => *octet != 0,
                _ => return Err("critical is not one octet".into()),
            }
        } else {
            false
        };
        let value = e.expect(0x04, "extnValue")?;
        out.push(Extension {
            oid: e.content(&oid),
            critical,
            value: e.content(&value),
        });
    }
    Ok((out, None))
}

/// Whether `oid` is the SCT-list extension's.
pub fn is_sct_list(oid: &[u8]) -> bool {
    oid == SCT_LIST
}

fn u16_at(b: &[u8], p: usize) -> usize {
    (b[p] as usize) << 8 | b[p + 1] as usize
}

/// The §9.2 SCT-list rule on one extension value: the kept items' (log id, timestamp), or None when the list fails.
pub fn sct_pairs(value: &[u8]) -> Option<Vec<(&[u8], u64)>> {
    let inner = inner_octet_string(value)?;
    if inner.len() < 2 || u16_at(inner, 0) > inner.len() - 2 {
        return None;
    }
    let region = &inner[2..2 + u16_at(inner, 0)];
    let mut pairs = Vec::new();
    let mut p = 0;
    while let Some((pair, next)) = sct_item(region, p) {
        pairs.push(pair);
        p = next;
    }
    (!pairs.is_empty()).then_some(pairs)
}

/// The content of the inner OCTET STRING: identifier `04`, then a short length or `81`–`FE` with that many octets
/// (leading zeros allowed, the value below 2^64 and within the extension value); bytes after it are ignored.
fn inner_octet_string(value: &[u8]) -> Option<&[u8]> {
    let (&identifier, rest) = value.split_first()?;
    let (&first, rest) = rest.split_first()?;
    if identifier != 0x04 || first == 0x80 || first == 0xff {
        return None;
    }
    let (octets, rest) = if first < 0x80 {
        (std::slice::from_ref(&first), rest)
    } else {
        let count = (first & 0x7f) as usize;
        (rest.get(..count)?, &rest[count..])
    };
    let significant: Vec<u8> = octets.iter().copied().skip_while(|&o| o == 0).collect();
    if significant.len() > 8 {
        return None;
    }
    let length = significant.iter().fold(0u64, |n, &o| n << 8 | o as u64);
    rest.get(..usize::try_from(length).ok()?)
}

/// One SCT item at `r[p..]`: a `u16`-prefixed item within the region holding version, a 32-octet log id, the u64
/// timestamp, `u16`-prefixed extensions, two algorithm octets and a `u16`-prefixed signature; any bytes after the
/// signature are ignored. Returns the pair and the offset after the item.
fn sct_item(r: &[u8], p: usize) -> Option<((&[u8], u64), usize)> {
    let length = u16_at(r.get(p..p + 2)?, 0);
    let item = r.get(p + 2..p + 2 + length)?;
    let log_id = item.get(1..33)?;
    let timestamp = u64::from_be_bytes(item.get(33..41)?.try_into().ok()?);
    let prefixed = |q: usize| -> Option<usize> { Some(q + 2 + u16_at(item.get(q..q + 2)?, 0)) };
    let after_extensions = prefixed(41)?;
    let after_signature = prefixed(after_extensions + 2)?;
    (after_signature <= item.len()).then_some(((log_id, timestamp), p + 2 + length))
}
