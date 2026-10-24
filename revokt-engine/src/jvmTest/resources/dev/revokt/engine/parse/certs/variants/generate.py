# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# Regenerates the structural variants of letsencrypt.org-2.der used by CertificateParserJdkTest (spec §9.2, revision
# 33): python3 -I generate.py ../letsencrypt.org-2.der .
# Part one is the PR #16 Independent review's set, part two the JDK boundary probe.

# --- part one ---
import sys, hashlib
src, out = sys.argv[1], sys.argv[2]
d = open(src, 'rb').read()
def hdr(b, i):
    t = b[i]; l = b[i+1]
    if l < 0x80: return t, i+2, l
    n = l & 0x7f; v = int.from_bytes(b[i+2:i+2+n], 'big'); return t, i+2+n, v
def L(n):
    if n < 0x80: return bytes([n])
    s = n.to_bytes((n.bit_length()+7)//8, 'big'); return bytes([0x80|len(s)]) + s
def tlv(t, c): return bytes([t]) + L(len(c)) + c
def kids(b, s, e):
    r = []
    while s < e:
        t, cs, l = hdr(b, s); r.append(b[s:cs+l]); s = cs+l
    return r
_, cs, l = hdr(d, 0); tbs, alg, sig = kids(d, cs, cs+l)
_, ts, tl = hdr(tbs, 0); els = kids(tbs, ts, ts+tl)
NUL = b'\x05\x00'
ext3 = els[7]; _, s3, l3 = hdr(ext3, 0); seq = ext3[s3:s3+l3]
_, ss, sl = hdr(seq, 0); exts = kids(seq, ss, ss+sl)
_, es, el = hdr(exts[0], 0); e0 = kids(exts[0], es, es+el)
def cert(tels): return tlv(0x30, tlv(0x30, b''.join(tels)) + alg + sig)
v = {
 'tbs-null-after-extensions': els + [NUL],
 'tbs-null-before-extensions': els[:7] + [NUL, ext3],
 'ext3-null-after-sequence': els[:7] + [tlv(0xa3, seq + NUL)],
 'extension-null-after-extnvalue': els[:7] + [tlv(0xa3, tlv(0x30, tlv(0x30, b''.join(e0) + NUL) + b''.join(exts[1:])))],
 'uid-constructed-a1': els[:7] + [bytes([0xa1,2,0,1]), ext3],
 'uid-82-then-81': els[:7] + [bytes([0x82,2,0,1]), bytes([0x81,2,0,1]), ext3],
}
for k, tels in v.items():
    b = cert(tels); open(f'{out}/{k}.der', 'wb').write(b)
    print(k, len(b), hashlib.sha256(b).hexdigest()[:16], 'TBS tail:', b[len(b)-len(alg)-len(sig)-12:len(b)-len(alg)-len(sig)].hex())


# --- part two ---
import sys
src, out = sys.argv[1], sys.argv[2]
d = open(src, 'rb').read()
def hdr(b, i):
    t = b[i]; l = b[i+1]
    if l < 0x80: return t, i+2, l
    n = l & 0x7f; v = int.from_bytes(b[i+2:i+2+n], 'big'); return t, i+2+n, v
def L(n):
    if n < 0x80: return bytes([n])
    s = n.to_bytes((n.bit_length()+7)//8, 'big'); return bytes([0x80|len(s)]) + s
def tlv(t, c): return bytes([t]) + L(len(c)) + c
def kids(b, s, e):
    r = []
    while s < e:
        t, cs, l = hdr(b, s); r.append(b[s:cs+l]); s = cs+l
    return r
def content(x): _, s, l = hdr(x, 0); return x[s:s+l]
_, cs, l = hdr(d, 0); tbs, alg, sig = kids(d, cs, cs+l)
_, ts, tl = hdr(tbs, 0); els = kids(tbs, ts, ts+tl)
ver, ser, sa, iss, val, sub, spki, ext3 = els
NUL = b'\x05\x00'
def cert(tels, outer=None): 
    body = tlv(0x30, b''.join(tels)) + alg + sig
    return tlv(0x30, body if outer is None else outer(body))
v = {
 'cert-null-after-signature': (None, lambda body: body + NUL),
 'validity-null-after-times': ([ver, ser, sa, iss, tlv(0x30, content(val) + NUL), sub, spki, ext3], None),
 'version-wrapper-trailing': ([tlv(0xa0, content(ver) + NUL), ser, sa, iss, val, sub, spki, ext3], None),
 'tbs-junk-after-extensions': (els + [b'\xff\xff\xff'], None),
 'tbs-junk-before-extensions': (els[:7] + [b'\xff\xff', ext3], None),
 'ext3-primitive-83': (els[:7] + [b'\x83\x00'], None),
 'extensions-seq-with-null-element': ([ver, ser, sa, iss, val, sub, spki, tlv(0xa3, tlv(0x30, content(content(ext3)) + NUL))], None),
 'extension-null-between-oid-and-value': (None, None),
 'uid-81-twice': (els[:7] + [b'\x81\x02\x00\x01', b'\x81\x02\x00\x01', ext3], None),
 'uid-a2-constructed': (els[:7] + [b'\xa2\x02\x00\x01', ext3], None),
 'tbs-two-ext3': (els + [ext3], None),
 'spki-then-null-then-uid': (els[:7] + [NUL, b'\x81\x02\x00\x01', ext3], None),
}
# extension with NULL between OID and value
seqc = content(content(ext3)); exts = kids(seqc, 0, len(seqc)); e0 = kids(content(exts[0]), 0, len(content(exts[0])))
v['extension-null-between-oid-and-value'] = (els[:7] + [tlv(0xa3, tlv(0x30, tlv(0x30, e0[0] + NUL + b''.join(e0[1:])) + b''.join(exts[1:])))], None)
for k, (tels, outer) in v.items():
    b = cert(els if tels is None else tels, outer)
    open(f'{out}/{k}.der', 'wb').write(b)
