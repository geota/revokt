# The keyability audit table

Spec §9.2 (revision 35): "The table is the proof." For each clause K1–K8 of the conservative keyability profile
(`dev.revokt.engine.parse.Keyability`, `KeyabilityKey`, `KeyabilityValues`, `ExtensionGrammars`), this table cites the
fatal return sites of the producer's strict parse that the clause covers. If a leaf satisfies every clause, then:

1. certificate-transparency-go's strict parse succeeds;
2. no `lax` retry runs, and zcrypto is never reached;
3. the stdlib re-parse keys `rawSerial`, and the SPKI recorded is `rawSpki` (D8).

Oracle 4 and the D8 replay (`ProducerD8Test`) test the table; they do not replace it. A pin bump re-runs this audit
as a diff of the files below.

## Pins

| Component | Pin | File |
|---|---|---|
| `mozilla/crlite` `go/types` | `v0.0.0-20260803162627-008299826177` (`0082998`) | `types.go` |
| certificate-transparency-go | `v1.3.2` | `x509/x509.go`, `asn1/asn1.go` |
| zcrypto | `v0.0.0-20260109180747-df961ee46a6c` (only reached when ct-go returns no certificate) | — |
| Go | 1.27.3 (`encoding/asn1` for the serial re-parse) | — |

The pins are `native/producer-oracle/go.mod`. Line numbers below are at these pins.

## The producer path

- **Parse.** `types.ParseCertificate` (`types.go:36–47`) keeps ct-go's certificate whenever `ctx509.ParseCertificate`
  returns one, and falls back to zcrypto only when it returns none. The table therefore covers ct-go's strict parse;
  the profile never relies on `lax` or zcrypto.
- **Keys.** `NewSerialFromCertificate` (`types.go:99`) → `NewSerialFromTBS` (`types.go:426–433`) re-parses the raw TBS
  with stdlib `encoding/asn1` into `tbsCertWithRawSerial { Raw, Version RawValue (explicit [0], optional), SerialNumber
  RawValue }` (`types.go:411–415`) and keys `SerialNumber.Bytes`. The SPKI is ct-go's `RawSubjectPublicKeyInfo`
  (`x509.go:1838`), the TBS's SPKI TLV.
- **Input.** Oracle 4 parses `canon(encoded)` (spec §9.2), so the outer `signatureAlgorithm` equals the TBS's
  byte for byte (`x509.go:1831–1833`, "mismatching signature algorithm identifiers"), and the BIT STRING has zero
  unused bits.

## The table

| Clause | What it requires | Fatal returns it covers |
|---|---|---|
| **K1 headers** | Every TLV header in the TBS content outside the opaque values has a single-octet tag and a minimal definite length; the walk descends into constructed elements and the `extnValue` of each extension on K8's list | `asn1.go:572` `parseTagAndLength`: high-tag form, `:600`, `:618` "truncated tag or length", `:612` "indefinite length found (not DER)", `:626` "length too large", `:633` "superfluous leading zeros in length", `:639` "non-minimal length"; `:937` "data truncated" (a length past its container). K1's walk reads every header of every element it descends into, so a header that fits its container and is minimal never reaches these returns. These run on every element ct-go's struct walk reads: `ParseCertificate` (`x509.go:2131`, strict `asn1.Unmarshal` of `certificate`; the `lax` retry at `:2137` never runs when strict succeeds), the name re-parses (`x509.go:1856–1875`), each extension parser (`x509.go:1885–2063`) and `parsePublicKey` (`x509.go:1343`). The stdlib re-parse reads the TBS, `[0]` and serial headers with stdlib `parseTagAndLength`, also minimal-only |
| **K2 TBS shape** | `[0]` absent or `00`/`01`/`02` (`02` with `[3]`); no unique ids; `[3]` holds one non-empty `Extensions`; no ignored element; AlgorithmIdentifier = OID + at most one TLV; names `SEQUENCE OF SET OF SEQUENCE { OID, value }`; Extension = OID, optional BOOLEAN, primitive OCTET STRING; BIT STRINGs primitive with Go's padding rule | `tbsCertificate` (`x509.go:190–202`) field by field: `asn1.go:932` "tags don't match" for any element out of place; `[0]` through `parseInt64` (`asn1.go:126`) with `checkInteger` (`:108`, `:119`); `pkix.AlgorithmIdentifier` (OID, optional RawValue); the RDNSequence (`x509.go:1856–1875`, trailing data `:1865`, `:1875`); `pkix.Extension` (OID, optional bool, `[]byte`); `parseBitString` (`asn1.go:227`: `:229` "zero length BIT STRING", `:236` "invalid padding bits"). Explicit tags: `asn1.go:840` "explicit tag has no child", `:853` a zero-length explicit tag, `:865` "explicitly tagged member didn't match" (`[0]` holding exactly one INTEGER, `[3]` exactly one SEQUENCE). ct-go silently ignores bytes after the last struct field of a SEQUENCE (`asn1.go:1049–1052`), so the trailing-element rule's ignored bytes are not a ct-go failure; K2 bans them because revokt and the JDK then read different extensions than ct-go may. Unique ids are banned for the same reason |
| **K3 integers** | The serial is non-empty and minimal, with any sign and length; every other INTEGER is non-empty, minimal and in its clause's range | `parseBigInt` (`asn1.go:167`) → `checkInteger` (`:108`, `:119` "integer not minimally-encoded"); the re-parse keys the serial's bytes as presented, so `rawSerial` equals them byte for byte |
| **K4 OIDs** | Non-empty, minimal subidentifiers each below 2^31 (the first included), the last terminated: algorithms, curves, attribute types, extension IDs, EKU purposes, policy identifiers, access methods | `parseObjectIdentifier` (`asn1.go:287`) → `parseBase128Int` (`:340`; `:347`, `:358` "base 128 integer too large", the 31-bit limit; `:363` "truncated base 128 integer"). ct-go has no leading-`80` check; K4's minimality is stricter (a D8-gap entry by rule) |
| **K5 names** | Each attribute value is a PrintableString in Go's set with `*` and `&`, valid UTF-8, or an ASCII IA5String | `parsePrintableString` (`asn1.go:435`) with `isPrintable(b, allowAsterisk, allowAmpersand)` (`:475`); `parseUTF8String` (`:523`, `utf8.Valid`); `parseIA5String` (`:500`). The strict name parse fails on any other content; its `lax` retry (`x509.go:1859`, `:1869`) never runs |
| **K6 times** | `YYMMDDHHMMSSZ`, `YYYYMMDDHHMMSSZ`, years 1950–9999, a real date, at most 23:59:59 | `parseUTCTime` (`asn1.go:369`) and `parseGeneralizedTime` (`:397`): Go `time.Parse` with the exact layouts, then a re-serialisation check ("day out of range" and similar) |
| **K7 key** | SPKI = AlgorithmIdentifier + BIT STRING, zero unused bits; RSA with NULL parameters and a minimal `RSAPublicKey { n > 0, 0 < e < 2^31 }`, headers minimal, nothing after; EC P-256/384/521 with an uncompressed point below p and on the curve; Ed25519 with absent parameters and 32 octets | `parsePublicKey` (`x509.go:1343`). RSA: `:1350` missing NULL (non-fatal, K7 stricter); strict `asn1.Unmarshal` of the key, whose `lax` retry at `:1372` never runs when headers and INTEGERs are minimal; `:1379` trailing data; `:1386` exponent not positive. EC: `:1435` parameters not a named-curve OID; `:1438` trailing data after the parameters; `:1442` unsupported curve; `:1446` `elliptic.Unmarshal` (`04`, exact length, coordinates below p, on the curve). Ed25519: `:1454` (no size check; K7 stricter). Any other algorithm is outside K7, so a parser ct-go adds later cannot break D8 |
| **K8 extensions** | Each extension on K8's list matches its grammar (`ExtensionGrammars`); nameConstraints and subjectInfoAccess outside by presence; every BOOLEAN anywhere in their values `00` or `FF` | keyUsage `x509.go:1890–1896` (`:1894` the strict `BitString`, `:1896` trailing data); basicConstraints `:1907–1913` (`:1911`; `parseBool` `asn1.go:83`, `:85`, `:98` "invalid boolean"; `int` via `parseInt64`, `asn1.go:131–133` "integer too large"); subjectAltName `:1923` → `forEachSAN` (`:1574` the outer element, `:1576` trailing data, `:1579` "bad SAN sequence", `:1587` each name; URI parsing `:1608`, `:1612`: K8 admits no URI); nameConstraints `:1934` (outside by presence); cRLDistributionPoints `:1941` → `parseDistributionPoints` (`:1536`); authorityKeyIdentifier `:1949`, `:1951`; extKeyUsage `:1973` (its `lax` retry never runs: K8 requires every element to be an OID and K4 makes each minimal), `:1978`; subjectKeyIdentifier `:1994`, `:1996`; certificatePolicies `:2004`, `:2006`; authorityInfoAccess `:2021`, `:2023`; subjectInfoAccess `:2044`, `:2046` (outside by presence). The `SEQUENCE OF` and struct reads behind them: `asn1.go:678` "sequence tag mismatch" (each element's tag), `:682` "truncated sequence", `:772` "sequence truncated" (a required field missing, such as an access location or a policy identifier), `:932` "tags don't match". The critical flag is `parseBool`. The opaque extensions (the SCT list, the poison, RFC 3779 and unknown ones) have no fatal return: the SCT branch and RPKI parsers add non-fatal errors, and unknown extensions are only recorded |

## Where the profile is stricter than the producer

These leaves are D8-gap entries by rule: the producer keys them, and the profile does not query them.

- ct-go keeps policy qualifiers and other `RawValue` fields without parsing their content. K1 walks every K8-listed
  value whole, so a non-minimal header deep inside a qualifier is outside the profile (the replay's `HEADER/ct` class).
- K4 rejects a leading `80` subidentifier; ct-go's `parseBase128Int` accepts it.
- K5 admits three string types; ct-go also parses T61String, BMPString and others.
- K7 drops P-224, RSA keys ct-go keys with a non-fatal error, and every algorithm ct-go keys without inspecting it.
- K8 drops trailing elements, other GeneralName forms and an empty SAN, EKU or AIA, which ct-go ignores or treats as
  non-fatal; a negative `pathLen` and one from 2^31 to 8 octets, which ct-go keys (over 8 octets is fatal there,
  `asn1.go:131–133`); non-ASCII `dNSName`, `rfc822Name` and URI content, which ct-go never checks; and an empty
  distribution-point `fullName`.
