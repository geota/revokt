// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * The first §9.2 keyability clause a leaf fails, K1 to K8 in order (spec §4, §9.2). Growable; `keyabilityClause !=
 * null` exactly when `parseReason == PRODUCER_UNKEYABLE`.
 */
public enum class KeyabilityClause {
    /** K1: a TLV header in the signed TBS content, outside the opaque extension values, is not single-octet and minimal. */
    HEADER,

    /** K2: the TBS is not the profile's shape (version, unique ids, `[3]`, ignored elements, names, algorithms). */
    TBS_SHAPE,

    /** K3: the serial, or another INTEGER the profile reads, is empty, not minimal or out of range. */
    INTEGER,

    /** K4: an OID the profile reads is empty, not minimal or has a subidentifier of 2^31 or more. */
    OID,

    /** K5: a name attribute value is not a PrintableString in Go's set, valid UTF-8 or ASCII IA5String. */
    NAME,

    /** K6: a time is not `YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ` with a valid date from 1950 to 9999. */
    TIME,

    /** K7: the key is not RSA, EC on P-256, P-384 or P-521, or Ed25519 in the profile's form. */
    KEY,

    /** K8: an extension ct-go parses fatally does not match the profile's grammar for its OID. */
    EXTENSION,
}
