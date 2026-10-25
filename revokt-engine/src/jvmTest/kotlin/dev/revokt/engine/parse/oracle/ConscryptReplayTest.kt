// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

/**
 * The replay against oracle 2, Conscrypt's `CertificateFactory` from `conscrypt-openjdk-uber` (spec §9.2). A difference
 * between `Cert.tbs` and Conscrypt's `getTBSCertificate()` is recorded as `CONSCRYPT_TBS`, not a violation: Conscrypt
 * verifies over the presented TBS TLV, so a difference marks an input it cannot verify. On the committed corpus its D1
 * domain is 209 inputs (it rejects every non-minimal mutant), and D2 and D6 exercise about 514.
 */
class ConscryptReplayTest : PlatformReplayTest(PlatformReplay.conscrypt, d1Floor = 200, d2Floor = 500, d6Floor = 500)
