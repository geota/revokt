// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.AnchorSnapshot
import dev.revokt.PlatformTrust
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktTestingApi
import dev.revokt.engine.parse.PlatformRead
import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.security.cert.X509Certificate
import java.util.Objects
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.X509TrustManager

/**
 * Builds the anchor snapshot of one delegate and its [CandidateIndex] (spec §5.1 "Anchor snapshot", §4
 * `AnchorSnapshot`, §5.3): `platformTrust.anchors(delegate)`, that is `getAcceptedIssuers()`, each anchor read through
 * the §9.2 read fallback ([PlatformRead]), then the index over the bytes read under `platformTrust.canonicalSubject`, so
 * a `PlatformTrust` override relates certificates by its own name equality (§3).
 *
 * - **Fails loudly.** A throwing `getAcceptedIssuers()`, a null or empty anchor set, a null anchor, and a set none of
 *   whose anchors revokt parses (an index that could only answer `NO_ISSUER`) throw `IllegalStateException`. What a
 *   caller does with that is its own (§11's 0.2 row: `start()` succeeds and `Evaluator.evaluate` throws until an index
 *   exists). A fatal error ([isFatal]) is rethrown as it is.
 * - **An anchor whose `getEncoded()` throws** is left out, with its platform encoding: it has no bytes to read.
 * - **The snapshot:** `id` from a process-wide counter, `createdMillis` the caller's [nowMillis]; `anchors` every other
 *   anchor's bytes read in the platform's order, duplicates and anchors revokt cannot parse kept (the index drops
 *   them), and beside each its `getEncoded()` for the PKIX fallback; `sha256` over the distinct bytes read, sorted as
 *   unsigned bytes and concatenated, so neither the platform's order nor a duplicate changes it.
 */
@RevoktInternalApi
public object AnchorSnapshots {
    private val ids = AtomicLong()

    @OptIn(RevoktTestingApi::class)
    @Suppress("TooGenericExceptionCaught") // a delegate's getAcceptedIssuers() can throw anything; §5.1 makes it an ISE
    public fun build(
        platformTrust: PlatformTrust,
        delegate: X509TrustManager,
        nowMillis: Long,
    ): IndexedSnapshot {
        val certificates: List<X509Certificate>? =
            try {
                platformTrust.anchors(delegate)
            } catch (t: Throwable) {
                if (isFatal(t)) throw t
                restoreInterrupt(t)
                throw IllegalStateException("getAcceptedIssuers() threw; no anchor snapshot (spec §5.1)", t)
            }
        check(!certificates.isNullOrEmpty()) { "the delegate has no trust anchors; no anchor snapshot (spec §5.1)" }
        check(certificates.none { Objects.isNull(it) }) { "the delegate's anchor set holds a null; no anchor snapshot" }
        val reads = certificates.mapNotNull { PlatformRead.of(it) }
        // The index build itself does not throw: an anchor the parser rejects is dropped, and a canonicaliser that
        // throws or returns null gives "no canonical match" (Cert.of).
        val index = CandidateIndex(reads.map { it.read }, platformTrust::canonicalSubject)
        check(index.store.isNotEmpty()) {
            "none of the delegate's ${certificates.size} trust anchors parses; no anchor snapshot (spec §5.1)"
        }
        val snapshot =
            AnchorSnapshot
                .Builder()
                .id(ids.incrementAndGet())
                .sha256(digest(reads.map { it.read.toByteString() }).toByteArray())
                .anchors(reads.map { it.read })
                .platformEncodings(reads.map { it.encoded })
                .createdMillis(nowMillis)
                .build()
        return IndexedSnapshot(snapshot, index)
    }

    /** SHA-256 of the distinct [ders], sorted as unsigned bytes and concatenated. */
    internal fun digest(ders: List<ByteString>): ByteString {
        val buffer = Buffer()
        ders.distinct().sorted().forEach { buffer.write(it) }
        return buffer.sha256()
    }
}
