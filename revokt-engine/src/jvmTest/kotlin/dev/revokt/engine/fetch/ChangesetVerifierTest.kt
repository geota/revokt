// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.verify.ContentSignature
import dev.revokt.engine.verify.X5uChainFixture
import dev.revokt.verify.JcaFixtures
import okio.ByteString.Companion.toByteString
import java.security.KeyPair
import java.security.PrivateKey
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * The changeset signature check (spec §7.1, revision 56, #191) over the §9 rows: a changeset whose first `signatures`
 * entry fails and whose second verifies installs; one with 5 entries, or whose every entry lacks `mode`, is `FAILED` at
 * `SIGNATURE`; two entries sharing one `x5u` URL fetch it once; one whose `metadata` holds only `signature`, or an
 * empty `signatures`, is `FAILED` at `SIGNATURE`; an entry with no `mode` is skipped; a P-256 leaf verifies. Plus the
 * rules around them: the failed URL not retried, the last tried entry's failure, the stages and the backoff. Chains and
 * signatures are #126's fixture's, made by the test JDK.
 */
internal class ChangesetVerifierTest : X5uChainFixture() {
    private val host = "https://content-signature-2.cdn.mozilla.net/g/chains"
    private val a = "$host/a.chain"
    private val b = "$host/b.chain"
    private val ts = 1793980622465
    private val recordsText =
        listOf(
            """{"id":"r1","last_modified":1793980622465,"channel":"default"}""",
            """{"id":"r2","last_modified":1793980622000,"channel":"default"}""",
        )
    private val records = recordsText.map(::json)

    private fun pem(chain: List<ByteArray>): String =
        chain.joinToString("") {
            "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(it) +
                "\n-----END CERTIFICATE-----\n"
        }

    private val goodPem = pem(chain())

    /** Autograph's signature over [records] at [ts] under [key]: raw `r ‖ s`, unpadded base64url. */
    private fun sign(
        key: PrivateKey = leafKey.private,
        over: List<JsonObject> = records,
    ): String {
        val payload =
            "Content-Signature:\u0000".encodeToByteArray() + checkNotNull(ContentSignature.recordsJson(over, ts))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
            JcaFixtures.sign("SHA384withECDSAinP1363Format", key, payload),
        )
    }

    private val good = sign()
    private val bad = sign(over = records.take(1))

    private fun entry(
        x5u: String? = a,
        signature: String? = good,
        mode: String? = ContentSignature.MODE,
    ) = SignatureEntry(signature, x5u, mode)

    /** A fetcher serving [bodies] by URL, anything else 404, each response with [headers]. */
    private fun served(
        bodies: Map<String, String> = mapOf(a to goodPem, b to goodPem),
        vararg headers: Pair<String, String>,
    ) = ScriptedFetcher { request ->
        bodies[request.url]?.let { ok(it, *headers) } ?: response(404, headers = arrayOf(*headers))
    }

    private fun verifier(
        fetcher: ScriptedFetcher,
        now: Long = NOW,
    ) = ChangesetVerifier(client(fetcher), pinned, verifier, now)

    private fun verify(
        vararg entries: SignatureEntry,
        fetcher: ScriptedFetcher = served(),
    ): ChangesetVerification = verifier(fetcher).verify(Changeset(ts, records, entries.toList()), records)

    private fun ChangesetVerification.assertVerified(index: Int): ChangesetVerification.Verified {
        val verified = assertIs<ChangesetVerification.Verified>(this, "$this")
        assertEquals(index, verified.index)
        return verified
    }

    private fun ChangesetVerification.assertFailed(
        failure: SignatureFailure,
        index: Int?,
        stage: SyncStage = SyncStage.SIGNATURE,
        outcome: SyncOutcome = SyncOutcome.FAILED,
    ): ChangesetVerification.Failed {
        val failed = assertIs<ChangesetVerification.Failed>(this, "$this")
        assertEquals(
            listOf(failure, index, stage, outcome),
            listOf(failed.failure, failed.index, failed.stage, failed.outcome),
            failed.detail,
        )
        return failed
    }

    @Test
    fun `one entry that verifies is accepted, with its x5u body as served`() {
        val fetcher = served()
        val verified = verify(entry(), fetcher = fetcher).assertVerified(0)
        assertEquals(good, verified.entry.signature)
        assertContentEquals(goodPem.encodeToByteArray(), verified.x5uBody.toByteArray())
        assertContentEquals(leafKey.public.encoded, verified.path.leafSpki)
        assertEquals(listOf(a), fetcher.requests.map { it.url })
    }

    @Test
    fun `a first entry that fails and a second that verifies installs`() {
        verify(entry(signature = bad), entry(x5u = b)).assertVerified(1)
        // The first entry's x5u is missing (404) and the second's verifies.
        verify(entry(x5u = "$host/missing.chain"), entry(x5u = b)).assertVerified(1)
        // The first entry's chain does not validate.
        val broken = mapOf(a to pem(chain(root = intermediate())), b to goodPem)
        verify(entry(), entry(x5u = b), fetcher = served(broken)).assertVerified(1)
    }

    @Test
    fun `5 entries is FAILED at SIGNATURE with nothing fetched, and the 4th of 4 is tried`() {
        val fetcher = served()
        verify(*Array(5) { entry() }, fetcher = fetcher).assertFailed(SignatureFailure.TOO_MANY_SIGNATURES, null)
        assertEquals(0, fetcher.requests.size)
        // At the cap every entry is tried: three that fail, then one that verifies.
        verify(entry(signature = bad), entry(signature = bad), entry(signature = bad), entry()).assertVerified(3)
        assertEquals(4, ChangesetVerifier.MAX_SIGNATURES)
    }

    @Test
    fun `entries all lacking mode, signature or x5u, or of another mode, are FAILED at SIGNATURE, unfetched`() {
        val fetcher = served()
        verify(
            entry(mode = null),
            entry(mode = null),
            fetcher = fetcher,
        ).assertFailed(SignatureFailure.NONE_TRIED, null)
        verify(
            entry(mode = "p256ecdsa"),
            entry(mode = "P384ECDSA"),
            entry(signature = null),
            entry(x5u = null),
            fetcher = fetcher,
        ).assertFailed(SignatureFailure.NONE_TRIED, null)
        assertEquals(0, fetcher.requests.size)
    }

    @Test
    fun `an entry with no mode is skipped`() {
        val fetcher = served()
        // The skipped entry names b; only a is fetched.
        verify(entry(x5u = b, mode = null), entry(), fetcher = fetcher).assertVerified(1)
        assertEquals(listOf(a), fetcher.requests.map { it.url })
    }

    @Test
    fun `metadata with only signature, or an empty signatures, is FAILED at SIGNATURE`() {
        val signature = """{"x5u":"$a","mode":"p384ecdsa","signature":"$good"}"""
        for (metadata in listOf(
            """{"signature":$signature}""",
            """{"signature":$signature,"signatures":[]}""",
            """{"signatures":{"0":$signature}}""",
            """{}""",
        )) {
            val fetcher =
                ScriptedFetcher { request ->
                    if ("changeset" in
                        request.url
                    ) {
                        ok(body(metadata))
                    } else {
                        ok(goodPem)
                    }
                }
            val changeset = client(fetcher).fetchChangeset(ts, null).assertOk()
            verifier(fetcher).verify(changeset, records).assertFailed(SignatureFailure.NO_SIGNATURES, null)
            assertEquals(1, fetcher.requests.size, "only the changeset is fetched: $metadata")
        }
        // A valid metadata.signature beside a signatures[] whose one entry fails is refused: signature is not read.
        val fetcher =
            ScriptedFetcher { request ->
                val bad = """{"x5u":"$a","mode":"p384ecdsa","signature":"$bad"}"""
                if ("changeset" in
                    request.url
                ) {
                    ok(body("""{"signature":$signature,"signatures":[$bad]}"""))
                } else {
                    ok(goodPem)
                }
            }
        val changeset = client(fetcher).fetchChangeset(ts, null).assertOk()
        verifier(fetcher).verify(changeset, records).assertFailed(SignatureFailure.CONTENT_SIGNATURE, 0)
        // And the same signature in signatures[] verifies, through the client's parse.
        val parsed =
            ScriptedFetcher { request ->
                if ("changeset" in request.url) ok(body("""{"signatures":[$signature]}""")) else ok(goodPem)
            }
        verifier(parsed).verify(client(parsed).fetchChangeset(ts, null).assertOk(), records).assertVerified(0)
    }

    private fun body(metadata: String): String =
        """{"metadata":$metadata,"timestamp":$ts,"changes":[${recordsText.joinToString(",")}]}"""

    @Test
    fun `two entries sharing one x5u URL fetch it once, in one verify and across one sync`() {
        val fetcher = served()
        val sync = verifier(fetcher)
        sync.verify(Changeset(ts, records, listOf(entry(signature = bad), entry())), records).assertVerified(1)
        assertEquals(listOf(a), fetcher.requests.map { it.url })
        // A second changeset in the same sync (the reset-and-retry) reuses the validated x5u.
        sync.verify(Changeset(ts, records, listOf(entry())), records).assertVerified(0)
        assertEquals(1, fetcher.requests.size)
        // A new sync fetches it again.
        verifier(fetcher).verify(Changeset(ts, records, listOf(entry())), records).assertVerified(0)
        assertEquals(2, fetcher.requests.size)
    }

    @Test
    fun `an x5u URL whose fetch or validation failed is not retried by a later entry`() {
        val missing = served(emptyMap())
        verify(entry(), entry(), fetcher = missing)
            .assertFailed(SignatureFailure.X5U_FETCH, 1, SyncStage.X5U)
            .also { assertEquals(ClientFailure.HTTP_STATUS to 404, it.clientFailure to it.httpStatus) }
        assertEquals(1, missing.requests.size)
        val unpinned = served(mapOf(a to pem(chain(root = intermediate()))))
        verify(entry(), entry(), fetcher = unpinned).assertFailed(SignatureFailure.X5U_CHAIN, 1)
        assertEquals(1, unpinned.requests.size)
        // Not retried across the sync either.
        val sync = verifier(missing)
        sync.verify(Changeset(ts, records, listOf(entry())), records)
        sync
            .verify(
                Changeset(ts, records, listOf(entry())),
                records,
            ).assertFailed(SignatureFailure.X5U_FETCH, 0, SyncStage.X5U)
        assertEquals(2, missing.requests.size)
    }

    @Test
    fun `when none verifies the last tried entry's failure is the outcome`() {
        val bodies = mapOf(b to goodPem)
        // a is missing (X5U_FETCH, stage X5U), b's signature is bad (CONTENT_SIGNATURE); a skipped entry comes last.
        verify(entry(x5u = a), entry(x5u = b, signature = bad), entry(mode = null), fetcher = served(bodies))
            .assertFailed(SignatureFailure.CONTENT_SIGNATURE, 1)
        verify(entry(x5u = b, signature = bad), entry(x5u = a), fetcher = served(bodies))
            .assertFailed(SignatureFailure.X5U_FETCH, 1, SyncStage.X5U)
        // A garbled signature is the content check's failure too.
        verify(entry(signature = "not base64url!")).assertFailed(SignatureFailure.CONTENT_SIGNATURE, 0)
    }

    @Test
    fun `a PEM failure is FAILED at SIGNATURE, and a link outside its window is CLOCK_SKEW at X5U`() {
        verify(entry(), fetcher = served(mapOf(a to "no certificate here\n"))).assertFailed(SignatureFailure.X5U_PEM, 0)
        val expired = pem(chain(leaf = leaf(validity = window("20200101000000Z", "20250101000000Z"))))
        verify(entry(), fetcher = served(mapOf(a to expired)))
            .assertFailed(SignatureFailure.X5U_VALIDITY, 0, SyncStage.X5U, SyncOutcome.CLOCK_SKEW)
        // The same chain at a clock inside the window verifies.
        val fetcher = served(mapOf(a to expired))
        verifier(fetcher, now = millis("2024-06-01T00:00:00Z"))
            .verify(Changeset(ts, records, listOf(entry())), records)
            .assertVerified(0)
    }

    @Test
    fun `a changeset signed by a P-256 leaf verifies`() {
        val p256: KeyPair = ecPair("x5u-leaf-p256", "secp256r1")
        val chain = pem(chain(leaf = leaf(spki = p256.public.encoded)))
        val signature = sign(p256.private)
        assertEquals(86, signature.length, "a 64-byte raw pair")
        verify(entry(signature = signature), fetcher = served(mapOf(a to chain))).assertVerified(0)
    }

    @Test
    fun `the longest x5u Backoff is carried on success and on failure`() {
        val fetcher = served(mapOf(a to goodPem), "Backoff" to "60")
        assertEquals(60_000, verify(entry(), fetcher = fetcher).assertVerified(0).backoffMillis)
        assertEquals(
            120_000,
            verify(entry(), fetcher = served(emptyMap(), "Backoff" to "120"))
                .assertFailed(SignatureFailure.X5U_FETCH, 0, SyncStage.X5U)
                .backoffMillis,
        )
        assertEquals(null, verify(entry()).assertVerified(0).backoffMillis)
        assertEquals(goodPem.encodeToByteArray().toByteString(), verify(entry()).assertVerified(0).x5uBody)
    }
}
