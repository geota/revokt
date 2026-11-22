// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.FetchResponse
import dev.revokt.MozillaRemoteSettings
import dev.revokt.SignatureVerifier
import dev.revokt.SyncFailure
import dev.revokt.VerifyResult
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.json.JsonString
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
import kotlin.test.assertTrue

/**
 * The changeset signature check (spec §7.1, revision 56, #191) over the §9 rows: a changeset whose first `signatures`
 * entry fails and whose second verifies installs; one with 5 entries, or whose every entry lacks `mode`, is
 * `SIGNATURE_INVALID` or `NO_SIGNATURE`; two entries sharing one `x5u` URL fetch it once; one whose `metadata` holds
 * only `signature`, or an empty `signatures`, is `NO_SIGNATURE`; an entry with no `mode` is skipped; a P-256 leaf
 * verifies. Plus the rules around them: the failed URL not retried, the last tried entry's failure, the codes and the
 * backoff. Chains and signatures are #126's fixture's, made by the test JDK.
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
        modeGiven: Boolean = mode != null,
    ) = SignatureEntry(signature, x5u, mode, modeGiven)

    /** A fetcher serving [bodies] by URL, anything else 404, each response with [headers]. */
    private fun served(
        bodies: Map<String, String> = mapOf(a to goodPem, b to goodPem),
        vararg headers: Pair<String, String>,
    ) = ScriptedFetcher { request ->
        bodies[request.url]?.let { ok(it, *headers) } ?: response(404, headers = arrayOf(*headers))
    }

    /** Mozilla's source with the fixture's test root pinned in place of `root-ca-production-amo`. */
    private val source =
        MozillaRemoteSettings.DEFAULT
            .newBuilder()
            .pinnedRootSpkiSha256s(pinned.map { it.toByteArray() })
            .build()

    private fun verifier(
        fetcher: ScriptedFetcher,
        now: Long = NOW,
        with: SignatureVerifier = verifier,
    ) = ChangesetVerifier(client(fetcher, source), with, now)

    private fun verify(
        vararg entries: SignatureEntry?,
        fetcher: ScriptedFetcher = served(),
    ): ChangesetVerification = verifier(fetcher).verify(Changeset(ts, records, entries.toList()), records)

    private fun ChangesetVerification.assertVerified(index: Int): ChangesetVerification.Verified {
        val verified = assertIs<ChangesetVerification.Verified>(this, "$this")
        assertEquals(index, verified.index)
        return verified
    }

    /**
     * A failure with [failure] at entry [index], whose detail holds [detail] when given (it tells `NO_SIGNATURE`s
     * apart).
     */
    private fun ChangesetVerification.assertFailed(
        failure: SyncFailure,
        index: Int?,
        detail: String? = null,
    ): ChangesetVerification.Failed {
        val failed = assertIs<ChangesetVerification.Failed>(this, "$this")
        assertEquals(failure to index, failed.failure to failed.index, failed.detail)
        if (detail != null) assertTrue(detail in failed.detail, "expected \"$detail\" in: ${failed.detail}")
        return failed
    }

    @Test
    fun `the chain is validated under the client's source's pins`() {
        // Mozilla's DEFAULT pins root-ca-production-amo, not the fixture's root, so the same chain is not pinned there.
        ChangesetVerifier(client(served(), MozillaRemoteSettings.DEFAULT), verifier, NOW)
            .verify(Changeset(ts, records, listOf(entry())), records)
            .assertFailed(SyncFailure.X5U_CHAIN, 0)
            .also { assertTrue("NOT_PINNED" in it.detail, it.detail) }
    }

    @Test
    fun `one entry that verifies is accepted, with its x5u body as served`() {
        val fetcher = served()
        val verified = verify(entry(), fetcher = fetcher).assertVerified(0)
        assertEquals(good, verified.entry.signature)
        assertContentEquals(goodPem.encodeToByteArray(), verified.x5uBody.toByteArray())
        assertContentEquals(leafKey.public.encoded, verified.path.leafSpki)
        assertEquals(listOf(a), fetcher.requests.map { it.url })
        assertEquals(records, verified.records)
        assertEquals(ts, verified.timestamp)
    }

    @Test
    fun `a first entry that fails and a second that verifies installs, under the second`() {
        val second = verify(entry(signature = bad), entry(x5u = b)).assertVerified(1)
        assertEquals(listOf(good, b), listOf(second.entry.signature, second.entry.x5u))
        // The first entry's x5u is missing (404) and the second's verifies.
        verify(entry(x5u = "$host/missing.chain"), entry(x5u = b)).assertVerified(1)
        // The first entry's chain does not validate.
        val broken = mapOf(a to pem(chain(root = intermediate())), b to goodPem)
        verify(entry(), entry(x5u = b), fetcher = served(broken)).assertVerified(1)
    }

    @Test
    fun `only the first 4 entries are tried, and the 4th of them is`() {
        // At the cap every entry is tried: three that fail, then one that verifies.
        val fourth =
            verify(
                entry(signature = bad),
                entry(signature = bad),
                entry(signature = bad),
                entry(),
            ).assertVerified(3)
        assertEquals(good, fourth.entry.signature)
        assertEquals(4, ChangesetVerifier.MAX_SIGNATURES)
        // A 5th entry is never read: one that would verify is not tried, so the 4th's failure is the outcome, and a
        // null 5th is not NULL_ENTRY.
        verify(*Array(4) { entry(signature = bad) }, entry()).assertFailed(SyncFailure.SIGNATURE_INVALID, 3)
        verify(*Array(4) { entry(signature = bad) }, null).assertFailed(SyncFailure.SIGNATURE_INVALID, 3)
        // Within the 4 a verifying entry is accepted whatever follows.
        val fetcher = served()
        verify(entry(), *Array(5) { entry(x5u = "$host/other-$it.chain") }, fetcher = fetcher).assertVerified(0)
        assertEquals(1, fetcher.requests.size)
    }

    @Test
    fun `entries all lacking signature or x5u, or of another mode, are NO_SIGNATURE, unfetched`() {
        val fetcher = served()
        // A mode that is "" or not a string (modeGiven with no string) is one revokt cannot verify.
        verify(
            entry(mode = ""),
            entry(mode = null, modeGiven = true),
            fetcher = fetcher,
        ).assertFailed(SyncFailure.NO_SIGNATURE, null, "no entry has")
        verify(
            entry(mode = "p256ecdsa"),
            entry(mode = "P384ECDSA"),
            entry(signature = null),
            entry(x5u = null),
            fetcher = fetcher,
        ).assertFailed(SyncFailure.NO_SIGNATURE, null, "no entry has")
        assertEquals(0, fetcher.requests.size)
    }

    @Test
    fun `an entry with no mode is tried as p384ecdsa, and one of another mode is skipped`() {
        verify(entry(mode = null)).assertVerified(0)
        val fetcher = served()
        // The skipped entry names b; only a is fetched.
        verify(entry(x5u = b, mode = "p256ecdsa"), entry(mode = null), fetcher = fetcher).assertVerified(1)
        assertEquals(listOf(a), fetcher.requests.map { it.url })
    }

    @Test
    fun `metadata with only signature, or an empty signatures, is NO_SIGNATURE`() {
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
            verifier(
                fetcher,
            ).verify(changeset, records).assertFailed(SyncFailure.NO_SIGNATURE, null, "absent, not an array or empty")
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
        verifier(fetcher).verify(changeset, records).assertFailed(SyncFailure.SIGNATURE_INVALID, 0)
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
            .assertFailed(SyncFailure.X5U_FETCH, 1)
            .also { assertEquals("status 404" to 404, it.detail to it.httpStatus) }
        assertEquals(1, missing.requests.size)
        val unpinned = served(mapOf(a to pem(chain(root = intermediate()))))
        verify(entry(), entry(), fetcher = unpinned).assertFailed(SyncFailure.X5U_CHAIN, 1)
        assertEquals(1, unpinned.requests.size)
        // Not retried across the sync either.
        val sync = verifier(missing)
        sync.verify(Changeset(ts, records, listOf(entry())), records)
        sync
            .verify(
                Changeset(ts, records, listOf(entry())),
                records,
            ).assertFailed(SyncFailure.X5U_FETCH, 0)
        assertEquals(2, missing.requests.size)
    }

    @Test
    fun `when none verifies the last tried entry's failure is the outcome`() {
        val bodies = mapOf(b to goodPem)
        // a is missing (X5U_FETCH, stage X5U), b's signature is bad (CONTENT_SIGNATURE); a skipped entry comes last.
        verify(entry(x5u = a), entry(x5u = b, signature = bad), entry(mode = "p256ecdsa"), fetcher = served(bodies))
            .assertFailed(SyncFailure.SIGNATURE_INVALID, 1)
        verify(entry(x5u = b, signature = bad), entry(x5u = a), fetcher = served(bodies))
            .assertFailed(SyncFailure.X5U_FETCH, 1)
        // A garbled signature is the content check's failure too.
        verify(entry(signature = "not base64url!")).assertFailed(SyncFailure.SIGNATURE_INVALID, 0)
    }

    @Test
    fun `a PEM failure is X5U_CHAIN, and a link outside its window is CLOCK_SKEW`() {
        verify(
            entry(),
            fetcher = served(mapOf(a to "no certificate here\n")),
        ).assertFailed(SyncFailure.X5U_CHAIN, 0, "FRAMING")
        val expired = pem(chain(leaf = leaf(validity = window("20200101000000Z", "20250101000000Z"))))
        verify(entry(), fetcher = served(mapOf(a to expired)))
            .assertFailed(SyncFailure.CLOCK_SKEW, 0)
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
                .assertFailed(SyncFailure.X5U_FETCH, 0)
                .backoffMillis,
        )
        assertEquals(null, verify(entry()).assertVerified(0).backoffMillis)
        assertEquals(goodPem.encodeToByteArray().toByteString(), verify(entry()).assertVerified(0).x5uBody)
    }

    @Test
    fun `a _since changeset verifies over the merged records, not its changes, and Verified carries the merge`() {
        val stored = records
        val changes =
            listOf(
                json("""{"id":"r1","last_modified":1793980623000,"deleted":true}"""),
                json("""{"id":"r3","last_modified":1793980624000,"channel":"default"}"""),
            )
        val merged = checkNotNull(ContentSignature.merge(stored, changes))
        assertEquals(listOf("r2", "r3"), merged.map { (it["id"] as JsonString).value })
        val delta = Changeset(ts, changes, listOf(entry(signature = sign(over = merged))))
        val verified = verifier(served()).verify(delta, merged).assertVerified(0)
        assertEquals(merged, verified.records)
        assertEquals(ts, verified.timestamp)
        // The changes alone are not what was signed.
        verifier(served()).verify(delta, changes).assertFailed(SyncFailure.SIGNATURE_INVALID, 0)
    }

    @Test
    fun `only a VERIFIED content signature is accepted - UNSUPPORTED and RECORDS are failures`() {
        val prefix = "Content-Signature:\u0000".encodeToByteArray()
        // The chain verifies as usual; only the content signature is answered UNSUPPORTED.
        val unsupported =
            stub { alg, spki, message, signature ->
                if (message.size >= prefix.size && message.copyOf(prefix.size).contentEquals(prefix)) {
                    VerifyResult.UNSUPPORTED
                } else {
                    verifier.verify(alg, spki, message, signature)
                }
            }
        verifier(served(), with = unsupported)
            .verify(Changeset(ts, records, listOf(entry())), records)
            .assertFailed(SyncFailure.SIGNATURE_INVALID, 0)
            .also { assertTrue("UNSUPPORTED" in it.detail, it.detail) }
        // Two records sharing an id leave no payload to verify.
        val twice = records + records.take(1)
        verifier(served())
            .verify(Changeset(ts, twice, listOf(entry())), twice)
            .assertFailed(SyncFailure.SIGNATURE_INVALID, 0)
            .also { assertTrue("RECORDS" in it.detail, it.detail) }
    }

    @Test
    fun `the longest Backoff of the call's fetches is carried, a failed entry's onto a later success`() {
        fun fetcher(
            aAnswer: () -> FetchResponse,
            bAnswer: () -> FetchResponse,
        ) = ScriptedFetcher { request -> if (request.url == a) aAnswer() else bAnswer() }
        val missing120 = { response(404, headers = arrayOf("Backoff" to "120")) }
        val good60 = { ok(goodPem, "Backoff" to "60") }
        val missing60 = { response(404, headers = arrayOf("Backoff" to "60")) }
        val good120 = { ok(goodPem, "Backoff" to "120") }
        val entries = arrayOf(entry(x5u = a), entry(x5u = b))
        assertEquals(120_000, verify(*entries, fetcher = fetcher(missing120, good60)).assertVerified(1).backoffMillis)
        assertEquals(120_000, verify(*entries, fetcher = fetcher(missing60, good120)).assertVerified(1).backoffMillis)
        // A reused x5u is not fetched again, so a later call of the same verifier does not report its Backoff again.
        val sync = verifier(fetcher(missing120, good60))
        assertEquals(120_000, sync.verify(Changeset(ts, records, entries.toList()), records).backoffMillis)
        assertEquals(null, sync.verify(Changeset(ts, records, entries.toList()), records).backoffMillis)
    }

    @Test
    fun `an empty x5u or signature is skipped as Firefox's !x5u and !signature skip it`() {
        val fetcher = served()
        verify(entry(x5u = ""), entry(signature = ""), entry(x5u = "", signature = ""), fetcher = fetcher)
            .assertFailed(SyncFailure.NO_SIGNATURE, null, "no entry has")
        assertEquals(0, fetcher.requests.size)
        verify(entry(signature = ""), entry(x5u = b)).assertVerified(1)
    }

    @Test
    fun `a null element reached in the loop is NO_SIGNATURE, as Firefox's destructuring throws`() {
        val fetcher = served()
        verify(null, entry(), fetcher = fetcher).assertFailed(SyncFailure.NO_SIGNATURE, 0, "is null")
        assertEquals(0, fetcher.requests.size)
        verify(entry(signature = bad), null, entry()).assertFailed(SyncFailure.NO_SIGNATURE, 1, "is null")
        // Firefox returns at the first entry that verifies, so a null after it is never reached.
        verify(entry(), null).assertVerified(0)
        // Through the client's parse: a JSON null element is null; another non-object one is skipped.
        val parsed =
            ScriptedFetcher { request ->
                if ("changeset" in request.url) {
                    ok(body("""{"signatures":[1,null]}"""))
                } else {
                    ok(goodPem)
                }
            }
        val changeset = client(parsed, source).fetchChangeset(ts, null).assertOk()
        assertEquals(null, changeset.signatures[1])
        verifier(parsed).verify(changeset, records).assertFailed(SyncFailure.NO_SIGNATURE, 1, "is null")
    }

    @Test
    fun `the x5u cache key is the URL exactly as served`() {
        val upper = "$host/A.chain"
        val port = "https://content-signature-2.cdn.mozilla.net:443/g/chains/a.chain"
        val fetcher = served(mapOf(a to goodPem, upper to goodPem))
        verify(entry(signature = bad), entry(x5u = upper, signature = bad), entry(x5u = port), fetcher = fetcher)
            .assertVerified(2)
        // A path differing in case is another URL, and so is the same one with :443 (fetched without it).
        assertEquals(listOf(a, upper, a), fetcher.requests.map { it.url })
    }
}
