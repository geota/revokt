// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.testing

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.TestDer
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/** The §9.1 chain generator: deterministic per seed, the honest world's shape, and DER every parser accepts. */
class ChainGeneratorTest {
    private fun mutations(seed: Long): List<Mutation> =
        Random(seed xor 0x5eed).let { r -> List(r.nextInt(0, 6)) { Mutation.random(r) } }

    /** One instance of every mutation kind, with selectors from [seed]. */
    private fun everyKind(seed: Long): List<Mutation> {
        val s = seed.toInt()
        return listOf(
            NameEncoding(s),
            AlgMismatch(s + 1),
            UnsupportedOwnSig(s + 2),
            DropIntermediate(s),
            Recover(s, s),
            Recover(s + 1),
            SameKeyDecoy(s),
            CrossCertToNonAnchor(s + 1),
            Stuff(20, related = true, at = s),
            Stuff(5, related = false),
            SelfSignedNonAnchor(s),
            Loop(s + 1),
            Permute(seed),
            Duplicate(s, s + 3),
            DepthPad(s, 20),
        )
    }

    private fun CertSpec.isSupported(): Boolean =
        key.keyOid == SymOids.KEY && key.curveOid == null && sigOid == SymOids.SIGNATURE

    private fun World.fingerprint(): List<Any> =
        listOf(
            presented.map { it.toByteString() },
            anchors.map { it.toByteString() },
            ok,
            honestKey,
            recoveredKeys,
            certificates.map { it.toByteString() },
            mutations,
        )

    @Test
    fun `the generator is deterministic for a seed`() {
        for (seed in 0L until 40) {
            val m = mutations(seed)
            assertEquals(
                ChainGenerator.generate(seed, m).fingerprint(),
                ChainGenerator.generate(seed, m).fingerprint(),
                "seed $seed",
            )
            assertEquals(m, mutations(seed))
        }
        assertNotEquals(ChainGenerator.generate(1).fingerprint(), ChainGenerator.generate(2).fingerprint())
    }

    @Test
    fun `honest worlds hold 1 to 200 anchors, depth 0 to 9 and cross-signs only between snapshot roots`() {
        val depths = HashSet<Int>()
        var withUnsupported = 0
        var crossSigned = 0
        var maxAnchors = 0
        for (seed in 0L until 400) {
            val model = ChainGenerator.honest(seed)
            assertTrue(model.anchors.size in 1..ChainGenerator.MAX_ANCHORS, "seed $seed: ${model.anchors.size} anchors")
            assertTrue(model.depth in 0..ChainGenerator.MAX_GENERATED_DEPTH, "seed $seed: depth ${model.depth}")
            depths += model.depth
            maxAnchors = maxOf(maxAnchors, model.anchors.size)
            assertEquals(
                model.anchors.size,
                model.anchors
                    .map { it.subject }
                    .toSet()
                    .size,
                "seed $seed: anchor names distinct",
            )
            val honestAnchor = model.anchors[model.honestAnchor]
            assertEquals(honestAnchor, model.honestPath.last())
            assertTrue(honestAnchor.isSupported(), "seed $seed: the honest anchor's OIDs are supported")
            if (!model.anchors.all { it.isSupported() }) withUnsupported++
            val anchorKeys = model.anchors.map { it.key }.toSet()
            for (extra in model.presented.filter { it !in model.honestPath }) {
                crossSigned++
                val crossSign = extra.key in anchorKeys && extra.signer in anchorKeys && extra.signer != extra.key
                assertTrue(crossSign, "seed $seed: $extra")
            }
            val chain = model.presented.filter { it !in model.anchors && it.key !in anchorKeys }
            assertEquals(model.honestPath.dropLast(1), chain, "seed $seed: the leaf and the intermediates, in order")
        }
        assertEquals((0..ChainGenerator.MAX_GENERATED_DEPTH).toSet(), depths)
        assertTrue(maxAnchors > 190, "large snapshots occur: $maxAnchors")
        assertTrue(withUnsupported > 300, "most large snapshots hold an unsupported anchor: $withUnsupported")
        assertTrue(crossSigned > 40, "cross-signs occur: $crossSigned")
    }

    @Test
    fun `every generated certificate parses with revokt's parser and with the JDK's CertificateFactory`() {
        val factory = CertificateFactory.getInstance("X.509")
        var count = 0
        for (seed in 0L until 30) {
            for (m in listOf(mutations(seed), everyKind(seed))) {
                val world = ChainGenerator.generate(seed, m)
                world.certificates.forEach { assertParses(factory, it, "seed $seed $m") }
                count += world.certificates.size
            }
        }
        assertTrue(count > 5_000, "$count certificates")
    }

    /** [der] parses with revokt's parser and the JDK's, and both read the same TBS, key and names. */
    private fun assertParses(
        factory: CertificateFactory,
        der: ByteArray,
        label: String,
    ) {
        val p =
            when (val r = CertificateParser.parse(der)) {
                is CertificateParse.Parsed -> r.certificate
                is CertificateParse.Failed -> fail("$label: ${r.reason} ${r.detail}")
            }
        val jdk = factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        assertContentEquals(jdk.tbsCertificate, p.tbsBytes, label)
        assertContentEquals(jdk.publicKey.encoded, p.rawSpki(), label)
        assertContentEquals(jdk.subjectX500Principal.encoded, p.rawSubject(), label)
        assertContentEquals(jdk.issuerX500Principal.encoded, p.rawIssuer(), label)
    }

    @Test
    fun `NameEncoding changes the issuer's raw bytes and keeps its canonical form`() {
        val model = ChainGenerator.honest(3, depth = 2)
        val before = model.honestPath[1]
        model.apply(NameEncoding(1))
        val after = model.honestPath[1]
        assertEquals(before.copy(issuer = after.issuer), after)
        val raw = before.issuer.der()
        val reencoded = after.issuer.der()
        assertFalse(raw.contentEquals(reencoded))
        assertContentEquals(raw, model.honestPath[2].subject.der())
        assertEquals(
            X500Principal(raw).getName(X500Principal.CANONICAL),
            X500Principal(reencoded).getName(X500Principal.CANONICAL),
        )
        // The issuer re-signed it: the new TBS is a link of the world.
        assertTrue(after.id to model.honestPath[2].key.id in model.render().ok)
    }

    @Test
    fun `AlgMismatch is NULL against absent parameters, which revokt does not report as a mismatch`() {
        val world = ChainGenerator.generate(5, listOf(AlgMismatch(0)), depth = 1)
        val p = (CertificateParser.parse(world.presented[0]) as CertificateParse.Parsed).certificate
        assertContentEquals(TestDer.seq(TestDer.oid(SymOids.SIGNATURE)), p.tbs.signature.bytes(p.tbsBytes))
        assertContentEquals(
            TestDer.seq(TestDer.oid(SymOids.SIGNATURE), TestDer.bytes(0x05, 0x00)),
            p.envelope.signatureAlgorithm.bytes(world.presented[0]),
        )
        assertFalse(p.envelope.algorithmIdMismatch)
        assertEquals(listOf<Mutation>(AlgMismatch(0)), world.mutations)
    }

    @Test
    fun `mutations that do not apply leave the world unchanged and are not listed`() {
        val honest = ChainGenerator.generate(9, depth = 0)
        val dropped = ChainGenerator.generate(9, listOf(DropIntermediate(0), Stuff(0, related = true)), depth = 0)
        assertEquals(honest.fingerprint(), dropped.fingerprint())
        assertEquals(emptyList(), dropped.mutations)
    }
}
