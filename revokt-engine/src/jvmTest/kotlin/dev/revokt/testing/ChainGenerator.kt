// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.testing

import dev.revokt.engine.parse.Oid
import dev.revokt.engine.parse.TestDer
import okio.ByteString.Companion.toByteString
import java.math.BigInteger
import kotlin.random.Random

/**
 * The private-arc OIDs of the §9.1 generator (under the test arc `1.3.6.1.4.1.99999` the parser tests already use).
 * [KEY] and [SIGNATURE] are the symbolic key and signature algorithms; the `UNSUPPORTED_*` OIDs are every world's
 * [World.unsupported], one per position the startup probe matches ([SymVerifier]).
 */
internal object SymOids {
    const val KEY: String = "1.3.6.1.4.1.99999.91.1"
    const val SIGNATURE: String = "1.3.6.1.4.1.99999.91.2"
    const val UNSUPPORTED_KEY: String = "1.3.6.1.4.1.99999.91.11"
    const val UNSUPPORTED_SIGNATURE: String = "1.3.6.1.4.1.99999.91.12"
    const val UNSUPPORTED_CURVE: String = "1.3.6.1.4.1.99999.91.13"

    val UNSUPPORTED: Set<String> = setOf(UNSUPPORTED_KEY, UNSUPPORTED_SIGNATURE, UNSUPPORTED_CURVE)
}

/**
 * A symbolic key: its SPKI is [keyOid] (with [curveOid] as the parameters when set) and a BIT STRING holding the key's
 * identity, the world seed and the key's [ordinal] (spec §9.1: the generator writes the key id into the SPKI BIT
 * STRING), so distinct keys have distinct SPKIs and `KeyId = SHA-256(spki)` tells them apart.
 */
internal data class SymKey(
    val worldSeed: Long,
    val ordinal: Int,
    val keyOid: String = SymOids.KEY,
    val curveOid: String? = null,
) {
    val spki: ByteArray by lazy {
        val seedOctets = ByteArray(8) { (worldSeed ushr (56 - 8 * it)).toByte() }
        val identity = seedOctets + ByteArray(4) { (ordinal ushr (24 - 8 * it)).toByte() }
        TestDer.seq(
            TestDer.seq(TestDer.oid(keyOid), curveOid?.let { TestDer.oid(it) } ?: ByteArray(0)),
            TestDer.tlv(0x03, byteArrayOf(0) + identity),
        )
    }

    val id: KeyId get() = KeyId.of(spki)

    /** The SKI value: the first 20 octets of SHA-256(spki). */
    val keyIdentifier: ByteArray get() = id.sha256.toByteArray().copyOf(20)

    /** Lowercase hex SHA-256 of the SPKI, the reference walker's leaf-issuer key form. */
    val hex: String get() = id.sha256.hex()
}

/** A one-RDN name `CN=[cn]`, its value a UTF8String, or a PrintableString when [printable] (§9.1 `NameEncoding`). */
internal data class SymName(
    val cn: String,
    val printable: Boolean = false,
) {
    fun der(): ByteArray {
        val value = TestDer.tlv(if (printable) 0x13 else 0x0c, TestDer.ascii(cn))
        return TestDer.seq(TestDer.tlv(0x31, TestDer.seq(TestDer.oid("2.5.4.3"), value)))
    }
}

/**
 * One certificate of a world. It is signed by [signer] (its `(CertId, KeyId)` link is in [World.ok]), or carries a
 * signature no key verifies when [signer] is null. [sigOid] is the TBS and outer signature OID; [outerNullParameters]
 * writes NULL parameters in the outer `signatureAlgorithm` only (`AlgMismatch`). With [keyIdentifiers] it carries an
 * SKI of [key] and, unless self-signed or unsigned, an AKI keyIdentifier of [signer].
 */
internal data class CertSpec(
    val serial: Int,
    val subject: SymName,
    val issuer: SymName,
    val key: SymKey,
    val signer: SymKey?,
    val keyIdentifiers: Boolean,
    val sigOid: String = SymOids.SIGNATURE,
    val outerNullParameters: Boolean = false,
) {
    val tbs: ByteArray by lazy {
        val extensions =
            if (!keyIdentifiers) {
                emptyList()
            } else {
                listOfNotNull(
                    TestDer.extension(Oid.SUBJECT_KEY_IDENTIFIER, TestDer.tlv(0x04, key.keyIdentifier)),
                    signer?.takeIf { it != key }?.let {
                        TestDer.extension(
                            Oid.AUTHORITY_KEY_IDENTIFIER,
                            TestDer.seq(TestDer.tlv(0x80, it.keyIdentifier)),
                        )
                    },
                )
            }
        TestDer.seq(
            TestDer.tlv(0xa0, TestDer.tlv(0x02, TestDer.bytes(2))),
            TestDer.tlv(0x02, BigInteger.valueOf(serial.toLong()).toByteArray()),
            TestDer.seq(TestDer.oid(sigOid)),
            issuer.der(),
            TestDer.seq(
                TestDer.tlv(0x17, TestDer.ascii("260101000000Z")),
                TestDer.tlv(0x17, TestDer.ascii("360101000000Z")),
            ),
            subject.der(),
            key.spki,
            if (extensions.isEmpty()) ByteArray(0) else TestDer.tlv(0xa3, TestDer.seq(*extensions.toTypedArray())),
        )
    }

    val der: ByteArray by lazy {
        val signature = (tbs + (signer?.spki ?: ByteArray(0))).toByteString().sha256().toByteArray()
        TestDer.seq(
            tbs,
            TestDer.seq(TestDer.oid(sigOid), if (outerNullParameters) TestDer.bytes(0x05, 0x00) else ByteArray(0)),
            TestDer.tlv(0x03, byteArrayOf(0) + signature),
        )
    }

    val id: CertId get() = CertId.of(tbs)
}

/**
 * A rendered world: the [presented] chain (leaf first), the anchor snapshot ([anchors]), the verifier's [ok] links and
 * [unsupported] OIDs, and the honest answer: [honestKey], the lowercase-hex SPKI hash of the honest leaf issuer.
 * [recoveredKeys] lists, in mutation order, the key each recovered-key mutation added to [ok]; [certificates] is every
 * distinct certificate the world issued, presented or not.
 */
internal class World(
    val depth: Int,
    val presented: List<ByteArray>,
    val anchors: List<ByteArray>,
    val ok: Set<Pair<CertId, KeyId>>,
    val honestKey: String,
    val honestAnchor: Int,
    val recoveredKeys: List<String>,
    val certificates: List<ByteArray>,
    val mutations: List<Mutation>,
) {
    /** The probe's OIDs, the same in every world. */
    val unsupported: Set<String> get() = SymOids.UNSUPPORTED

    fun verifier(): SymVerifier = SymVerifier(ok, unsupported)
}

/**
 * The world a §9.1 generator run builds and its mutations transform. [honestPath] is leaf, intermediates, honest
 * anchor; [presented] is what the server sends, leaf first; [anchors] is the snapshot. Mutations replace certificates
 * (a re-issued certificate keeps its key and signer, so its issuer re-signs it), insert attacker certificates and add
 * recovered links; [render] turns the model into DER and links.
 */
internal class WorldModel(
    val seed: Long,
    val keyIdentifiers: Boolean,
) {
    val anchors: MutableList<CertSpec> = ArrayList()
    val honestPath: MutableList<CertSpec> = ArrayList()
    val presented: MutableList<CertSpec> = ArrayList()
    var honestAnchor: Int = 0
    private val issued = ArrayList<CertSpec>()
    private val recovered = ArrayList<Pair<CertSpec, SymKey>>()
    private val applied = ArrayList<Mutation>()
    private var keys = 0
    private var serials = 0
    private var names = 0

    /** The honest certificates whose own signature a mutation may touch: the leaf and the intermediates. */
    val honestChildren: List<CertSpec> get() = honestPath.dropLast(1)

    /** The honest issuers: the intermediates and the honest anchor. */
    val honestIssuers: List<CertSpec> get() = honestPath.drop(1)

    val depth: Int get() = honestPath.size - 2

    fun freshKey(
        keyOid: String = SymOids.KEY,
        curveOid: String? = null,
    ): SymKey = SymKey(seed, keys++, keyOid, curveOid)

    fun freshName(prefix: String): SymName = SymName("$prefix ${names++}")

    /** A new certificate, recorded so its link is in [World.ok] whether or not it is presented. */
    fun issue(
        subject: SymName,
        issuer: SymName,
        key: SymKey,
        signer: SymKey?,
        sigOid: String = SymOids.SIGNATURE,
    ): CertSpec = CertSpec(++serials, subject, issuer, key, signer, keyIdentifiers, sigOid).also { issued += it }

    /** Replaces every occurrence of [old] by [new] (a re-issue: same serial, key and signer). */
    fun replace(
        old: CertSpec,
        new: CertSpec,
    ) {
        issued += new
        for (list in listOf(anchors, honestPath, presented)) list.replaceAll { if (it == old) new else it }
    }

    /** Inserts [specs] right after the leaf, in order, ahead of every honest issuer the server sends. */
    fun insertAfterLeaf(vararg specs: CertSpec) {
        presented.addAll(1, specs.toList())
    }

    /** A fresh key that verifies [child]'s signature (an ECDSA-recovered or RSA duplicate-signature key). */
    fun recover(child: CertSpec): SymKey = freshKey().also { recovered += child to it }

    /** Applies [m]; it is listed in [World.mutations] only when it changed the world. */
    fun apply(m: Mutation) {
        if (m.applyTo(this)) applied += m
    }

    fun render(): World {
        val ok = LinkedHashSet<Pair<CertId, KeyId>>()
        for (spec in issued) spec.signer?.let { ok += spec.id to it.id }
        for ((spec, key) in recovered) ok += spec.id to key.id
        return World(
            depth = depth,
            presented = presented.map { it.der },
            anchors = anchors.map { it.der },
            ok = ok,
            honestKey = honestPath[1].key.hex,
            honestAnchor = honestAnchor,
            recoveredKeys = recovered.map { it.second.hex },
            certificates = issued.distinct().map { it.der },
            mutations = applied.toList(),
        )
    }
}

/**
 * The §9.1 chain generator. [honest] builds an honest world from a seed: 1–200 anchors with distinct names, about a
 * quarter of the others with an unsupported key, curve or signature OID (never the honest anchor); a chain of depth
 * 0–9 (the number of intermediates) under the honest anchor; certificates with or without SKI/AKI (one choice per
 * world); the honest anchor itself presented in a quarter of the worlds, and in another quarter a cross-certificate of
 * it issued by another supported snapshot root (cross-signs are only ever between snapshot roots). [generate] applies
 * [Mutation]s in order. A world is a function of the seed and the mutation list alone (a seeded [Random] is a fixed
 * algorithm).
 */
internal object ChainGenerator {
    const val MAX_ANCHORS: Int = 200
    const val MAX_GENERATED_DEPTH: Int = 9

    /**
     * An honest world for [seed]. [depth] and [anchors] override the seed's choices (a test can ask for a chain deeper
     * than [MAX_GENERATED_DEPTH]); the rest of the world still comes from the seed.
     */
    fun honest(
        seed: Long,
        depth: Int? = null,
        anchors: Int? = null,
    ): WorldModel {
        val rng = Random(seed)
        val anchorCount = anchors ?: rng.nextInt(1, MAX_ANCHORS + 1)
        val chainDepth = depth ?: rng.nextInt(0, MAX_GENERATED_DEPTH + 1)
        require(anchorCount >= 1) { "a world has at least one anchor" }
        require(chainDepth >= 0) { "depth is the number of intermediates" }
        val model = WorldModel(seed, keyIdentifiers = rng.nextBoolean())
        val honestIndex = rng.nextInt(anchorCount)
        val supported = ArrayList<Int>()
        for (i in 0 until anchorCount) {
            val kind = if (i == honestIndex) 3 else rng.nextInt(12)
            val key =
                when (kind) {
                    0 -> model.freshKey(keyOid = SymOids.UNSUPPORTED_KEY)
                    1 -> model.freshKey(curveOid = SymOids.UNSUPPORTED_CURVE)
                    else -> model.freshKey()
                }
            val sigOid = if (kind == 2) SymOids.UNSUPPORTED_SIGNATURE else SymOids.SIGNATURE
            if (kind > 2) supported += i
            val name = model.freshName("Root")
            model.anchors += model.issue(name, name, key, key, sigOid)
        }
        model.honestAnchor = honestIndex
        val root = model.anchors[honestIndex]
        val path = ArrayList<CertSpec>()
        var parent = root
        repeat(chainDepth) {
            val key = model.freshKey()
            parent = model.issue(model.freshName("Intermediate"), parent.subject, key, parent.key)
            path.add(0, parent)
        }
        val leaf = model.issue(SymName("leaf.example"), parent.subject, model.freshKey(), parent.key)
        model.honestPath += listOf(leaf) + path + root
        model.presented += listOf(leaf) + path
        when (rng.nextInt(4)) {
            0 -> {
                model.presented += root
            }

            1 -> {
                supported.filter { it != honestIndex }.takeIf { it.isNotEmpty() }?.let { others ->
                    val by = model.anchors[others[rng.nextInt(others.size)]]
                    model.presented += model.issue(root.subject, by.subject, root.key, by.key)
                }
            }
        }
        return model
    }

    /** The honest world for [seed] with [mutations] applied in order, rendered. */
    fun generate(
        seed: Long,
        mutations: List<Mutation> = emptyList(),
        depth: Int? = null,
        anchors: Int? = null,
    ): World = honest(seed, depth, anchors).also { model -> mutations.forEach { model.apply(it) } }.render()
}
