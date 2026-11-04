// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.testing

import dev.revokt.RevoktLimits
import kotlin.random.Random

/**
 * One §9.1 mutation of a [WorldModel]: named (its class), with every free choice an explicit selector, so a mutation
 * list is the whole structured input. A selector picks from a list modulo its size, so any `Int` is valid. A mutation
 * that does not apply to a world (for example [DropIntermediate] at depth 0) leaves it unchanged and returns false.
 * Attacker certificates are inserted right after the leaf, ahead of every honest issuer the server sends; [Permute]
 * reorders them.
 */
internal sealed interface Mutation {
    /** Applies this mutation; false when it does not apply and the world is unchanged. */
    fun applyTo(model: WorldModel): Boolean

    val name: String get() = this::class.simpleName.orEmpty()

    companion object {
        private val kinds: List<(Random) -> Mutation> =
            listOf(
                { r -> NameEncoding(r.nextInt()) },
                { r -> AlgMismatch(r.nextInt()) },
                { r -> UnsupportedOwnSig(r.nextInt()) },
                { r -> DropIntermediate(r.nextInt()) },
                { r -> Recover(r.nextInt(), if (r.nextBoolean()) r.nextInt() else null) },
                { r -> SameKeyDecoy(r.nextInt()) },
                { r -> CrossCertToNonAnchor(r.nextInt()) },
                { r -> Stuff(r.nextInt(0, Stuff.MAX + 1), r.nextBoolean(), r.nextInt()) },
                { r -> SelfSignedNonAnchor(r.nextInt()) },
                { r -> Loop(r.nextInt()) },
                { r -> Permute(r.nextLong()) },
                { r -> Duplicate(r.nextInt(), r.nextInt()) },
                { r -> DepthPad(r.nextInt(), r.nextInt(1, DepthPad.MAX + 1)) },
            )

        /** A random mutation drawn from [rng], every kind equally likely. */
        fun random(rng: Random): Mutation = kinds[rng.nextInt(kinds.size)](rng)
    }
}

/** The world mutations of §9.1: honest-world variation, not an attack. Each targets an honest leaf or intermediate. */
internal sealed interface WorldMutation : Mutation

/** The attacker mutations of §9.1: certificates and links a server can add without any honest CA's key. */
internal sealed interface AttackerMutation : Mutation

private fun <T> List<T>.pick(selector: Int): T = this[selector.mod(size)]

/**
 * Re-encodes the issuer name of an honest leaf or intermediate ([target]) in the other string type (UTF8String and
 * PrintableString): its raw bytes no longer equal the issuer's subject, its `X500Principal` canonical form still does.
 * The issuer re-signs the certificate.
 */
internal data class NameEncoding(
    val target: Int = 0,
) : WorldMutation {
    override fun applyTo(model: WorldModel): Boolean {
        val c = model.honestChildren.pick(target)
        model.replace(c, c.copy(issuer = c.issuer.copy(printable = !c.issuer.printable)))
        return true
    }
}

/**
 * Writes NULL parameters into the outer `signatureAlgorithm` of an honest leaf or intermediate ([target]) while the TBS
 * `signature` keeps them absent: the NULL-vs-absent mismatch of the §9.2 D7 corpus. The OID-mismatch form (walker
 * fixture (r)) is not generated: the JDK's `CertificateFactory` rejects it ("Signature algorithm mismatch"), and every
 * generated certificate must parse there.
 */
internal data class AlgMismatch(
    val target: Int = 0,
) : WorldMutation {
    override fun applyTo(model: WorldModel): Boolean {
        val c = model.honestChildren.pick(target)
        model.replace(c, c.copy(outerNullParameters = true))
        return true
    }
}

/**
 * Re-issues an honest leaf or intermediate ([target]) under [SymOids.UNSUPPORTED_SIGNATURE], in the TBS and the outer
 * `signatureAlgorithm`. Its link stays in [World.ok]: only the probe stops it. Never an anchor, whose self-signature is
 * never verified.
 */
internal data class UnsupportedOwnSig(
    val target: Int = 0,
) : WorldMutation {
    override fun applyTo(model: WorldModel): Boolean {
        val c = model.honestChildren.pick(target)
        model.replace(c, c.copy(sigOid = SymOids.UNSUPPORTED_SIGNATURE))
        return true
    }
}

/** Removes an honest intermediate ([target]) from the presented chain; does not apply at depth 0. */
internal data class DropIntermediate(
    val target: Int = 0,
) : WorldMutation {
    override fun applyTo(model: WorldModel): Boolean {
        if (model.depth == 0) return false
        val i = model.honestPath[1 + target.mod(model.depth)]
        return model.presented.removeAll { it == i }
    }
}

/**
 * `Recover(child)`: a fresh key that verifies an honest leaf or intermediate ([child]), in a certificate whose subject
 * is the child's issuer name (so it is a related candidate). With [certifiedBy] the certificate is issued by that
 * anchor (`CertifiedBy(anchor)`, an attacker-owned sub-CA under a real anchor, selected modulo the snapshot); otherwise
 * it names a fresh attacker issuer and carries a signature no key verifies.
 */
internal data class Recover(
    val child: Int = 0,
    val certifiedBy: Int? = null,
) : AttackerMutation {
    override fun applyTo(model: WorldModel): Boolean {
        val c = model.honestChildren.pick(child)
        val key = model.recover(c)
        val anchor = certifiedBy?.let { model.anchors.pick(it) }
        model.insertAfterLeaf(model.issue(c.issuer, anchor?.subject ?: model.freshName("Attacker"), key, anchor?.key))
        return true
    }
}

/**
 * A decoy carrying an honest issuer's ([target], an intermediate or the honest anchor) subject and key, its issuer name
 * the honest anchor's, under a signature no key verifies (walker fixture (k)): it verifies the child and is a dead end.
 */
internal data class SameKeyDecoy(
    val target: Int = 0,
) : AttackerMutation {
    override fun applyTo(model: WorldModel): Boolean {
        val t = model.honestIssuers.pick(target)
        model.insertAfterLeaf(model.issue(t.subject, model.honestPath.last().subject, t.key, null))
        return true
    }
}

/**
 * A cross-certificate of an honest issuer ([target]: its subject and key) issued by a retired root that is not in the
 * snapshot (walker fixture (l)); the retired root's self-signed certificate is presented last.
 */
internal data class CrossCertToNonAnchor(
    val target: Int = 0,
) : AttackerMutation {
    override fun applyTo(model: WorldModel): Boolean {
        val t = model.honestIssuers.pick(target)
        val key = model.freshKey()
        val name = model.freshName("Retired root")
        val retired = model.issue(name, name, key, key)
        model.insertAfterLeaf(model.issue(t.subject, name, t.key, key))
        model.presented += retired
        return true
    }
}

/**
 * `Stuff(n, related)`: [n] junk certificates, each under a fresh key no link names, so every one is an `INVALID`
 * exploration. [related] gives them the issuer name of an honest leaf or intermediate ([at], the leaf by default) as
 * their subject, so they are related candidates of that node; otherwise each has a fresh, unrelated name.
 */
internal data class Stuff(
    val n: Int,
    val related: Boolean,
    val at: Int = 0,
) : AttackerMutation {
    init {
        require(n in 0..MAX) { "Stuff(n ≤ $MAX), got $n" }
    }

    override fun applyTo(model: WorldModel): Boolean {
        if (n == 0) return false
        val c = model.honestChildren.pick(at)
        val junk =
            List(n) {
                val subject = if (related) c.issuer else model.freshName("Junk")
                model.issue(subject, model.freshName("Junk issuer"), model.freshKey(), null)
            }
        model.insertAfterLeaf(*junk.toTypedArray())
        return true
    }

    companion object {
        const val MAX: Int = 300
    }
}

/**
 * A self-signed certificate that is not in the snapshot, its subject and issuer the issuer name of an honest leaf or
 * intermediate ([child]), under a recovered key that verifies the child: a walker that took any self-signed
 * certificate for a terminal would gain its key.
 */
internal data class SelfSignedNonAnchor(
    val child: Int = 0,
) : AttackerMutation {
    override fun applyTo(model: WorldModel): Boolean {
        val c = model.honestChildren.pick(child)
        val key = model.recover(c)
        model.insertAfterLeaf(model.issue(c.issuer, c.issuer, key, key))
        return true
    }
}

/**
 * An A↔B loop entered from an honest leaf or intermediate ([child]): A carries a recovered key that verifies the child
 * and the child's issuer name, and is signed by B; B is signed by A and names the child's issuer as its issuer.
 */
internal data class Loop(
    val child: Int = 0,
) : AttackerMutation {
    override fun applyTo(model: WorldModel): Boolean {
        val c = model.honestChildren.pick(child)
        val a = model.recover(c)
        val b = model.freshKey()
        val bName = model.freshName("Loop")
        model.insertAfterLeaf(model.issue(c.issuer, bName, a, b), model.issue(bName, c.issuer, b, a))
        return true
    }
}

/** Shuffles every presented certificate after the leaf with [seed]; the leaf stays first. */
internal data class Permute(
    val seed: Long,
) : AttackerMutation {
    override fun applyTo(model: WorldModel): Boolean {
        val tail = model.presented.subList(1, model.presented.size)
        val shuffled = tail.shuffled(Random(seed))
        if (shuffled == tail) return false
        tail.clear()
        tail.addAll(shuffled)
        return true
    }
}

/**
 * Presents an exact-byte copy of a presented certificate ([source]) again, at position 1 + [position] modulo the
 * chain's size (never in the leaf's place).
 */
internal data class Duplicate(
    val source: Int = 0,
    val position: Int = 0,
) : AttackerMutation {
    override fun applyTo(model: WorldModel): Boolean {
        val c = model.presented.pick(source)
        model.presented.add(1 + position.mod(model.presented.size), c)
        return true
    }
}

/**
 * `DepthPad`: a dead-end branch of [length] junk certificates off the honest path, which it never lengthens. The first
 * carries a recovered key that verifies an honest leaf or intermediate ([at]) and that node's issuer name, so walkers
 * descend into it; each is signed by the next, and the last is self-signed and not in the snapshot. A branch longer
 * than `MAX_DEPTH` is also a depth dead end.
 */
internal data class DepthPad(
    val at: Int = 0,
    val length: Int = RevoktLimits.MAX_DEPTH + 1,
) : AttackerMutation {
    init {
        require(length in 1..MAX) { "DepthPad length in 1..$MAX, got $length" }
    }

    override fun applyTo(model: WorldModel): Boolean {
        val c = model.honestChildren.pick(at)
        val keys = List(length) { if (it == 0) model.recover(c) else model.freshKey() }
        val subjects = List(length) { if (it == 0) c.issuer else model.freshName("Pad") }
        val pad =
            List(length) {
                val last = it == length - 1
                model.issue(subjects[it], subjects[if (last) it else it + 1], keys[it], keys[if (last) it else it + 1])
            }
        model.insertAfterLeaf(*pad.toTypedArray())
        return true
    }

    companion object {
        const val MAX: Int = 32
    }
}
