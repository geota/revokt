// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

import dev.revokt.MozillaRemoteSettings
import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonInteger
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.parse.X5uPem
import dev.revokt.engine.parse.X5uPemRead
import dev.revokt.engine.parse.producer.ExternalCorpus
import dev.revokt.verify.JcaSignatureVerifier
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import java.io.File
import java.security.cert.CertificateFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * The large corpus's Remote Settings changeset (#113, `remote-settings/` of revokt-corpus v7): the x5u chain its
 * signature names, recorded as served, ends in the root the spec pins (Appendix A), so the recorded chain and the pin
 * agree. It validates under [MozillaRemoteSettings.DEFAULT]'s pins ([validateX5uChain], every check but validity) and is
 * valid at the changeset's own timestamp; with its terminal replaced, it is not pinned.
 */
class RemoteSettingsCorpusTest {
    private val dir = "remote-settings/cert-revocations/2026-11-19"

    /** Spec Appendix A: the SPKI SHA-256 of `root-ca-production-amo`. */
    private val pin = "3317FA45154AC7DA55694D3782316056471FC147C04AED3E03FFE99565B1E2E7".lowercase().decodeHex()

    private fun ders(corpus: File): List<ByteArray> =
        when (val read = X5uPem.read(File(corpus, "$dir/x5u.pem").readBytes())) {
            is X5uPemRead.Certificates -> read.ders
            is X5uPemRead.Failed -> error("x5u.pem does not read: $read")
        }

    private fun spkiSha256(der: ByteArray) =
        CertificateFactory
            .getInstance("X.509")
            .generateCertificate(der.inputStream())
            .publicKey.encoded
            .toByteString()
            .sha256()

    @Test
    fun `the recorded x5u chain ends in the pinned root and validates under the default pins`() {
        val corpus = ExternalCorpus.dir ?: return println("x5u pin: no large corpus on this run (-Prevokt.corpus)")
        val ders = ders(corpus)
        assertEquals(pin, spkiSha256(ders.last()), "the terminal's SPKI SHA-256 is Appendix A's pin")
        assertEquals(setOf(pin), MozillaRemoteSettings.DEFAULT.pinnedRootSpkis)
        val chain = validateX5uChain(ders, MozillaRemoteSettings.DEFAULT.pinnedRootSpkis, JcaSignatureVerifier())
        assertIs<X5uChainResult.Valid>(chain, "$chain")
        val changeset = Json.parse(File(corpus, "$dir/changeset.json").readBytes()) as JsonObject
        val timestamp = checkNotNull((changeset["timestamp"] as JsonInteger).toLongOrNull())
        assertEquals(X5uValidity.Valid, checkValidity(chain.path, timestamp), "valid at the recorded timestamp")
    }

    @Test
    fun `with its terminal replaced the recorded chain is not pinned`() {
        val corpus = ExternalCorpus.dir ?: return println("x5u pin: no large corpus on this run (-Prevokt.corpus)")
        val ders = ders(corpus)
        val other =
            checkNotNull(javaClass.getResourceAsStream("/dev/revokt/engine/parse/certs/mozilla-content-signing-c0.der"))
                .use { it.readBytes() }
        val replaced = ders.dropLast(1) + listOf(other)
        assertEquals(false, spkiSha256(replaced.last()) == pin)
        val chain = validateX5uChain(replaced, MozillaRemoteSettings.DEFAULT.pinnedRootSpkis, JcaSignatureVerifier())
        assertEquals(X5uChainFailure.NOT_PINNED, assertIs<X5uChainResult.Failed>(chain).failure)
    }
}
