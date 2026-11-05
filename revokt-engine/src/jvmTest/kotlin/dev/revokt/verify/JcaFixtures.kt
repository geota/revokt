// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.verify

import dev.revokt.engine.parse.TestDer
import java.security.Key
import java.security.KeyFactory
import java.security.KeyFactorySpi
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureSpi
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.KeySpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

/** Keys, signatures and encodings for the verifier tests: every signature is made by the test JDK's own providers. */
internal object JcaFixtures {
    const val PKCS1 = "1.2.840.113549.1.1"
    const val RSA_KEY = "$PKCS1.1"
    const val PSS = "$PKCS1.10"
    const val SHA256_RSA = "$PKCS1.11"
    const val SHA1_RSA = "$PKCS1.5"
    const val EC_KEY = "1.2.840.10045.2.1"
    const val ECDSA_SHA256 = "1.2.840.10045.4.3.2"
    const val ECDSA_SHA384 = "1.2.840.10045.4.3.3"
    const val ECDSA_SHA1 = "1.2.840.10045.4.1"
    const val P256 = "1.2.840.10045.3.1.7"
    const val P384 = "1.3.132.0.34"
    const val P521 = "1.3.132.0.35"
    const val P224 = "1.3.132.0.33"
    const val BRAINPOOL_P256 = "1.3.36.3.3.2.8.1.1.7"
    const val SECP256K1 = "1.3.132.0.10"
    const val ED25519 = "1.3.101.112"
    const val ED448 = "1.3.101.113"
    const val ML_DSA_44 = "2.16.840.1.101.3.4.3.17"
    const val ML_DSA_65 = "2.16.840.1.101.3.4.3.18"
    const val ML_DSA_87 = "2.16.840.1.101.3.4.3.19"
    const val SLH_DSA_SHA2_128S = "2.16.840.1.101.3.4.3.20"
    const val COMPOSITE_MLDSA44_ED25519 = "1.3.6.1.5.5.7.6.39"
    const val SHA1 = "1.3.14.3.2.26"
    const val SHA256 = "2.16.840.1.101.3.4.2.1"
    const val SHA384 = "2.16.840.1.101.3.4.2.2"
    const val SHA512 = "2.16.840.1.101.3.4.2.3"
    const val MGF1 = "$PKCS1.8"

    val NULL: ByteArray = TestDer.bytes(0x05, 0x00)
    val MESSAGE: ByteArray = "revokt verifier test message".encodeToByteArray()

    private val pairs = HashMap<String, KeyPair>()

    /** A fresh key pair from the test JDK's default providers. */
    fun generate(
        algorithm: String,
        spec: AlgorithmParameterSpec? = null,
        size: Int? = null,
    ): KeyPair {
        val g = KeyPairGenerator.getInstance(algorithm)
        spec?.let { g.initialize(it) }
        size?.let { g.initialize(it) }
        return g.generateKeyPair()
    }

    /** One key pair per [label] for the test run (RSA generation is slow). */
    fun pair(
        label: String,
        make: () -> KeyPair,
    ): KeyPair = synchronized(pairs) { pairs.getOrPut(label, make) }

    fun rsa(label: String = "rsa"): KeyPair = pair(label) { generate("RSA", size = 2048) }

    fun ec(curve: String): KeyPair = pair("ec-$curve") { generate("EC", ECGenParameterSpec(curve)) }

    fun sign(
        algorithm: String,
        key: PrivateKey,
        message: ByteArray = MESSAGE,
        params: AlgorithmParameterSpec? = null,
    ): ByteArray {
        val s = Signature.getInstance(algorithm)
        params?.let { s.setParameter(it) }
        s.initSign(key)
        s.update(message)
        return s.sign()
    }

    /** The test JDK's own answer for the same inputs: a throw is `false`. */
    fun jdkVerifies(
        algorithm: String,
        key: PublicKey,
        signature: ByteArray,
        message: ByteArray = MESSAGE,
        params: AlgorithmParameterSpec? = null,
    ): Boolean =
        runCatching {
            val s = Signature.getInstance(algorithm)
            s.initVerify(key)
            params?.let { s.setParameter(it) }
            s.update(message)
            s.verify(signature)
        }.getOrDefault(false)

    fun algId(
        oid: String,
        parameters: ByteArray? = null,
    ): ByteArray = TestDer.seq(TestDer.oid(oid), parameters ?: ByteArray(0))

    /** An SPKI with [algorithm] and the given key bits. */
    fun spki(
        algorithm: ByteArray,
        bits: ByteArray = TestDer.bytes(0x04, 0x01, 0x02),
    ): ByteArray = TestDer.seq(algorithm, TestDer.tlv(0x03, TestDer.bytes(0x00), bits))

    /** `RSASSA-PSS-params` with each field written out when given (null omits it, so it takes its DEFAULT). */
    fun pssParams(
        hash: String? = null,
        mgfHash: String? = null,
        salt: Int? = null,
        trailer: Int? = null,
    ): ByteArray =
        TestDer.seq(
            hash?.let { TestDer.tlv(0xa0, algId(it)) } ?: ByteArray(0),
            mgfHash?.let { TestDer.tlv(0xa1, algId(MGF1, algId(it))) } ?: ByteArray(0),
            salt?.let { TestDer.tlv(0xa2, integer(it)) } ?: ByteArray(0),
            trailer?.let { TestDer.tlv(0xa3, integer(it)) } ?: ByteArray(0),
        )

    fun pssSpec(
        hash: String,
        mgfHash: String,
        salt: Int,
    ): PSSParameterSpec = PSSParameterSpec(hash, "MGF1", MGF1ParameterSpec(mgfHash), salt, 1)

    fun integer(value: Int): ByteArray =
        TestDer.tlv(
            0x02,
            java.math.BigInteger
                .valueOf(value.toLong())
                .toByteArray(),
        )

    fun flip(
        bytes: ByteArray,
        index: Int = bytes.size - 1,
    ): ByteArray = bytes.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }
}

/**
 * A provider built per test: each service is a factory, so a test chooses what the provider's `Signature` or
 * `KeyFactory` does (spec §9 "Verifier": a throwing provider, a provider owning a composite OID).
 */
internal class TestProvider(
    name: String,
) : Provider(name, "1", "revokt verifier test provider") {
    fun signature(
        algorithm: String,
        make: () -> SignatureSpi,
    ): TestProvider = also { putService(Factory(this, "Signature", algorithm, make)) }

    fun keyFactory(
        algorithm: String,
        make: () -> KeyFactorySpi,
    ): TestProvider = also { putService(Factory(this, "KeyFactory", algorithm, make)) }

    private class Factory(
        provider: Provider,
        type: String,
        algorithm: String,
        private val make: () -> Any,
    ) : Service(provider, type, algorithm, Any::class.java.name, null, null) {
        override fun newInstance(constructorParameter: Any?): Any = make()
    }
}

/** A `SignatureSpi` over a real JDK [Signature]; [onVerify] may replace the answer or throw. */
internal open class DelegatingSignature(
    private val inner: Signature,
    private val onVerify: (Boolean) -> Boolean = { it },
) : SignatureSpi() {
    override fun engineInitVerify(publicKey: PublicKey) = inner.initVerify(publicKey)

    override fun engineInitSign(privateKey: PrivateKey) = inner.initSign(privateKey)

    override fun engineUpdate(b: Byte) = inner.update(b)

    override fun engineUpdate(
        b: ByteArray,
        off: Int,
        len: Int,
    ) = inner.update(b, off, len)

    override fun engineSign(): ByteArray = inner.sign()

    override fun engineVerify(sigBytes: ByteArray): Boolean = onVerify(inner.verify(sigBytes))

    @Deprecated("JCA legacy API", ReplaceWith(""))
    override fun engineSetParameter(
        param: String?,
        value: Any?,
    ): Unit = throw UnsupportedOperationException()

    @Deprecated("JCA legacy API", ReplaceWith(""))
    override fun engineGetParameter(param: String?): Any = throw UnsupportedOperationException()
}

/** A `KeyFactorySpi` over a real JDK [KeyFactory]; [onPublic] may replace the key or throw. */
internal class DelegatingKeyFactory(
    private val inner: KeyFactory,
    private val onPublic: (KeySpec) -> PublicKey = { inner.generatePublic(it) },
) : KeyFactorySpi() {
    override fun engineGeneratePublic(keySpec: KeySpec): PublicKey = onPublic(keySpec)

    override fun engineGeneratePrivate(keySpec: KeySpec): PrivateKey = throw UnsupportedOperationException()

    override fun <T : KeySpec> engineGetKeySpec(
        key: Key,
        keySpec: Class<T>,
    ): T = throw UnsupportedOperationException()

    override fun engineTranslateKey(key: Key): Key = throw UnsupportedOperationException()
}

/**
 * A `SignatureSpi` that accepts every signature under any parameters: a provider that checks nothing, so a test can
 * show which rejections are the verifier's own rules rather than the provider's.
 */
internal class AcceptingSignature : SignatureSpi() {
    override fun engineInitVerify(publicKey: PublicKey) = Unit

    override fun engineInitSign(privateKey: PrivateKey) = Unit

    override fun engineUpdate(b: Byte) = Unit

    override fun engineUpdate(
        b: ByteArray,
        off: Int,
        len: Int,
    ) = Unit

    override fun engineSign(): ByteArray = ByteArray(0)

    override fun engineVerify(sigBytes: ByteArray): Boolean = true

    override fun engineSetParameter(params: AlgorithmParameterSpec?) = Unit

    @Deprecated("JCA legacy API", ReplaceWith(""))
    override fun engineSetParameter(
        param: String?,
        value: Any?,
    ): Unit = throw UnsupportedOperationException()

    @Deprecated("JCA legacy API", ReplaceWith(""))
    override fun engineGetParameter(param: String?): Any = throw UnsupportedOperationException()
}
