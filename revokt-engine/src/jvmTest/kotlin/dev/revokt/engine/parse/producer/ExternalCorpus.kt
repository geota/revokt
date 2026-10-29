// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.engine.parse.records.Json
import okio.ByteString.Companion.toByteString
import java.io.File
import java.util.Base64
import java.util.zip.GZIPInputStream
import java.util.zip.ZipInputStream

/**
 * The large corpus of spec §9.2 (docs/dev/corpus.md): the revokt-corpus checkout `-Prevokt.corpus` names, which the build
 * passes to the tests as `revokt.corpus`. Its inputs join the replay corpus, and their goldens and records sit beside them
 * in its `replay/` directory, gzipped; without it the replay is the committed corpus alone.
 */
internal object ExternalCorpus {
    /** The checkout, or null when the run has none. */
    val dir: File? = System.getProperty("revokt.corpus")?.takeIf { it.isNotEmpty() }?.let(::File)

    /** The name prefix of every input from `x509-limbo/`, and of the bytes an oracle reads for one. */
    const val LIMBO = "x509-limbo/"

    /** The name prefix of the issuer corpus's inputs (spec §9.2 "Issuer corpus", revision 42). */
    const val ISSUER = "issuer/"

    /** The name prefix of the CT seed corpus's inputs (spec §9.2, the seed corpus's CT leaves). */
    const val CT_SEED = "ct-seed/"

    private val PREFIXES = listOf(LIMBO, ISSUER, CT_SEED)

    /** Whether the input (or read) named [name] belongs to this corpus, so that its goldens and records live here. */
    fun owns(name: String): Boolean = PREFIXES.any { name.startsWith(it) }

    /** This corpus's inputs, none without a checkout. */
    fun inputs(): List<ProducerCorpus.Input> =
        dir?.let { limbo(File(it, "x509-limbo/limbo.json").readText()) + issuer.inputs + ctSeed(it) }.orEmpty()

    /** An issuer-corpus certificate's snapshots, by input name: the sources its records name. */
    class Issuer(
        val inputs: List<ProducerCorpus.Input>,
        val sources: Map<String, Set<String>>,
    )

    /**
     * The issuer corpus (`issuer/`, its PROVENANCE): every distinct certificate of each snapshot, named
     * `issuer/<sha256>`, with the snapshots that hold it. Only the snapshots' own files are read.
     */
    val issuer: Issuer by lazy {
        val root = dir?.let { File(it, "issuer") }
        if (root == null) return@lazy Issuer(emptyList(), emptyMap())
        val sources = LinkedHashMap<String, MutableSet<String>>()
        val ders = HashMap<String, ByteArray>()

        fun add(
            source: String,
            der: ByteArray,
        ) {
            val name = ISSUER + der.toByteString().sha256().hex()
            ders.getOrPut(name) { der }
            sources.getOrPut(name) { sortedSetOf() } += source
        }
        pemBlocks(File(root, "ccadb-mozilla-unexpired/MozillaAllUnexpiredPEMs.csv").readText()).forEach {
            add("ccadb-mozilla-unexpired", it)
        }
        File(root, "ccadb-all/pems").listFiles { f -> f.name.endsWith(".csv") }!!.sorted().forEach { f ->
            pemBlocks(f.readText()).forEach { add("ccadb-all", it) }
        }
        // The records export's certificates the PEM export lacks, fetched from crt.sh by fingerprint (PROVENANCE).
        File(root, "ccadb-all/crtsh").listFiles { f -> f.name.endsWith(".pem") }.orEmpty().sorted().forEach { f ->
            pemBlocks(f.readText()).forEach { add("ccadb-all (crt.sh)", it) }
        }
        ZipInputStream(File(root, "mozilla-intermediates/security-state--intermediates.zip").inputStream()).use { z ->
            generateSequence { z.nextEntry }.forEach { _ ->
                pemBlocks(String(z.readBytes(), Charsets.ISO_8859_1)).forEach { add("mozilla-intermediates", it) }
            }
        }
        File(root, "jdk-cacerts").listFiles { f -> f.name.endsWith(".txt") }!!.sorted().forEach { f ->
            pemBlocks(f.readText()).forEach { add("jdk-cacerts/" + f.name.removeSuffix(".txt"), it) }
        }
        File(root, "aosp/files").listFiles()!!.sorted().forEach { f ->
            pemBlocks(String(f.readBytes(), Charsets.ISO_8859_1)).forEach { add("aosp", it) }
        }
        Issuer(ders.entries.sortedBy { it.key }.map { (n, d) -> ProducerCorpus.Input(n, d) }, sources)
    }

    /**
     * The CT seed corpus's leaves (sha256, log id, index, entry type, base64 DER), named `ct-seed/<sha256>`: the 16
     * shards `ct-seed/leaves/<0-f>.tsv.gz` by the sha256's first hex digit (#64), or `ct-seed/leaves.tsv.gz` of an older
     * tag. Each line's sha256 must be its DER's, a shard holds only its digit's leaves, and a leaf appears once.
     */
    fun ctSeed(dir: File): List<ProducerCorpus.Input> {
        val shards = File(dir, "ct-seed/leaves")
        val single = File(dir, "ct-seed/leaves.tsv.gz")
        val files = shardFiles(shards, single).ifEmpty { listOf(single) }
        val seen = HashSet<String>()
        return files.flatMap { file ->
            val digit = file.name.removeSuffix(".tsv.gz").takeIf { file.parentFile == shards }
            GZIPInputStream(file.inputStream()).bufferedReader().useLines { lines ->
                lines
                    .filter { it.isNotBlank() }
                    .map { line ->
                        val f = line.split('\t')
                        val der = Base64.getDecoder().decode(f[4])
                        check(
                            der.toByteString().sha256().hex() == f[0],
                        ) { "ct-seed leaf ${f[0]}: its DER hashes otherwise" }
                        check(digit == null || f[0].startsWith(digit)) { "ct-seed leaf ${f[0]} in shard $digit" }
                        check(seen.add(f[0])) { "ct-seed leaf ${f[0]} twice" }
                        ProducerCorpus.Input(CT_SEED + f[0], der)
                    }.toList()
            }
        }
    }

    /** The DER of every PEM `CERTIFICATE` block in [text] (a CSV field, a PEM bundle, a store file). */
    fun pemBlocks(text: String): List<ByteArray> =
        Regex("-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\\s\"']*?)-----END CERTIFICATE-----")
            .findAll(text)
            .map {
                Base64.getDecoder().decode(
                    it.groupValues[1].filter { c ->
                        c.isLetterOrDigit() || c == '+' || c == '/' ||
                            c == '='
                    },
                )
            }.toList()

    /**
     * Every distinct certificate of `limbo.json`'s testcases (trusted, untrusted intermediates and peer), once each since
     * one certificate can serve many testcases, named `x509-limbo/<sha256>` and sorted by name.
     */
    fun limbo(text: String): List<ProducerCorpus.Input> {
        val testcases = (Json.parse(text) as Json.Obj).array("testcases")
        val ders = LinkedHashMap<String, ByteArray>()
        for (t in testcases) {
            val o = t as? Json.Obj ?: error("a limbo testcase is not an object")
            val pems =
                o.strings("trusted_certs") + o.strings("untrusted_intermediates") +
                    listOfNotNull(o.stringOrNull("peer_certificate"))
            for (pem in pems) {
                val der = pemDer(pem)
                ders.getOrPut(der.toByteString().sha256().hex()) { der }
            }
        }
        return ders.map { (sha, der) -> ProducerCorpus.Input("$LIMBO$sha", der) }.sortedBy { it.name }
    }

    /** One PEM `CERTIFICATE` block's DER; anything else fails. */
    fun pemDer(pem: String): ByteArray {
        val lines = pem.trim().lines().map { it.trim() }
        check(lines.first() == "-----BEGIN CERTIFICATE-----" && lines.last() == "-----END CERTIFICATE-----") {
            "not one PEM certificate: ${lines.first()}"
        }
        return Base64.getDecoder().decode(lines.subList(1, lines.size - 1).joinToString(""))
    }

    /**
     * The goldens `replay/<name>`: the 16 shards `replay/<name>/<0-f>.tsv.gz`, keyed by the first hex digit of the key
     * (#64), or the single file `replay/<name>.tsv.gz` of an older tag. Key → rest of line; empty without a checkout or
     * before they are recorded.
     */
    fun tsv(name: String): Map<String, String> {
        val out = HashMap<String, String>()
        for (file in goldenFiles(name)) {
            GZIPInputStream(file.inputStream()).bufferedReader().useLines { lines ->
                val shard = file.name.removeSuffix(".tsv.gz").takeIf { file.parentFile.name == name }
                lines.filter { it.isNotBlank() && !it.startsWith("#") }.forEach { line ->
                    val key = line.substringBefore('\t')
                    check(
                        shard == null || key.startsWith(shard),
                    ) { "$name/${file.name}: key $key in another digit's shard" }
                    check(out.put(key, line.substringAfter('\t')) == null) { "$name: key $key twice" }
                }
            }
        }
        return out
    }

    /** The first line of `replay/<name>`'s goldens, which every shard must carry, or null before they are recorded. */
    fun header(name: String): String? {
        val headers =
            goldenFiles(name).map { f -> GZIPInputStream(f.inputStream()).bufferedReader().use { it.readLine() } }
        check(headers.distinct().size <= 1) { "$name: shards with different headers" }
        return headers.firstOrNull()
    }

    private fun goldenFiles(name: String): List<File> {
        val shards = replay(name) ?: return emptyList()
        val single = File(shards.parentFile, "$name.tsv.gz")
        return shardFiles(shards, single).ifEmpty { listOfNotNull(single.takeIf { it.isFile }) }
    }

    /** The 16 shards `<0-f>.tsv.gz` of [shards] when it is a directory, all of them and never beside [single]; else empty. */
    private fun shardFiles(
        shards: File,
        single: File,
    ): List<File> {
        if (!shards.isDirectory) return emptyList()
        check(!single.exists()) { "both $shards and $single: one layout per tag" }
        return (0 until 16).map { File(shards, "%x.tsv.gz".format(it)) }.onEach {
            check(it.isFile) { "$it: a shard is missing" }
        }
    }

    /** A file of `replay/`, or null without a checkout. */
    fun replay(name: String): File? = dir?.let { File(it, "replay/$name") }
}
