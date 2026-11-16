// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonArray
import dev.revokt.engine.json.JsonInteger
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.json.JsonParseException
import dev.revokt.engine.json.JsonString
import dev.revokt.engine.json.JsonValue
import dev.revokt.engine.store.GenerationNames
import okio.ByteString
import okio.ByteString.Companion.decodeHex

/**
 * One `files` entry of a C2SP mirror's `manifest.json` as served (spec §7.3): unchecked until [ManifestNames.check].
 * [size] is the declared size, [Long.MAX_VALUE] for a `u64` beyond it, which every cap refuses.
 */
internal class ManifestFile(
    val filename: String,
    val size: Long,
    val hash: String,
) {
    override fun toString(): String = "ManifestFile($filename, $size bytes, $hash)"
}

/**
 * A C2SP mirror's `manifest.json` (spec §7.3, upki v1.0.1's `Manifest`): `generated_at` (seconds, an unsigned integer),
 * `comment` (a string, required) and `files` (serde alias `filters`), an array of `{filename, size, hash}`. Unsigned:
 * nothing in it names anything until [ManifestNames.check] passes it.
 */
internal class C2spManifest(
    val generatedAt: ULong,
    val comment: String,
    val files: List<ManifestFile>,
) {
    override fun toString(): String = "C2spManifest(generatedAt=$generatedAt, ${files.size} files)"

    internal companion object {
        /**
         * The manifest in [bytes], parsed with the engine's JSON tree under [maxJsonBytes] (duplicate keys refused), or
         * why it is not one: not a JSON object; `generated_at` not an integer from 0 to [MAX_GENERATED_AT] (upki's
         * range); no string `comment`; neither or both of `files` and `filters` (serde refuses an alias given twice as a
         * duplicate field); an entry that is not an object, or whose `filename` or `hash` is not a string or whose `size`
         * is not an integer from 0 to `u64`. Other members are allowed, as serde allows them. The values are checked by [ManifestNames].
         */
        fun parse(
            bytes: ByteString,
            maxJsonBytes: Long,
        ): ManifestRead {
            val root =
                try {
                    Json.parse(bytes.toByteArray(), maxJsonBytes) as? JsonObject
                } catch (e: JsonParseException) {
                    return ManifestRead.Malformed("not JSON: ${e.message}")
                } ?: return ManifestRead.Malformed("not a JSON object")
            val generatedAt =
                unsigned(root["generated_at"])?.takeIf { it <= MAX_GENERATED_AT }
                    ?: return ManifestRead.Malformed("generated_at is not an integer from 0 to 9999-12-30T22:00:00Z")
            val comment = string(root["comment"]) ?: return ManifestRead.Malformed("comment is not a string")
            val files = root["files"]
            val filters = root["filters"]
            if (files != null && filters != null) return ManifestRead.Malformed("both files and filters")
            val entries =
                ((files ?: filters) as? JsonArray)?.items
                    ?: return ManifestRead.Malformed("files is not an array")
            val read = ArrayList<ManifestFile>(entries.size)
            for ((i, entry) in entries.withIndex()) {
                val o = entry as? JsonObject ?: return ManifestRead.Malformed("files[$i] is not an object")
                val filename = string(o["filename"]) ?: return ManifestRead.Malformed("files[$i].filename")
                val size = unsigned(o["size"]) ?: return ManifestRead.Malformed("files[$i].size")
                val hash = string(o["hash"]) ?: return ManifestRead.Malformed("files[$i].hash")
                read += ManifestFile(filename, minOf(size, Long.MAX_VALUE.toULong()).toLong(), hash)
            }
            return ManifestRead.Parsed(C2spManifest(generatedAt, comment, read))
        }

        /**
         * The last `generated_at` upki v1.0.1 accepts: `Manifest::introduce` (`revocation/mod.rs:124-133`) refuses one
         * that `jiff::Timestamp::from_second` refuses (`FetchError::InvalidTimestamp`). jiff-core 0.1.1, which upki's
         * `Cargo.lock` pins under jiff 0.2.38, ends Unix seconds at 9999-12-31T23:59:59 less the largest offset,
         * 25:59:59 (`bounds.rs:384`): 9999-12-30T22:00:00Z.
         */
        const val MAX_GENERATED_AT: ULong = 253_402_207_200uL

        private fun string(value: JsonValue?): String? = (value as? JsonString)?.value

        private fun unsigned(value: JsonValue?): ULong? = (value as? JsonInteger)?.takeIf { !it.negative }?.magnitude
    }
}

/** A [C2spManifest.parse]: the manifest, or why the body is not one (`FAILED` at the manifest fetch's stage). */
internal sealed interface ManifestRead {
    class Parsed(
        val manifest: C2spManifest,
    ) : ManifestRead

    class Malformed(
        val detail: String,
    ) : ManifestRead
}

/**
 * A checked manifest entry: [filename] as served, which only its URL carries; [name], its name in the generation (spec
 * §6.5: the filename when it is a C2SP filename, otherwise its derived name); [sha256], the 32 bytes of its `hash`,
 * whose lowercase re-encoding is its `blobs/<sha256>` key; and [size], the declared size.
 */
internal class MirrorFile(
    val filename: String,
    val name: String,
    val sha256: ByteString,
    val size: Long,
) {
    override fun toString(): String = "MirrorFile($filename as $name, ${sha256.hex()}, $size bytes)"
}

/** What [ManifestNames.check] decided: every entry checked, in manifest order, or why the manifest is refused whole. */
internal sealed interface ManifestCheck {
    class Checked(
        val files: List<MirrorFile>,
    ) : ManifestCheck

    class Refused(
        val detail: String,
    ) : ManifestCheck
}

/**
 * Spec §7.3 "Manifest names" (revision 52; a mirror's data is unsigned, so a name it serves is checked before it names
 * anything). Every `manifest.json` filename passes §6.3's filename rule (1 to 64 bytes of `[A-Za-z0-9._-]`, not `.` or
 * `..`), does not end in `.` (Win32 strips a trailing `.`, so `meta.json.` would open `meta.json`), is none of §6.3's
 * reserved names compared ignoring ASCII case, and is unique in the manifest ignoring ASCII case; the names in the
 * generation ([GenerationNames.derive]) are unique ignoring ASCII case too. Each `hash` is exactly 64 hexadecimal
 * characters, either case. Any failure refuses the whole manifest, before any body is fetched or written.
 */
internal object ManifestNames {
    private const val SHA256_HEX = 64

    private val RESERVED: Set<String> = AttachmentName.RESERVED.mapTo(HashSet()) { lowerAscii(it) }

    fun check(files: List<ManifestFile>): ManifestCheck {
        val filenames = HashSet<String>()
        val names = HashSet<String>()
        val checked = ArrayList<MirrorFile>(files.size)
        for (file in files) {
            val f = file.filename
            val folded = lowerAscii(f)
            val problem =
                when {
                    !GenerationNames.isSourceFilename(f) -> "fails §6.3's filename rule"
                    f.endsWith('.') -> "ends in '.'"
                    folded in RESERVED -> "is a reserved name, ignoring ASCII case"
                    !filenames.add(folded) -> "appears twice, ignoring ASCII case"
                    !isSha256Hex(file.hash) -> "has a hash that is not 64 hex characters"
                    else -> null
                }
            if (problem != null) return ManifestCheck.Refused("\"$f\" $problem")
            val name = GenerationNames.derive(f)
            if (!names.add(lowerAscii(name))) {
                return ManifestCheck.Refused(
                    "\"$f\" is named $name in the generation, a name taken ignoring ASCII case",
                )
            }
            checked += MirrorFile(f, name, lowerAscii(file.hash).decodeHex(), file.size)
        }
        return ManifestCheck.Checked(checked)
    }

    private fun isSha256Hex(hash: String): Boolean =
        hash.length == SHA256_HEX && hash.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    /** [s] with only `A` to `Z` lowercased, the ASCII case folding §7.3 compares names under. */
    private fun lowerAscii(s: String): String =
        buildString(s.length) {
            for (c in s) {
                append(
                    if (c in
                        'A'..'Z'
                    ) {
                        c + 32
                    } else {
                        c
                    },
                )
            }
        }
}
