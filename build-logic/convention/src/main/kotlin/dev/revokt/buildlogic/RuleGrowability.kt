// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/** The `Rule` growability golden fixture, relative to the root project (spec §4 "Growability contract", #72). */
const val RULE_FIXTURE = "revokt-engine/src/jvmTest/resources/dev/revokt/engine/policy/rule-growability.tsv"

/**
 * Spec §4 "Growability contract": the golden fixture's diff against its version at the merge base may only add a rule
 * with `ALLOW` in both presets in the minor that introduces it, at the end of its class group; make a preset's
 * one-minor `ALLOW → REJECT` flip, setting that preset's `flippedIn`; turn `exemptable` from false to true; and add a
 * dataset's rows outside the staleness map. Existing rules keep their relative order, which is the precedence. Anything
 * else fails, naming the row and field and saying what to do (#73). The contract holds within a major: a fixture whose
 * rules all predate the current major is not compared.
 */
abstract class VerifyRuleGrowabilityTask : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val fixture: RegularFileProperty

    /** The fixture's text at the base; absent when the base could not be read or has no fixture. */
    @get:Input
    @get:Optional
    abstract val baseFixture: Property<String>

    /** Where the base came from, for the messages. */
    @get:Input
    abstract val baseRef: Property<String>

    /** True when the base was given explicitly (CI): a base commit that cannot be read then fails instead of skipping. */
    @get:Input
    abstract val required: Property<Boolean>

    /** Whether the base commit exists locally; with no fixture at an existing base, the fixture is being introduced. */
    @get:Input
    abstract val baseCommitExists: Property<Boolean>

    /** The project version (`revokt.version` in gradle.properties); its `major.minor` is the current minor. */
    @get:Input
    abstract val projectVersion: Property<String>

    @TaskAction
    fun verify() {
        val outcome =
            RuleGrowability.decide(
                base = baseFixture.orNull,
                head = fixture.get().asFile.readText(),
                currentMinor = RuleGrowability.minorOf(projectVersion.get()),
                baseRef = baseRef.get(),
                required = required.get(),
                baseCommitExists = baseCommitExists.get(),
            )
        when (outcome) {
            is RuleGrowability.Outcome.Pass -> outcome.note?.let { logger.lifecycle("verifyRuleGrowability: $it") }
            is RuleGrowability.Outcome.Fail -> throw GradleException("verifyRuleGrowability: ${outcome.message}")
        }
    }
}

/** The fixture's parse and the contract's rules, kept free of Gradle so they can be tested directly. */
object RuleGrowability {
    private const val NONE = "-"
    private val PRESETS = listOf("DEFAULT", "STRICT")
    private val SECTIONS = listOf("rules", "presets", "datasets")
    private val FROZEN = listOf("class", "layer", "emptyPath", "basicReason", "introducedIn")

    /** M2's evidence rules ship `REJECT` from 0.4, as the 0.4 → 1.0 transition: the one exception to the `ALLOW` rule. */
    private val M2_TRANSITION = setOf("DENYLIST", "ONECRL", "CRLSET")

    /** What the task does with a comparison: pass (with a note to log, if any) or fail with a message. */
    sealed interface Outcome {
        data class Pass(val note: String?) : Outcome

        data class Fail(val message: String) : Outcome
    }

    /** The task's whole decision, including the cases with no base to compare against. */
    fun decide(base: String?, head: String, currentMinor: String, baseRef: String, required: Boolean, baseCommitExists: Boolean): Outcome {
        if (base == null) {
            if (required && !baseCommitExists) {
                return Outcome.Fail(
                    "the base commit $baseRef is not in this clone; fetch it first (git fetch --depth=1 origin $baseRef), " +
                        "as ci.yml's ci-extras job does.",
                )
            }
            val why = if (baseCommitExists) "the fixture does not exist there yet, so it is being introduced" else "no base commit"
            return Outcome.Pass("no base fixture at $baseRef ($why); nothing to compare.")
        }
        val found = problems(base, head, currentMinor)
        if (found.isEmpty()) return Outcome.Pass(null)
        return Outcome.Fail(
            "$RULE_FIXTURE changed against $baseRef in ways the growability contract (spec §4) forbids:\n" +
                found.joinToString("\n") { "  - $it" },
        )
    }

    /** `major.minor` of a version such as `0.1.0-SNAPSHOT` or `0.2-SNAPSHOT`. */
    fun minorOf(version: String): String =
        version.substringBefore("-").split(".").take(2).let { if (it.size == 2) it.joinToString(".") else "${it[0]}.0" }

    private fun majorOf(minor: String): Int = minor.substringBefore(".").toInt()

    private fun minorNumber(minor: String): Int = minor.substringAfter(".").toInt()

    /** The minor before [minor], or null at a major's first minor, where no rule of the major was introduced earlier. */
    private fun previous(minor: String): String? = if (minorNumber(minor) == 0) null else "${majorOf(minor)}.${minorNumber(minor) - 1}"

    private class Section(val header: List<String>, val rows: List<Map<String, String>>)

    private class Malformed(message: String) : Exception(message)

    private fun parse(text: String, which: String): Map<String, Section> {
        val lines = text.lines().filter { it.isNotBlank() && !it.startsWith("#") }
        val sections = linkedMapOf<String, Section>()
        var i = 0
        while (i < lines.size) {
            if (!lines[i].startsWith("[") || i + 1 >= lines.size) throw Malformed("the $which fixture has no section header before '${lines[i]}'")
            val name = lines[i].removeSurrounding("[", "]")
            if (name in sections) throw Malformed("the $which fixture has the [$name] section twice")
            val header = lines[i + 1].split("\t")
            val rows = mutableListOf<Map<String, String>>()
            i += 2
            while (i < lines.size && !lines[i].startsWith("[")) {
                val cells = lines[i].split("\t")
                if (cells.size != header.size) {
                    throw Malformed("the $which fixture's [$name] row '${lines[i]}' has ${cells.size} cells and the header ${header.size}; remove stray tabs")
                }
                rows += header.zip(cells).toMap()
                i++
            }
            sections[name] = Section(header, rows)
        }
        return sections
    }

    /** Every way [head] departs from [base] beyond what the contract permits; empty when the diff is allowed. */
    fun problems(base: String, head: String, currentMinor: String): List<String> {
        val (b, h) =
            try {
                parse(base, "base") to parse(head, "head")
            } catch (e: Malformed) {
                return listOf("${e.message}")
            }
        val out = mutableListOf<String>()
        (h.keys - SECTIONS.toSet()).forEach { out += "the head fixture has an unknown section [$it]; the fixture has [rules], [presets] and [datasets]" }
        for (name in SECTIONS) {
            if (name !in h) {
                out += "the [$name] section is missing from the head fixture; restore it"
                continue
            }
            val was = b[name]?.header ?: continue
            val now = h.getValue(name).header
            if (was != now) {
                val added = now - was.toSet()
                val removed = was - now.toSet()
                out +=
                    "the [$name] columns changed (added $added, removed $removed${if (added.isEmpty() && removed.isEmpty()) ", reordered" else ""}); " +
                    "the columns are frozen within a major: restore $was"
            }
        }
        if (out.isNotEmpty()) return out
        // The contract holds within a major: when every base rule predates the current major, nothing is frozen.
        val baseRules = b["rules"]?.rows.orEmpty()
        if (baseRules.isNotEmpty() && baseRules.maxOf { majorOf(it.getValue("introducedIn")) } < majorOf(currentMinor)) return emptyList()
        b["rules"]?.let { rules(it, h.getValue("rules"), currentMinor, out) }
        b["presets"]?.let { keyed("presets", it, h.getValue("presets"), listOf("preset"), out) { _ -> "a preset is never added within a major" } }
        b["datasets"]?.let {
            keyed("datasets", it, h.getValue("datasets"), listOf("preset", "dataset"), out) { row ->
                if (row["staleAfterMillis"] == NONE && row["rejectStaleAfterMillis"] == NONE) null
                else "a new dataset joins no preset's staleness map within a major: set both staleness columns to $NONE"
            }
        }
        return out
    }

    private fun rules(b: Section, h: Section, currentMinor: String, out: MutableList<String>) {
        duplicates("rules", h.rows.map { it.getValue("rule") }, out)
        val baseRules = b.rows.associateBy { it.getValue("rule") }
        val headRules = h.rows.associateBy { it.getValue("rule") }
        for ((name, was) in baseRules) {
            val now = headRules[name]
            if (now == null) {
                out += "rule $name was removed: a rule stays within a major (spec §4); restore its row"
                continue
            }
            for (col in FROZEN) {
                if (was[col] != now[col]) out += "rule $name: $col changed from ${was[col]} to ${now[col]}; it is frozen within a major: restore ${was[col]}"
            }
            if (was["exemptable"] != now["exemptable"] && !(was["exemptable"] == "false" && now["exemptable"] == "true")) {
                out += "rule $name: exemptable changed from ${was["exemptable"]} to ${now["exemptable"]}; only false to true is permitted: restore ${was["exemptable"]}"
            }
            for (preset in PRESETS) flip(name, preset, was, now, currentMinor, out)
        }
        val order = h.rows.map { it.getValue("rule") }
        for ((index, name) in order.withIndex()) {
            val row = headRules.getValue(name)
            if (name in baseRules) continue
            newRule(name, row, currentMinor, out)
            // A new rule goes at the end of its class group: no existing rule of its class may follow it.
            val after = order.drop(index + 1).filter { it in baseRules && baseRules.getValue(it)["class"] == row["class"] }
            if (after.isNotEmpty()) out += "new rule $name: placed before ${after.first()} of its class ${row["class"]}; append it after the last ${row["class"]} rule"
        }
        val kept = order.filter { it in baseRules }
        val was = b.rows.map { it.getValue("rule") }.filter { it in headRules }
        if (kept != was) {
            val moved = kept.zip(was).first { (k, w) -> k != w }
            out += "the rules were reordered: ${moved.first} now stands where ${moved.second} stood; existing rules keep their order (the precedence): restore $was"
        }
    }

    private fun newRule(name: String, row: Map<String, String>, currentMinor: String, out: MutableList<String>) {
        if (row["introducedIn"] != currentMinor) {
            out += "new rule $name: introducedIn is ${row["introducedIn"]}; a rule is added with the current minor: set it to $currentMinor"
        }
        // The 0.4 → 1.0 transition (§8, §11): M2's evidence rules may ship REJECT in both presets.
        val m2 =
            name in M2_TRANSITION && row["class"] == "EVIDENCE" && majorOf(currentMinor) == 0 && minorNumber(currentMinor) >= 4 &&
                PRESETS.all { row[it] == "REJECT" }
        for (preset in PRESETS) {
            if (row[preset] != "ALLOW" && !m2) out += "new rule $name: $preset is ${row[preset]}; a new rule ships ALLOW in every preset for one minor: set it to ALLOW"
            if (row["flippedIn.$preset"] != NONE) out += "new rule $name: flippedIn.$preset is ${row["flippedIn.$preset"]}; a new rule has not flipped: set it to $NONE"
        }
    }

    private fun flip(name: String, preset: String, was: Map<String, String>, now: Map<String, String>, currentMinor: String, out: MutableList<String>) {
        val flippedIn = "flippedIn.$preset"
        val (bo, ho, bf, hf) = listOf(was[preset], now[preset], was[flippedIn], now[flippedIn])
        when {
            bo == ho && bf == hf -> {}
            bo == ho -> out += "rule $name: $flippedIn changed from $bf to $hf without a flip: restore $bf"
            bo == "ALLOW" && ho == "REJECT" -> {
                val previous = previous(currentMinor)
                if (bf != NONE) {
                    out += "rule $name: $preset flipped ALLOW to REJECT again; it already flipped in $bf, and a rule flips at most once per preset"
                } else if (was["introducedIn"] != previous) {
                    out += "rule $name: $preset flipped ALLOW to REJECT, but it was introduced in ${was["introducedIn"]}; the flip comes in the minor " +
                        "after its introduction (${previous ?: "never at a major's first minor"}): keep ALLOW"
                } else if (hf != currentMinor) {
                    out += "rule $name: $preset flipped ALLOW to REJECT, so $flippedIn must record it: set it to $currentMinor (it is $hf)"
                }
            }
            else -> out += "rule $name: $preset changed from $bo to $ho; the only permitted change to a preset's outcome is the one-minor ALLOW to REJECT flip: restore $bo"
        }
    }

    private fun duplicates(section: String, ids: List<String>, out: MutableList<String>) {
        ids.groupingBy { it }.eachCount().filterValues { it > 1 }.keys.forEach { out += "[$section] has the row $it more than once; keep one" }
    }

    /** A section whose rows are frozen once present; [whyNotAddable] says why a new row may not be added, or null if it may. */
    private fun keyed(section: String, b: Section, h: Section, key: List<String>, out: MutableList<String>, whyNotAddable: (Map<String, String>) -> String?) {
        fun id(row: Map<String, String>) = key.joinToString("/") { row.getValue(it) }
        duplicates(section, h.rows.map(::id), out)
        val baseRows = b.rows.associateBy(::id)
        val headRows = h.rows.associateBy(::id)
        for ((id, was) in baseRows) {
            val now = headRows[id]
            if (now == null) {
                out += "[$section] row $id was removed; rows are frozen within a major: restore it"
            } else {
                for ((col, value) in was) if (now[col] != value) out += "[$section] row $id: $col changed from $value to ${now[col]}; it is frozen within a major: restore $value"
            }
        }
        for ((id, row) in headRows) {
            if (id in baseRows) continue
            whyNotAddable(row)?.let { out += "[$section] row $id was added: $it" }
        }
    }
}
