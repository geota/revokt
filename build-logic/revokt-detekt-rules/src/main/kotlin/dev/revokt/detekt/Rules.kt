// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.detekt

import io.gitlab.arturbosch.detekt.api.CodeSmell
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Entity
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Rule
import io.gitlab.arturbosch.detekt.api.Severity
import io.gitlab.arturbosch.detekt.api.config
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtDeclaration
import org.jetbrains.kotlin.psi.KtElement
import org.jetbrains.kotlin.psi.KtEnumEntry
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtImportDirective
import org.jetbrains.kotlin.psi.KtModifierListOwner
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.psiUtil.containingClassOrObject

private val MARKERS = setOf("RevoktInternalApi", "RevoktTestingApi")

/** No `internal`/`private`/`protected` on this declaration or any containing one (no type resolution needed). */
private fun KtDeclaration.isEffectivelyPublic(): Boolean {
    var current: KtDeclaration? = this
    while (current != null) {
        val m = current.modifierList
        if (m != null && (m.hasModifier(KtTokens.INTERNAL_KEYWORD) || m.hasModifier(KtTokens.PRIVATE_KEYWORD) || m.hasModifier(KtTokens.PROTECTED_KEYWORD))) return false
        current = current.containingClassOrObject
    }
    return true
}

private fun KtModifierListOwner.hasMarker(): Boolean =
    annotationEntries.any { entry -> entry.shortName?.asString() in MARKERS } ||
        (this as? KtDeclaration)?.containingClassOrObject?.hasMarker() == true

private fun KtElement.packageName(): String = containingKtFile.packageFqName.asString()

/**
 * Spec §4: every public value or output type is a final class with a private constructor and a nested Builder.
 * Exempt structurally: `Builder` classes, exception types, objects/enums/annotations/interfaces, marker-annotated
 * declarations, and the configured service types (`allowedClasses`, fully qualified).
 */
class PublicConstructorOnFinalClass(config: Config = Config.empty) : Rule(config) {
    override val issue = Issue(
        javaClass.simpleName,
        Severity.Maintainability,
        "A public final class on the published surface must take a private constructor and a nested Builder (spec §4).",
        Debt.TWENTY_MINS,
    )

    private val allowedClasses: List<String> by config(emptyList())

    override fun visitClass(klass: KtClass) {
        super.visitClass(klass)
        if (klass is KtEnumEntry) return
        if (klass.isInterface() || klass.isEnum() || klass.isAnnotation() || klass.isSealed() || klass.hasModifier(KtTokens.ABSTRACT_KEYWORD)) return
        if (klass.hasModifier(KtTokens.OPEN_KEYWORD)) return
        if (klass.name == "Builder") return
        if (!klass.isEffectivelyPublic()) return
        if (klass.hasMarker()) return
        if (klass.superTypeListEntries.any { it.typeAsUserType?.referencedName?.let { n -> n.endsWith("Exception") || n.endsWith("Error") } == true }) return
        val fqn = klass.fqName?.asString() ?: return
        if (fqn in allowedClasses) return

        val primary = klass.primaryConstructor
        val primaryPublic = primary == null || primary.modifierList?.let {
            !(it.hasModifier(KtTokens.PRIVATE_KEYWORD) || it.hasModifier(KtTokens.INTERNAL_KEYWORD) || it.hasModifier(KtTokens.PROTECTED_KEYWORD))
        } ?: true
        val secondaryPublic = klass.secondaryConstructors.any { c ->
            c.modifierList?.let { !(it.hasModifier(KtTokens.PRIVATE_KEYWORD) || it.hasModifier(KtTokens.INTERNAL_KEYWORD) || it.hasModifier(KtTokens.PROTECTED_KEYWORD)) } ?: true
        }
        if (primaryPublic || secondaryPublic) {
            report(
                CodeSmell(
                    issue,
                    Entity.from(klass),
                    "Public constructor on final class $fqn: give it a private constructor and a nested Builder (CONTRIBUTING §3, spec §4), " +
                        "or, for a service type, add it to revokt>PublicConstructorOnFinalClass>allowedClasses in detekt.yml with a reason.",
                ),
            )
        }
    }
}

/** Spec §4: no data classes and no inline value classes on the public surface. */
class NoDataOrValueClassOnPublicSurface(config: Config = Config.empty) : Rule(config) {
    override val issue = Issue(
        javaClass.simpleName,
        Severity.Maintainability,
        "No data class or value class on the published surface (spec §4).",
        Debt.TWENTY_MINS,
    )

    override fun visitClass(klass: KtClass) {
        super.visitClass(klass)
        if (klass is KtEnumEntry) return
        if (!klass.isEffectivelyPublic() || klass.hasMarker()) return
        val kind = when {
            klass.isData() -> "data class"
            klass.isValue() -> "value class"
            else -> return
        }
        report(
            CodeSmell(
                issue,
                Entity.from(klass),
                "$kind ${klass.fqName?.asString()} is public: public types use a final class with content-based equals/hashCode/toString " +
                    "and a Builder (spec §4); make it internal, or convert it.",
            ),
        )
    }
}

/** Spec §3.1 item 5: no `inline fun` and no `const val` in the clubcard port package. */
class ClubcardPortRules(config: Config = Config.empty) : Rule(config) {
    override val issue = Issue(
        javaClass.simpleName,
        Severity.Maintainability,
        "The MPL port package carries no inline functions and no const vals (spec §3.1 item 5).",
        Debt.TEN_MINS,
    )

    private fun inPort(element: KtElement) = element.packageName().contains(".clubcard.port")

    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        if (inPort(function) && function.hasModifier(KtTokens.INLINE_KEYWORD)) {
            report(CodeSmell(issue, Entity.from(function), "inline fun ${function.name} in the clubcard port: remove `inline` (spec §3.1 item 5; inline bodies would be copied into Apache-licensed callers)."))
        }
    }

    override fun visitProperty(property: KtProperty) {
        super.visitProperty(property)
        if (inPort(property) && property.hasModifier(KtTokens.CONST_KEYWORD)) {
            report(CodeSmell(issue, Entity.from(property), "const val ${property.name} in the clubcard port: use a plain `val` (spec §3.1 item 5; constants would be inlined into Apache-licensed callers)."))
        }
    }
}

/**
 * CONTRIBUTING §3 / §6: test sources never open an HTTP client; loopback TLS fixtures live under a `fetch`
 * directory, which detekt.yml excludes. Advisory: the runner's egress policy is the real gate.
 */
class NoHttpClientInTests(config: Config = Config.empty) : Rule(config) {
    override val issue = Issue(
        javaClass.simpleName,
        Severity.Maintainability,
        "No HTTP client in test sources outside fetch fixtures (CONTRIBUTING §6).",
        Debt.TEN_MINS,
    )

    private val imports: List<String> by config(
        listOf("java.net.http.", "java.net.URL", "java.net.HttpURLConnection", "javax.net.ssl.HttpsURLConnection"),
    )

    override fun visitImportDirective(importDirective: KtImportDirective) {
        super.visitImportDirective(importDirective)
        val path = importDirective.importedFqName?.asString() ?: return
        if (imports.any { path == it.trimEnd('.') || path.startsWith(it) }) {
            report(CodeSmell(issue, Entity.from(importDirective), "import $path in a test: tests never touch the network (CONTRIBUTING §6); use the injected HttpFetcher seam or move a loopback fixture under a fetch/ directory."))
        }
    }

    override fun visitKtFile(file: KtFile) {
        if (!file.virtualFilePath.contains("Test") && !file.virtualFilePath.contains("/test/")) return
        super.visitKtFile(file)
    }
}
