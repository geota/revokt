// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import java.lang.reflect.Field
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.lang.reflect.ParameterizedType
import java.lang.reflect.Type
import java.lang.reflect.WildcardType
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The facts an exemption or a later policy language sees are plain data (#120's CEL-readiness criteria for #81 and
 * #84): every public member of `Verdict`, `ExemptionContext` and the types they reach returns a primitive, a `String`, a
 * `ByteArray`, an enum, a `List`, `Set` or `Map` of those, or another fact type held to the same rule. No lambda, no
 * platform object, nothing computed lazily from one.
 */
@OptIn(RevoktInternalApi::class)
class FactShapeTest {
    /** The fact types, each checked member by member; `Finding`'s subtypes are reached through `Verdict.findings`. */
    private val checked: Set<Class<*>> =
        setOf(
            Verdict.Accepted::class.java,
            Verdict.Rejected::class.java,
            ExemptionContext::class.java,
            PresentedChain::class.java,
            WalkStats::class.java,
        ) + Finding::class.java.declaredClasses.filter { Finding::class.java.isAssignableFrom(it) }

    /** What a fact member may return besides plain data: another fact type, or `Finding` itself (it has no members). */
    private val facts: Set<Class<*>> = checked + Finding::class.java + Verdict::class.java

    private val plain: Set<Class<*>> =
        setOf(
            String::class.java,
            ByteArray::class.java,
            Long::class.javaObjectType,
            Int::class.javaObjectType,
            Boolean::class.javaObjectType,
        )

    private val containers: Set<Class<*>> = setOf(List::class.java, Set::class.java, Map::class.java)

    private fun isPlain(type: Type): Boolean =
        when (type) {
            is Class<*> -> type.isPrimitive || type in plain || type.isEnum || type in facts
            is WildcardType -> type.upperBounds.all(::isPlain)
            is ParameterizedType -> type.rawType in containers && type.actualTypeArguments.all(::isPlain)
            else -> false
        }

    /** The members a consumer can call: public, not static, not `Object`'s, not the builder, not mangled internals. */
    private fun members(type: Class<*>): List<Method> =
        type.methods.filter { m ->
            !Modifier.isStatic(m.modifiers) &&
                !m.isSynthetic &&
                m.declaringClass != Any::class.java &&
                '$' !in m.name &&
                m.name !in setOf("newBuilder", "equals", "hashCode", "toString")
        }

    /** The public instance fields (`@JvmField`), which a policy runtime could read as well. */
    private fun fields(type: Class<*>): List<Field> =
        type.fields.filter { !Modifier.isStatic(it.modifiers) && !it.isSynthetic && '$' !in it.name }

    @Test
    fun `every fact member returns plain data`() {
        val offending =
            checked.flatMap { type ->
                members(type).filterNot { isPlain(it.genericReturnType) }.map {
                    "${type.simpleName}.${it.name}(): ${it.genericReturnType}"
                } +
                    fields(type).filterNot { isPlain(it.genericType) }.map {
                        "${type.simpleName}.${it.name}: ${it.genericType}"
                    }
            }
        assertEquals(emptyList(), offending)
    }

    @Test
    fun `every fact type has members to check`() {
        val empty = checked.filter { members(it).isEmpty() && fields(it).isEmpty() }.map { it.simpleName }
        assertEquals(emptyList(), empty)
        assertTrue(checked.size >= 14, "the Finding subtypes were found: $checked")
    }

    @Test
    fun `the check reaches the verdict's fields`() {
        val names = members(Verdict.Rejected::class.java).map { it.name }.toSet()
        for (getter in listOf(
            "getRules",
            "getRule",
            "getFindings",
            "getElapsedNanos",
            "getPath",
            "getCrlite",
            "getDataStates",
        )) {
            assertTrue(getter in names, "$getter missing from $names")
        }
        assertTrue(Finding.DataState::class.java in facts && Finding.Crlite::class.java in facts)
    }
}
