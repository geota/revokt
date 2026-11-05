// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

/**
 * Spec §5.5's catch rule: true for a `VirtualMachineError` other than `StackOverflowError`, the only throwables a catch
 * of consumer or server-driven code rethrows. Everything else, a `StackOverflowError` or a consumer's
 * `NotImplementedError` included, is caught.
 */
internal expect fun isFatal(t: Throwable): Boolean
