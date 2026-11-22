// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.FetchResponse

/** How one [fetchWithin] call ended. */
internal sealed class Timed {
    /** The fetcher returned; [response] is null when a Java fetcher returned null. */
    class Done(
        val response: FetchResponse?,
    ) : Timed()

    /** The fetcher threw [cause], the executor refused the task, or the waiting thread was interrupted. */
    class Threw(
        val cause: Throwable,
    ) : Timed()

    /** The deadline passed; the fetch was cancelled and, on the JVM, its thread interrupted. */
    data object TimedOut : Timed()
}
