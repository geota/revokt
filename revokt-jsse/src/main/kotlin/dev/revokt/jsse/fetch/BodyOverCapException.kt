// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse.fetch

import java.io.IOException

/** The decoded body of a response is longer than the request's `maxBodyBytes` (spec §3 `FetchResponse`). */
internal class BodyOverCapException(
    maxBodyBytes: Long,
) : IOException("the decoded body exceeds maxBodyBytes ($maxBodyBytes)")
