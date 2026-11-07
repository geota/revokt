// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import java.io.InputStream

/**
 * Opens a seed archive for `SeedSource.of` (spec §4): called on every start task and seed re-check, from Java as a
 * lambda. A null stream means there is no archive to open; a throw makes the seed unreadable. revokt closes the stream.
 */
public fun interface SeedOpener {
    public fun open(): InputStream?
}
