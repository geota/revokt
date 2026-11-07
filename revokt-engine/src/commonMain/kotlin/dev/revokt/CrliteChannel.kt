// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * Mozilla's CRLite channel a configuration follows (spec §4, §7.2). Mandatory whenever a CRLite source, a seed included,
 * is configured: the consumer chooses. Growable. Store paths and the bundled seed's resource name use the lowercase enum
 * name (`/revokt/seed-compat.zip`, spec §6.5).
 */
public enum class CrliteChannel {
    COMPAT,
    DEFAULT,
}
