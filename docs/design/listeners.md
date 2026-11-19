<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Listeners

Not normative. Moved out of the spec's §5.1 at revision 59 (#216), as it stood at revision 58; milestone: 0.3. A note is promoted into the spec when its milestone starts, and edited there.

**Listeners** are dispatched off the handshake thread. `Accepted` events go through a ring of
`EVENT_RING_CAPACITY` (drop-oldest, `droppedEvents`); a `Rejected` event evicts the oldest `Accepted`
one, and when the ring holds only `Rejected` events it overflows into a side queue of
`REJECTED_QUEUE_CAPACITY` with its own counter `droppedRejectedEvents`. Events carry monotonic
sequence numbers. **Drain**: the ring is sequence-indexed; each registered listener holds its own
cursor (set to the current tail by `addListener`, so a listener sees only events enqueued after
registration; `removeListener` clears it and a running drain stops at its next event) and its own `drainScheduled` flag; each delivery runs under try/catch (a throwing `onVerdict` counts `listenerFailures` and the drain continues, so a cursor never stalls; a throwing `executor.execute` removes the listener instead, flow 3b); an event whose verdict carries `Finding.Exempted` is enqueued with `Rejected` priority (it evicts `Accepted` events and overflows to the side queue), so exempted evidence never vanishes from the audit stream under load; on enqueue the handshake thread CASes each listener's flag
and submits one drain task to that listener's executor; the task delivers every event with
`sequence > cursor` still in the ring or side queue in order, advances the cursor and clears the
flag, then re-checks `tail > cursor` and, if so, re-CASes and loops (no lost wake-up). The task copies
the pending slice under the ring lock and delivers outside it. Events are enqueued, and drops counted,
only while at least one listener is registered; side-queue entries are released once every cursor has
passed them. Delivery latency is one executor hop. `droppedEvents`/`droppedRejectedEvents` count
evictions from the ring (global); a slow listener misses evicted events and its gap is visible as a
sequence jump.
