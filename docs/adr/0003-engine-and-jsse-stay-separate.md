# ADR-0003: `revokt-engine` and `revokt-jsse` stay separate artifacts through 0.3

- Status: accepted, 2026-10-22
- Deciders: maintainer

## Context

`revokt-engine` is the multiplatform core (parser, clubcard port, walker, policy, updater) with a purity gate that
compiles it for `linuxX64`; `revokt-jsse` is the JVM facade (`Revokt`, `RevoktTrustManager`). The split costs
cross-artifact plumbing under `@RevoktInternalApi` and invites drift (one review found the `Rule → BasicReason` map
on the wrong side). Merging would drop the purity gate's value and widen what a third-party engine author depends on.

## Decision

Keep the split through 0.3, since the purity gate and the engine seam are 0.1 deliverables that depend on it.
Reconsider at 1.0 if the `@RevoktInternalApi` surface between the two has grown.

## Consequences

The `Rule → BasicReason` map lives in `revokt-engine` jvmMain so the 0.1 golden fixture is total. `verifyDependencyScopes`
keeps Okio and the clubcard port out of every api variant.
