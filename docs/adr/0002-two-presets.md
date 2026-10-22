# ADR-0002: Two presets, `DEFAULT` and `STRICT`

- Status: accepted, 2026-10-22
- Deciders: maintainer

## Context

A single `STRICT` preset that consumers loosen would remove the "which one" question. But `STRICT` is not deployable
without per-anchor exemptions and a seed under the stale rule, and the §4 growability contract (new rules ship `ALLOW`
for one minor, then flip) is written around a preset that rejects by default.

## Decision

Keep both. `DEFAULT` is what 1.0 ships under `OBSERVE` first; `shadowPolicy` (spec §4) is the measurement path from
`DEFAULT` to `STRICT`, not a third preset.

## Consequences

Every first-time integrator gets a working configuration without the enterprise-CA recipe. The migration procedure
is: shadow `STRICT`, drive `shadowWouldRejects` to the exemptions, then set `policy = STRICT`.
