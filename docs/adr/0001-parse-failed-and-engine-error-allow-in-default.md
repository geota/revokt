# ADR-0001: `PARSE_FAILED` and `ENGINE_ERROR` allow in `DEFAULT`

- Status: accepted, 2026-10-22
- Deciders: maintainer

## Context

Both rules are `UNEVALUABLE` (spec §4): revokt could not evaluate the chain, through its own parser or its own
engine. `STRICT` rejects both. The question was whether `DEFAULT` should too, now or on a schedule.

## Decision

`DEFAULT` keeps `ALLOW` for both. A flip to `REJECT` is a later minor through the §4 growability rule (one minor at
`ALLOW` with `RULE_FLIPPED_THIS_MINOR`, then the flip with a release note), decided on field data: `fired[PARSE_FAILED]`
and `fired[ENGINE_ERROR]` from `OBSERVE` and `shadowPolicy` deployments.

## Consequences

A leaf the platform accepts and the Kotlin parser rejects is unchecked under `DEFAULT` (spec §10 item 8; the §9.2
differential oracle is the mitigation). A revokt bug never rejects traffic under `DEFAULT`. Nothing in the spec changes now.
