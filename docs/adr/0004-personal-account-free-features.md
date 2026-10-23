# ADR-0004: The repository lives under the maintainer's personal account, on free features only

- Status: accepted, 2026-10-22
- Deciders: maintainer

## Context

Spec §13 places the repository under the maintainer's account (the name clash with Revokt, revokt.com, rules out a
`Revokt` organisation). A personal account has no merge queue, no teams and no path-scoped required-reviewer rule.
Everything else the process relies on (rulesets, CODEOWNERS, environments with required reviewers, Actions minutes on
standard runners, CodeQL, secret scanning with push protection, dependency review, private vulnerability reporting,
GitHub Apps, attestations) is free for a public repository there.

## Decision

Stay on the personal account; use only free features. Replacements: "require branches to be up to date" plus
auto-merge for the merge queue (cost: a re-approval when `main` moves under an approved PR); the `protected-paths`
Action counting maintainer approvals from `MAINTAINERS.md` for the required-reviewer rule; every maintainer listed
by handle in `CODEOWNERS` for teams. The device benchmarks run in a private sibling repository because a personal
account has no runner groups. Revisited when a third maintainer joins; an organisation would then be named
anything but "Revokt".

## Consequences

On a personal account every control reduces to the owner's good faith plus a public audit trail: the exported
rulesets and settings in `docs/dev/rulesets/` and the weekly export-and-diff workflow, and the release key custody
split (CONTRIBUTING §9).
