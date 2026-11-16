<!-- Every section is mandatory; pr-lint fails when one is empty (CONTRIBUTING §5). Title: Conventional Commits, ≤ 72 chars. -->

## What

<!-- one paragraph -->

## Why

Fixes: #

## Spec

<!-- sections implemented, and "no observable behaviour outside the spec", or the spec PR link. `Spec: none (<reason>)` for build/ci/docs/chore. -->

## Tests

<!-- fixture ids or test names added or changed; for a bug, the test that failed first and the red run. `none, no behaviour change` for build/ci/docs/chore.
     Say so here if an existing test's assertion changed, and why.
     Then the commands run and their results (test counts, the full gate), exactly as run.
     Mutation, if you ran it: the survivors you found and the tests you added for them, not a kill count. -->

## API

<!-- "no public API change", or the api/*.api diff summary and the `!` justification -->

## Risk and rollout

<!-- the spec §10 item touched, or "none"; any preset row, data format or seedFormat involved -->

## AI assistance

<!-- "none", or which parts an agent wrote (sets the ai-assisted label) -->

## Handoff

<!-- AGENTS.md §12. Required when an agent wrote any part (pr-lint checks it then); otherwise "none, no agent".
     Update it after each round of fixes. The commands run go under Tests. -->

### JDK and OS

### Gates not run locally and why

### Assumptions made

<!-- each one lands in a spec revision or is dropped (ADR-0006) -->

### Files touched outside the issue's module

### Open questions

## Checklist

- [ ] spec cited
- [ ] tests added
- [ ] `./gradlew check` green locally (or which part was skipped and why)
- [ ] API dump updated (`./gradlew apiDump`) if the surface changed
- [ ] SPDX headers present (`reuse lint`)
- [ ] dependency entries added (catalog, lockfiles, verification metadata) if a dependency changed
- [ ] fuzz target added for any new byte parser

## Trailers

<!-- last section on purpose: GitHub copies the description into the squash body and git parses trailers at the end -->
Spec:
Co-authored-by:
Signed-off-by:
