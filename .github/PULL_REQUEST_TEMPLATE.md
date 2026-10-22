<!-- Every section is mandatory; pr-lint fails when one is empty (CONTRIBUTING §5). Title: Conventional Commits, ≤ 72 chars. -->

## What

<!-- one paragraph -->

## Why

Fixes: #

## Spec

<!-- sections implemented, and "no observable behaviour outside the spec", or the spec PR link. `Spec: none (<reason>)` for build/ci/docs/chore. -->

## Tests

<!-- fixture ids or test names added or changed; for a bug, the test that failed first and the red run. `none, no behaviour change` for build/ci/docs/chore. -->

## API

<!-- "no public API change", or the api/*.api diff summary and the `!` justification -->

## Risk and rollout

<!-- the spec §10 item touched, or "none"; any preset row, data format or seedFormat involved -->

## AI assistance

<!-- "none", or which parts an agent wrote (sets the ai-assisted label) -->

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
