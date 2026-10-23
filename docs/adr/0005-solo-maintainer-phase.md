# ADR-0005: Solo-maintainer phase

- Status: accepted, 2026-10-22
- Deciders: maintainer

## Context

Until `MAINTAINERS.md` lists a second maintainer, no human can approve the maintainer's own PRs: GitHub forbids
self-approval and the two-person rule of CONTRIBUTING §5 cannot be satisfied. The project is built with one local
agent operated by the maintainer, one task at a time.

## Decision

Compensating controls, all enforced:

- rulesets require every status check but 0 approvals; "require review from code owners", "require approval of the
  most recent reviewable push" and "require extra approval for unattributed changes" are off (each demands an approver
  other than the author, who does not exist, so each would block every PR); all four switch on in the PR that adds the
  second maintainer;
- every PR carries an **independent review**: a fresh-context agent pass over the diff that did not write it, posted as
  a PR comment under the heading `Independent review`; `pr-lint` requires it before the PR can leave draft;
- the maintainer reads the full diff before enabling auto-merge;
- the `cooling` check is **paused** (it reports success): the hold exists to give a second reader time before
  release-critical paths merge, and no second reader exists; the independent review and the maintainer's full read are
  the controls. It activates by itself, on its three paths, in the PR that adds the second maintainer;
- no release is cut and no 1.0 promise is made in this phase (spec §14 requires two release-capable maintainers and
  external review before 1.0); no release key is created.

The phase ends, and the two-person rule activates, in the PR that adds the second maintainer.

## Consequences

Throughput is bounded by one human's reading. Agent output is never merged on the agent's word: the independent
review and the human read are both required, and the Handoff comment states exactly what ran. Nothing in this phase
waits on a clock, since a timer with one reader only delays the same person.
