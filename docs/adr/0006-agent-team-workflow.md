# ADR-0006: An agent team under one maintainer

- Status: accepted, 2026-11-16
- Deciders: maintainer
- Replaces the control list of [ADR-0005](0005-solo-maintainer-phase.md). The rest of ADR-0005 stands.

## Context

ADR-0005 assumed one local agent, one issue at a time, and a maintainer who reads every diff before enabling
auto-merge. Since 0.2's first wave (2026-11-05) the project has been built by a team of agents that one maintainer
directs: a coordinator, up to about three builders at a time in their own worktrees, and a fresh-context reviewer
for every PR. The coordinator merges. The maintainer answers the decision questions and reads every must-fix
finding, not every diff. At that rate (95 merged PRs in the project's first 24 days, by the audit's count) no human
reads every line.

The 2026-11-16 design audit (#230, finding C-F5) found that AGENTS.md §12 and ADR-0005 still described the old
process. The repository will be published with its history, so the written process has to be the one in use.

The audit also found that the fresh-context review, with a follow-up after each fix round, is the control that
finds the serious defects: it found every serious defect the audit traced, including the data-loss bugs of #205 and
#207.

## Decision

### Roles

- **The maintainer** is the operating human. They are the git author and the `Signed-off-by` on every commit, and
  every GitHub action runs under their account. They set priorities and answer every decision question. A
  decision question shows how the references (upki/webpki, Firefox) handle the point, with a recommendation. They
  read every must-fix finding and how it was fixed. They approve, before it is built, anything on the "ask first"
  list of AGENTS.md §12 that an issue does not cover. They do not read every diff.
- **The coordinator** is one agent session. It turns the maintainer's priorities into issues and lanes, and writes
  each builder's brief ([`docs/dev/builder-brief.md`](../dev/builder-brief.md) plus the issue). It settles narrow
  readings, and sends readings that change observable behaviour to the maintainer. It starts the reviewers, posts
  their reports as the `Independent review` comment, and merges. It alone edits `docs/spec/`, `ROADMAP.md` and
  `README.md`.
- **Builders** are agents, up to about three at a time, each on one issue in its own worktree and in an area of the
  code the others are not touching. A builder opens a draft PR with the Handoff in its body (AGENTS.md §12),
  reports to the coordinator, and fixes what review finds. It never merges, marks a PR ready, or edits the spec.
- **Reviewers** are fresh-context agents that did not write the diff ([`docs/dev/reviewer-brief.md`](../dev/reviewer-brief.md)).
  Each works read-only in its own detached worktree and commits nothing. It re-runs the tests rather than trusting
  the Handoff. It aims its own mutants at the guards that decide what is deleted, overwritten, reused or trusted, and
  challenges the readings the coordinator accepted. Its verdict is one of: must-fix, should-fix, or nothing to fix.

### The flow of one PR

1. The builder posts any reading that touches delete, reuse or trust class on the issue, and waits for the
   coordinator before coding it.
2. The builder opens a draft PR with every template section filled, Handoff included, after the full gate passes.
3. A fresh reviewer reviews the head SHA. The coordinator posts the report as the `Independent review` comment.
4. The builder fixes what was found. After a round that fixes a must-fix finding, a follow-up review checks the fix
   commits (`Independent review: follow-up at <sha>`). The coordinator may ask for one after a should-fix round too,
   as on #205. The coordinator checks smaller fixes by reading the diff.
5. The maintainer reads each must-fix finding and its fix, and answers any decision question, before the merge.
6. The coordinator marks the PR ready, brings it up to date (`gh pr update-branch`), waits for every required check,
   and squash-merges (`gh pr merge --squash`).

Each item in a PR's "Assumptions made" lands in a spec revision or is dropped. A reading left only in a PR is lost.

### What the gates prove

Every gate runs as one account. The commits, the PRs, the `Independent review` comment, the merge, the DCO sign-off
and every token belong to the maintainer. `pr-lint` can check that an `Independent review` comment exists. It cannot
check who wrote it, or that a review happened. So the gates guard against mistakes, not against the process being
skipped. This record, the comments on each PR, and the public history are what show the process was followed.

### What stays from ADR-0005

- The rulesets require every status check and 0 approvals. The three approver-dependent rules stay off.
- `cooling` stays paused.
- No release is cut and no 1.0 promise is made.
- The phase ends, and the two-person rule of CONTRIBUTING §5 activates, in the PR that adds a second maintainer. That
  PR also revisits this ADR: a second maintainer's approval replaces the coordinator's merge.

## Consequences

- Throughput is bounded by review, not by one person's reading. The maintainer's time goes to decisions and must-fix
  findings, where it changes outcomes.
- A defect that neither the builder nor the reviewer imagines can merge. Both data-loss bugs of 2026-11-15 came from
  a damaged-store state that the builder had not considered and that a reviewer found by improvising a scenario. The
  model-based fault-injection test (#214) adds a second line of defence that does not depend on a reviewer's
  ideas.
- Builder mutation runs are a working method, not evidence. The reviewer's mutants are the recorded check.
- The briefs are committed (`docs/dev/`), so they survive between sessions and can be reviewed like any other rule.
