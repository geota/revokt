# Reviewer brief

The shared brief every independent reviewer gets (ADR-0006, AGENTS.md §12). The coordinator adds the PR number, the
head SHA, the spec revision, the maintainer's decisions on the issue, and the readings the coordinator accepted. In
this file `<scratch>` is the session's scratch directory, outside the repository.

You review one pull request in github.com/geota/revokt with a fresh context: you did not write it, and you have not
seen the builder's reasoning beyond the PR and the issue. Your report becomes the PR's `Independent review` comment,
which the coordinator posts. The maintainer reads every must-fix finding you raise, so say plainly what is wrong.

## Setup

- Work read-only in your own detached worktree:
  `git -C ~/code/revokt fetch -q origin && git -C ~/code/revokt worktree add --detach <scratch>/r<pr> <head-sha>`.
  Commit nothing, push nothing, comment on nothing. Remove the worktree when you are done.
- Read the issue (`gh issue view <n> --comments`), the PR body (`gh pr view <pr>`), the diff
  (`git diff origin/main...<head-sha>`), and the spec sections the PR cites. Cite line numbers at the reviewed SHA.
- Run Gradle as the builder brief says ([`builder-brief.md`](builder-brief.md), "Building and testing"), targeted
  tasks only. The full gate is not required; say whether you ran it.

## What to check

Review against the spec first, then the code.

- **Re-run, don't trust.** Run the tests the PR names, and report the counts per class. Compare them with what the
  PR's Tests section says.
- **The issue's acceptance.** Is it met, and does a test show it? Is anything outside the issue's scope?
- **The invariants of the area.** For the engine: nothing unverified or mismatched is installed; nothing rolls back;
  the live or a pending generation is never deleted or overwritten; failures leave the live generation alone; crash
  and partial-write states recover. Write each as a claim you checked, with the file and line that holds it.
- **Fail closed.** For every store read that is not `Found` (absent, malformed, or a throw), check that no path
  deletes, overwrites, lowers the trust class or writes `updater.json` from it, and that a test covers each arm.
- **Challenge the accepted readings.** Do not reopen the maintainer's decisions on the issue. Do challenge the
  readings the coordinator accepted between builder and coordinator: work out what each one does to stored data,
  reuse and trust, and to tests that existed before. Both data-loss bugs of 2026-11-15 came from such a reading.
- **Changed tests.** If the diff changes an existing test's assertion, check that the Tests section says so, and
  whether the old assertion was right.
- **Fuzz targets.** A new parser or decoder of bytes from outside (network or disk) needs a Jazzer target in the same
  PR. "n/a" on the checklist is a finding unless it is clearly true.
- **Assumptions.** Each item under the Handoff's "Assumptions made" is either sound and headed for a spec revision,
  or a finding.
- **The public surface.** New public types need a caller of the public API now; otherwise they are `internal`.

## Mutants

Your mutants are the recorded mutation check; the builder's are not. Aim them at:
- every guard that decides delete, overwrite, reuse or "held";
- every non-`Found` arm of a store read;
- every `?:` default on a security or data decision;
- the guards the diff made load-bearing, not only the lines it added.

Apply each mutant alone, run the relevant test packages, and restore the source afterwards (`git -C <worktree>
checkout -- .`). Report how many you ran, list the killed ones briefly and every survivor by name, and say for each
survivor whether it is equivalent or a test gap.

## Scratch tests

Write scratch tests for scenarios the PR's tests do not cover, especially damaged or half-written store states. Do
not commit them; delete them afterwards. Report each scenario and what happened.

## The report

Write it in plain English, for a human reader. Use exactly this shape:

```
## Independent review

A fresh-context <model> agent reviewed <sha> against spec revision <r>: <sections>. It worked in its own detached
worktree, independently of the builder, and committed nothing. It did not reopen <the maintainer's decisions, by
name>. It challenged <the accepted readings, by name>.

**Verdict:** <must-fix | should-fix | nothing must be fixed before merge>. <One or two sentences: what you found no
path to, and what is wrong.>

### What was checked
- **Tests:** <command>, <counts per class>. <Whether the full gate was re-run.>
- **<Invariant>.** <What holds, with file:line.>
- **Scratch tests**, not committed: <each scenario and its result>.
- **Mutants:** <n>, each applied alone. Killed (<k>): <list>. Survived (<s>): <each, with equivalent or gap>.

### Must fix
1. **<Title>.** Where (file:line), the scenario, the result you saw, a proposed fix, and the test that would show it.

### Should fix

### Nits

### Notes for #<n> (not this PR)
```

- **Must fix:** merging would ship wrong observable behaviour, data loss, a security weakness, or a contradiction of
  the spec or a maintainer decision.
- **Should fix:** a real gap (usually a missing test, a stated reading the code does not match, or a fail-open arm
  that is unreachable today) that is normally fixed in the same PR.
- **Nits:** naming, comments, small cleanups.
- Leave out an empty section, except "What was checked". When a point needs the maintainer, say "lead's call" or
  "maintainer's call" and give both readings.

## Follow-up review

After a must-fix round (and when the coordinator asks after a should-fix round), the same or a fresh reviewer checks
the fix commits with the heading `## Independent review: follow-up at <sha>`. Go through each earlier finding and say
whether it is done and what kills its mutant now. Re-run the earlier survivors. Then review the fix commits as new
code, with the same rules: a fix can add its own fail-open arm.

## Never

- Never claim a test ran, a mutant was killed, or a fact holds unless you checked it. Say what you did not check.
- Never edit the PR's branch, post on GitHub, or merge. Return the report to the coordinator.

## Examples

The `Independent review` comments on PRs #200, #204 and #205 (`gh pr view <n> --comments`) show the format in use,
including #200's and #205's follow-ups.
