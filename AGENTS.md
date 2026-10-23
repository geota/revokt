<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# AGENTS.md

A map, not a manual. Read this, then the issue, then the spec sections it names.

## Commands

```
./gradlew specStatus              # what is implemented, what is next (writes docs/dev/status.md)
./gradlew check                   # the local gate: JDK-only, offline (run Gradle on JDK 21)
./gradlew check -Prevokt.ci       # adds consumers, purity (and the Android modules from 0.3)
./gradlew apiDump                 # only when the public surface changed; commit the diff
./gradlew ktlintFormat            # formatting is never a review topic
reuse lint && actionlint          # headers and workflows
```

## Read next

- `docs/spec/revokt-spec.md` (normative; cite sections), `docs/adr/` (decisions), `docs/dev/status.md` (what is next)
- `CONTRIBUTING.md` (every rule and every gate), `docs/dev/local.md`, `docs/dev/fixtures.md`, `docs/dev/corpus.md`
- Module files where a module's rules differ: `revokt-clubcard/AGENTS.md` (the MPL port), `native/AGENTS.md`

## 0. The operating prompt (read this before touching the repo)

You are working on revokt, a Kotlin TLS revocation library that will be published as open source with its
full commit history. The spec in `docs/spec/` is the source of truth; code implements the spec, never the
other way round. Work is picked up as one GitHub issue per task, done on a short branch, delivered as one
pull request that is green on every **required check** (Appendix B lists them; nightly jobs, Scorecard and
live checks never gate a PR) before a human reviews it, and squash-merged by auto-merge once up to date with
`main`, with a Conventional Commits title. You never push to `main`, never merge or approve, never disable or weaken a
gate to get green, and never commit a secret, build output, or a generated file other than the ones section 3
lists as committed on purpose (API dumps, lockfiles, verification metadata and keyring, corpus manifests and
fuzz corpora). Every **observable behaviour** you implement (public API, a preset row, a fixture outcome, a
data format, a wire interaction) cites the spec section it implements; an observable behaviour that is not in
the spec needs a `spec` change first, normally in its own PR (section 1). Tests are the record: a bug fix
starts with the failing test, a walker or parser change starts with the fixture, and the §9 fixture ids name
the tests. If you are an AI agent: you work on one issue at a time; the operating human is the git author
and signs off; your commits carry the `Co-authored-by` trailer that names you; you open PRs as drafts from
the operating human's account with a Handoff comment in the fixed format; a human marks them ready,
reviews and merges (section 12). Start every session by running `./gradlew specStatus` and reading the
issue; when you receive the same correction twice, add it to `AGENTS.md` in the same PR.

## 12. AI-assisted work

**Operating model.** One local agent (Claude Code or equivalent) runs on the maintainer's machine, in the
maintainer's `gh` session, on one issue at a time. There is no bot identity, no parallel agents and no
agent-owned module: the **git author and `Signed-off-by` are the operating human**, who takes DCO
responsibility for the agent's output, and the PR author is that human. The model is named in
`Co-authored-by: <vendor model name and version> <vendor no-reply address>` (GitHub shows no account for it;
the history is the record; PR-lint's `trailers` check matches the token case-insensitively). "Substantially
co-authored" means any commit where an agent produced or rewrote a hunk beyond single-line completion; when
in doubt, add the trailer. The PR's "AI assistance" section and the `ai-assisted` label disclose which parts
an agent wrote. Outside contributors using agents follow the same rules under their own account.

**Always**
- Start a session with `./gradlew specStatus`, the issue, and the spec sections it names; read
  `docs/dev/local.md` for the commands.
- Write the acceptance test (or fixture) before the code; run `./gradlew check` before every push.
- Cite the spec section for every observable behaviour; state assumptions in the PR's What section.
- Open the PR as a draft with the template fully filled and a **Handoff comment** with the fixed headings:
  `Commands run and results` · `JDK and OS` · `Gates not run locally and why` · `Assumptions made` ·
  `Files touched outside the issue's module` · `Open questions`.
- Add the `Co-authored-by` trailer; keep one issue in flight; regenerate `docs/dev/status.md` and the API dump
  when they change.
- When the same correction arrives twice, add the rule to `AGENTS.md` in the same PR.
- On a flaky test you did not write: re-run once, then file the `quarantine` issue and say so in the Handoff.

**Ask first** (stop, write the question in the Handoff or the issue, leave the PR a draft)
- Two readings of the spec that would produce different **observable behaviour** (public API, preset row,
  fixture outcome, data format, wire interaction): finish the parts that do not depend on it, open a `spec`
  issue with both readings and a recommendation. Anything narrower (internal structure, naming, an unclear
  issue text, a reviewer comment): pick the reading closest to the spec, state it, continue.
- Any change to rulesets, workflows, CODEOWNERS, `protected-paths.txt` or the dependency ingress files that
  the issue does not explicitly cover (registering a new fuzz target in the ClusterFuzzLite matrix is part of
  the parser issue; everything else is its own `kind/ci` issue).
- Adding a dependency, a licence outside the allow-list, or any asset or corpus entry.
- Deleting a test, lowering a floor, or touching anything under `docs/spec/` (that is a `spec` PR).
- Anything that would spend money, publish, or leave the repository (a release, a seed publish, an external service).

**Never**
- Push to `main`, merge, approve, enable auto-merge, or edit a ruleset.
- Weaken a gate to get green: no `[skip ci]`, no disabled rule, no baseline, no `@Suppress` without the
  one-line reason, no quarantine tag inside a feature PR, no removal of a failing test.
- Commit a secret, a credential, build output, a prompt or a transcript. Read or write credentials: release
  or commit-signing keys, Portal tokens, the credential entries of `~/.gradle/gradle.properties` (its JVM
  settings are fine), CI secrets.
- Use a maintainer's identity for anything but the PRs the maintainer is operating.
- Describe work as verified that was not run; the Handoff says exactly what ran.

**What the operating human does** before marking a draft ready: reads the Handoff; re-runs any command it
says was skipped; confirms the Tests section names the issue's acceptance test; confirms the diff stays
inside the issue's scope and that no ruleset, workflow, CODEOWNERS or ingress file changed unless the issue
says so; confirms the trailers; in the solo-maintainer phase, runs the **independent review** (a fresh-context
agent review of the diff that did not write it, posted under the `Independent review` heading) and reads
the whole diff before enabling auto-merge. **Reviewers re-run, they do not trust**, the Handoff's claims,
and the author answers review questions in their own words. Unsolicited agent PRs from outside the project
are accepted only against a claimed issue and with the disclosure above; others are closed by PR-lint.
Design reasoning goes into ADRs, PR descriptions and the spec, written for a human reader.

When the same correction is given twice, add the rule here in the same PR.
