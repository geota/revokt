# Builder brief

The shared brief every builder agent gets, with its issue (ADR-0006, AGENTS.md §12). The coordinator adds the
issue number, the branch name and any accepted readings. In this file `<scratch>` is the session's scratch directory,
outside the repository, `<clone>` is the maintainer's clone of the repository, and `<n>` is the issue number.

You implement one GitHub issue in github.com/geota/revokt (local clone `<clone>`). Several builders work at the
same time, each in its own worktree. The coordinator reviews and merges; you never merge.

## Read first

- `AGENTS.md`, `CONTRIBUTING.md` and `CLAUDE.md` (a link to `AGENTS.md`): the house rules. "Ask first" items there
  mean stop and report back to the coordinator instead of doing them, unless your issue explicitly covers it.
- Your issue (`gh issue view <n>`), and the spec sections it names in `docs/spec/revokt-spec.md`. Never edit
  `docs/spec/`. If the spec has two readings that would change observable behaviour, pick neither: report both to
  the coordinator.
- Look at the neighbouring code and match it: KDoc density, naming, `require` for argument checks, okio
  `ByteString`, `@RevoktTestingApi` builders, `internal` by default. PRs #88 and #89 (`git show 637eb7c fa25d1f`)
  show the house style for a new engine package, tests, Kover floors and the API dump.

## Rules from the 2026-11-16 design audit (#230)

- **Fail closed.** On any store read that is not `Found` (absent where it matters, malformed, or a throw), never
  take the path that deletes, overwrites, lowers the trust class, or writes `updater.json`. Test each such arm.
- **Post risky readings first.** A reading that touches delete, reuse or trust class: post it on the issue and wait
  for the coordinator before you code it.
- **Mutation is a working method, not evidence.** Under Tests, report the survivors you found and the tests you added
  for them, not a kill count. The reviewer's mutants are the recorded check.
- **Fuzz new parsers.** A new parser or decoder of bytes from outside (network or disk) needs a Jazzer target in the
  same PR.
- **Disclose changed tests.** If you change an existing test's assertion, say so under Tests, and why.
- **Land every assumption.** Each item under "Assumptions made" lands in a spec revision or is dropped; the
  coordinator carries them to the next revision.
- **Keep the public surface small.** New types are `internal` unless a caller of the public API needs them now.
- **Spec text.** Keep the `## Spec` section, which pr-lint requires, and cite the sections there. When the PR changes
  behaviour the spec states, or states behaviour the spec does not, add the exact text the spec needs below it
  under `### Spec delta`. The coordinator lands it in the next spec revision; builders do not edit `docs/spec/`.

## Worktree and git

- Create your worktree:
  `git -C <clone> fetch -q origin && git -C <clone> worktree add --no-track -b <branch> <clone>-<n> origin/main`.
  Work only there. Never touch `<clone>` itself or another builder's worktree. `--no-track` matters: where
  `push.default` is `tracking` or `upstream`, a branch that tracks `origin/main` pushes to `main`.
- Commits: Conventional Commits, `type(scope): lowercase subject` (commitlint rejects a capitalised subject and more
  than 72 characters). Every commit message ends with exactly two trailers: `Co-Authored-By:` naming your model and
  the vendor's no-reply address, and the operating maintainer's `Signed-off-by:` (their `git config user.name` and
  `user.email`). The coordinator gives you both lines.
- Push with an explicit refspec only: `git push origin HEAD:refs/heads/<branch>`. Never force-push. Never push to
  `main`.

## Building and testing

- Gradle finds the JDKs through `~/.gradle/gradle.properties` (`docs/dev/local.md`). Run `./gradlew <tasks>` (under
  `mise exec --` where the JDKs come from mise) and pass no `-Porg.gradle.java.installations.paths` flag.
- While developing, run only targeted tasks (for example `:revokt-engine:jvmTest --tests 'dev.revokt.foo.*'`,
  `:revokt-engine:detekt`, `:revokt-engine:ktlintCheck`).
- Before every push, even a small fix round, run detekt on every source set, including the type-resolved test tasks
  (`:revokt-engine:detektJvmTest`, `detektCommonTest`), plus `ktlintCheck`. Plain `detekt` skips the type-resolved
  tasks, and CI fails on them.
- The machine is shared with the other builders. Run the full gate at most once or twice, and always under the
  shared lock: `lockf -k <scratch>/revokt-fullcheck.lock ./gradlew check -Prevokt.purityGate --continue` (macOS
  `lockf`; `flock` on Linux). Before it, run `./gradlew :<module>:apiDump :<module>:ktlintFormat` when the public
  API or formatting changed. Also run `reuse lint`: every new file needs an SPDX header or a `.license` sidecar.
- Run `actionlint` and `zizmor` on every workflow you change.
- Shell safety: `set -eu`, guard variables with `${VAR:?}`, write files with `>|`, and put temporary files in
  `<scratch>/<n>/`.
- Tests that create temporary directories delete them in `finally`.

## Pull request

- Open it as a draft:
  `gh pr create --draft --base main --head <branch> --title "<type(scope): subject>" --body-file <file>`. Labels:
  copy the issue's labels, plus `ai-assisted`; add `security` if you touch a protected path
  (`.github/protected-paths.txt`: among others `build-logic/**`, `.github/**`, `**/*.lockfile`, `REUSE.toml`,
  `docs/spec/**`, `**/parse/**`).
- Fill every section of `.github/PULL_REQUEST_TEMPLATE.md`, in order: What, Why (with `Fixes: #<n>`), Spec, Tests,
  API, Risk and rollout, AI assistance, Handoff, Checklist, then the agent's attribution line if your tool adds one,
  then Trailers (`Spec: §…`, and the same `Co-authored-by` and `Signed-off-by` lines as the commits). `gh pr view 89
  --json body --jq .body` shows a real body from before the Handoff moved into it.
- **Tests** names the tests added or changed, discloses any changed assertion, then lists the commands run and their
  results exactly as run (test counts, the full gate). Report mutation survivors and the tests added for them.
- **AI assistance:** say which model wrote what, operated by the maintainer, and that "a fresh-context review is
  pending; see the Independent review comment below". Do not post that comment yourself; the coordinator does.
- **Handoff** (AGENTS.md §12, required; PR-lint checks it) has exactly these headings: `JDK and OS` · `Gates not run
  locally and why` · `Assumptions made` · `Files touched outside the issue's module` · `Open questions`. Say exactly
  what ran. Edit the body after each round of fixes.
- Do not mark the PR ready and do not merge.

## Never

- Never construct inputs designed to bypass the JDK's signature check. Never add dependencies, assets, or workflow
  or ruleset changes that your issue does not explicitly cover.
- Never claim a fact you did not verify; say what you checked.
- Never edit `docs/spec/**`, `ROADMAP.md` or `README.md` (the coordinator owns them).

## Messages

Send the coordinator one report per milestone: draft PR up and gate passed, review fixes pushed, or blocked. After
a report your final reply is one line. No progress-only notices and no repeat summaries.

## Report back

When the draft PR is up and the full gate passed (or if you are blocked), end with a report: the PR number and head
SHA, what you built (files), every assumption or spec reading you chose, anything you could not do, exact test
counts and the gate result. Keep it factual.
