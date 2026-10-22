<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Governance


- **Maintainers** are listed in `MAINTAINERS.md` with the milestone lead marked. Added by a PR to that file
  approved by every current maintainer, after three merged PRs on protected paths and six months of activity;
  moved to emeritus after six months without a review or merge; removed for cause by the other maintainers
  with a written reason. Two release-capable maintainers at all times (§14) is the floor, not the target.
- **Decisions**: section 1 item 5 (spec text wins; milestone lead breaks a tie, recorded in an ADR).
- **Code of conduct**: Contributor Covenant 2.1; report privately to any maintainer listed in `MAINTAINERS.md` (a GitHub
  direct message), or through GitHub's private vulnerability reporting when the report is sensitive; handled within 14 days.
- **Name and home**: §13 rules; no `revokt.com` anywhere; the repository stays under the maintainer's
  personal account at least until a third maintainer joins, when ADR-0004 is revisited.
- **Repository files present from the bootstrap PR**: `LICENSE`, `LICENSES/`, `NOTICE`, `CONTRIBUTING.md`,
  `AGENTS.md` + `CLAUDE.md`, `SECURITY.md`, `MAINTAINERS.md`, `GOVERNANCE.md`, `CODEOWNERS`,
  `CODE_OF_CONDUCT.md`, `.editorconfig`, `.gitattributes`, `REUSE.toml`, `renovate.json`, `osv-scanner.toml`,
  `.commitlintrc.cjs`, `detekt.yml` + `detekt-common.yml`, `gradle/libs.versions.toml`,
  `gradle/verification-metadata.xml`, `gradle/verification-keyring.keys`, the lockfiles,
  `.github/{ISSUE_TEMPLATE,PULL_REQUEST_TEMPLATE.md,protected-paths.txt,workflows/*}`, `docs/spec/`,
  `docs/adr/` (0001–0005), `docs/dev/{local,deps,scorecard,fixtures,corpus,status}.md` (`docs/dev/rulesets/*.json`
  follows in the PR after the bootstrap, section 2), `ROADMAP.md` (the "Current focus" line and the milestone list),
  (`perf/baseline.json` arrives with the first benchmark run from the private `revokt-bench` repository, not with the bootstrap).

