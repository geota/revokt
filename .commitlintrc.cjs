// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//
// Runs on the PR title only (CONTRIBUTING §4, Appendix A). Trailers, the Spec: rule and the template are PR-lint's job.
module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [2, 'always', ['feat', 'fix', 'perf', 'refactor', 'test', 'docs', 'build', 'ci', 'chore', 'revert', 'spec']],
    'scope-enum': [2, 'always', ['clubcard', 'engine', 'jsse', 'bc', 'okhttp', 'ktor', 'android', 'work', 'testing', 'bom', 'oracle', 'upki', 'seed', 'repo', 'deps', 'release', 'consumers']],
    'scope-empty': [2, 'never'],
    'header-max-length': [2, 'always', 72],
    'body-max-line-length': [0],
  },
  ignores: [(m) => /^chore\(deps\)/.test(m)], // Renovate PRs; PR-lint's exemption is in CONTRIBUTING §2
};
