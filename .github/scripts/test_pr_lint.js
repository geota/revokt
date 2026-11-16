// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//
// Tests of pr_lint.js's body rules (#210), run by the `static` job: `node .github/scripts/test_pr_lint.js`, from the
// repository root (pr_lint.js reads MAINTAINERS.md from the working directory). The GitHub API is a stub.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const script = fs.readFileSync(path.join(__dirname, 'pr_lint.js'), 'utf8');
const template = fs.readFileSync(path.join(__dirname, '..', 'PULL_REQUEST_TEMPLATE.md'), 'utf8');

/** Runs pr_lint.js on one PR; returns the failures, the notices and the labels it added. */
async function lint({ body, commits = [], comments = [], createdAt = '2026-11-16T00:00:00Z', draft = true }) {
  const out = { failures: [], notices: [], added: [] };
  const listCommits = {}; const listComments = {}; const listFiles = {};
  const github = {
    rest: {
      pulls: {
        get: async () => ({ data: { body, title: 'docs(repo): a change', draft, created_at: createdAt, user: { type: 'User', login: 'someone' }, labels: [] } }),
        listCommits, listFiles,
      },
      issues: { listComments, addLabels: async ({ labels }) => out.added.push(...labels), removeLabel: async () => {} },
    },
    paginate: async (fn) => {
      if (fn === listCommits) return commits.map((message) => ({ commit: { message } }));
      if (fn === listComments) return comments.map((b) => ({ body: b }));
      return [];
    },
  };
  const context = { payload: { pull_request: { number: 1 } }, repo: { owner: 'o', repo: 'r' } };
  const core = {
    setFailed: (m) => out.failures.push(...m.split('\n')),
    info: () => {}, warning: () => {}, notice: (m) => out.notices.push(m),
  };
  await new Function('github', 'context', 'core', 'require', `return (async () => { ${script} })();`)(github, context, core, require);
  return out;
}

/** The template with the sections pr-lint requires filled, the Handoff left as the template has it. */
function filled({ coAuthor = '', handoff = null } = {}) {
  let b = template
    .replace('## What\n', '## What\n\nA change.\n')
    .replace('Fixes: #', 'Fixes: #1')
    .replace('## Spec\n', '## Spec\n\nnone (docs)\n')
    .replace('## Tests\n', '## Tests\n\nnone, no behaviour change\n')
    .replace('## API\n', '## API\n\nno public API change\n')
    .replace('## Risk and rollout\n', '## Risk and rollout\n\nnone\n')
    .replace('## AI assistance\n', '## AI assistance\n\nnone\n')
    .replace(/^Spec:$/m, 'Spec: none (docs)')
    .replace(/^Signed-off-by:$/m, 'Signed-off-by: A Person <a@example.org>');
  if (coAuthor) b = b.replace(/^Co-authored-by:$/m, `Co-authored-by: ${coAuthor}`);
  if (handoff !== null) b = b.replace('### JDK and OS\n', `### JDK and OS\n\n${handoff}\n`);
  return b;
}

const handoffFailure = (r) => r.failures.some((f) => f.includes('"## Handoff"'));
const agent = 'Claude Opus 5.5 <noreply@anthropic.com>';
const agentCommit = `docs(repo): x\n\nCo-Authored-By: ${agent}\nSigned-off-by: A Person <a@example.org>`;

const cases = {
  'a human PR that keeps the blank Co-authored-by line is neither agent-written nor failed for its Handoff': async () => {
    const r = await lint({ body: filled(), commits: ['docs(repo): x\n\nSigned-off-by: A Person <a@example.org>'] });
    assert.equal(handoffFailure(r), false, r.failures.join('\n'));
    assert.deepEqual(r.added, []);
  },
  'an agent PR with a filled Handoff passes': async () => {
    const r = await lint({ body: filled({ coAuthor: agent, handoff: 'macOS, JDK 21' }), commits: [agentCommit] });
    assert.deepEqual(r.failures, []);
    assert.deepEqual(r.added, ['ai-assisted']);
  },
  "an agent PR with only the template's Handoff headings fails": async () => {
    const r = await lint({ body: filled({ coAuthor: agent }), commits: [agentCommit] });
    assert.equal(handoffFailure(r), true);
  },
  'text on a heading line counts as filled': async () => {
    const body = filled({ coAuthor: agent }).replace('### JDK and OS\n', '### JDK and OS: macOS, JDK 21\n');
    assert.equal(handoffFailure(await lint({ body, commits: [agentCommit] })), false);
  },
  'grace: a Handoff comment passes for a PR opened before 2026-11-18, and not after': async () => {
    const body = filled({ coAuthor: agent });
    const comments = ['## Handoff\n\n### Commands run and results\n...'];
    const before = await lint({ body, commits: [agentCommit], comments, createdAt: '2026-11-15T08:54:28Z' });
    assert.equal(handoffFailure(before), false);
    assert.equal(before.notices.length, 1);
    const after = await lint({ body, commits: [agentCommit], comments, createdAt: '2026-11-18T00:00:01Z' });
    assert.equal(handoffFailure(after), true);
  },
};

(async () => {
  let failed = 0;
  for (const [name, test] of Object.entries(cases)) {
    try { await test(); console.log(`ok   ${name}`); } catch (e) { failed++; console.log(`FAIL ${name}\n${e.message}`); }
  }
  console.log(`${Object.keys(cases).length - failed}/${Object.keys(cases).length} passed`);
  process.exit(failed ? 1 : 0);
})();
