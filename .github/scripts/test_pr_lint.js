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
async function lint({ body, commits = [], comments = [], createdAt = '2026-11-16T00:00:00Z', draft = true, title = 'docs(repo): a change', files = [], baseFiles = {} }) {
  const out = { failures: [], notices: [], added: [] };
  const listCommits = {}; const listComments = {}; const listFiles = {};
  const github = {
    rest: {
      pulls: {
        get: async () => ({ data: { body, title, draft, created_at: createdAt, user: { type: 'User', login: 'someone' }, labels: [], base: { sha: 'base' }, head: { sha: 'head' } } }),
        listCommits, listFiles,
      },
      issues: { listComments, addLabels: async ({ labels }) => out.added.push(...labels), removeLabel: async () => {} },
      repos: {
        getContent: async ({ path: p, ref }) => {
          if (ref !== 'base' || !(p in baseFiles)) throw new Error(`no ${p} at ${ref}`);
          return { data: { content: Buffer.from(baseFiles[p]).toString('base64') } };
        },
      },
    },
    paginate: async (fn) => {
      if (fn === listCommits) return commits.map((message) => ({ commit: { message } }));
      if (fn === listComments) return comments.map((b) => ({ body: b }));
      if (fn === listFiles) return files;
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

// Changelog fragments (#272). The base CHANGELOG.md: the newest block is lines 5 to 8.
const baseLog = '# Spec changelog\n\nIntro.\n\n### Changes in revision 61 (x, 2026-11-20)\n\n- **#1:** a.\n\n### Changes in revision 60 (y)\n\n- **#0:** b.\n';
const baseFiles = { 'docs/spec/CHANGELOG.md': baseLog };
const specEdit = { filename: 'docs/spec/revokt-spec.md', status: 'modified', patch: '@@ -10,3 +10,3 @@\n a\n-b\n+B\n c' };
const fragment = (n) => ({ filename: `docs/spec/changes/${n}.md`, status: 'added', patch: '@@ -0,0 +1 @@\n+- **#1:** x.' });
const logEdit = (patch) => ({ filename: 'docs/spec/CHANGELOG.md', status: 'modified', patch });
const fragmentFailures = (r) => r.failures.filter((f) => f.includes('(CONTRIBUTING §1)'));
const lintFiles = (files, title) => lint({ body: filled(), files, baseFiles, ...(title ? { title } : {}) });
const cutTitle = 'spec(engine): cut revision 62';

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
  'a spec edit without a fragment fails, and passes with the fragment of the Why issue': async () => {
    assert.equal(fragmentFailures(await lintFiles([specEdit])).length, 1);
    assert.deepEqual(fragmentFailures(await lintFiles([specEdit, fragment(1)])), []);
    for (const f of ['docs/spec/test-plan.md', 'docs/spec/references.md']) {
      assert.equal(fragmentFailures(await lintFiles([{ ...specEdit, filename: f }])).length, 1, f);
    }
  },
  'a fragment named after an issue the Why section does not reference fails': async () => {
    const r = await lintFiles([specEdit, fragment(2)]);
    assert.ok(fragmentFailures(r).some((f) => f.includes('named after the issue')), r.failures.join('\n'));
  },
  'removing a fragment is not adding one': async () => {
    assert.equal(fragmentFailures(await lintFiles([specEdit, { ...fragment(1), status: 'removed' }])).length, 1);
  },
  'a status-line edit fails outside the cut and passes in it': async () => {
    const status = { ...specEdit, patch: '@@ -1,3 +1,3 @@\n # revokt\n \n-Status: **draft spec, revision 61** · Date: 1\n+Status: **draft spec, revision 62** · Date: 2' };
    const r = await lintFiles([status, fragment(1)]);
    assert.ok(fragmentFailures(r).some((f) => f.includes('status line')), r.failures.join('\n'));
    assert.deepEqual(fragmentFailures(await lintFiles([status], cutTitle)), []);
  },
  'a core diff GitHub does not show fails closed': async () => {
    const r = await lintFiles([{ filename: 'docs/spec/revokt-spec.md', status: 'modified' }, fragment(1)]);
    assert.ok(fragmentFailures(r).some((f) => f.includes('no diff')), r.failures.join('\n'));
  },
  "a new block above the newest one, or a line appended to it, fails outside the cut": async () => {
    const above = logEdit('@@ -3,3 +3,5 @@\n Intro.\n \n+### Changes in revision 62 (in progress)\n+\n ### Changes in revision 61 (x, 2026-11-20)');
    const appended = logEdit('@@ -6,4 +6,5 @@\n \n - **#1:** a.\n+- **#2:** c.\n \n ### Changes in revision 60 (y)');
    const zeroContext = logEdit('@@ -8,0 +9 @@\n+- **#2:** c.');
    const removed = logEdit('@@ -6,3 +6,2 @@\n \n-- **#1:** a.\n ');
    for (const f of [above, appended, zeroContext, removed]) {
      const r = await lintFiles([f]);
      assert.ok(fragmentFailures(r).some((m) => m.includes('newest block')), `${f.patch}\n${r.failures.join('\n')}`);
      assert.deepEqual(fragmentFailures(await lintFiles([f], cutTitle)), []);
    }
  },
  'an edit to the intro or an older block passes': async () => {
    const intro = logEdit('@@ -1,4 +1,4 @@\n # Spec changelog\n \n-Intro.\n+Intro, edited.\n ');
    const older = logEdit('@@ -9,3 +9,3 @@\n ### Changes in revision 60 (y)\n \n-- **#0:** b.\n+- **#0:** B.');
    for (const f of [intro, older]) assert.deepEqual(fragmentFailures(await lintFiles([f])), [], f.patch);
  },
  'without the base CHANGELOG.md any edit fails closed': async () => {
    const intro = logEdit('@@ -1,4 +1,4 @@\n # Spec changelog\n \n-Intro.\n+Intro, edited.\n ');
    const r = await lint({ body: filled(), files: [intro] });
    assert.ok(fragmentFailures(r).some((m) => m.includes('newest block')), r.failures.join('\n'));
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
