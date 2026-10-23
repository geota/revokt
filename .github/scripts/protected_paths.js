// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//
// Runs inside actions/github-script, checked out at the base branch (CONTRIBUTING §5).
const fs = require('fs');
const { owner, repo } = context.repo;
const number = context.payload.pull_request.number;
const pr = (await github.rest.pulls.get({ owner, repo, pull_number: number })).data;

const maintainers = (fs.readFileSync('MAINTAINERS.md', 'utf8').match(/\| @([A-Za-z0-9-]+) \|/g) || []).map((m) => m.replace(/[|@ ]/g, ''));
const globs = fs.readFileSync('.github/protected-paths.txt', 'utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));

function globToRegex(g) {
  let re = '^';
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === '*' && g[i + 1] === '*') { re += '.*'; i++; if (g[i + 1] === '/') i++; }
    else if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else if ('.+^$()[]{}|\\'.includes(c)) re += '\\' + c;
    else re += c;
  }
  return new RegExp(re + '$');
}
const matchers = globs.map(globToRegex);

const files = await github.paginate(github.rest.pulls.listFiles, { owner, repo, pull_number: number, per_page: 100 });
const touched = files.map((f) => f.filename).filter((f) => matchers.some((m) => m.test(f)));
if (touched.length === 0) { core.info('protected-paths: no protected path changed'); return; }
core.info(`protected-paths: ${touched.length} protected file(s) changed: ${touched.slice(0, 20).join(', ')}`);

// The author never counts; neither does the handle named by the head commits' Signed-off-by (the operating human).
const commits = await github.paginate(github.rest.pulls.listCommits, { owner, repo, pull_number: number, per_page: 100 });
const excluded = new Set([pr.user.login.toLowerCase()]);
for (const c of commits) {
  const m = (c.commit.message.match(/^Signed-off-by:\s*(.+?)\s*<([^>]+)>/im) || []);
  if (c.author && c.author.login) excluded.add(c.author.login.toLowerCase());
  if (m[2]) for (const h of maintainers) {
    const mail = m[2].toLowerCase();
    if (mail.startsWith(h.toLowerCase() + '@') || mail.endsWith('+' + h.toLowerCase() + '@users.noreply.github.com')) excluded.add(h.toLowerCase());
  }
}

const reviews = await github.paginate(github.rest.pulls.listReviews, { owner, repo, pull_number: number, per_page: 100 });
const latest = new Map();
for (const r of reviews) { if (r.user && ['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'].includes(r.state)) latest.set(r.user.login.toLowerCase(), r); }
const approvers = [...latest.values()].filter((r) => r.state === 'APPROVED' && r.commit_id === pr.head.sha).map((r) => r.user.login.toLowerCase());
const maintainerApprovals = approvers.filter((a) => maintainers.map((m) => m.toLowerCase()).includes(a) && !excluded.has(a));

let required;
if (maintainers.length < 2) required = 0;                                   // solo phase (ADR-0005): pr-lint requires the Independent review instead
else if (maintainers.length === 2) required = 1;                             // author + one other maintainer
else required = maintainers.map((m) => m.toLowerCase()).includes(pr.user.login.toLowerCase()) ? 1 : 2;

core.info(`protected-paths: maintainers=${maintainers.length} required=${required} approvals on head=${maintainerApprovals.length} (${maintainerApprovals.join(', ') || 'none'})`);
if (maintainerApprovals.length < required) {
  core.setFailed(`protected-paths: ${required} maintainer approval(s) on the current head are required for ${touched.length} protected file(s); have ${maintainerApprovals.length}. The author and the sign-off human never count (CONTRIBUTING §5).`);
}
