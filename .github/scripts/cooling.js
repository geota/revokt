// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//
// Runs inside actions/github-script (CONTRIBUTING §8). On a pull_request event it evaluates that PR; on the schedule
// it re-evaluates every open PR and writes a `cooling` check run on each head SHA.
const fs = require('fs');
const { owner, repo } = context.repo;
const HOLD_MS = 24 * 60 * 60 * 1000;
const maintainers = (fs.readFileSync('MAINTAINERS.md', 'utf8').match(/\| @([A-Za-z0-9-]+) \|/g) || []);
const solo = maintainers.length < 2;
const always = ['data/seed/', '.github/workflows/release', '/verify/'];

async function evaluate(pr) {
  const files = await github.paginate(github.rest.pulls.listFiles, { owner, repo, pull_number: pr.number, per_page: 100 });
  const names = files.map((f) => f.filename);
  // Solo-maintainer phase (ADR-0005): the hold exists to give a second reader time, and there is none; the independent
  // review and the maintainer's full read are the controls. The check reports success and activates by itself when
  // MAINTAINERS.md gains a second maintainer.
  if (solo) return { ok: true, summary: 'solo-maintainer phase: cooling paused (ADR-0005); activates with the second maintainer' };
  const hits = names.filter((n) => always.some((a) => n.includes(a)));
  const exempt = pr.labels.some((l) => ['advisory-fix', 'revert'].includes(l.name)) || /^revert\(/.test(pr.title);
  if (hits.length === 0 || exempt) return { ok: true, summary: 'no cooling path touched, or exempt' };
  // "Last push" = when this head SHA first produced a check run (the author controls commit dates, not CI clocks).
  const runs = await github.paginate(github.rest.checks.listForRef, { owner, repo, ref: pr.head.sha, per_page: 100 });
  const started = runs.map((r) => new Date(r.started_at || r.completed_at || 0).getTime()).filter((t) => t > 0);
  const last = started.length ? Math.min(...started) : new Date(pr.updated_at).getTime();
  const remaining = last + HOLD_MS - Date.now();
  if (remaining <= 0) return { ok: true, summary: `24 h cooling elapsed for ${hits.length} path(s)` };
  const hours = (remaining / 3600000).toFixed(1);
  return { ok: false, summary: `cooling: ${hits.length} protected path(s) changed ${hours} h before the 24 h hold ends (CONTRIBUTING §8); the schedule re-runs this check hourly` };
}

if (context.payload.pull_request) {
  const r = await evaluate(context.payload.pull_request);
  core.info(r.summary);
  if (!r.ok) core.setFailed(r.summary);
} else {
  const open = await github.paginate(github.rest.pulls.list, { owner, repo, state: 'open', per_page: 100 });
  for (const pr of open) {
    const r = await evaluate(pr);
    await github.rest.checks.create({
      owner, repo, name: 'cooling', head_sha: pr.head.sha, status: 'completed',
      conclusion: r.ok ? 'success' : 'failure',
      output: { title: 'cooling', summary: r.summary },
    });
    core.info(`#${pr.number}: ${r.summary}`);
  }
}
