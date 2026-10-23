// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//
// Runs inside actions/github-script with `github`, `context`, `core` in scope (CONTRIBUTING §5, §12, ADR-0005).
const number = context.payload.pull_request ? context.payload.pull_request.number : context.payload.issue.number;
const { owner, repo } = context.repo;
const pr = (await github.rest.pulls.get({ owner, repo, pull_number: number })).data;
const body = pr.body || '';
const title = pr.title || '';
const failures = [];

const isRenovate = pr.user.type === 'Bot' && /renovate/i.test(pr.user.login);
const type = (title.match(/^([a-z]+)(\(|!|:)/) || [])[1] || '';
const scope = (title.match(/^[a-z]+\(([a-z]+)\)/) || [])[1] || '';
const moduleScopes = ['clubcard', 'engine', 'jsse', 'bc', 'okhttp', 'ktor', 'android', 'work', 'testing', 'bom', 'oracle', 'upki', 'seed'];

function section(name) {
  const m = body.match(new RegExp(`^## ${name}\\s*\\n([\\s\\S]*?)(?=^## |$(?![\\r\\n]))`, 'm'));
  if (!m) return null;
  return m[1].replace(/<!--[\s\S]*?-->/g, '').trim();
}

if (!isRenovate) {
  for (const name of ['What', 'Why', 'Spec', 'Tests', 'API', 'Risk and rollout', 'AI assistance', 'Checklist', 'Trailers']) {
    const s = section(name);
    if (s === null || s.length === 0) failures.push(`section "## ${name}" is missing or empty (PR template, CONTRIBUTING §5)`);
  }
  const why = section('Why') || '';
  if (!/#\d+|github\.com\/[^\s]+\/(issues|pull)\/\d+/.test(why)) failures.push('the Why section must reference the issue (Fixes: #n); a PR without an issue is closed (CONTRIBUTING §2)');
}

// Trailers must be the last section and must carry what the branch commits carry.
const trailersIdx = body.lastIndexOf('## Trailers');
if (trailersIdx >= 0 && /^## /m.test(body.slice(trailersIdx + 11))) failures.push('the Trailers block must be the last section so git parses the trailers (CONTRIBUTING §5)');
const trailers = section('Trailers') || '';
const specLine = (trailers.match(/^Spec:\s*(.*)$/m) || [])[1] || '';
if (['feat', 'fix', 'perf', 'refactor'].includes(type) && moduleScopes.includes(scope)) {
  if (!/§\d/.test(specLine)) failures.push(`${type}(${scope}) needs a "Spec: §x.y" trailer naming the sections implemented (CONTRIBUTING §4)`);
} else if (specLine && !/§\d|^none/.test(specLine)) {
  failures.push('Spec: must cite sections or read "none (<reason>)"');
}

const commits = await github.paginate(github.rest.pulls.listCommits, { owner, repo, pull_number: number, per_page: 100 });
const needCo = commits.some((c) => /^Co-authored-by:/im.test(c.commit.message));
const needSign = commits.some((c) => /^Signed-off-by:/im.test(c.commit.message));
if (needCo && !/^Co-authored-by:\s*\S/im.test(trailers)) failures.push('a branch commit carries Co-authored-by but the Trailers block does not: copy it, so the AI disclosure survives the squash (CONTRIBUTING §4)');
if (needSign && !/^Signed-off-by:\s*\S/im.test(trailers)) failures.push('a branch commit carries Signed-off-by but the Trailers block does not: copy the human sign-off (CONTRIBUTING §4)');
// Labels this check owns (CONTRIBUTING §2, §12): ai-assisted from the trailers, size/XL from production-source additions.
const wantAi = /^Co-authored-by:\s*\S/im.test(trailers);

// Solo-maintainer phase (ADR-0005): an "Independent review" comment from a fresh-context review is required.
const maintainers = require('fs').readFileSync('MAINTAINERS.md', 'utf8').match(/\| @([A-Za-z0-9-]+) \|/g) || [];
if (maintainers.length < 2 && !pr.draft && !isRenovate) {
  const comments = await github.paginate(github.rest.issues.listComments, { owner, repo, issue_number: number, per_page: 100 });
  if (!comments.some((c) => /^#+\s*Independent review/m.test(c.body || '') || /^Independent review/m.test(c.body || ''))) {
    failures.push('solo-maintainer phase: post an "Independent review" comment from a fresh-context review of the diff before marking ready (ADR-0005)');
  }
}

const files = await github.paginate(github.rest.pulls.listFiles, { owner, repo, pull_number: number, per_page: 100 });

// Trademark rule (spec §13): every added line that mentions revokt.com is the disambiguation sentence, except in
// the files that state the rule itself.
const ruleFiles = /^(CONTRIBUTING\.md|GOVERNANCE\.md|README\.md|NOTICE|docs\/spec\/.*|docs\/adr\/.*|\.github\/scripts\/pr_lint\.js)$/;
for (const f of files) {
  if (!f.patch || ruleFiles.test(f.filename)) continue;
  for (const line of f.patch.split('\n')) {
    if (/^\+/.test(line) && /revokt\.com/.test(line) && !/not affiliated with Revokt \(revokt\.com\)/.test(line)) {
      failures.push(`${f.filename} mentions revokt.com outside the disambiguation sentence (spec §13)`);
      break;
    }
  }
}

// size/XL: more than 400 added lines of production source (tests, fixtures, corpora, dumps, lockfiles excluded).
const nonProduction = /(\/test\/|\/jvmTest\/|\/commonTest\/|^corpus\/|\.api$|\.lockfile$|verification-metadata\.xml$|verification-keyring\.keys$|^docs\/|\.md$|Cargo\.lock$)/;
const productionAdded = files.filter((f) => !nonProduction.test(f.filename)).reduce((n, f) => n + (f.additions || 0), 0);
const wantXl = productionAdded > 400;
{
  const have = new Set(pr.labels.map((l) => l.name));
  const add = []; const remove = [];
  if (wantAi && !have.has('ai-assisted')) add.push('ai-assisted');
  if (!wantAi && have.has('ai-assisted')) remove.push('ai-assisted');
  if (wantXl && !have.has('size/XL')) add.push('size/XL');
  if (!wantXl && have.has('size/XL')) remove.push('size/XL');
  try {
    if (add.length) await github.rest.issues.addLabels({ owner, repo, issue_number: number, labels: add });
    for (const l of remove) await github.rest.issues.removeLabel({ owner, repo, issue_number: number, name: l });
  } catch (e) { core.warning(`labels not applied (fork PR without write token?): ${e.message}`); }
  if (wantXl) core.notice(`size/XL: ${productionAdded} production lines added; the PR must state the exception (CONTRIBUTING §2)`);
}

if (failures.length) {
  core.setFailed(failures.map((f) => `pr-lint: ${f}`).join('\n'));
} else {
  core.info('pr-lint: ok');
}
