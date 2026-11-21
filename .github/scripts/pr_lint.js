// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//
// Runs inside actions/github-script with `github`, `context`, `core` in scope (CONTRIBUTING §5, §12, ADR-0005, ADR-0006).
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
// One line with a value: the template's blank `Co-authored-by:` above `Signed-off-by:` is not a co-author.
const wantAi = /^Co-authored-by:[^\S\r\n]*\S/im.test(trailers);

// An agent-written PR carries its Handoff in the body (AGENTS.md §12, ADR-0006): something besides the template's own
// headings. Grace (#210): a PR opened before the rule existed may keep its Handoff as a "## Handoff" comment.
const handoffHeadings = /^###[^\S\r\n]*(JDK and OS|Gates not run locally and why|Assumptions made|Files touched outside the issue's module|Open questions)[^\S\r\n]*$/gm;
if (wantAi && !isRenovate && (section('Handoff') || '').replace(handoffHeadings, '').trim().length === 0) {
  const grace = new Date(pr.created_at) < new Date('2026-11-18T00:00:00Z');
  const comments = grace ? await github.paginate(github.rest.issues.listComments, { owner, repo, issue_number: number, per_page: 100 }) : [];
  if (comments.some((c) => /^#+\s*Handoff\b/m.test(c.body || ''))) {
    core.notice('pr-lint: the Handoff is a comment; accepted for a PR opened before 2026-11-18 (#210)');
  } else {
    failures.push('section "## Handoff" is missing or empty: an agent-written PR fills it in the body (AGENTS.md §12)');
  }
}

// Solo-maintainer phase (ADR-0005): an "Independent review" comment from a fresh-context review is required.
const maintainers = require('fs').readFileSync('MAINTAINERS.md', 'utf8').match(/\| @([A-Za-z0-9-]+) \|/g) || [];
if (maintainers.length < 2 && !pr.draft && !isRenovate) {
  const comments = await github.paginate(github.rest.issues.listComments, { owner, repo, issue_number: number, per_page: 100 });
  if (!comments.some((c) => /^#+\s*Independent review/m.test(c.body || '') || /^Independent review/m.test(c.body || ''))) {
    failures.push('solo-maintainer phase: post an "Independent review" comment from a fresh-context review of the diff before marking ready (ADR-0005)');
  }
}

// The solo phase turns off the cooling schedule (#211). Once MAINTAINERS.md lists two maintainers it comes back: the
// PR head's cooling.yml must have an active cron (read from the head, so the PR that restores it can pass).
if (maintainers.length >= 2) {
  let cooling = '';
  try {
    const { data } = await github.rest.repos.getContent({ owner, repo, path: '.github/workflows/cooling.yml', ref: pr.head.sha });
    cooling = Buffer.from(data.content || '', 'base64').toString('utf8');
  } catch (e) { core.warning(`cooling.yml not read: ${e.message}`); }
  if (!/^ {2}schedule:[^\S\r\n]*\r?\n[^\S\r\n]+- cron:/m.test(cooling)) {
    failures.push('MAINTAINERS.md lists two maintainers: turn the cooling schedule back on in .github/workflows/cooling.yml (CONTRIBUTING §8)');
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

// Changelog fragments (#272, CONTRIBUTING §1): a PR that edits the spec adds docs/spec/changes/<issue>.md, named after
// an issue its Why section references. Only the cut PR, titled "spec(<scope>): cut revision <N>" (tools/spec_cut.py),
// writes CHANGELOG.md's newest block or the core's status line, so no two open PRs edit the same spec file region.
const isCut = /^spec\([a-z]+\): cut revision \d+\b/.test(title);
const specFile = /^docs\/spec\/(revokt-spec|test-plan|references)\.md$/;
const fragmentFile = /^docs\/spec\/changes\/(\d+)\.md$/;
const cutOnly = 'only the cut PR ("spec(<scope>): cut revision <N>", tools/spec_cut.py)';
if (!isCut && !isRenovate) {
  if (files.some((f) => specFile.test(f.filename) || specFile.test(f.previous_filename || ''))) {
    const why = section('Why') || '';
    const issues = new Set([...why.matchAll(/#(\d+)|\/(?:issues|pull)\/(\d+)/g)].map((m) => m[1] || m[2]));
    const fragments = files.filter((f) => f.status !== 'removed' && fragmentFile.test(f.filename));
    if (fragments.length === 0) {
      failures.push('a PR that edits revokt-spec.md, test-plan.md or references.md adds its changelog bullets as docs/spec/changes/<issue>.md (CONTRIBUTING §1)');
    } else if (!fragments.some((f) => issues.has(f.filename.match(fragmentFile)[1]))) {
      failures.push('the changelog fragment is named after the issue: docs/spec/changes/<n>.md for an issue the Why section references (CONTRIBUTING §1)');
    }
  }
  const specCore = files.find((f) => f.filename === 'docs/spec/revokt-spec.md');
  if (specCore && specCore.status !== 'added') {
    if (specCore.status === 'removed' || typeof specCore.patch !== 'string') {
      failures.push('docs/spec/revokt-spec.md: GitHub shows no diff, so the status-line rule cannot be checked; split the PR (CONTRIBUTING §1)');
    } else if (/^[-+]Status: /m.test(specCore.patch)) {
      failures.push(`${cutOnly} edits the core's status line (CONTRIBUTING §1)`);
    }
  }
  const log = files.find((f) => f.filename === 'docs/spec/CHANGELOG.md');
  if (log && log.status !== 'added') {
    let touched = log.status === 'removed' || typeof log.patch !== 'string';
    if (!touched) {
      let base = null;
      try {
        const { data } = await github.rest.repos.getContent({ owner, repo, path: 'docs/spec/CHANGELOG.md', ref: pr.base.sha });
        base = Buffer.from(data.content || '', 'base64').toString('utf8');
      } catch (e) { core.warning(`CHANGELOG.md not read at the base: ${e.message}`); }
      // The newest block in the base's 1-based lines: its heading to the line before the next heading. Without a
      // heading the whole file counts; without the base file every edit does (fail closed).
      const lines = (base || '').split('\n');
      const headings = lines.flatMap((l, i) => (/^### Changes in revision /.test(l) ? [i + 1] : []));
      const start = headings.length ? headings[0] : 1;
      const end = headings.length > 1 ? headings[1] - 1 : lines.length;
      if (base === null) touched = true;
      let old = 0;
      for (const l of log.patch.split('\n')) {
        const hunk = l.match(/^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@/);
        // An empty old range ("-7,0") names the line before the insertion.
        if (hunk) { old = Number(hunk[1]) + (hunk[2] === '0' ? 1 : 0); continue; }
        // A removed line is old line `old`; an added line goes between old lines old-1 and old, so one added just
        // above the newest heading (a new block) or just above the next heading (appended) counts.
        if (l.startsWith('-')) { if (old >= start && old <= end) touched = true; old++; }
        else if (l.startsWith('+')) { if (old >= start && old <= end + 1) touched = true; }
        else if (l.startsWith(' ')) old++;
      }
    }
    if (touched) failures.push(`${cutOnly} writes CHANGELOG.md's newest block; add docs/spec/changes/<issue>.md instead (CONTRIBUTING §1)`);
  }
}

// size/XL: more than 1000 added lines of production source (tests, fixtures, corpora, dumps, lockfiles excluded); raised
// from 400 in #211, when a quarter of all PRs carried the label and it had stopped being a signal.
const nonProduction = /(\/test\/|\/jvmTest\/|\/commonTest\/|^corpus\/|\.api$|\.lockfile$|verification-metadata\.xml$|verification-keyring\.keys$|^docs\/|\.md$|Cargo\.lock$)/;
const productionAdded = files.filter((f) => !nonProduction.test(f.filename)).reduce((n, f) => n + (f.additions || 0), 0);
const wantXl = productionAdded > 1000;
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
