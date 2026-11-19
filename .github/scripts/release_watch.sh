#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# One watch issue (CONTRIBUTING §6, §7; #211, #241): keeps one open issue, titled $TITLE, while a watch finds something.
# Used by the nightly's release watches and the weekly rulesets audit. $1 is the Markdown of the findings; an empty
# file means nothing holds. INTRO and OUTRO, when set, replace the release watches' first and last lines. A finding opens the
# issue, or rewrites the body of the open one (an edit sends no notification); no finding closes it. Exits 0 unless
# the GitHub API fails, so the nightly stays green on news.
set -euo pipefail

news=${1:?usage: release_watch.sh <findings.md>}
: "${TITLE:?}" "${LABELS:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_RUN_ID:?}"
repo=$GITHUB_REPOSITORY
run_url="${GITHUB_SERVER_URL:-https://github.com}/$repo/actions/runs/$GITHUB_RUN_ID"
default_intro="The nightly's release watch (\`.github/workflows/nightly.yml\`, CONTRIBUTING §6) found:"
default_outro="The nightly rewrites this list while it holds and closes the issue once the pins are current."

# The open issue with exactly this title, among those carrying the first label (a search could lag behind).
number=$(gh issue list --repo "$repo" --state open --label "${LABELS%%,*}" --limit 500 --json number,title \
  --jq 'map(select(.title == env.TITLE)) | first | .number // empty')

if [ -s "$news" ]; then
  body=$(mktemp)
  {
    echo "${INTRO:-$default_intro}"
    echo
    cat "$news"
    echo
    echo "Last seen by $run_url. ${OUTRO:-$default_outro}"
  } >| "$body"
  if [ -n "$number" ]; then
    gh issue edit "$number" --repo "$repo" --body-file "$body" >/dev/null
    echo "release watch: updated #$number"
  else
    gh issue create --repo "$repo" --title "$TITLE" --label "$LABELS" --body-file "$body"
  fi
  rm -f -- "$body"
elif [ -n "$number" ]; then
  gh issue close "$number" --repo "$repo" --comment "${CLOSE_NOTE:-The pins are current again} ($run_url)."
  echo "release watch: closed #$number"
else
  echo "release watch: nothing awaits admission"
fi
