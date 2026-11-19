#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# The owner-power audit trail's export (CONTRIBUTING §7, #241): the repository's rulesets, environments and merge
# settings, as GH_TOKEN can read them, into $1 (normally docs/dev/rulesets), one canonical JSON file each (keys sorted,
# the volatile members created_at, updated_at, _links, node_id and current_user_can_bypass removed). The weekly
# housekeeping job runs it to compare with the committed files; a maintainer runs it, with a token that may read the
# rulesets' bypass list, to refresh them: `REPO=geota/revokt .github/scripts/rulesets_export.sh docs/dev/rulesets`.
set -euo pipefail

out=${1:?usage: rulesets_export.sh <directory>}
repo=${REPO:-${GITHUB_REPOSITORY:?REPO or GITHUB_REPOSITORY}}
mkdir -p "$out"
drop='del(.created_at, .updated_at, ._links, .node_id, .current_user_can_bypass)'

gh api "repos/$repo/rulesets?includes_parents=false" | jq -S "sort_by(.id) | map($drop)" >| "$out/rulesets.json"
for id in $(jq -r '.[].id' "$out/rulesets.json"); do
  case $id in '' | *[!0-9]*) echo "a ruleset id that is not a number" >&2; exit 1 ;; esac
  gh api "repos/$repo/rulesets/$id" | jq -S "$drop" >| "$out/ruleset-$id.json"
done
gh api "repos/$repo" | jq -S '{allow_squash_merge, allow_merge_commit, allow_rebase_merge, allow_auto_merge,
  delete_branch_on_merge, squash_merge_commit_title, squash_merge_commit_message, has_issues,
  web_commit_signoff_required}' >| "$out/repository.json"
gh api "repos/$repo/environments" | jq -S '[.environments[] | {name,
  protection_rules: [.protection_rules[] | {type, reviewers: [.reviewers[]? | {type, login: .reviewer.login}],
  prevent_self_review}], deployment_branch_policy}] | sort_by(.name)' >| "$out/environments.json"
