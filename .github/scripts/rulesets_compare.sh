#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# The owner-power audit's comparison (CONTRIBUTING §7, #241): the committed export $1 (docs/dev/rulesets) against the
# live export $2 (rulesets_export.sh), with the issue text written to $3 (empty when they match). Only the members that
# need an admin read are ever left out, and only when they come back absent or null while ADMIN is not true: a
# ruleset's bypass_actors, and seven merge settings. Any other absent or null member is compared, so a protection
# removed from a live ruleset is a difference. With ADMIN true nothing is left out, and an unreadable allow-listed
# member is a difference too. Each member left out is named in a warning and in the issue text. Exits 0 whether or not
# the files differ; a missing or malformed file fails.
set -euo pipefail

committed=${1:?usage: rulesets_compare.sh <committed dir> <live dir> <issue text>}
live=${2:?}
news=${3:?}
work=$(mktemp -d)
trap 'rm -rf -- "${work:?}"' EXIT
cp -R "$committed" "$work/committed"
cp -R "$live" "$work/live"

admin=${ADMIN:-false}
# The members github.token cannot read, per file: the only ones ever left out.
ruleset_admin_only='["bypass_actors"]'
repository_admin_only='["allow_auto_merge","allow_merge_commit","allow_rebase_merge","allow_squash_merge","delete_branch_on_merge","squash_merge_commit_message","squash_merge_commit_title"]'
skipped=()
unread_with_admin=()
for f in "$work/live"/ruleset-*.json "$work/live/repository.json"; do
  [ -f "$f" ] || continue
  name=${f##*/}
  c=$work/committed/$name
  [ -f "$c" ] || continue
  case $name in repository.json) allowed=$repository_admin_only ;; *) allowed=$ruleset_admin_only ;; esac
  # The allow-listed members the live file lacks or holds as null, of those either file has.
  keys=$(jq -c --argjson a "$allowed" --slurpfile c "$c" \
    '[$a[] as $k | select(((has($k) | not) or .[$k] == null) and (has($k) or ($c[0] | has($k)))) | $k] | unique' "$f")
  [ "$keys" != "[]" ] || continue
  if [ "$admin" = "true" ]; then
    # An admin token reads these, so an absent or null one is reported, never left out.
    echo "::warning::$name: $keys came back unreadable with RULESETS_AUDIT_TOKEN; reported as a difference"
    unread_with_admin+=("\`$name\`: $keys")
    continue
  fi
  echo "::warning::$name: $keys need an admin read, so not compared (RULESETS_AUDIT_TOKEN, CONTRIBUTING §7)"
  skipped+=("\`$name\`: $keys")
  for x in "$f" "$c"; do
    jq -S --argjson k "$keys" 'with_entries(select(.key as $x | $k | index($x) | not))' "$x" >| "$x.tmp"
    mv "$x.tmp" "$x"
  done
done

: >| "$news"
differs=0
diff -ru "$work/committed" "$work/live" >| "$work/audit.diff" || differs=1
if [ "$differs" -eq 0 ] && [ "${#unread_with_admin[@]}" -eq 0 ]; then
  echo "no change"
  exit 0
fi
{
  echo "The live settings differ from \`docs/dev/rulesets/\`. If the change is intended, refresh the files in a PR"
  echo "(\`.github/scripts/rulesets_export.sh docs/dev/rulesets\` with an admin token); otherwise revert the setting."
  if [ "${#unread_with_admin[@]}" -gt 0 ]; then
    echo
    echo "Unreadable although RULESETS_AUDIT_TOKEN was set (check the token's permissions):"
    for s in "${unread_with_admin[@]}"; do echo "- $s"; done
  fi
  if [ "${#skipped[@]}" -gt 0 ]; then
    echo
    echo "Not compared, as they need an admin read (no RULESETS_AUDIT_TOKEN):"
    for s in "${skipped[@]}"; do echo "- $s"; done
  fi
  echo
  echo '```diff'
  sed -e "s|$work/committed|docs/dev/rulesets|; s|$work/live|live|" "$work/audit.diff" | head -c 50000
  echo
  echo '```'
} >| "$news"
echo "the settings differ from docs/dev/rulesets"
