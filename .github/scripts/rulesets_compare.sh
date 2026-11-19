#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# The owner-power audit's comparison (CONTRIBUTING §7, #241): the committed export $1 (docs/dev/rulesets) against the
# live export $2 (rulesets_export.sh), with the issue text written to $3 (empty when they match). A member is left out
# of the comparison only where the token could not read it: absent or null in the live file, in a ruleset or in the
# merge settings, so a member the token can read is always compared, whatever token ran. Each member left out is
# named in a warning and in the issue text. Exits 0 whether or not the files differ; a missing or malformed file fails.
set -euo pipefail

committed=${1:?usage: rulesets_compare.sh <committed dir> <live dir> <issue text>}
live=${2:?}
news=${3:?}
work=$(mktemp -d)
trap 'rm -rf -- "${work:?}"' EXIT
cp -R "$committed" "$work/committed"
cp -R "$live" "$work/live"

# The object members the live file lacks or holds as null, as a JSON array of names.
unread() { jq -c 'if type == "object" then [to_entries[] | select(.value == null) | .key] else [] end' "$1"; }
skipped=()
for f in "$work/live"/ruleset-*.json "$work/live/repository.json"; do
  [ -f "$f" ] || continue
  name=${f##*/}
  c=$work/committed/$name
  [ -f "$c" ] || continue
  # Members of the committed file that are absent from the live one, plus the live file's nulls.
  keys=$(jq -c --slurpfile l "$f" '[keys[] as $k | select(($l[0] | has($k) | not) or $l[0][$k] == null) | $k]' "$c")
  keys=$(jq -c -n --argjson a "$keys" --argjson b "$(unread "$f")" '$a + $b | unique')
  if [ "$keys" != "[]" ]; then
    echo "::warning::$name: $keys not readable with this token, so not compared (RULESETS_AUDIT_TOKEN, CONTRIBUTING §7)"
    skipped+=("\`$name\`: $keys")
    for x in "$f" "$c"; do
      jq -S --argjson k "$keys" 'with_entries(select(.key as $x | $k | index($x) | not))' "$x" >| "$x.tmp"
      mv "$x.tmp" "$x"
    done
  fi
done

: >| "$news"
if diff -ru "$work/committed" "$work/live" >| "$work/audit.diff"; then
  echo "no change"
  exit 0
fi
{
  echo "The live settings differ from \`docs/dev/rulesets/\`. If the change is intended, refresh the files in a PR"
  echo "(\`.github/scripts/rulesets_export.sh docs/dev/rulesets\` with an admin token); otherwise revert the setting."
  if [ "${#skipped[@]}" -gt 0 ]; then
    echo
    echo "Not compared, as the token could not read them:"
    for s in "${skipped[@]}"; do echo "- $s"; done
  fi
  echo
  echo '```diff'
  sed -e "s|$work/committed|docs/dev/rulesets|; s|$work/live|live|" "$work/audit.diff" | head -c 50000
  echo
  echo '```'
} >| "$news"
echo "the settings differ from docs/dev/rulesets"
