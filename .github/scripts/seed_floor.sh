#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# The seed job's monotonic freshness check (spec §7.2, CONTRIBUTING §9). A seed is never older than the last released
# seed of its channel. The last release is the highest published seed-YYYY.MM.DD release; drafts don't count. For each
# channel, that release's jar must pass `gh attestation verify` twice, as this workflow's work on main: once for
# provenance, once for the seed-v1 predicate. Its content signature is then verified again, as an app's start loads it
# (SEED_VERIFY: seed_verify.sh, the engine's seed load under Mozilla's pins, x5u validity at the signed <ts>), and the
# <ts> that verifies, its records.json <ts> and the attested recordsLastModified must be one value. Firefox's client
# does the same before it ignores an older changeset (RemoteSettingsClient.sys.mjs, _importChanges), but where its
# local data does not verify it imports the older changeset; here a release that does not verify fails the run. The
# new jar's signed <ts> is then compared with it:
# - older: the run fails;
# - equal on every channel: nothing new, so publishing is skipped and the run stays green;
# - otherwise: publish.
# The first seed release has no floor; a seed-* tag with no published seed release fails the run, so deleting the
# releases does not reset the floor. A previous release that is missing a channel's jar, or whose attestation or content
# signature does not verify, fails the run: the maintainer repairs it by hand.
#
#   seed_floor.sh <version> <dir>   <dir> holds revokt-seed-<channel>-<version>.jar for both channels; writes
#                                   publish=true|false to $GITHUB_OUTPUT
# Needs GH_TOKEN, GITHUB_REPOSITORY, GITHUB_OUTPUT, PREDICATE_TYPE, SIGNER_WORKFLOW and SEED_VERIFY (a bash script run
# as `SEED_VERIFY <channel> <jar>`, printing the jar's verified <ts> alone, failing when it does not verify).
set -euo pipefail

fail() {
  echo "::error::seed floor: $*" >&2
  exit 1
}

[ $# -eq 2 ] || { echo "usage: seed_floor.sh <version> <dir>" >&2; exit 2; }
version=$1 dir=$2
: "${GITHUB_REPOSITORY:?}" "${GITHUB_OUTPUT:?}" "${PREDICATE_TYPE:?}" "${SIGNER_WORKFLOW:?}" "${SEED_VERIFY:?}"
printf '%s' "$version" | grep -Eqx '[0-9]{4}\.[0-9]{2}\.[0-9]{2}' || fail "not a version: $version"
repo=$GITHUB_REPOSITORY
here=$(cd "$(dirname "$0")" && pwd)
channels="compat default"

# Published releases only (a draft is not a release; a contents: read token does not list drafts anyway).
releases=$(gh api --paginate "repos/$repo/releases?per_page=100") || fail "cannot list the releases"
prev=$(printf '%s\n' "$releases" | jq -r '.[] | select(.draft | not) | .tag_name' |
  { grep -Ex 'seed-[0-9]{4}\.[0-9]{2}\.[0-9]{2}' || true; } | sort | tail -n 1)

if [ -z "$prev" ]; then
  # Deleting every seed release must not reset the floor: a seed-* tag left behind means one existed.
  refs=$(gh api --paginate "repos/$repo/git/matching-refs/tags/seed-") || fail "cannot list the seed tags"
  tags=$(printf '%s\n' "$refs" | jq -r '.[].ref' | { grep -Ex 'refs/tags/seed-[0-9]{4}\.[0-9]{2}\.[0-9]{2}' || true; })
  [ -z "$tags" ] || fail "seed tags exist but no published seed release does: restore the release or ask the maintainer"
  echo "::notice::seed floor: no earlier seed release or tag, so no floor (the first seed release)"
  echo "publish=true" >>"$GITHUB_OUTPUT"
  exit 0
fi
prev_version=${prev#seed-}
[[ "$prev_version" < "$version" ]] || fail "the newest seed release $prev is not older than $version"

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
newer=0
for channel in $channels; do
  jar="$dir/revokt-seed-$channel-$version.jar"
  new_ts=$(bash "$here/seed_predicate.sh" ts "$jar" "$channel" "$version") || fail "cannot read the new $channel seed"

  name="revokt-seed-$channel-$prev_version.jar"
  gh release download "$prev" --repo "$repo" --pattern "$name" --dir "$work" >/dev/null 2>&1 ||
    fail "$prev has no $name: repair or delete that release by hand"
  [ -f "$work/$name" ] || fail "$prev has no $name: repair or delete that release by hand"
  verify=(--repo "$repo" --signer-workflow "$SIGNER_WORKFLOW" --source-ref refs/heads/main --deny-self-hosted-runners)
  gh attestation verify "$work/$name" "${verify[@]}" >/dev/null ||
    fail "$prev's $name has no provenance from $SIGNER_WORKFLOW on main"
  gh attestation verify "$work/$name" "${verify[@]}" --predicate-type "$PREDICATE_TYPE" --format json \
    >|"$work/verified.json" || fail "$prev's $name has no seed-v1 attestation from $SIGNER_WORKFLOW on main"
  attested=$(jq -r --arg ch "$channel" --arg v "$prev_version" '
    [.[].verificationResult.statement.predicate
      | if .channel == $ch and .version == $v then .recordsLastModified else error("another seed") end]
    | unique | if length == 1 and (.[0] | type == "number") then .[0] | tostring else error("no single <ts>") end' \
    "$work/verified.json") || fail "$prev's $name attestation is not for $channel $prev_version with one <ts>"
  old_ts=$(bash "$here/seed_predicate.sh" ts "$work/$name" "$channel" "$prev_version") ||
    fail "cannot read $prev's $name"
  [ "$old_ts" = "$attested" ] || fail "$prev's $name holds <ts> $old_ts, its attestation $attested"
  verified=$(bash "$SEED_VERIFY" "$channel" "$work/$name") ||
    fail "$prev's $name does not verify under Mozilla's pins: repair or delete that release by hand"
  [[ $verified =~ ^[0-9]{1,16}$ ]] || fail "the verification of $prev's $name printed no single <ts>"
  [ "$verified" = "$attested" ] || fail "$prev's $name verifies at <ts> $verified, its attestation $attested"

  if [ "$new_ts" -lt "$old_ts" ]; then
    fail "refusing an older seed: the $channel <ts> $new_ts is older than $prev's $old_ts"
  elif [ "$new_ts" -gt "$old_ts" ]; then
    newer=1
    echo "seed floor: $channel <ts> $new_ts is newer than $prev's $old_ts"
  else
    echo "seed floor: $channel <ts> $new_ts equals $prev's"
  fi
  rm -f -- "$work/$name" "$work/verified.json"
done

if [ "$newer" = 1 ]; then
  echo "publish=true" >>"$GITHUB_OUTPUT"
else
  echo "::notice::seed floor: every channel's <ts> equals $prev's; nothing new to publish"
  echo "publish=false" >>"$GITHUB_OUTPUT"
fi
