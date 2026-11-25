#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# The seed job's reading of one seed jar (CONTRIBUTING §9; docs/attestation/seed-v1.md): the stored
# revokt/seed-<channel>.zip, its seed.json and the signed records.json. The build already verified, self-loaded and
# smoke-loaded the archive; this reads facts out of it and cross-checks them, failing on anything it does not expect:
# - seed.json's channel is <channel>, its seedFormat an integer and its recordsLastModified the signed <ts>, which is
#   records.json's last_modified;
# - every attachments/<f> entry is exactly one signed record's attachment.filename, with that record's size and
#   SHA-256, and there is at least one.
#
#   seed_predicate.sh ts <jar> <channel> <version>         prints the signed <ts>
#   seed_predicate.sh predicate <jar> <channel> <version>  prints the seed-v1 predicate (JSON); needs JDK_RUNTIME_VERSION,
#                                                          JDK_ARCHIVE and JDK_ARCHIVE_SHA256, reads ImageOS and
#                                                          ImageVersion (the runner's) when set
set -euo pipefail

usage() {
  echo "usage: seed_predicate.sh ts|predicate <jar> <channel> <version>" >&2
  exit 2
}
fail() {
  echo "::error::seed_predicate: $*" >&2
  exit 1
}
sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

[ $# -eq 4 ] || usage
mode=$1 jar=$2 channel=$3 version=$4
case $mode in ts | predicate) ;; *) usage ;; esac
case $channel in compat | default) ;; *) usage ;; esac
printf '%s' "$version" | grep -Eqx '[0-9]{4}\.[0-9]{2}\.[0-9]{2}' || usage
[ -f "$jar" ] || fail "no file $jar"
if [ "$mode" = predicate ]; then
  : "${JDK_RUNTIME_VERSION:?}" "${JDK_ARCHIVE:?}" "${JDK_ARCHIVE_SHA256:?}"
fi

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

entry="revokt/seed-$channel.zip"
# grep reads to the end (no -q), so unzip never writes into a closed pipe and dies of SIGPIPE under pipefail.
unzip -Z1 "$jar" | grep -xF "$entry" >/dev/null || fail "$jar holds no $entry"
unzip -p "$jar" "$entry" >| "$work/seed.zip"
unzip -p "$work/seed.zip" seed.json >| "$work/seed.json" || fail "$entry holds no seed.json"
unzip -p "$work/seed.zip" records.json >| "$work/records.json" || fail "$entry holds no records.json"

# The signed <ts>: a decimal string in records.json, the same integer in seed.json.
ts=$(jq -r '.last_modified | if type == "string" and test("^[0-9]{1,16}$") then . else error("not a <ts>") end' \
  "$work/records.json") || fail "records.json has no signed last_modified"
header=$(jq -r --arg ch "$channel" '
  if (.channel == ($ch | ascii_upcase)) and (.seedFormat | type == "number" and . == floor)
    and (.recordsLastModified | type == "number" and . == floor)
  then "\(.seedFormat) \(.recordsLastModified)" else error("unexpected header") end' "$work/seed.json") ||
  fail "seed.json is not a $channel header"
seed_format=${header%% *}
[ "${header#* }" = "$ts" ] || fail "seed.json's recordsLastModified ${header#* } is not records.json's last_modified $ts"

if [ "$mode" = ts ]; then
  printf '%s\n' "$ts"
  exit 0
fi

# The placed records, in the archive's order: each attachments/<f> entry against the one signed record naming f.
printf '[]' >| "$work/records.out"
while IFS= read -r name; do
  case $name in attachments/*) ;; *) continue ;; esac
  file=${name#attachments/}
  printf '%s' "$file" | grep -Eqx '[A-Za-z0-9._+-]+' || fail "unexpected entry name in $entry"
  unzip -p "$work/seed.zip" "$name" >| "$work/attachment"
  sha=$(sha256 "$work/attachment")
  size=$(wc -c <"$work/attachment" | tr -d ' ')
  jq -c --arg f "$file" '[.data[] | select(.attachment.filename == $f)]
      | if length == 1 then .[0] | {id, filename: .attachment.filename, size: .attachment.size, sha256: .attachment.hash}
        else error("not exactly one record") end' "$work/records.json" >| "$work/record" ||
    fail "not exactly one signed record names $file"
  jq -e --arg sha "$sha" --argjson size "$size" '.sha256 == $sha and .size == $size' "$work/record" >/dev/null ||
    fail "$file is not its signed record's size and SHA-256"
  jq -c --slurpfile r "$work/record" '. + $r' "$work/records.out" >| "$work/records.next"
  mv -f -- "$work/records.next" "$work/records.out"
done < <(unzip -Z1 "$work/seed.zip")
jq -e 'length > 0' "$work/records.out" >/dev/null || fail "$entry places no attachment"

jq -n \
  --arg channel "$channel" \
  --arg version "$version" \
  --argjson seedFormat "$seed_format" \
  --argjson ts "$ts" \
  --arg entry "$entry" \
  --arg zipSha "$(sha256 "$work/seed.zip")" \
  --slurpfile records "$work/records.out" \
  --arg jdkVersion "$JDK_RUNTIME_VERSION" \
  --arg jdkArchive "$JDK_ARCHIVE" \
  --arg jdkSha "$JDK_ARCHIVE_SHA256" \
  --arg imageOs "${ImageOS:-}" \
  --arg imageVersion "${ImageVersion:-}" \
  '{
    channel: $channel,
    version: $version,
    seedFormat: $seedFormat,
    recordsLastModified: $ts,
    archive: {name: $entry, sha256: $zipSha},
    records: $records[0],
    jdk: {vendor: "Eclipse Adoptium", runtimeVersion: $jdkVersion, archive: $jdkArchive, archiveSha256: $jdkSha},
    runner: {imageOs: $imageOs, imageVersion: $imageVersion}
  }'
