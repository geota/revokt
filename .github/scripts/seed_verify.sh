#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# The floor check's re-verification of a released seed jar (#308; seed_floor.sh's SEED_VERIFY in release-seed.yml).
# Runs :revokt-seed:seedTimestamp<Channel>, the engine's verifySeedSignature: the parts of a seed load that do not depend
# on the seed format, as Firefox re-verifies its local data. seed.json's channel, the x5u chain inside the archive to
# Mozilla's pinned root, the content signature over records.json, the canonical payload that gives the <ts>, and the x5u
# validity at that <ts>. No network. Gradle runs on $JAVA_HOME alone, toolchain detection off, as the build step's does,
# and without the job's tokens. Gradle's own output goes to stderr; stdout is the verified <ts> alone.
#
#   seed_verify.sh <channel> <jar>   prints the jar's verified signed <ts>; fails when it does not verify
# Needs JAVA_HOME.
set -euo pipefail

usage() {
  echo "usage: seed_verify.sh compat|default <jar>" >&2
  exit 2
}
fail() {
  echo "::error::seed_verify: $*" >&2
  exit 1
}

[ $# -eq 2 ] || usage
channel=$1 jar=$2
case $channel in compat) task=seedTimestampCompat ;; default) task=seedTimestampDefault ;; *) usage ;; esac
: "${JAVA_HOME:?}"
[ -f "$jar" ] || fail "no file $jar"
jar=$(cd "$(dirname "$jar")" && pwd)/$(basename "$jar")
root=$(cd "$(dirname "$0")/../.." && pwd)

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
out="$work/ts"
# The build reads no token: GH_TOKEN and GITHUB_TOKEN stay out of Gradle and everything it runs.
env -u GH_TOKEN -u GITHUB_TOKEN "$root/gradlew" -p "$root" ":revokt-seed:$task" \
  -Prevokt.seedJar="$jar" \
  -Prevokt.seedTimestampOut="$out" \
  -Porg.gradle.java.installations.auto-detect=false \
  -Porg.gradle.java.installations.paths="$JAVA_HOME" \
  --no-daemon --no-build-cache --no-configuration-cache >&2 || fail "$jar does not verify as a $channel seed"
[ -f "$out" ] || fail "seedTimestamp wrote no <ts> for $jar"
ts=$(cat -- "$out")
[[ $ts =~ ^[0-9]{1,16}$ ]] || fail "seedTimestamp wrote '$ts', not one <ts>"
printf '%s\n' "$ts"
