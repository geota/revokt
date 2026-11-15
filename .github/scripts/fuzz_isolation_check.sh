# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# fuzz.yml (#115): run as the fuzzing user, before any code of the fuzzed tree runs, it checks the uid boundary that
# keeps that code away from the advisory token. The user is not root, is in no group but its own, cannot use sudo,
# and can write none of the paths given (the step's file commands, the runner-owned checkout and the runner user's
# temporary directory), nothing under the runner user's home, and not the Docker socket. It exits 0 only
# when every check holds; otherwise it prints an ::error:: for the first that fails and exits 1.
#
# Usage, from the runner user, with the script on stdin so the user needs no read access to the checkout:
#   sudo -u <user> -- /usr/bin/env -i PATH=/usr/bin:/bin /bin/bash -s -- <user> <runner home> <path>... < this file
# shellcheck shell=bash
set -euo pipefail

user=${1:?the fuzzing user}
runner_home=${2:?the runner user home}
shift 2

fail() {
  echo "::error::the fuzzing user $*; nothing of the fuzzed tree runs"
  exit 1
}

[ "$(id -un)" = "$user" ] || fail "check runs as $(id -un), not $user"
[ "$(id -u)" -ne 0 ] || fail "is root"
[ "$(id -Gn)" = "$user" ] || fail "is in groups other than its own: $(id -Gn)"
# -n: fail at once instead of asking for a password. A missing sudo counts as no sudo.
if sudo -n true > /dev/null 2>&1; then fail "can use sudo"; fi

for path in "$@" /var/run/docker.sock; do
  if [ -w "$path" ]; then fail "can write $path"; fi
done
# Whatever the user cannot reach, it cannot write either, so find's permission errors are not failures.
writable=$(find "$runner_home" -writable -print -quit 2> /dev/null || true)
[ -z "$writable" ] || fail "can write $writable"

echo "the fuzzing user $user (uid $(id -u)) has no sudo and cannot write the runner user's files"
