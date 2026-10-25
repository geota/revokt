#!/bin/sh
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# Records oracle 3a's goldens (spec §9.2, #35): x509-parser 0.18.1 on every input of the replay corpus. Needs Rust and
# JDK 21; the PR tier replays the committed goldens and needs neither. Run from the repository root:
#   sh native/revokt-oracle/record-3a-goldens.sh
set -eu
root=$(pwd)
out="$root/revokt-engine/src/jvmTest/resources/dev/revokt/engine/parse/oracle/3a.tsv"
work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT
( cd native && cargo build --locked --release -q )
./gradlew -q :revokt-engine:jvmTest --tests 'dev.revokt.engine.parse.oracle.Oracle3aTest.the 3a recording hook*' \
  -Drevokt.writeOracleInputs="$work/inputs.tsv" --rerun </dev/null
cut -f2 "$work/inputs.tsv" > "$work/b64.txt"
echo '##' >> "$work/b64.txt"
"$root/native/target/release/revokt-oracle" x509 < "$work/b64.txt" | grep -v '^##$' > "$work/replies.txt"
[ "$(wc -l < "$work/inputs.tsv")" -eq "$(wc -l < "$work/replies.txt")" ] || { echo "reply count mismatch" >&2; exit 1; }
mkdir -p "$(dirname "$out")"
{
  echo "# Oracle 3a (x509-parser 0.18.1, native/revokt-oracle x509) replies for the replay corpus of ProducerCorpus."
  echo "# sha256 of the input <TAB> OK <fields> | ERR <error> | PANIC <error>. Regenerate, never edit."
  cut -f1 "$work/inputs.tsv" | paste - "$work/replies.txt" | LC_ALL=C sort -u
} > "$out"
echo "wrote $(grep -vc '^#' "$out") 3a goldens to $out"
