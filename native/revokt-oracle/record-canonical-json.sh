#!/bin/sh
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# Records the canonical JSON goldens of spec §7.1 and §9 (#92) from canonical_json 0.7.0 (native/revokt-oracle):
# - canonical-json.tsv: the oracle's reply to every curated input of canonical-json-inputs.tsv and to the generated
#   numbers (`gen-numbers`, below), each with its input;
# - remote-settings.tsv: the SHA-256 and length of the canonical JSON of two Remote Settings changesets, as a document
#   and as its content-signature payload (`signed-payload`): the synthetic CRLite-shaped crlite-changeset.json and the
#   large corpus's recorded security-state/intermediates changeset (docs/dev/corpus.md, pinned in
#   gradle/corpus-pin.properties), which REVOKT_CORPUS must name a checkout of.
# CanonicalJsonOracleTest replays both. Needs Rust and python3; the PR tier replays the committed goldens and needs
# neither. Run from the repository root:
#   REVOKT_CORPUS=build/corpus sh native/revokt-oracle/record-canonical-json.sh
set -eu
root=$(pwd)
dir="$root/revokt-engine/src/jvmTest/resources/dev/revokt/engine/json"
changeset="issuer/mozilla-intermediates/changeset.json"
count=4000
seed=92
corpus=${REVOKT_CORPUS:?set REVOKT_CORPUS to a revokt-corpus checkout at the pinned tag}
[ -f "$corpus/$changeset" ] || { echo "REVOKT_CORPUS=$corpus has no $changeset" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT
( cd native && cargo build --locked --release -q )
oracle="$root/native/target/release/revokt-oracle"

# name <TAB> base64 of the text, for the curated inputs and the generated numbers.
python3 -I -c '
import base64, sys
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.rstrip("\n")
    if not line or line.startswith("#"):
        continue
    name, form, data = line.split("\t", 2)
    raw = data.encode("utf-8") if form == "text" else base64.b64decode(data, validate=True)
    print(name + "\t" + base64.b64encode(raw).decode())
' "$dir/canonical-json-inputs.tsv" > "$work/inputs.tsv"
"$oracle" gen-numbers "$count" "$seed" >> "$work/inputs.tsv"
{ cut -f2 "$work/inputs.tsv"; echo '##'; } | "$oracle" canonical-json | grep -v '^##$' > "$work/replies.tsv"
[ "$(wc -l < "$work/inputs.tsv")" -eq "$(wc -l < "$work/replies.tsv")" ] || { echo "reply count mismatch" >&2; exit 1; }
! grep -q '^PANIC' "$work/replies.tsv" || { echo "canonical_json panicked:" >&2; grep '^PANIC' "$work/replies.tsv" >&2; exit 1; }
{
  # REUSE-IgnoreStart (the golden's own header, written out; not this script's)
  echo "# SPDX-FileCopyrightText: 2026 revokt contributors"
  echo "# SPDX-License-Identifier: Apache-2.0"
  # REUSE-IgnoreEnd
  echo "# canonical_json 0.7.0 (native/revokt-oracle canonical-json) on canonical-json-inputs.tsv and gen-numbers $count $seed."
  echo "# name <TAB> base64 input <TAB> OK <TAB> base64 canonical JSON | ERR <TAB> error. Regenerate with"
  echo "# native/revokt-oracle/record-canonical-json.sh, never edit."
  paste "$work/inputs.tsv" "$work/replies.tsv"
} > "$dir/canonical-json.tsv"
echo "wrote $(grep -vc '^#' "$dir/canonical-json.tsv") goldens to $dir/canonical-json.tsv"

# record <path as named in the golden> <file>: the document's and the payload's canonical SHA-256 and length.
record() {
  input=$(shasum -a 256 "$2" | cut -d' ' -f1)
  { base64 < "$2" | tr -d '\n'; echo; echo '##'; } | "$oracle" canonical-json | head -n 1 > "$work/reply"
  [ "$(cut -f1 "$work/reply")" = OK ] || { echo "$1: $(cat "$work/reply")" >&2; exit 1; }
  cut -f2 "$work/reply" | python3 -I -c 'import base64, sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' > "$work/document"
  "$oracle" signed-payload "$2" "$work/payload"
  for form in document payload; do
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$input" "$form" "$(shasum -a 256 "$work/$form" | cut -d' ' -f1)" \
      "$(wc -c < "$work/$form" | tr -d ' ')"
  done
}
{
  # REUSE-IgnoreStart
  echo "# SPDX-FileCopyrightText: 2026 revokt contributors"
  echo "# SPDX-License-Identifier: Apache-2.0"
  # REUSE-IgnoreEnd
  echo "# canonical_json 0.7.0 on Remote Settings changesets (native/revokt-oracle/record-canonical-json.sh, never edit):"
  echo "# file <TAB> its SHA-256 <TAB> document | payload <TAB> SHA-256 of the canonical JSON <TAB> its length. A file"
  echo "# named issuer/... is in the large corpus; the payload is the content-signature payload without its prefix."
  record crlite-changeset.json "$dir/crlite-changeset.json"
  record "$changeset" "$corpus/$changeset"
} > "$dir/remote-settings.tsv"
echo "wrote $dir/remote-settings.tsv"
