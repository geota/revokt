#!/bin/sh
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# Records the spec §9 "index.bin byte comparison" golden (#86): upki's own `index.bin` for the corpus/clubcard filters.
# Builds upki-cli at the pinned tag, serves the filters as a local mirror (manifest.json plus the files, on 127.0.0.1),
# runs `upki fetch` against it, and commits the index.bin upki writes, with its provenance. revokt's C2spIndex writer
# must reproduce it byte for byte (C2spIndexUpkiTest). Needs Rust, network for the build, python3 for the local server
# and curl; the PR tier replays the committed golden and needs none of them. Run from the repository root:
#   sh native/revokt-oracle/record-upki-index.sh
set -eu
root=$(pwd)
tag=v1.0.1   # rustls/upki, spec §3.2 and Appendix A; #85 moves this pin into gradle/oracle-matrix.properties
out="$root/revokt-engine/src/jvmTest/resources/dev/revokt/engine/c2sp"
work=$(mktemp -d)
cleanup() {
  if [ -n "${server:-}" ]; then kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

cargo install --quiet --locked --git https://github.com/rustls/upki --tag "$tag" upki-cli --root "$work/upki"
upki="$work/upki/bin/upki"

# The mirror: each filter under a C2SP-legal name of at most 32 bytes, in this order (the index's filename order).
mkdir -p "$work/mirror/revocation" "$work/cache"
set -- \
  full-v3 corpus/clubcard/compat-full/20261017-1-compat.filter \
  delta-v3 corpus/clubcard/compat-delta/20261021-1-compat.filter.delta \
  delta-v4 corpus/clubcard/compat-delta/20261021-1-compat.filter.delta.v4 \
  synthetic-v3 corpus/clubcard/synthetic/synthetic.v3.filter
files=""
order=""
while [ $# -gt 0 ]; do
  name=$1 src=$2
  shift 2
  cp "$src" "$work/mirror/revocation/$name"
  size=$(wc -c < "$src" | tr -d ' ')
  hash=$(shasum -a 256 "$src" | cut -d' ' -f1)
  files="$files${files:+,}{\"filename\":\"$name\",\"size\":$size,\"hash\":\"$hash\"}"
  order="$order$name	$src	$hash
"
done
printf '{"generated_at":1793318400,"comment":"revokt #86 index golden","files":[%s]}\n' "$files" > "$work/mirror/revocation/manifest.json"

# Port 0: the server binds a free port itself and reports it, so no other process can take it in between.
python3 -I -u -m http.server 0 --bind 127.0.0.1 --directory "$work/mirror" > "$work/server.log" 2>&1 &
server=$!
port=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  kill -0 "$server" 2>/dev/null || { echo "the local mirror server exited:" >&2; cat "$work/server.log" >&2; exit 1; }
  port=$(sed -n 's/.* port \([0-9][0-9]*\) .*/\1/p' "$work/server.log" | head -n 1)
  [ -n "$port" ] && curl -fsS "http://127.0.0.1:$port/revocation/manifest.json" >/dev/null 2>&1 && break
  port=""
  sleep 1
done
[ -n "$port" ] || { echo "the local mirror server did not answer" >&2; exit 1; }
printf 'cache-dir = "%s"\n[revocation]\nfetch-url = "http://127.0.0.1:%s/revocation/"\n' "$work/cache" "$port" > "$work/config.toml"
"$upki" --config-file "$work/config.toml" fetch
[ -f "$work/cache/revocation/index.bin" ] || { echo "upki wrote no index.bin" >&2; exit 1; }

mkdir -p "$out"
cp "$work/cache/revocation/index.bin" "$out/upki-index.bin"
{
  # REUSE-IgnoreStart (the golden's own header, written out; not this script's)
  echo "# SPDX-FileCopyrightText: 2026 revokt contributors"
  echo "# SPDX-License-Identifier: Apache-2.0"
  # REUSE-IgnoreEnd
  echo "# upki-index.bin: written by rustls/upki $tag's \`upki fetch\` (native/revokt-oracle/record-upki-index.sh) from a local"
  echo "# mirror of these filters, in this order. Columns: mirror filename, source, SHA-256."
  printf '%s' "$order"
} > "$out/upki-index.tsv"
echo "wrote $out/upki-index.bin ($(wc -c < "$out/upki-index.bin" | tr -d ' ') bytes) from upki $tag"
