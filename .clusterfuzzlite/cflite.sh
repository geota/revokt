#!/bin/bash
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# The ClusterFuzzLite steps of cflite_batch.yml and cflite_cron.yml (#119; spec §9.1, CONTRIBUTING §6), one subcommand
# per step. ClusterFuzzLite's build_fuzzers and run_fuzzers images run here by digest, in its `standalone` platform with
# the `filesystem` filestore, instead of through the google/clusterfuzzlite actions, because on GitHub those actions
# publish on their own: the job log gets every fuzzer log (libFuzzer prints a crashing input of up to 256 bytes, and
# Jazzer's stack trace can quote it), crashes are uploaded as public `crashes-*` artifacts even with a storage
# repository, and the images are tag-pinned (`:v1`) under a SHA-pinned action. Here:
# - the build log is public (it runs Gradle and build.sh only; the bad-build check, which runs each target, is off);
# - the run log is private: it goes to $CFL_WORK/private, the public log gets the exit status and libFuzzer's
#   `Done <n> runs` line, and a finding or an error is sealed with age to FUZZ_AGE_RECIPIENT before any upload;
# - nothing in the ClusterFuzzLite containers holds a token or talks to GitHub: the corpus and the coverage report
#   live in the private storage repository, which only `clone` and `push` touch, with CFL_CORPUS_TOKEN from their
#   own step's environment (a credential helper reads it, so it is in no command's arguments).
# The filestore's layout (corpus/<target>, coverage/latest) is ClusterFuzzLite's git filestore's, so the storage
# repository reads the same as one the actions would write.
#
# Environment: CFL_WORK (an empty directory; default $RUNNER_TEMP/cflite), BUILD_IMAGE and RUN_IMAGE (the images by digest), CORPUS_REPO
# (owner/name), and per subcommand CFL_CORPUS_TOKEN, RECIPIENT, GITHUB_WORKSPACE, GITHUB_RUN_ID.
set -euo pipefail

work=${CFL_WORK:-${RUNNER_TEMP:?}/cflite}
ws=$work/workspace
store=$work/filestore
private=$work/private
sealed=$work/sealed

die() {
  echo "::error::$*"
  exit 1
}

# git with CFL_CORPUS_TOKEN from the environment; the helper's text holds the variable's name, not its value.
git_auth() {
  : "${CFL_CORPUS_TOKEN:?the CFL_CORPUS_TOKEN repository secret is unset (CONTRIBUTING §6)}"
  # shellcheck disable=SC2016 # expanded by the helper's shell, not here
  git -c credential.helper= \
    -c 'credential.helper=!f() { test "$1" = get && printf "username=x-access-token\npassword=%s\n" "$CFL_CORPUS_TOKEN"; }; f' \
    "$@"
}

# The ClusterFuzzLite build and run containers see the checkout, the workspace and the filestore at their own paths,
# so the builder container they start (--volumes-from) sees the same.
mounts() {
  printf '%s\n' -v "${GITHUB_WORKSPACE:?}:$GITHUB_WORKSPACE" -v "$ws:$ws" -v "$store:$store"
}

common_env() {
  printf '%s\n' -e CFL_PLATFORM=standalone -e "WORKSPACE=$ws" -e "PROJECT_SRC_PATH=$GITHUB_WORKSPACE" \
    -e REPOSITORY=revokt -e FILESTORE=filesystem -e "FILESTORE_ROOT_DIR=$store" -e LANGUAGE=jvm \
    -e LOW_DISK_SPACE=false -e DRY_RUN=false
}

# prepare: the directories, in a CFL_WORK that is new or empty.
cmd_prepare() {
  mkdir -p "$work"
  if [ -n "$(ls -A "$work")" ]; then die "$work is not empty"; fi
  mkdir -p "$ws" "$store/corpus" "$sealed"
  mkdir -m 700 "$private"
}

# clone <branch> <dir> [<path>...]: a blobless, sparse clone of the storage repository's branch (an orphan branch if it
# does not exist yet), with only the given paths checked out.
cmd_clone() {
  local branch=${1:?} dir=${2:?}
  shift 2
  git_auth clone --quiet --filter=blob:none --no-checkout "https://github.com/${CORPUS_REPO:?}.git" "$dir"
  git -C "$dir" sparse-checkout set --no-cone "${@:-/README.md}"
  if git -C "$dir" rev-parse --verify --quiet "refs/remotes/origin/$branch" > /dev/null; then
    git_auth -C "$dir" checkout --quiet -B "$branch" "origin/$branch"
  else
    echo "the storage repository has no $branch branch yet; this run starts it"
    git -C "$dir" checkout --quiet --orphan "$branch"
  fi
}

# build <sanitizer> <target>: ClusterFuzzLite's build_fuzzers (OSS-Fuzz's `compile`, .clusterfuzzlite/build.sh) into
# the workspace's build-out.
cmd_build() {
  local sanitizer=${1:?} target=${2:?}
  local -a args
  mapfile -t args < <(mounts; common_env)
  # The build's lines are not workflow commands: the runner ignores commands until the random end token.
  local stop status=0
  stop=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  echo "::stop-commands::$stop"
  docker run --rm --name cflite-build -v /var/run/docker.sock:/var/run/docker.sock "${args[@]}" \
    -e CFL_CONTAINER_ID=cflite-build -e "SANITIZER=$sanitizer" -e BAD_BUILD_CHECK=false -e UPLOAD_BUILD=false \
    -e KEEP_UNAFFECTED_FUZZ_TARGETS=true -e "CFL_EXTRA_TARGET=$target" "${BUILD_IMAGE:?}" < /dev/null || status=$?
  echo "::$stop::"
  if [ "$status" -ne 0 ]; then die "the ClusterFuzzLite build failed (exit $status); its log is above"; fi
}

# run <mode> <sanitizer> <seconds>: ClusterFuzzLite's run_fuzzers. Its output stays in $private/run.log; the exit status
# is ClusterFuzzLite's (0 nothing found, 2 a finding, other an error), and `status=` goes to $GITHUB_OUTPUT.
cmd_run() {
  local mode=${1:?} sanitizer=${2:?} seconds=${3:?}
  local -a args
  mapfile -t args < <(mounts; common_env)
  local status=0
  docker run --rm --name cflite-run "${args[@]}" -e "MODE=$mode" -e "SANITIZER=$sanitizer" \
    -e "FUZZ_SECONDS=$seconds" -e REPORT_TIMEOUTS=true -e REPORT_OOMS=true -e MINIMIZE_CRASHES=true \
    -e REPORT_UNREPRODUCIBLE_CRASHES=false -e PARALLEL_FUZZING=false -e OUTPUT_SARIF=false "${RUN_IMAGE:?}" \
    < /dev/null > "$private/run.log" 2>&1 || status=$?
  grep -E '^Done [0-9]+ runs in [0-9]+ second' "$private/run.log" || true
  echo "status=$status" >> "${GITHUB_OUTPUT:?}"
  case $status in
    0) echo "ClusterFuzzLite $mode: done, nothing found" ;;
    2) echo "::error::ClusterFuzzLite $mode: a finding; it is sealed to the maintainer's age key (CONTRIBUTING §6)" ;;
    *) echo "::error::ClusterFuzzLite $mode: an error (exit $status); its log is sealed to the maintainer's age key" ;;
  esac
  return "$status"
}

# corpus-in <corpus clone> <target>...: each target's stored corpus into the filestore.
cmd_corpus_in() {
  local clone=${1:?} t
  shift
  for t in "$@"; do
    mkdir -p "$store/corpus/$t"
    if [ -d "$clone/corpus/$t" ]; then cp -R "$clone/corpus/$t/." "$store/corpus/$t/"; fi
    echo "$t: $(find "$store/corpus/$t" -type f | wc -l) corpus inputs in"
  done
}

# corpus-out <corpus clone> <target>...: each target's filestore corpus (batch adds to it, prune replaces it) back into
# the clone; an empty one leaves the stored corpus as it is.
cmd_corpus_out() {
  local clone=${1:?} t
  shift
  for t in "$@"; do
    if [ -z "$(find "$store/corpus/$t" -type f -print -quit 2> /dev/null)" ]; then
      echo "$t: no corpus out; the stored one is kept"
      continue
    fi
    rm -rf -- "${clone:?}/corpus/$t"
    mkdir -p "$clone/corpus"
    cp -R "$store/corpus/$t" "$clone/corpus/$t"
    echo "$t: $(find "$clone/corpus/$t" -type f | wc -l) corpus inputs out"
  done
}

# push <clone> <branch> <message>: commits the clone's checked-out paths and pushes, rebasing on a concurrent push
# (each job writes only its own targets' directories, so a rebase does not conflict).
cmd_push() {
  local clone=${1:?} branch=${2:?} message=${3:?} i
  git -C "$clone" add -A
  if git -C "$clone" diff --cached --quiet; then
    echo "nothing new for $branch"
    return 0
  fi
  git -C "$clone" -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit --quiet -m "$message"
  for i in 1 2 3 4 5; do
    if git_auth -C "$clone" push --quiet origin "HEAD:refs/heads/$branch"; then
      echo "pushed to $branch"
      return 0
    fi
    sleep $((i * 5))
    git_auth -C "$clone" fetch --quiet origin "$branch"
    git -C "$clone" -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
      rebase --quiet "origin/$branch"
  done
  die "could not push to the storage repository's $branch branch"
}

# seal <files...>: one gzipped tar of the files (named by their base names), age-armoured to RECIPIENT, into $sealed;
# prints the sealed file's name.
seal_files() {
  local name=${1:?}
  shift
  local stage
  stage=$(mktemp -d "$private/stage.XXXXXX")
  local f
  for f in "$@"; do
    if [ -f "$f" ]; then cat < "$f" > "$stage/${f##*/}"; fi
  done
  tar -C "$stage" -czf - . | age -a -r "${RECIPIENT:?}" -o "$sealed/$name"
  rm -rf -- "${stage:?}"
}

# seal-finding <Class.method> <module> <target> <sanitizer>: each reproducer ClusterFuzzLite saved (at most 8) with its
# minimised form, its stack trace and the run log's last 64 KiB, sealed one file each, and the manifest
# fuzz_advisory.py reads (the same as fuzz.yml's). libFuzzer names a reproducer by the input's SHA-1, which gives a
# short input away, so no name reaches an argument or a log: each one is read through a redirection, as input,
# minimised and stacktrace. `dir=` goes to $GITHUB_OUTPUT.
cmd_seal_finding() {
  local name=${1:?} module=${2:?} target=${3:?} sanitizer=${4:?}
  local dir=$ws/out/artifacts/$target/$sanitizer f n=0 token
  tail -c 65536 "$private/run.log" > "$private/run-tail.log"
  local -a files=()
  for f in "$dir"/*; do
    [ -f "$f" ] || continue
    case $f in *.summary|*-minimized) continue ;; esac
    [ "$n" -lt 8 ] || break
    n=$((n + 1))
    cat < "$f" > "$private/input"
    rm -f "$private/minimised" "$private/stacktrace"
    if [ -f "$f-minimized" ]; then cat < "$f-minimized" > "$private/minimised"; fi
    if [ -f "$f.summary" ]; then head -c 65536 < "$f.summary" > "$private/stacktrace"; fi
    seal_files "finding-$n.tar.age" "$private/input" "$private/minimised" "$private/stacktrace" "$private/run-tail.log"
    files+=("finding-$n.tar.age")
  done
  if [ "$n" -eq 0 ]; then
    # ClusterFuzzLite reported a finding without a reproducer: the log alone.
    n=1
    seal_files finding-1.tar.age "$private/run-tail.log"
    files=(finding-1.tar.age)
  fi
  token=$(cat "$dir"/*.summary "$private/run.log" 2> /dev/null | grep -oE 'DEDUP_TOKEN: [0-9a-f]{8,64}' | head -n 1 || true)
  token=${token#DEDUP_TOKEN: }
  # module is a jq keyword, so the key is quoted and the variable named mod.
  jq -n --arg target "$name" --arg mod "$module" --arg hash "$token" \
    '{"target": $target, "module": $mod, "hash": $hash, "files": $ARGS.positional}' --args "${files[@]}" \
    > "$sealed/manifest.json"
  echo "$name: finding ${token:-without a DEDUP_TOKEN}; $n sealed"
  echo "dir=$sealed" >> "${GITHUB_OUTPUT:?}"
}

# seal-log: the private run log (its last 1 MiB), sealed, for a run that ended in an error. `dir=` goes to
# $GITHUB_OUTPUT.
cmd_seal_log() {
  tail -c 1048576 "$private/run.log" > "$private/run-tail.log"
  seal_files log.tar.age "$private/run-tail.log"
  echo "dir=$sealed" >> "${GITHUB_OUTPUT:?}"
}

cmd=${1:?usage: cflite.sh <subcommand> [args]}
shift
case $cmd in
  prepare) cmd_prepare "$@" ;;
  clone) cmd_clone "$@" ;;
  build) cmd_build "$@" ;;
  run) cmd_run "$@" ;;
  corpus-in) cmd_corpus_in "$@" ;;
  corpus-out) cmd_corpus_out "$@" ;;
  push) cmd_push "$@" ;;
  seal-finding) cmd_seal_finding "$@" ;;
  seal-log) cmd_seal_log "$@" ;;
  *) die "cflite.sh: unknown subcommand $cmd" ;;
esac
