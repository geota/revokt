# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# fuzz.yml (#115): the uid boundary that keeps the fuzzed tree's code away from the advisory token, checked before any of
# that code runs. It runs twice, and the job fails unless both pass.
#
# As the fuzzing user ("user" mode), with the kernel deciding each access:
# - the user is not root, is in no group but its own, and cannot use sudo;
# - it can write none of the paths given (the step's file commands, the runner-owned checkout, the runner user's
#   temporary directory), nothing under the runner user's home, and not the Docker socket;
# - the PATH checks below.
#
# As root ("root" mode), only the PATH checks. Root walks the paths and links, so it sees into the directories the user
# cannot search (such as a runner home of mode 750) and follows the links there, which the runner user follows too; but
# every judgement is still the kernel's, asked as the user (setpriv with its uid and gid and no other group), so ACLs
# count.
#
# In both modes, "writable by the user" means: the kernel grants the user write access (mode bits and ACLs), or the
# user's uid owns it (the owner can chmod it), or it cannot be stat'ed (fail closed).
#
# The PATH checks, for the runner user's PATH as the actions' post steps see it:
# - each entry is resolved the way the kernel resolves it, one component and one link at a time; no directory that
#   passes through, and no regular file or directory it ends at, may be writable (a device such as /dev/null may be);
# - then the whole tree each entry belongs to (the entry without a trailing /bin) is checked, and so is the tree of
#   every link target in it, until no link leads anywhere new. In a tree, as the user: nothing may be writable, nothing
#   may be owned by the user, and no directory may be one the user can enter but not list (it could hide a writable
#   path); a directory the user can neither list nor enter hides nothing it can reach;
# - a link that cannot be read, more than 40 links in one resolution, and a relative PATH entry fail the check.
#
# It exits 0 only when every check holds; otherwise it prints an ::error:: for the first that fails and exits 1.
#
# Usage, from the runner user, with the script on stdin so neither needs read access to the checkout:
#   sudo -u <user> -- /usr/bin/env -i PATH=/usr/bin:/bin /bin/bash -s -- user <user> <runner home> <runner PATH> \
#     <path>... < this file
#   sudo -- /usr/bin/env -i PATH=/usr/bin:/bin /bin/bash -s -- root <user> <runner PATH> < this file
# shellcheck shell=bash
set -euo pipefail

mode=${1:?user or root}
user=${2:?the fuzzing user}
case $mode in
  user)
    runner_home=${3:?the runner user home}
    runner_path=${4:?the runner user PATH}
    shift 4
    ;;
  root)
    runner_path=${3:?the runner user PATH}
    shift 3
    ;;
  *) echo "::error::fuzz_isolation_check.sh: unknown mode $mode" >&2; exit 1 ;;
esac
uid=$(id -u -- "$user")
gid=$(id -g -- "$user")
# The prefix that asks the kernel as the user: nothing in user mode; setpriv as root.
as_user=()
if [ "$mode" = root ]; then
  as_user=(setpriv "--reuid=$uid" "--regid=$gid" --clear-groups --)
fi

# Errors go to fd 3, the script's stdout, so one raised inside $(...) is still printed; the subshell's exit 1 then
# fails the assignment, and set -e the script.
exec 3>&1
fail() {
  echo "::error::the fuzzing user $*; nothing of the fuzzed tree runs" >&3
  exit 1
}

if [ "$mode" = root ]; then
  # A setpriv that does not switch would make every answer root's; fail unless it does.
  [ "$("${as_user[@]}" id -u 2> /dev/null || true)" = "$uid" ] || fail "cannot be checked: setpriv does not run as uid $uid"
fi

# Whether the user can write $1 (not a link): its uid owns it, the kernel grants it write access, or it cannot be
# stat'ed.
writable() {
  local owner
  owner=$(stat -c %u -- "$1" 2> /dev/null) || return 0
  [ "$owner" != "$uid" ] || return 0
  "${as_user[@]}" test -w "$1"
}

if [ "$mode" = user ]; then
  [ "$(id -un)" = "$user" ] || fail "check runs as $(id -un), not $user"
  [ "$(id -u)" -ne 0 ] || fail "is root"
  [ "$(id -Gn)" = "$user" ] || fail "is in groups other than its own: $(id -Gn)"
  # -n: fail at once instead of asking for a password. A missing sudo counts as no sudo.
  if sudo -n true > /dev/null 2>&1; then fail "can use sudo"; fi

  # A path that does not exist (the Docker socket may not) is covered by its directory, which is in the list.
  for path in "$@" /var/run/docker.sock; do
    if [ -e "$path" ] && writable "$path"; then fail "can write or owns $path"; fi
  done
  # Whatever the user cannot reach, it cannot write either, so find's permission errors are not failures.
  hit=$(find "$runner_home" \( -writable -o -uid "$uid" \) -print -quit 2> /dev/null || true)
  [ -z "$hit" ] || fail "can write or owns $hit"
fi

# Resolves $1 as the kernel does: one component at a time, following each link one hop at a time (at most 40). Fails
# if the user can write a directory the resolution passes through, or the regular file or directory it ends at, or if
# a link cannot be read. Sets resolved to where it ends, which may not exist (a variable, not output, so that a
# failure exits the script itself). In user mode, a component the user cannot inspect reads as a plain missing name;
# root mode resolves it.
resolved=""
# Directories and files already found not writable; most resolutions share their first components.
declare -A checked=()
resolve() {
  local rest=$1 from=$2 cur=/ comp next target links=0
  if writable /; then fail "can write /"; fi
  while [ -n "$rest" ]; do
    comp=${rest%%/*}
    if [ "$comp" = "$rest" ]; then rest=""; else rest=${rest#*/}; fi
    case $comp in
      '' | .) continue ;;
      ..) cur=${cur%/*}; cur=${cur:-/}; continue ;;
    esac
    next=${cur%/}/$comp
    if [ -L "$next" ]; then
      links=$((links + 1))
      [ "$links" -le 40 ] || fail "cannot be checked: more than 40 links resolving $1, from $from"
      target=$(readlink -- "$next") || fail "cannot be checked: the link $next cannot be read, from $from"
      [ -n "$target" ] || fail "cannot be checked: the link $next is empty, from $from"
      case $target in /*) cur=/ ;; esac
      rest=$target${rest:+/$rest}
      continue
    fi
    cur=$next
    if [ -z "${checked[$cur]:-}" ]; then
      if [ -d "$cur" ] && writable "$cur"; then fail "can write $cur, reached from $from"; fi
      checked[$cur]=1
    fi
  done
  if [ -z "${checked[$cur]:-}" ]; then
    if [ -f "$cur" ] && writable "$cur"; then fail "can write $cur, reached from $from"; fi
    checked[$cur]=1
  fi
  resolved=$cur
}

trees=()
inside_trees() {
  local t
  for t in "${trees[@]}"; do
    case $1 in "$t" | "$t"/*) return 0 ;; esac
  done
  return 1
}
# The tree a resolved path belongs to: the directory itself, or a file's directory, without a trailing /bin. A device,
# a socket or a missing path adds no tree; resolve has checked the directories leading to it.
add_tree_of() {
  local tree
  if [ -d "$1" ]; then tree=$1; elif [ -f "$1" ]; then tree=${1%/*}; else return 0; fi
  tree=${tree:-/}
  if [ "$tree" != /bin ] && [ -n "${tree%/bin}" ]; then tree=${tree%/bin}; fi
  if ! inside_trees "$tree"; then trees+=("$tree"); fi
}
# The first path in the tree $1, found by find as the user, that the user can write (links are left to the caller), that
# its uid owns, or that is a directory it can enter but not list. find's errors are the directories it can neither list
# nor enter, which hide nothing the user can reach.
first_writable() {
  "${as_user[@]}" find "$1" \( \( ! -type l -writable \) -o -uid "$uid" -o \( -type d ! -readable -executable \) \) \
    -print -quit 2> /dev/null || true
}

IFS=: read -r -a entries <<< "$runner_path"
for entry in "${entries[@]}"; do
  case $entry in
    /*) ;;
    *) echo "::error::the runner's PATH has a relative or empty entry ('$entry'); nothing of the fuzzed tree runs" >&3; exit 1 ;;
  esac
  resolve "$entry" "the runner's PATH entry $entry"
  add_tree_of "$resolved"
done
# A worklist: checking a tree can add the trees its links lead to.
i=0
while [ "$i" -lt "${#trees[@]}" ]; do
  tree=${trees[$i]}
  i=$((i + 1))
  resolve "$tree" "the tree $tree"
  hit=$(first_writable "$tree")
  [ -z "$hit" ] || fail "can write, owns, or can enter without listing $hit, in the tree $tree of the runner's PATH ($mode check)"
  # Every link is resolved hop by hop from its own path, never judged by its target string (a target such as
  # ../lnk/../x reads as inside a tree when lnk leads elsewhere); the tree it ends in joins the list unless the resolved
  # path is already inside one.
  while IFS= read -r -d '' link; do
    resolve "$link" "the link $link in the tree $tree"
    add_tree_of "$resolved"
  done < <(find "$tree" -type l -print0 2> /dev/null || true)
done

if [ "$mode" = user ]; then
  echo "the fuzzing user $user (uid $(id -u)) has no sudo and cannot write the runner user's files or PATH (${#trees[@]} trees)"
else
  echo "the fuzzing user $user cannot write the runner's PATH, walked as root and asked as the user (${#trees[@]} trees)"
fi
