#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
# Temporary #275 diagnostic: what the restored Gradle home holds for build-logic's classpath, and whether it resolves offline.
set +e
c="$HOME/.gradle/caches/modules-2"
ls "$c" "$c"/metadata-*/
for m in kotlin-gradle-plugin kotlin-gradle-plugins-bom kotlin-sam-with-receiver kotlin-assignment kotlin-sam-with-receiver-compiler-plugin-embeddable kotlin-assignment-compiler-plugin-embeddable; do
  echo "== files $m"; find "$c"/files-2.1/org.jetbrains.kotlin/"$m"/2.4.21 -type f 2>&1 | head -8
  echo "== descriptors $m"; find "$c"/metadata-*/descriptors/org.jetbrains.kotlin/"$m"/2.4.21 -type f 2>&1 | head -12
done
f="$c/files-2.1"
for ext in jar pom module jar.asc pom.asc module.asc; do
  printf '%-11s %s\n' "$ext" "$(find "$f" -type f -name "*.$ext" | wc -l)"
done
echo "modules with a descriptor: $(find "$c"/metadata-*/descriptors -name descriptor.bin | wc -l)"
echo "versions with a .pom.asc but no .pom: $(find "$f" -name '*.pom.asc' -printf '%h\n' | xargs -r -n1 dirname | sort -u | while read -r v; do ls "$v"/*/*.pom >/dev/null 2>&1 || echo "$v"; done | wc -l)"
echo "versions with a .module.asc but no .module: $(find "$f" -name '*.module.asc' -printf '%h\n' | xargs -r -n1 dirname | sort -u | while read -r v; do ls "$v"/*/*.module >/dev/null 2>&1 || echo "$v"; done | wc -l)"
# A failed Gradle build in the job skips the on-success cleanup, so the offline run is opt-in.
[ -n "${DIAG_OFFLINE:-}" ] || exit 0
log="$RUNNER_TEMP/diag-offline.log"
./gradlew --offline --no-configuration-cache --debug -m "$@" --no-daemon >| "$log" 2>&1
echo "offline dry run exit: $?"
grep -E "kotlin-(gradle-plugin|gradle-plugins-bom|sam-with-receiver|assignment)(-compiler-plugin-embeddable)?:2\.4\.21|offline mode|No cached" "$log" \
  | sed -E 's/^[0-9:.T+-]+ \[[A-Z]+\] \[[^]]*\] //' | sort | uniq -c | sort -rn | head -120
grep -A30 "What went wrong" "$log" | sed -E 's/^[0-9:.T+-]+ \[[A-Z]+\] \[[^]]*\] //' | head -40
exit 0
