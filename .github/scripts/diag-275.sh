#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
# Temporary #275 diagnostic: what the restored Gradle home holds for build-logic's classpath, and whether it resolves offline.
set +e
c="$HOME/.gradle/caches/modules-2"
ls "$c" "$c"/metadata-*/
for m in kotlin-gradle-plugin kotlin-gradle-plugins-bom kotlin-sam-with-receiver-compiler-plugin-embeddable kotlin-assignment-compiler-plugin-embeddable; do
  echo "== files $m"; ls -l "$c"/files-2.1/org.jetbrains.kotlin/"$m"/*/ 2>&1 | head -8
  echo "== descriptors $m"; find "$c"/metadata-*/descriptors/org.jetbrains.kotlin/"$m" 2>&1 | head -12
done
log="$RUNNER_TEMP/diag-offline.log"
./gradlew --offline --no-configuration-cache --debug -m "$@" --no-daemon >| "$log" 2>&1
echo "offline dry run exit: $?"
grep -E "kotlin-(gradle-plugin|gradle-plugins-bom|sam-with-receiver-compiler-plugin-embeddable|assignment-compiler-plugin-embeddable):2\.4\.21" "$log" \
  | sed -E 's/^[0-9:.T+-]+ \[[A-Z]+\] \[[^]]*\] //' | sort | uniq -c | sort -rn | head -60
grep -E "What went wrong|Could not|BUILD (SUCCESSFUL|FAILED)" "$log" | sed -E 's/^[0-9:.T+-]+ \[[A-Z]+\] \[[^]]*\] //' | head -30
exit 0
