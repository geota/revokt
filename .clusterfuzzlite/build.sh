#!/bin/bash
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# ClusterFuzzLite build (#119; spec §9.1, CONTRIBUTING §6), run by OSS-Fuzz's `compile` in the builder image
# (.clusterfuzzlite/Dockerfile) with $SRC, $OUT and $SANITIZER set. Gradle runs on the image's JDK 21 (the build JDK)
# and compiles the jvmTest sources; `fuzzTargets` lists the @FuzzTest methods with their §9.1 flags, as for fuzz.yml.
# .github/scripts/cflite_build.py then writes one launcher, .options file and seed corpus per target into $OUT, with
# the image's JDK 25 copied to $OUT/jdk to run them. $CFL_EXTRA_TARGET (Class.method, passed through by
# ClusterFuzzLite) builds that target alone; unset or `all` builds every target. A target without a -max_len fails the
# build.
set -euo pipefail

cd "$SRC/revokt"
# Some test classes have non-ASCII names (Kotlin backticked test names); the image's POSIX locale cannot map them.
export LANG=C.UTF-8 LC_ALL=C.UTF-8
export JAVA_HOME=/opt/jdk-21
export PATH="$JAVA_HOME/bin:$PATH"
target=${CFL_EXTRA_TARGET:-all}
case $target in *[!A-Za-z0-9_.]*) echo "build.sh: CFL_EXTRA_TARGET must be all or Class.method" >&2; exit 1 ;; esac

./gradlew --no-daemon --no-configuration-cache --console=plain \
  --init-script .clusterfuzzlite/classpath.init.gradle.kts \
  -Porg.gradle.java.installations.paths=/opt/jdk-21,/opt/jdk-25 \
  fuzzTargets cfliteClasspath < /dev/null

rm -rf "${OUT:?}/jdk"
cp -a /opt/jdk-25 "$OUT/jdk"

coverage=()
if [ "$SANITIZER" = "coverage" ]; then coverage=(--coverage); fi
python3 .github/scripts/cflite_build.py --root "$PWD" --out "$OUT" --src "$SRC" --target "$target" "${coverage[@]}"
