# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
#
# The ClusterFuzzLite builder image (#119; spec §9.1, CONTRIBUTING §6): OSS-Fuzz's JVM builder, pinned by digest, which
# brings Jazzer's driver (OSS-Fuzz's build of Jazzer 0.26.0), plus two Temurin JDKs pinned by SHA-256 from Adoptium's
# release API: 21 runs Gradle (the build JDK) and 25 runs the fuzz targets (spec §9.2 "Tiers and matrix": one pinned
# JDK >= 22, as fuzz.yml). The repository is copied in; build.sh builds it.
FROM gcr.io/oss-fuzz-base/base-builder-jvm@sha256:bd13a763de1a0fb22099442094e7e0049657a8c47f01e9d7af8bb849e0ad4699

RUN set -eu; \
    curl -fsSL --retry 3 -o /tmp/jdk.tar.gz \
      https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_9.tar.gz; \
    echo "d7f5d5cf865a2902b70ff549b97586a7d3f234e016f041ab447ea740c7d66d1c  /tmp/jdk.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/jdk-21; \
    tar -xzf /tmp/jdk.tar.gz --strip-components=1 -C /opt/jdk-21; \
    rm -rf /tmp/jdk.tar.gz /opt/jdk-21/jmods /opt/jdk-21/lib/src.zip

RUN set -eu; \
    curl -fsSL --retry 3 -o /tmp/jdk.tar.gz \
      https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_linux_hotspot_25.0.5_8.tar.gz; \
    echo "68982529869257d0ee6b824ec5aa270ff8b118bb438670da0b97ebdab178d7fb  /tmp/jdk.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/jdk-25; \
    tar -xzf /tmp/jdk.tar.gz --strip-components=1 -C /opt/jdk-25; \
    rm -rf /tmp/jdk.tar.gz /opt/jdk-25/jmods /opt/jdk-25/lib/src.zip

COPY . $SRC/revokt
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/revokt
