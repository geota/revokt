# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Write the ClusterFuzzLite fuzz targets into $OUT (.clusterfuzzlite/build.sh, #119; spec §9.1, CONTRIBUTING §6).

Input: build/fuzz/targets.json (`./gradlew fuzzTargets`) and each target module's build/cflite/classpath.txt (the
`cfliteClasspath` task of .clusterfuzzlite/classpath.init.gradle.kts). For each selected target, in $OUT:
- `<Class>-<method>`: the launcher ClusterFuzzLite runs, OSS-Fuzz's JVM launcher shape: Jazzer's driver from
  base-builder-jvm (`jazzer_driver` and `jazzer_agent_deploy.jar`, which OSS-Fuzz's `compile` copies into $OUT) on the
  bundled JDK in $OUT/jdk, the target's static `fuzzerTestOneInput`, `--jvm_args=-Xmx256m` (§9.1) and the libFuzzer
  arguments ClusterFuzzLite passes. ClusterFuzzLite takes a target name of [A-Za-z0-9_-] only, so `Class.method`
  becomes `Class-method` (a Kotlin name has no `-`, so the mapping is one to one);
- `<Class>-<method>.options`: §9.1's `-max_len` (the target's cap + 1), `-timeout` and `-rss_limit_mb=1024`;
- `<Class>-<method>_seed_corpus.zip`: the target's committed inputs (src/jvmTest/resources/<package>/<Class>Inputs/),
  when it has any;
- the classpath under $OUT/cp: each module's class and resource directories, and one copy of each jar. Jazzer's own
  jars (`jazzer-*.jar`, the Gradle build's Jazzer for JUnit) are left out, as the base image's driver brings its own.
A target whose source names no `-max_len` is a build error (§9.1), as is a name or path outside the expected
characters. With --coverage, each target module's main classes and Kotlin sources are also copied under $OUT/$SRC,
where OSS-Fuzz's `coverage` script looks for them (it reads sources from directories named `java`).

Python 3.10 or later, standard library only. Usage:
  cflite_build.py --root <repo> --out <$OUT> [--src <$SRC>] [--target all|Class.method] [--coverage]
"""
import argparse
import filecmp
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

NAME = re.compile(r"[A-Za-z0-9_]+\.[A-Za-z0-9_]+")
CLASS = re.compile(r"[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*")
MODULE = re.compile(r"[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*")
JAR = re.compile(r"[A-Za-z0-9._+-]+\.jar")
JAZZER_JAR = re.compile(r"jazzer(-[a-z]+)*-[0-9][A-Za-z0-9.+-]*\.jar")
RSS_LIMIT_MB = 1024
XMX = "-Xmx256m"
INSTRUMENT = "dev.revokt.**"
MAIN_CLASSES = "build/classes/kotlin/jvm/main"
MAIN_SOURCES = ("commonMain", "jvmMain")


class BuildError(Exception):
    """A target or classpath this build cannot turn into a fuzz target."""


def binary_name(name: str) -> str:
    """`Class.method` as a ClusterFuzzLite target name."""
    return name.replace(".", "-")


def load_targets(path: Path, selected: str) -> list[dict]:
    """The targets to build: all of them, or the one named; each checked before anything is written."""
    targets = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(targets, list):
        raise BuildError(f"{path}: not a JSON list")
    if selected not in ("", "all"):
        targets = [t for t in targets if isinstance(t, dict) and t.get("name") == selected]
        if not targets:
            raise BuildError(f"no fuzz target named {selected}")
    if not targets:
        raise BuildError("fuzzTargets lists no target")
    problems = []
    for t in targets:
        name = t.get("name") if isinstance(t, dict) else None
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise BuildError("a target whose name is not Class.method")
        if not isinstance(t.get("class"), str) or not CLASS.fullmatch(t["class"]):
            raise BuildError(f"{name}: a class name outside [A-Za-z0-9_.]")
        if not isinstance(t.get("module"), str) or not MODULE.fullmatch(t["module"]):
            raise BuildError(f"{name}: a module path outside [A-Za-z0-9_/-]")
        timeout = t.get("timeout")
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 25:
            raise BuildError(f"{name}: a -timeout outside 1 to 25 s (ClusterFuzzLite caps it at 25)")
        max_len = t.get("maxLen")
        if max_len is None:
            problems.append(f"{name} ({t.get('source')}) names no -max_len; spec §9.1 runs each target at its cap + 1")
        elif not isinstance(max_len, int) or isinstance(max_len, bool) or max_len < 1:
            raise BuildError(f"{name}: a -max_len that is not a positive whole number")
    if problems:
        raise BuildError("; ".join(problems))
    return targets


def options(target: dict) -> str:
    return (f"[libfuzzer]\nmax_len = {target['maxLen']}\ntimeout = {target['timeout']}\n"
            f"rss_limit_mb = {RSS_LIMIT_MB}\n")


def launcher(target: dict, classpath: list[str]) -> str:
    """The launcher script; classpath entries are relative to $OUT."""
    cp = ":".join(f"$this_dir/{entry}" for entry in classpath)
    return "\n".join([
        "#!/bin/bash",
        "# LLVMFuzzerTestOneInput: ClusterFuzzLite finds a fuzz target by this string.",
        f"# {target['name']} ({target.get('source')}), written by .github/scripts/cflite_build.py (#119): OSS-Fuzz's",
        "# Jazzer driver on the bundled JDK, with spec §9.1's heap; the .options file holds -max_len, -timeout and",
        "# -rss_limit_mb.",
        'this_dir=$(dirname "$0")',
        "# Some test classes on the classpath have non-ASCII names, which the POSIX locale cannot map.",
        "export LANG=C.UTF-8 LC_ALL=C.UTF-8",
        'export JAVA_HOME="$this_dir/jdk"',
        'LD_LIBRARY_PATH="$this_dir/jdk/lib/server:$this_dir" exec "$this_dir/jazzer_driver" \\',
        '  --agent_path="$this_dir/jazzer_agent_deploy.jar" \\',
        f'  --cp="{cp}" \\',
        f"  --target_class={target['class']} \\",
        f"  '--instrumentation_includes={INSTRUMENT}' \\",
        f"  --jvm_args={XMX} \\",
        '  "$@"',
        "",
    ])


def stage_classpath(root: Path, out: Path, module: str, staged_jars: dict[str, Path]) -> list[str]:
    """Copies one module's classpath under $OUT/cp; returns its entries relative to $OUT, in classpath order."""
    listing = root / module / "build/cflite/classpath.txt"
    if not listing.is_file():
        raise BuildError(f"{module}: no build/cflite/classpath.txt (the cfliteClasspath task did not run)")
    entries = []
    n = 0
    for line in listing.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        path = Path(line)
        if path.is_dir():
            n += 1
            rel = f"cp/{module}/{n}"
            shutil.copytree(path, out / rel, dirs_exist_ok=False)
            entries.append(rel)
        elif path.is_file() and path.suffix == ".jar":
            if not JAR.fullmatch(path.name):
                raise BuildError(f"{module}: a jar name outside [A-Za-z0-9._+-]")
            if JAZZER_JAR.fullmatch(path.name):
                continue
            rel = f"cp/lib/{path.name}"
            seen = staged_jars.get(path.name)
            if seen is None:
                (out / "cp/lib").mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, out / rel)
                staged_jars[path.name] = path
            elif seen != path and not filecmp.cmp(seen, path, shallow=False):
                raise BuildError(f"two different jars named {path.name} on the classpath")
            entries.append(rel)
        elif path.exists():
            raise BuildError(f"{module}: a classpath entry that is neither a directory nor a jar")
        # A listed directory the build did not create (a source set without resources) is skipped.
    return entries


def seed_corpus(root: Path, target: dict, dest: Path) -> int:
    """Zips the target's committed inputs; returns the number of files (0 writes nothing)."""
    package = target["class"].rsplit(".", 1)[0].replace(".", "/") if "." in target["class"] else ""
    simple = target["class"].rsplit(".", 1)[-1]
    inputs = root / target["module"] / "src/jvmTest/resources" / package / f"{simple}Inputs"
    files = sorted(p for p in inputs.rglob("*") if p.is_file()) if inputs.is_dir() else []
    if files:
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
            for i, f in enumerate(files):
                z.write(f, f"{i:04d}")
    return len(files)


def copy_coverage_sources(root: Path, out: Path, src: str, module: str) -> None:
    """Main classes and Kotlin sources where OSS-Fuzz's `coverage` script finds them (under $OUT/$SRC)."""
    base = out / src.lstrip("/") / "revokt" / module
    classes = root / module / MAIN_CLASSES
    if not classes.is_dir():
        raise BuildError(f"{module}: no {MAIN_CLASSES} for the coverage report")
    shutil.copytree(classes, base / "classes", dirs_exist_ok=True)
    for source_set in MAIN_SOURCES:
        kotlin = root / module / "src" / source_set / "kotlin"
        if kotlin.is_dir():
            shutil.copytree(kotlin, base / "src" / source_set / "java", dirs_exist_ok=True)


def build(root: Path, out: Path, src: str, selected: str, coverage: bool) -> list[str]:
    targets = load_targets(root / "build/fuzz/targets.json", selected)
    for name in ("jazzer_driver", "jazzer_agent_deploy.jar", "jdk/lib/server/libjvm.so"):
        if not (out / name).exists():
            raise BuildError(f"$OUT has no {name}")
    staged_jars: dict[str, Path] = {}
    module_classpath: dict[str, list[str]] = {}
    written = []
    for t in targets:
        module = t["module"]
        if module not in module_classpath:
            module_classpath[module] = stage_classpath(root, out, module, staged_jars)
            if coverage:
                copy_coverage_sources(root, out, src, module)
        binary = binary_name(t["name"])
        script = out / binary
        script.write_text(launcher(t, module_classpath[module]), encoding="utf-8")
        script.chmod(0o755)
        (out / f"{binary}.options").write_text(options(t), encoding="utf-8")
        seeds = seed_corpus(root, t, out / f"{binary}_seed_corpus.zip")
        written.append(f"{binary}: -max_len={t['maxLen']} -timeout={t['timeout']}, {seeds} seed inputs")
    return written


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--src", default="/src")
    parser.add_argument("--target", default="all")
    parser.add_argument("--coverage", action="store_true")
    args = parser.parse_args(argv)
    try:
        for line in build(args.root, args.out, args.src, args.target, args.coverage):
            print(line)
    except BuildError as e:
        print(f"cflite_build: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
