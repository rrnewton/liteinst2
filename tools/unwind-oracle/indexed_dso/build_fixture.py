#!/usr/bin/env python3
"""Fixed GNU C fixture build only; no native invocation or semantic admission.

Run under a root-owned outer command after reviewing these exact source bytes.
Toolchain JSON: {tools: {ROLE: canonical_absolute_path}, files: [canonical_path]}.
Roles are gcc/cc1/assembler/collect2/linker/libgcc/helper_python/timeout. Files
must cover every role, compiler runtime/plugin, CRT, header and link input.
Source admission: {schema: "indexed-dso-build-source-v1", base_revision: SHA40,
source_files: {repo_relative_path: SHA256}, review: {path: absolute, sha256: SHA}}.
Its exact eight source entries are SOURCES below. This is a provenance input,
never authority that compiler output, CRT, CFI or an unwinder is qualified.
Only fixed resolution/version probes, three compilations and two links run.
All are owned by the existing bounded_command.py; this is not a supervisor.
"""
import sys
if sys.flags.optimize:
    raise SystemExit("Assertions required")
sys.dont_write_bytecode = True
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import struct
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
HELPER = HERE.parent / "bounded_command.py"
HELPER_SHA = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
CAP = 128 * 1024 * 1024
ROLES = {"gcc", "cc1", "assembler", "collect2", "linker", "libgcc", "helper_python", "timeout"}
SOURCES = [HERE / n for n in ("subject.c", "collector.c", "caller.c", "witness.h",
                            "caller.h", "README.md", "build_fixture.py")] + [HELPER]
CFLAGS = ["-std=gnu11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-fPIC",
          "-fomit-frame-pointer", "-fno-lto", "-fno-optimize-sibling-calls",
          "-fcf-protection=none", "-fno-stack-protector", "-fvisibility=hidden",
          "-fasynchronous-unwind-tables"]
PROBES = [("gcc-version", "gcc", ["--version"]),
          ("assembler-version", "assembler", ["--version"]),
          ("linker-version", "linker", ["--version"])]
RESOLVE = {"cc1": "cc1", "assembler": "as", "collect2": "collect2", "linker": "ld.bfd"}
STAGES = [n for n, _, _ in PROBES] + ["resolve-" + n for n in RESOLVE] + ["resolve-libgcc"]
STAGES += ["compile-" + n for n in ("subject", "collector", "caller")]
STAGES += ["link-subject", "link-caller"]
SUCCESS = b'{"exit": 0, "wall_timeout": false, "absence_proof": "ECHILD", "descendants": 0, "success": true}\n'
LOOKUPS = {}


def capture(path, retain=False, cap=CAP):
    path = Path(path)
    assert path.is_absolute() and path.resolve(strict=True) == path, str(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap, str(path)
        digest, chunks, size = hashlib.sha256(), [], 0
        while True:
            block = os.read(fd, min(512 * 1024, cap + 1 - size))
            if not block:
                break
            size += len(block)
            assert size <= cap, str(path)
            digest.update(block)
            if retain:
                chunks.append(block)
        after = os.fstat(fd)
        fields = lambda s: [s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_mtime_ns, s.st_ctime_ns]
        assert fields(before) == fields(after) == fields(path.lstat())
        assert size == before.st_size
        return dict(path=str(path), bytes=size, sha256=digest.hexdigest(), stat=fields(before)), b"".join(chunks)
    finally:
        os.close(fd)


def pin(path):
    return capture(path)[0]


def raw(path):
    return capture(path, True, 16 * 1024 * 1024)[1]


def unique(pairs):
    value = dict(pairs)
    assert len(value) == len(pairs), "duplicate JSON key"
    return value


def load(path):
    return json.loads(raw(path), object_pairs_hook=unique)


def save(path, value, replace=False):
    target = path.with_name(path.name + ".pending") if replace else path
    with target.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
    if replace:
        os.replace(target, path)


def archive(path, directory):
    row, content = capture(path, True)
    dest = directory / row["sha256"]
    if not dest.exists():
        with dest.open("xb") as stream:
            stream.write(content)
    assert pin(dest)["sha256"] == row["sha256"]
    return dict(original=row, archived=pin(dest))


def check(rows):
    for row in rows:
        assert pin(row["path"]) == row, row["path"]
    for path, row in LOOKUPS.items():
        assert lookup(Path(path)) == row, path


def lookup(path):
    s = path.lstat()
    return dict(resolved=str(path.resolve(strict=True)),
                stat=[s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_mtime_ns, s.st_ctime_ns],
                symlink=os.readlink(path) if stat.S_ISLNK(s.st_mode) else None)


def resolved(value, environment):
    assert value and "\0" not in value
    path = Path(value)
    if not path.is_absolute():
        assert "/" not in value
        found = shutil.which(value, path=environment["PATH"])
        assert found is not None, value
        path = Path(found)
    row = lookup(path)
    assert LOOKUPS.setdefault(str(path), row) == row
    return row["resolved"]


def tool_trace(path, required, environment, tools, bound):
    """Join GCC's retained -v subprocess commands, in addition to its queries."""
    commands, seen, include_search, auxiliary = [], set(), False, set()
    roles = {tools[n]["path"]: n for n in ("cc1", "assembler", "collect2", "linker")}
    for line in raw(path).decode("utf-8").splitlines():
        if line.startswith("Reading specs from "):
            auxiliary.add(line[len("Reading specs from "):])
        if line in ('#include "..." search starts here:', '#include <...> search starts here:'):
            include_search = True
            continue
        if line == "End of search list.":
            include_search = False
            continue
        if include_search:
            continue
        if not line.startswith(" "):
            continue
        words = shlex.split(line)
        if not words or not (words[0].startswith("/") or words[0] in RESOLVE.values()):
            continue
        executable = resolved(words[0], environment)
        assert executable in roles, words[0]
        for index, word in enumerate(words):
            if word == "-plugin":
                assert index + 1 < len(words)
                auxiliary.add(words[index + 1])
            elif word.startswith("-plugin-opt=/"):
                auxiliary.add(word[len("-plugin-opt="):])
        seen.add(roles[executable])
        commands.append(dict(role=roles[executable], argv=words, executable=tools[roles[executable]]))
    assert not include_search and required <= seen, (str(path), required, seen)
    inputs = []
    for value in sorted(auxiliary):
        canonical = str(Path(value).resolve(strict=True))
        assert canonical in bound and pin(canonical) == bound[canonical], value
        inputs.append(bound[canonical])
    return dict(commands=commands, specs_and_plugin_inputs=inputs)


def retained(out):
    """Closed-owner outputs only; never collect from an unresolved child."""
    assert not any((out / "tmp").iterdir()) and not any((out / "home").iterdir())
    result, count = {}, 0
    for directory in (out, out / "sources", out / "inputs"):
        for path in directory.iterdir():
            count += 1
            assert count <= 4096
            if path in {out / n for n in ("sources", "inputs", "tmp", "home", "manifest.json")}:
                continue
            result[str(path.relative_to(out))] = pin(path)
    return result


def run_one(name, argv, out, env, tools, frozen, manifest):
    check(frozen)
    row = next(r for r in manifest["stages"] if r["name"] == name)
    assert row["status"] == "UNRUN"
    qpath, rpath = out / (name + ".request.json"), out / (name + ".receipt.json")
    q = dict(argv=argv, cwd=str(ROOT), env=env, stdout=str(out / (name + ".stdout")),
             stderr=str(out / (name + ".stderr")), cpu_seconds=60, wall_seconds=90, file_bytes=CAP)
    save(qpath, q)
    helper = [tools["timeout"]["path"], "--signal=TERM", "--kill-after=10s", "100s",
              tools["helper_python"]["path"], "-B", str(HELPER), "--request", str(qpath), "--receipt", str(rpath)]
    row.update(status="DISPATCHED_UNRESOLVED", attempts=None, argv=argv, helper_argv=helper, request=pin(qpath))
    save(out / "manifest.json", manifest, True)
    with (out / (name + ".helper.stdout")).open("xb") as so, (out / (name + ".helper.stderr")).open("xb") as se:
        result = subprocess.run(helper, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                stdout=so, stderr=se, timeout=115)
    row.update(status="CLOSED_UNVERIFIED", attempts=1, helper_exit=result.returncode)
    if rpath.exists():
        row["receipt"] = pin(rpath)
        row["owner"] = load(rpath)
    save(out / "manifest.json", manifest, True)
    r = row["owner"]
    assert set(r) == {"request_sha256", "helper_sha256", "exit", "wall_timeout", "unexpected_descendants",
                      "absence_proof", "stdout_sha256", "stderr_sha256", "elapsed_seconds", "cleanup_events",
                      "cleanup_error", "aborted", "inputs_unchanged"}
    assert result.returncode == 0 and r["exit"] == 0 and r["wall_timeout"] is False
    assert r["request_sha256"] == pin(qpath)["sha256"] == row["request"]["sha256"]
    assert r["helper_sha256"] == HELPER_SHA and r["inputs_unchanged"] is True
    assert r["unexpected_descendants"] == r["cleanup_events"] == []
    assert r["absence_proof"] == "ECHILD" and r["cleanup_error"] is None and r["aborted"] is None
    assert math.isfinite(r["elapsed_seconds"]) and r["elapsed_seconds"] >= 0
    row["logs"] = {suffix: pin(out / (name + "." + suffix))
                   for suffix in ("stdout", "stderr", "helper.stdout", "helper.stderr")}
    assert r["stdout_sha256"] == row["logs"]["stdout"]["sha256"]
    assert r["stderr_sha256"] == row["logs"]["stderr"]["sha256"]
    assert raw(out / (name + ".helper.stdout")) == SUCCESS
    assert raw(out / (name + ".helper.stderr")) == b""
    check(frozen)
    frozen.extend([row["request"], row["receipt"]] + list(row["logs"].values()))
    row["status"] = "PASS"
    save(out / "manifest.json", manifest, True)


def dependencies(out, name, bound):
    obj, dep = out / (name + ".o"), out / (name + ".d")
    text = raw(dep).decode("utf-8").replace("\\\n", "")
    assert text.count(":") == 1 and not any(c in text for c in ("$", "\0", "\r"))
    left, right = text.split(":")
    assert shlex.split(left) == [str(obj)]
    words = shlex.split(right)
    assert words and len(words) == len(set(words))
    paths = [str(Path(p).resolve(strict=True)) for p in words]
    assert str(out / "sources" / (name + ".c")) in paths
    assert str(out / "sources/witness.h") in paths
    if name == "caller":
        assert str(out / "sources/caller.h") in paths
    for path in paths:
        assert path in bound and pin(path) == bound[path], path
    assert raw(obj)[:4] == b"\x7fELF"
    return dict(object=pin(obj), depfile=pin(dep), inputs=[archive(p, out / "inputs") for p in paths])


def link_binding(out, name, objects, bound, libgcc):
    trace = out / ("link-" + name + ".stdout")
    lines = raw(trace).decode("utf-8").splitlines()
    assert lines and all(n == n.strip() and n.startswith("/") for n in lines)
    paths = [str(Path(n).resolve(strict=True)) for n in lines]
    assert {str(p) for p in objects} | {libgcc} <= set(paths)
    for path in paths:
        assert path in bound and pin(path) == bound[path], path
    mapping = out / (name + ".map")
    loads = [line[5:] for line in raw(mapping).decode("utf-8").splitlines() if line.startswith("LOAD ")]
    assert loads and all(str(Path(n).resolve(strict=True)) in paths for n in loads)
    binary = out / ("libli2_uw_" + name + ".so")
    contents = raw(binary)
    assert len(contents) >= 64 and contents[:7] == b"\x7fELF\x02\x01\x01"
    assert struct.unpack_from("<HH", contents, 16) == (3, 62)
    assert struct.unpack_from("<Q", contents, 24) == (0,), "ET_DYN with zero entry"
    return dict(elf=pin(binary), map=pin(mapping), trace=pin(trace), trace_lines=lines,
                inputs=[archive(p, out / "inputs") for p in sorted(set(paths))])


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain", type=Path, required=True)
    parser.add_argument("--toolchain-sha256", required=True)
    parser.add_argument("--source-admission", type=Path, required=True)
    parser.add_argument("--source-admission-sha256", required=True)
    args = parser.parse_args()
    args.toolchain, args.source_admission = args.toolchain.absolute(), args.source_admission.absolute()
    out = args.out.absolute()
    assert out.resolve() == out and out.is_relative_to(ROOT / "ignored") and not out.exists()
    assert out.parent.is_dir() and not any(c.isspace() or c in "$:#\\," for c in str(out))
    for path, digest in ((args.toolchain, args.toolchain_sha256), (args.source_admission, args.source_admission_sha256)):
        assert re.fullmatch("[0-9a-f]{64}", digest) and pin(path)["sha256"] == digest
    config, admission = load(args.toolchain), load(args.source_admission)
    assert set(config) == {"tools", "files"} and set(config["tools"]) == ROLES
    assert type(config["files"]) is list and 1 <= len(config["files"]) <= 4096
    tools = {name: pin(path) for name, path in config["tools"].items()}
    files = [pin(path) for path in config["files"]]
    bound = {row["path"]: row for row in files}
    assert len(bound) == len(files) and {r["path"] for r in tools.values()} <= set(bound)
    assert Path(tools["linker"]["path"]).name.endswith("ld.bfd")
    assert pin(Path(sys.executable).resolve()) == tools["helper_python"]
    assert set(admission) == {"schema", "base_revision", "source_files", "review"}
    assert admission["schema"] == "indexed-dso-build-source-v1"
    assert re.fullmatch("[0-9a-f]{40}", admission["base_revision"])
    source_rows = [pin(p) for p in SOURCES]
    assert admission["source_files"] == {str(Path(r["path"]).relative_to(ROOT)): r["sha256"] for r in source_rows}
    assert pin(HELPER)["sha256"] == HELPER_SHA
    assert set(admission["review"]) == {"path", "sha256"}
    review = pin(admission["review"]["path"])
    assert review["sha256"] == admission["review"]["sha256"]
    frozen = source_rows + files + [pin(args.toolchain), pin(args.source_admission), review]
    out.mkdir(mode=0o700)
    for name in ("sources", "inputs", "tmp", "home"):
        (out / name).mkdir(mode=0o700)
    manifest = dict(schema="indexed-dso-build-v1", status="INCOMPLETE_BUILD_ONLY", native_executed=False,
                    native_qualification=False, consumer_qualification=False, source_admission=admission,
                    sources=source_rows, tools=tools, toolchain_files=files, tool_resolution=LOOKUPS, prerequisites=frozen[-3:],
                    bounds=dict(cpu_seconds=60, wall_seconds=90, file_bytes=CAP, read_bytes=16 * 1024 * 1024,
                                retained_members=4096), cflags=CFLAGS,
                    stage_status_scope="Owning-wrapper attempts and bounded command closure only; later binding refusal fails the build",
                    stages=[dict(name=n, status="UNRUN", attempts=0) for n in STAGES], objects={}, links={})
    save(out / "manifest.json", manifest)
    try:
        manifest["input_archives"] = [archive(p, out / "inputs") for p in
                                      SOURCES + [args.toolchain, args.source_admission, Path(review["path"])]]
        frozen.extend(row["archived"] for row in manifest["input_archives"])
        manifest["source_copies"] = []
        for source in SOURCES:
            if source.parent == HERE:
                dest = out / "sources" / source.name
                with dest.open("xb") as stream:
                    stream.write(raw(source))
                bound[str(dest)] = pin(dest)
                assert bound[str(dest)]["sha256"] == pin(source)["sha256"]
                frozen.append(bound[str(dest)])
                manifest["source_copies"].append(bound[str(dest)])
        env = dict(PATH="/usr/bin:/bin", LC_ALL="C", LANG="C", HOME=str(out / "home"),
                   TMPDIR=str(out / "tmp"), PYTHONDONTWRITEBYTECODE="1")
        manifest.update(environment=env, interpreter_version=sys.version)
        for name, role, flags in PROBES:
            run_one(name, [tools[role]["path"]] + flags, out, env, tools, frozen, manifest)
            assert b"GNU" in raw(out / (name + ".stdout")) or b"Free Software Foundation" in raw(out / (name + ".stdout"))
        gcc = [tools["gcc"]["path"], "-fuse-ld=bfd"]
        for role, program in RESOLVE.items():
            name = "resolve-" + role
            run_one(name, gcc + ["-print-prog-name=" + program], out, env, tools, frozen, manifest)
            assert resolved(raw(out / (name + ".stdout")).decode().strip(), env) == tools[role]["path"]
        run_one("resolve-libgcc", gcc + ["-print-file-name=libgcc_s.so.1"], out, env, tools, frozen, manifest)
        assert resolved(raw(out / "resolve-libgcc.stdout").decode().strip(), env) == tools["libgcc"]["path"]
        for name in ("subject", "collector", "caller"):
            obj = out / (name + ".o")
            argv = gcc + CFLAGS + ["-v", "-MD", "-MF", str(out / (name + ".d")), "-MT", str(obj),
                                    "-c", str(out / "sources" / (name + ".c")), "-o", str(obj)]
            run_one("compile-" + name, argv, out, env, tools, frozen, manifest)
            manifest["objects"][name] = dependencies(out, name, bound)
            manifest["objects"][name]["subprocesses"] = tool_trace(
                out / ("compile-" + name + ".stderr"), {"cc1", "assembler"}, env, tools, bound)
            bound[str(obj)] = pin(obj)
            frozen.extend([bound[str(obj)], manifest["objects"][name]["depfile"]])
            frozen.extend(row["archived"] for row in manifest["objects"][name]["inputs"])
            save(out / "manifest.json", manifest, True)
        for name, members in (("subject", ("subject", "collector")), ("caller", ("caller",))):
            objects = [out / (n + ".o") for n in members]
            argv = gcc + ["-v", "-shared", "-shared-libgcc", "-fno-lto", "-Wl,--eh-frame-hdr", "-Wl,--hash-style=both",
                          "-Wl,-e,0",
                          "-Wl,-z,now", "-Wl,-z,noexecstack", "-Wl,-z,defs", "-Wl,-t",
                          "-Wl,-Map," + str(out / (name + ".map"))] + [str(p) for p in objects]
            argv += ["-Wl,--no-as-needed", tools["libgcc"]["path"], "-Wl,--as-needed",
                     "-o", str(out / ("libli2_uw_" + name + ".so"))]
            run_one("link-" + name, argv, out, env, tools, frozen, manifest)
            manifest["links"][name] = link_binding(out, name, objects, bound, tools["libgcc"]["path"])
            manifest["links"][name]["subprocesses"] = tool_trace(
                out / ("link-" + name + ".stderr"), {"collect2"}, env, tools, bound)
            frozen.extend([manifest["links"][name]["elf"], manifest["links"][name]["map"]])
            frozen.extend(row["archived"] for row in manifest["links"][name]["inputs"])
            save(out / "manifest.json", manifest, True)
        check(frozen)
        assert all(row["status"] == "PASS" for row in manifest["stages"])
        manifest.update(status="BUILD_ONLY_REVIEW_REQUIRED", retained_files=retained(out),
                        pending="Actual ELF/CRT/registration/IFUNC/CFI/loaded-consumer and native admission remain UNRUN")
    except BaseException as error:
        manifest.update(status="FAILED_OR_INCOMPLETE_BUILD_ONLY", error=type(error).__name__ + ": " + str(error))
        raise
    finally:
        save(out / "manifest.json", manifest, True)


if __name__ == "__main__":
    main()
