#!/usr/bin/env python3
"""Bind active Cargo artifacts to the fixed generated-unwind witnesses, in separate phases.

The copied bounded_command helper owns process cleanup. This adapter neither
implements a supervisor nor executes generated machine code itself.
"""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import argparse
import errno
import importlib.util
import shlex
import hashlib
import json
import math
import os
from pathlib import Path
import re
import struct
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
HELPER_SHA = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
SUCCESS = b'{"exit": 0, "wall_timeout": false, "absence_proof": "ECHILD", "descendants": 0, "success": true}\n'
SUPPORT = ["quiescent_oracle.rs", "entry_signal.rs", "parked_signal.rs",
           "boundary_signal.rs", "process_text.rs", "word_sync.rs", "word_trace_method.rs"]
LIBRARIES = {"cfg_aliases", "cfg_if", "lazy_static", "bitflags", "libc", "memmap2", "nix", "iced_x86", "liteinst2"}
PACKAGE_NAMES = {name: name for name in LIBRARIES}
PACKAGE_NAMES.update(cfg_if="cfg-if", iced_x86="iced-x86")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(512 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    with Path(path).open("x") as stream:
        stream.write(json.dumps(value, indent=2) + "\n")


def regular(path):
    path = Path(path)
    assert path.is_absolute() and path.is_file() and not path.is_symlink(), str(path)
    assert str(path.resolve()) == str(path), str(path)
    return path


def identity(path):
    path = Path(path).absolute()
    assert path.is_file()
    st = path.stat()
    return dict(path=str(path), resolved_path=str(path.resolve()), sha256=sha(path),
                stat=[st.st_dev, st.st_ino, st.st_size, st.st_mode & 0o777])


def check_identity(row):
    assert identity(row["path"]) == row, row["path"]


def files(directory):
    result = {}
    for p in sorted(Path(directory).rglob("*")):
        assert not p.is_symlink(), str(p)
        if p.is_file():
            result[str(p.relative_to(directory))] = sha(p)
    return result


def copy_exact(old, new):
    old = regular(old)
    expected = sha(old)
    Path(new).parent.mkdir(parents=True, exist_ok=True)
    with old.open("rb") as source, Path(new).open("xb") as target:
        for chunk in iter(lambda: source.read(512 * 1024), b""):
            target.write(chunk)
    assert sha(old) == sha(new) == expected
    return expected


def source_files():
    paths = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "README.md"]
    paths += sorted((ROOT / "src").rglob("*.rs"))
    paths += [ROOT / "tests/support" / n for n in SUPPORT]
    paths += [p for p in sorted(HERE.rglob("*")) if p.is_file()]
    assert 20 < len(paths) < 512 and len(paths) == len(set(paths))
    assert all(p.resolve().is_relative_to(ROOT) for p in paths)
    assert not any(p.suffix in {".pyc", ".pyo"} or "__pycache__" in p.parts for p in paths)
    return {str(regular(p).relative_to(ROOT)): sha(p) for p in paths}


def configuration_presence(path):
    """Record only permission-denied observation, never infer absent contents."""
    try:
        return Path(path).exists()
    except OSError as error:
        if error.errno not in (errno.EPERM, errno.EACCES):
            raise
        return dict(kind="unreadable", operation="exists", errno=error.errno)


def verify(frozen, expected):
    assert sha(frozen / "freeze.json") == expected
    data = read(frozen / "freeze.json")
    assert data["root"] == str(ROOT) and data["adapter"] == str(HERE)
    assert source_files() == data["source_files"]
    assert files(frozen / "sources") == data["source_files"]
    assert sha(frozen / "toolchain.json") == data["toolchain_sha256"]
    assert sha(frozen / "source-admission.json") == data["source_admission_sha256"]
    assert read(frozen / "source-admission.json") == data["source_admission"]
    assert sha(data["source_admission"]["review"]["path"]) == data["source_admission"]["review"]["sha256"]
    for row in data["tools"].values():
        check_identity(row)
    for row in data["toolchain_files"]:
        check_identity(row)
    for path, row in data["cargo_configuration"].items():
        if row is None:
            assert not Path(path).exists(), path
        elif row.get("kind") == "unreadable":
            assert configuration_presence(path) == row, path
        else:
            check_identity(row)
            assert sha(frozen / "cargo-configuration" / row["sha256"]) == row["sha256"]
    assert data["tools"]["helper"]["sha256"] == HELPER_SHA
    assert sha(HERE / "bounded_command.py") == HELPER_SHA
    return data


def request(argv, out, name, environment, cpu, wall, cap):
    return dict(argv=argv, cwd=str(ROOT), env=environment,
                stdout=str(out / (name + ".stdout")), stderr=str(out / (name + ".stderr")),
                cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)


def receipt(qp, rp, helper):
    q, r = read(qp), read(rp)
    assert set(r) == {"request_sha256", "helper_sha256", "exit", "wall_timeout", "unexpected_descendants", "absence_proof", "stdout_sha256", "stderr_sha256", "elapsed_seconds", "cleanup_events", "cleanup_error", "aborted", "inputs_unchanged"}
    assert r["request_sha256"] == sha(qp) and r["helper_sha256"] == helper
    assert r["exit"] == 0 and r["wall_timeout"] is False
    assert r["unexpected_descendants"] == [] and r["cleanup_events"] == []
    assert r["cleanup_error"] is None and r["aborted"] is None
    assert r["absence_proof"] == "ECHILD" and r["inputs_unchanged"] is True
    assert math.isfinite(r["elapsed_seconds"]) and r["elapsed_seconds"] >= 0
    assert r["stdout_sha256"] == sha(q["stdout"]) and r["stderr_sha256"] == sha(q["stderr"])
    return r


def run_one(frozen, digest, out, name, q, steps):
    data = verify(frozen, digest)
    qp, rp = out / (name + ".request.json"), out / (name + ".receipt.json")
    save(qp, q)
    tools = data["tools"]
    wall = q["wall_seconds"]
    argv = [tools["timeout"]["path"], "--signal=TERM", "--kill-after=10s", str(wall + 10) + "s",
            tools["helper_python"]["path"], "-B", tools["helper"]["path"], "--request", str(qp), "--receipt", str(rp)]
    with (out / (name + ".helper.stdout")).open("xb") as so, (out / (name + ".helper.stderr")).open("xb") as se:
        result = subprocess.run(argv, cwd=ROOT, env=q["env"], stdout=so, stderr=se, timeout=wall + 25)
    steps.append(dict(name=name, helper_argv=argv, helper_exit=result.returncode,
                      request_sha256=sha(qp), receipt_sha256=sha(rp) if rp.exists() else None))
    (out / "steps.json").write_text(json.dumps(steps, indent=2) + "\n")
    assert verify(frozen, digest) == data
    assert result.returncode == 0, name
    r = receipt(qp, rp, tools["helper"]["sha256"])
    assert (out / (name + ".helper.stdout")).read_bytes() == SUCCESS
    assert (out / (name + ".helper.stderr")).read_bytes() == b""
    return r


def freeze(out, toolchain, admission, admission_sha):
    assert out.is_relative_to(ROOT / "ignored") and not out.exists()
    assert sha(HERE / "bounded_command.py") == HELPER_SHA
    config = read(toolchain)
    assert set(config) == {"tools", "files"}
    expected = {"cargo", "rustc", "gcc", "cxx", "linker", "assembler", "helper_python", "timeout", "libgcc", "libstdcxx"}
    assert set(config["tools"]) == expected
    assert 1 <= len(config["files"]) <= 4096
    tools = {name: identity(path) for name, path in config["tools"].items()}
    tools["helper"] = identity(HERE / "bounded_command.py")
    assert tools["libgcc"]["resolved_path"] != tools["libstdcxx"]["resolved_path"]
    assert Path(tools["cargo"]["resolved_path"]).name == "cargo"
    assert Path(tools["rustc"]["resolved_path"]).name == "rustc"
    assert Path(tools["cargo"]["resolved_path"]).parent == Path(tools["rustc"]["resolved_path"]).parent
    assert Path(tools["linker"]["resolved_path"]).name == "ld.bfd"
    tool_files = [identity(path) for path in config["files"]]
    assert len({r["path"] for r in tool_files}) == len(tool_files)
    assert {r["resolved_path"] for r in tools.values()} - {tools["helper"]["resolved_path"]} <= {r["resolved_path"] for r in tool_files}
    sources = source_files()
    assert {"src/patcher/synchronized.rs", "src/patcher/synchronized/tests.rs",
            "src/sync_core.rs", "src/generated_unwind/mod.rs", "src/generated_unwind/cfi.rs",
            "src/generated_unwind/parser.rs", "src/generated_unwind/tests.rs"} <= set(sources)
    assert sha(admission) == admission_sha
    admitted = read(admission)
    assert admitted["schema"] == "unwind-source-admission-v1"
    assert admitted["status"] == "REVIEWED_SOURCE_FOR_NEW_BUILD"
    assert all(admitted["source_files"].get(n) == h for n, h in sources.items())
    assert re.fullmatch(r"[0-9a-f]{40}", admitted["base_revision"])
    assert admitted["source_kind"] in {"git_commit", "worktree_snapshot"}
    if admitted["source_kind"] == "git_commit":
        assert re.fullmatch(r"[0-9a-f]{40}", admitted["tested_revision"])
        assert admitted["clean_tracked"] is True
    else:
        assert admitted["tested_revision"] is None
    assert re.fullmatch(r"[0-9a-f]{64}", admitted["source_tree_sha256"])
    assert admitted["source_tree_sha256"] == hashlib.sha256((json.dumps(admitted["source_files"],
        sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()).hexdigest()
    assert re.fullmatch(r"[0-9a-f]{64}", admitted["tracked_diff_sha256"])
    assert sha(admitted["review"]["path"]) == admitted["review"]["sha256"]
    out.mkdir()
    (out / "sources").mkdir()
    (out / "tmp").mkdir()
    for name in sources:
        copy_exact(ROOT / name, out / "sources" / name)
    copy_exact(Path(toolchain).resolve(), out / "toolchain.json")
    copy_exact(Path(admission).resolve(), out / "source-admission.json")
    home = Path(os.environ["HOME"]).resolve()
    assert home.is_dir()
    config_dirs = [p / ".cargo" for p in [ROOT] + list(ROOT.parents)] + [home / ".cargo"]
    configs = {}
    (out / "cargo-configuration").mkdir()
    for directory in config_dirs:
        for name in ["config", "config.toml"]:
            path = directory / name
            if str(path) in configs:
                continue
            presence = configuration_presence(path)
            if isinstance(presence, dict):
                configs[str(path)] = presence
            elif presence:
                row = identity(regular(path))
                dest = out / "cargo-configuration" / row["sha256"]
                if not dest.exists():
                    copy_exact(path, dest)
                configs[str(path)] = row
            else:
                configs[str(path)] = None
    env = dict(CARGO_BUILD_JOBS="4", CARGO_INCREMENTAL="0", CARGO_NET_OFFLINE="true",
               CARGO_TARGET_DIR=str(ROOT / "target"), CARGO_HOME=str(home / ".cargo"), HOME=str(home), LC_ALL="C",
               PATH=str(Path(tools["cargo"]["path"]).parent) + ":/usr/bin:/bin",
               PYTHONDONTWRITEBYTECODE="1", RUSTC=tools["rustc"]["path"], RUST_TEST_THREADS="1",
               RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="",
               RUSTFLAGS="-Dwarnings -Ccodegen-units=1 -Clinker=" + tools["gcc"]["path"] + " -Clink-arg=-fuse-ld=bfd",
               TMPDIR=str(out / "tmp"), CARGO_PROFILE_DEV_CODEGEN_UNITS="1", CARGO_PROFILE_TEST_CODEGEN_UNITS="1")
    for path, row in configs.items():
        if row is not None and row.get("kind") == "unreadable":
            assert configuration_presence(path) == row, path
    save(out / "freeze.json", dict(status="FROZEN_SOURCE_ONLY_NO_BUILD", root=str(ROOT), adapter=str(HERE),
         source_files=sources, toolchain_sha256=sha(out / "toolchain.json"), tools=tools,
         toolchain_files=tool_files, cargo_configuration=configs, environment=env, target=str(ROOT / "target"),
         source_admission_sha256=admission_sha, source_admission=admitted))
    print("FROZEN", sha(out / "freeze.json"), flush=True)


def dep_rules(depfile):
    text = depfile.read_text()
    assert text and not any(c in text for c in ["\\", "$", "\r"])
    rows, env = {}, []
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith("# env-dep:"):
            env.append(line)
            continue
        assert "#" not in line and line.count(":") == 1
        target, tail = line.split(":")
        assert target and not any(c.isspace() for c in target) and target not in rows
        values = tail.split()
        assert len(values) == len(set(values))
        rows[target] = values
    return rows, env


def locked_packages(text):
    """Accept the fixed lockfile's unambiguous Cargo-v4 subset, or refuse."""
    assert 0 < len(text) <= 1024 * 1024
    lines = text.splitlines()
    assert len(lines) <= 16384
    lines = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    assert lines and lines.pop(0) == "version = 4"
    packages, current, in_dependencies = {}, None, False
    for line in lines:
        if in_dependencies:
            if line == "]":
                in_dependencies = False
            else:
                assert re.fullmatch(r'"[A-Za-z0-9_-]+",', line), line
                value = json.loads(line[:-1])
                assert value not in current["dependencies"]
                current["dependencies"].append(value)
            continue
        if line == "[[package]]":
            if current is not None:
                assert "name" in current and current["name"] not in packages
                packages[current["name"]] = current
            current = {}
            assert len(packages) < 1024
            continue
        assert current is not None
        if line == "dependencies = [":
            assert "dependencies" not in current
            current["dependencies"] = []
            in_dependencies = True
            continue
        match = re.fullmatch(r'(name|version|source|checksum) = "([A-Za-z0-9_./:+-]+)"', line)
        assert match is not None, line
        key, value = match.groups()
        assert key not in current
        current[key] = value
    assert not in_dependencies and current is not None and "name" in current
    assert current["name"] not in packages
    packages[current["name"]] = current
    for name, package in packages.items():
        assert re.fullmatch(r"[A-Za-z0-9_-]+", name)
        assert "version" in package and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", package["version"])
        required = {"name", "version"}
        if "source" in package:
            assert package["source"] == REGISTRY
            assert re.fullmatch(r"[0-9a-f]{64}", package.get("checksum", ""))
            required |= {"source", "checksum"}
        assert set(package) == required | ({"dependencies"} if "dependencies" in package else set())
        assert all(dep in packages for dep in package.get("dependencies", []))
    closure, pending = set(), ["liteinst2"]
    while pending:
        name = pending.pop()
        assert name in packages
        if name not in closure:
            closure.add(name)
            pending.extend(packages[name].get("dependencies", []))
    assert closure == set(PACKAGE_NAMES.values())
    assert packages["liteinst2"]["version"] == "0.1.0" and "source" not in packages["liteinst2"]
    assert all("source" in packages[name] for name in closure - {"liteinst2"})
    return {name: packages[name] for name in sorted(closure)}


def cargo_owner(row, packages, data):
    name = PACKAGE_NAMES[row["target"]["name"]]
    package = packages[name]
    manifest = regular(Path(row["manifest_path"]))
    source = regular(Path(row["target"]["src_path"]))
    owner = manifest.parent
    assert manifest.name == "Cargo.toml" and source == owner / "src/lib.rs"
    if name == "liteinst2":
        expected = "path+file://" + str(ROOT) + "#liteinst2@0.1.0"
        assert owner == ROOT
        assert sha(manifest) == data["source_files"]["Cargo.toml"]
    else:
        expected = package["source"] + "#" + name + "@" + package["version"]
        registry_root = Path(data["environment"]["CARGO_HOME"]) / "registry/src"
        assert owner.parent.parent == registry_root
        assert re.fullmatch(r"[A-Za-z0-9_.-]+", owner.parent.name)
        assert owner.name == name + "-" + package["version"]
    assert row["package_id"] == expected
    assert row["target"]["kind"] == row["target"]["crate_types"] == ["lib"]
    assert row["executable"] is None
    return dict(package=package, package_id=expected, manifest=identity(manifest),
                target_source=identity(source), owner=str(owner))


def cargo_dependencies(row, rlib, rmeta, dep, owner, data):
    """Bind the actual three rustc depfile targets, including Cargo's root alias."""
    target = row["target"]["name"]
    assert rmeta.parent == ROOT / "target/debug/deps"
    assert re.fullmatch(r"lib" + re.escape(target) + r"-[0-9a-f]{16}\.rmeta", rmeta.name)
    hashed_rlib = regular(rmeta.with_suffix(".rlib"))
    assert dep == rmeta.with_name(rmeta.name.removeprefix("lib").removesuffix(".rmeta") + ".d")
    if target == "liteinst2":
        assert rlib == ROOT / "target/debug/libliteinst2.rlib"
        assert sha(rlib) == sha(hashed_rlib)
    else:
        assert rlib == hashed_rlib
    rules, environment = dep_rules(dep)
    nonempty = {t: values for t, values in rules.items() if values}
    empty = {t for t, values in rules.items() if not values}
    assert set(nonempty) == {str(dep), str(hashed_rlib), str(rmeta)}
    values = nonempty[str(dep)]
    assert values and all(other == values for other in nonempty.values())
    dependencies = sorted(str(regular(Path(value).resolve())) for value in values)
    assert len(dependencies) == len(set(dependencies))
    assert len(empty) == len(dependencies)
    assert {str(regular(Path(value).resolve())) for value in empty} == set(dependencies)
    assert row["target"]["src_path"] in dependencies
    for value in dependencies:
        path = Path(value)
        assert path.is_relative_to(Path(owner["owner"]))
        if target == "liteinst2":
            relative = str(path.relative_to(ROOT))
            assert relative in data["source_files"] and sha(path) == data["source_files"][relative]
    return rules, environment, dependencies, identity(hashed_rlib)


def archive_cargo(out, data):
    rows = [json.loads(line) for line in (out / "cargo.stdout").read_text().splitlines()]
    assert rows[-1] == {"reason": "build-finished", "success": True}
    assert all(row.get("reason") in {"compiler-artifact", "compiler-message", "build-script-executed", "build-finished"} for row in rows)
    assert not any(row.get("reason") == "compiler-message" and row["message"]["level"] in {"error", "warning"} for row in rows)
    libs = [r for r in rows if r.get("reason") == "compiler-artifact" and r["target"]["kind"] == ["lib"]]
    assert {r["target"]["name"] for r in libs} == LIBRARIES and len(libs) == len(LIBRARIES)
    root = next(r for r in libs if r["target"]["name"] == "liteinst2")
    assert root["target"]["src_path"] == str(ROOT / "src/lib.rs")
    assert root["package_id"] == "path+file://" + str(ROOT) + "#liteinst2@0.1.0"
    assert root["features"] == [] and root["executable"] is None
    assert root["profile"] == {"opt_level": "0", "debuginfo": 2, "debug_assertions": True, "overflow_checks": True, "test": False}
    libc = next(r for r in libs if r["target"]["name"] == "libc")
    assert "#libc@" in libc["package_id"] and libc["executable"] is None
    lock = ROOT / "Cargo.lock"
    assert sha(lock) == data["source_files"]["Cargo.lock"]
    packages = locked_packages(lock.read_text())
    archive = out / "archives"
    archive.mkdir()
    source_archive = out / "dependency-sources"
    source_archive.mkdir()
    bound, externs, depfiles, owners = {}, {}, {}, {}
    for row in libs:
        assert row["profile"]["test"] is False
        owner = cargo_owner(row, packages, data)
        manifest = Path(owner["manifest"]["path"])
        manifest_copy = source_archive / owner["manifest"]["sha256"]
        if not manifest_copy.exists():
            copy_exact(manifest, manifest_copy)
        assert sha(manifest_copy) == owner["manifest"]["sha256"]
        owner["manifest_archive"] = identity(manifest_copy)
        owners[row["target"]["name"]] = owner
        rlibs = [Path(f) for f in row["filenames"] if f.endswith(".rlib")]
        rmeta = [Path(f) for f in row["filenames"] if f.endswith(".rmeta")]
        assert len(rlibs) == len(rmeta) == 1 and len(row["filenames"]) == 2
        for path in rlibs + rmeta:
            assert path.is_relative_to(ROOT / "target/debug") and path.name not in bound
            copy_exact(path, archive / path.name)
            (archive / path.name).chmod(0o444)
            bound[path.name] = dict(original=str(path), copied=identity(archive / path.name), cargo_record=row)
        externs[row["target"]["name"]] = str(archive / rlibs[0].name)
        dep = rmeta[0].with_name(rmeta[0].name.removeprefix("lib").removesuffix(".rmeta") + ".d")
        copy_exact(dep, archive / dep.name)
        rules, environment = dep_rules(dep)
        dependencies = sorted({v for values in rules.values() for v in values})
        assert dependencies
        if row is root:
            assert all(str(Path(v).resolve().relative_to(ROOT)) in data["source_files"] for v in dependencies)
        checked_rules, checked_environment, checked_dependencies, hashed_rlib = cargo_dependencies(
            row, rlibs[0], rmeta[0], dep, owner, data)
        assert rules == checked_rules and environment == checked_environment
        assert sorted(str(Path(v).resolve()) for v in dependencies) == checked_dependencies
        owner["hashed_rlib"] = hashed_rlib
        owner["cargo_rlib_alias"] = identity(rlibs[0])
        source_rows = []
        for value in dependencies:
            row = identity(Path(value).resolve())
            copied = source_archive / row["sha256"]
            if not copied.exists():
                copy_exact(Path(row["path"]), copied)
            assert sha(copied) == row["sha256"]
            source_rows.append(dict(original=row, archived=identity(copied)))
        depfiles[dep.name] = dict(original=str(dep), sha256=sha(dep), rules=rules,
                                 environment=environment, sources=source_rows)
    save(out / "cargo-binding.json", dict(records=libs, archives=bound, depfiles=depfiles, externs=externs,
         locked_packages=packages, cargo_lock_sha256=sha(lock), package_owners=owners,
         cargo_stdout_sha256=sha(out / "cargo.stdout"), cargo_receipt_sha256=sha(out / "cargo.receipt.json")))
    return externs



def cargo_json(path):
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
    assert rows and rows[-1] == {"reason": "build-finished", "success": True}
    assert sum(row.get("reason") == "build-finished" for row in rows) == 1
    assert all(row.get("reason") in {"compiler-artifact", "compiler-message", "build-script-executed", "build-finished"} for row in rows)
    assert not any(row.get("reason") == "compiler-message" and row["message"]["level"] in {"error", "warning"} for row in rows)
    return rows


def recheck_archives(out):
    binding = read(out / "cargo-binding.json")
    for row in binding["archives"].values():
        check_identity(row["copied"])
    for owner in binding["package_owners"].values():
        check_identity(owner["manifest"])
        check_identity(owner["manifest_archive"])
    for dep in binding["depfiles"].values():
        for row in dep["sources"]:
            check_identity(row["original"])
            check_identity(row["archived"])
    return binding


def archive_build_scripts(out, data, phase):
    """Preserve every ancillary Cargo executable before later target writes."""
    rows = cargo_json(out / (phase + ".stdout"))
    artifacts = [r for r in rows if r.get("reason") == "compiler-artifact" and r["target"]["kind"] == ["custom-build"]]
    packages = locked_packages((ROOT / "Cargo.lock").read_text())
    records = []
    for row in artifacts:
        manifest, source = regular(Path(row["manifest_path"])), regular(Path(row["target"]["src_path"]))
        assert manifest.name == "Cargo.toml" and source.is_relative_to(manifest.parent)
        owners = [p for p in packages.values() if row["package_id"] == p.get("source", "") + "#" + p["name"] + "@" + p["version"]]
        assert len(owners) == 1 and owners[0]["name"] in {"libc", "nix"}
        owner = owners[0]
        assert manifest.parent.name == owner["name"] + "-" + owner["version"]
        assert manifest.parent.parent.parent == Path(data["environment"]["CARGO_HOME"]) / "registry/src"
        assert row["target"]["crate_types"] == ["bin"] and row["profile"]["test"] is False
        assert len(row["filenames"]) == 1
        original = regular(Path(row["filenames"][0]))
        assert original.is_relative_to(ROOT / "target/debug/build")
        copied = out / "cargo-build-scripts" / sha(original)
        if not copied.exists():
            copy_exact(original, copied)
        assert sha(original) == sha(copied)
        captured = {}
        for p in (manifest, source):
            target = out / "dependency-sources" / sha(p)
            if not target.exists():
                copy_exact(p, target)
            captured[str(p)] = dict(original=identity(p), archived=identity(target))
        records.append(dict(cargo_record=row, original=identity(original), archived=identity(copied), sources=captured))
    assert len(records) == 2 and {r["cargo_record"]["package_id"] for r in records} == {
        packages[name]["source"] + "#" + name + "@" + packages[name]["version"] for name in ("libc", "nix")}
    save(out / (phase + "-ancillary.json"), dict(records=records, stdout_sha256=sha(out / (phase + ".stdout"))))


def archive_unit(out, data):
    rows = cargo_json(out / "unit.stdout")
    candidates = [row for row in rows if row.get("reason") == "compiler-artifact" and row.get("executable") is not None]
    assert len(candidates) == 1
    row = candidates[0]
    assert row["package_id"] == "path+file://" + str(ROOT) + "#liteinst2@0.1.0"
    assert row["target"]["kind"] == row["target"]["crate_types"] == ["lib"]
    assert row["target"]["src_path"] == str(ROOT / "src/lib.rs")
    assert row["manifest_path"] == str(ROOT / "Cargo.toml") and row["features"] == []
    assert row["profile"] == {"opt_level": "0", "debuginfo": 2, "debug_assertions": True, "overflow_checks": True, "test": True}
    assert row["filenames"] == [row["executable"]]
    original = regular(Path(row["executable"]))
    assert original.parent == ROOT / "target/debug/deps"
    saved = out / "consumer-unit-tests"
    copy_exact(original, saved)
    saved.chmod(0o555)
    dep = original.with_suffix(".d")
    rules, environment = dep_rules(dep)
    nonempty = {k: v for k, v in rules.items() if v}
    assert set(nonempty) == {str(original), str(dep)}
    values = nonempty[str(original)]
    assert values and nonempty[str(dep)] == values
    dependencies = {str(Path(v).resolve()) for v in values}
    assert len(dependencies) == len(values)
    assert {str(Path(v).resolve()) for v, tail in rules.items() if not tail} == dependencies
    assert str(ROOT / "src/lib.rs") in dependencies
    sources = {}
    for value in sorted(dependencies):
        p = regular(Path(value))
        relative = str(p.relative_to(ROOT))
        assert relative in data["source_files"] and sha(p) == data["source_files"][relative]
        sources[value] = sha(p)
    copy_exact(dep, out / "consumer-unit-tests.d")
    return dict(identity(saved), cargo_record=row, source_dependencies=sources,
                depfile_sha256=sha(out / "consumer-unit-tests.d"),
                request_sha256=sha(out / "unit.request.json"), receipt_sha256=sha(out / "unit.receipt.json"))


def object_binding(out, name, source, data):
    obj, dep = out / (name + ".o"), out / (name + ".d")
    assert regular(obj).read_bytes()[:4] == b"\x7fELF"
    text = dep.read_text().replace("\\\n", "")
    assert text.count(":") == 1 and "$" not in text and "\0" not in text
    left, right = text.split(":", 1)
    assert shlex.split(left) == [str(obj)]
    words = shlex.split(right)
    assert words and len(words) == len(set(words))
    paths = [regular((ROOT / value).resolve()) for value in words]
    assert HERE / source in paths
    if name == "collector":
        assert HERE / "witness.h" in paths
    bound = {row["resolved_path"]: row["sha256"] for row in data["toolchain_files"]}
    bound.update({str((ROOT / n).resolve()): h for n, h in data["source_files"].items()})
    headers = {}
    for p in paths:
        assert str(p) in bound and sha(p) == bound[str(p)], str(p)
        copy = out / "headers" / sha(p)
        if not copy.exists():
            copy_exact(p, copy)
        headers[str(p)] = dict(original=identity(p), archived=identity(copy))
    return dict(object=identity(obj), depfile=identity(dep), headers=headers,
                request_sha256=sha(out / ("compile-" + name + ".request.json")),
                receipt_sha256=sha(out / ("compile-" + name + ".receipt.json")))


def fixture_environment(name, environment, compile_environment):
    """Authenticate the fixed fixture's absent compile-time environment input."""
    assert type(name) is str and name in {
        "consumer-main", "consumer-launcher", "consumer-calibrations"
    }
    assert type(environment) is list and all(type(line) is str for line in environment)
    assert type(compile_environment) is dict
    assert all(type(key) is str and type(value) is str
               for key, value in compile_environment.items())
    variable = "CARGO_BIN_EXE_unwind-consumer-oracle-driver"
    # No compile-time executable path is admitted, including an empty value.
    assert variable not in compile_environment
    expected = ["# env-dep:" + variable] if name == "consumer-launcher" else []
    assert environment == expected


def bind_fixture(out, name, source, data):
    binary, dep = out / name, out / (name + ".d")
    raw = regular(binary).read_bytes()
    assert raw[:7] == b"\x7fELF\x02\x01\x01" and len(raw) > 4096
    assert struct.unpack_from("<H", raw, 18)[0] == 62
    assert struct.unpack_from("<H", raw, 16)[0] in {2, 3}
    required = {str(HERE / source)} | {str(ROOT / "tests/support" / n) for n in SUPPORT}
    if name != "consumer-calibrations":
        required |= {str(HERE / n) for n in ("consumer.rs", "elf.rs", "isolation.rs")}
    rules, environment = dep_rules(dep)
    fixture_environment(name, environment,
                        read(out / ("compile-" + name + ".request.json"))["env"])
    nonempty = {k: v for k, v in rules.items() if v}
    assert set(nonempty) == {str(binary), str(dep)}
    assert {str(Path(n).resolve()) for n, tail in rules.items() if not tail} == required
    for values in nonempty.values():
        assert len(values) == len(required) and {str(Path(v).resolve()) for v in values} == required
    sources = {n: data["source_files"][str(Path(n).relative_to(ROOT))] for n in sorted(required)}
    for n, digest in sources.items():
        assert sha(n) == digest
    binary.chmod(0o555)
    return dict(identity(binary), source_dependencies=sources, depfile_sha256=sha(dep),
                request_sha256=sha(out / ("compile-" + name + ".request.json")),
                receipt_sha256=sha(out / ("compile-" + name + ".receipt.json")))


def bind_linker(out, name, data, digest):
    binary = out / name
    capture_path = Path(str(binary) + ".link-inputs.json")
    record = read(capture_path)
    assert record["freeze_sha256"] == digest and record["cwd"] == str(ROOT)
    assert record["argv"][0] == data["tools"]["gcc"]["path"]
    assert record["compiler_sha256"] == data["tools"]["gcc"]["sha256"]
    captured = {}
    for row in record["files"]:
        assert row["resolved_path"] not in captured
        assert sha(row["archive"]) == row["archive_sha256"] == row["sha256"]
        captured[row["resolved_path"]] = row
    assert captured and any(n.endswith(".o") for n in captured)
    stdout = Path(str(binary) + ".linker.stdout")
    assert record["linker_stdout"] == str(stdout) and stdout.is_file() and not stdout.is_symlink()
    lines = stdout.read_text().splitlines()
    assert lines and all(line and line == line.strip() and line.startswith("/") and "\0" not in line for line in lines)
    bound = {row["resolved_path"]: row["sha256"] for row in data["toolchain_files"]}
    for archive in (out / "archives").iterdir():
        if archive.is_file():
            bound[str(archive.resolve(strict=True))] = sha(archive)
    for object_name in ("witness.o", "collector.o"):
        path = out / object_name
        bound[str(path.resolve(strict=True))] = sha(path)
    linked, removed = {}, {}
    for value in lines:
        p = Path(value)
        canonical = str(p.resolve())
        if p.is_file():
            assert canonical in bound and sha(p) == bound[canonical], value
            if canonical in captured:
                assert sha(p) == captured[canonical]["sha256"]
            copied = out / "linker-persistent" / sha(p)
            if not copied.exists():
                copy_exact(p.resolve(), copied)
            linked[value] = dict(original=identity(p), archived=identity(copied))
        else:
            assert canonical in captured, value
            removed[value] = captured[canonical]
    if name != "consumer-calibrations":
        for role in ("libgcc", "libstdcxx"):
            assert data["tools"][role]["resolved_path"] in {row["original"]["resolved_path"] for row in linked.values()}
    return dict(capture_sha256=sha(capture_path), stdout_sha256=sha(stdout), lines=lines,
                persistent=linked, removed=removed, pre_exec_inputs=record["files"])


def build(frozen, digest):
    data = verify(frozen, digest)
    out = frozen / "build"
    out.mkdir()
    (out / "headers").mkdir()
    (out / "linker-persistent").mkdir()
    steps = []
    try:
        tools, env = data["tools"], dict(data["environment"])
        env.update(UNWIND_SOURCE_FREEZE=str(frozen), UNWIND_SOURCE_FREEZE_SHA256=digest)
        calibration = [tools["helper_python"]["path"], "-B", str(HERE / "mapping_entry.py"), str(frozen), digest]
        run_one(frozen, digest, out, "mapping-calibrations",
                request(calibration, out, "mapping-calibrations", env, 20, 30, 16 * 1024 * 1024), steps)
        assert read(out / "mapping-calibrations.stdout") == read(HERE / "mapping-expected.json")
        assert (out / "mapping-calibrations.stderr").read_bytes() == b""
        shim = out / "linker-capture"
        content = Path(HERE / "linker_capture.py").read_bytes()
        assert content.startswith(b"#!/usr/bin/python3\n")
        with shim.open("xb") as stream:
            stream.write(("#!" + tools["helper_python"]["resolved_path"] + "\n").encode() + content.split(b"\n", 1)[1])
        shim.chmod(0o555)
        save(out / "linker-shim.json", dict(path=str(shim), sha256=sha(shim),
             public_source_sha256=sha(HERE / "linker_capture.py"), interpreter=tools["helper_python"]))
        cargo = [tools["cargo"]["path"], "build", "--offline", "--locked", "--lib", "-p", "liteinst2", "--message-format=json"]
        run_one(frozen, digest, out, "cargo", request(cargo, out, "cargo", env, 60, 90, 128 * 1024 * 1024), steps)
        externs = archive_cargo(out, data)
        archive_build_scripts(out, data, "cargo")
        unit = [tools["cargo"]["path"], "test", "--offline", "--locked", "--lib", "-p", "liteinst2", "--no-run", "--message-format=json"]
        run_one(frozen, digest, out, "unit", request(unit, out, "unit", env, 60, 90, 128 * 1024 * 1024), steps)
        archive_build_scripts(out, data, "unit")
        recheck_archives(out)
        binaries = {"consumer-unit-tests": archive_unit(out, data)}
        objects = {}
        for name, source in (("witness", "witness.S"), ("collector", "collector.cpp")):
            if name == "witness":
                argv = [tools["gcc"]["path"], "-g", "-fPIC", "-fcf-protection=none"]
            else:
                argv = [tools["cxx"]["path"], "-std=c++17", "-O0", "-g", "-Wall", "-Wextra", "-Werror", "-fPIC",
                        "-fno-omit-frame-pointer", "-fno-optimize-sibling-calls", "-fno-exceptions", "-fno-rtti",
                        "-fasynchronous-unwind-tables", "-fcf-protection=none", "-fno-lto"]
            argv += ["-MD", "-MF", str(out / (name + ".d")), "-c", str(HERE / source), "-o", str(out / (name + ".o"))]
            key = "compile-" + name
            run_one(frozen, digest, out, key, request(argv, out, key, env, 60, 90, 128 * 1024 * 1024), steps)
            assert (out / (key + ".stdout")).read_bytes() == (out / (key + ".stderr")).read_bytes() == b""
            objects[name] = object_binding(out, name, source, data)
        links = {}
        for name, source, test, with_objects in (("consumer-main", "native.rs", False, True),
                ("consumer-launcher", "native.rs", True, True), ("consumer-calibrations", "calibrations.rs", True, False)):
            recheck_archives(out)
            check_binary(binaries["consumer-unit-tests"])
            for obj in objects.values():
                check_identity(obj["object"])
                check_identity(obj["depfile"])
                for header in obj["headers"].values():
                    check_identity(header["original"])
                    check_identity(header["archived"])
            argv = [tools["rustc"]["path"], "--edition=2024", "-Dwarnings", "-Ccodegen-units=1", "-Copt-level=0",
                    "-Cdebug-assertions=yes", "-Coverflow-checks=yes", "-Cdebuginfo=2", "-Cforce-unwind-tables=yes",
                    "-Cforce-frame-pointers=yes", "-Clinker=" + str(shim), "-Clink-arg=-fuse-ld=bfd", "-Clink-arg=-Wl,-t",
                    "-L", "dependency=" + str(out / "archives"), "--extern", "liteinst2=" + externs["liteinst2"],
                    "--extern", "libc=" + externs["libc"], "--crate-name", name.replace("-", "_")]
            if test:
                argv.append("--test")
            argv.append(str(HERE / source))
            if with_objects:
                argv += ["-Clink-arg=" + str(out / "witness.o"), "-Clink-arg=" + str(out / "collector.o"),
                         "-Clink-arg=" + tools["libgcc"]["resolved_path"], "-Clink-arg=" + tools["libstdcxx"]["resolved_path"]]
            argv += ["--emit=link,dep-info=" + str(out / (name + ".d")), "-o", str(out / name)]
            key = "compile-" + name
            run_one(frozen, digest, out, key, request(argv, out, key, env, 60, 90, 128 * 1024 * 1024), steps)
            assert (out / (key + ".stdout")).read_bytes() == (out / (key + ".stderr")).read_bytes() == b""
            assert sha(shim) == read(out / "linker-shim.json")["sha256"]
            binaries[name] = bind_fixture(out, name, source, data)
            links[name] = bind_linker(out, name, data, digest)
        assert len(steps) == 8 and len(binaries) == 4 and len(links) == 3
        recheck_archives(out)
        for obj in objects.values():
            check_identity(obj["object"])
            check_identity(obj["depfile"])
            for header in obj["headers"].values():
                check_identity(header["original"])
                check_identity(header["archived"])
        for row in binaries.values():
            check_binary(row)
        assert verify(frozen, digest) == data
        save(out / "binary-binding.json", dict(status="BUILT_REVIEW_REQUIRED_NO_EXECUTION", binaries=binaries,
             objects=objects, links=links, freeze_sha256=digest, cargo_binding_sha256=sha(out / "cargo-binding.json"),
             native_executed=False))
        save(out / "build-audit.json", dict(status="BUILT_REVIEW_REQUIRED_NO_EXECUTION", freeze_sha256=digest,
             binary_binding_sha256=sha(out / "binary-binding.json"), files=files(out), steps=steps, native_executed=False))
        print("BUILT_REVIEW_REQUIRED_NO_EXECUTION", sha(out / "build-audit.json"), flush=True)
    except BaseException as error:
        save(out / "failed-incomplete.json", dict(status="FAILED_INCOMPLETE_NO_BUILD_PASS", error=repr(error),
             steps=steps, cleanup_claimed=False, files=files(out)))
        raise


def check_binary(row):
    assert identity(row["path"]) == {key: row[key] for key in ("path", "resolved_path", "sha256", "stat")}


def elf(path):
    data = Path(path).read_bytes()
    assert data[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<H', data, 18)[0] == 62
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    assert size == 56 and 1 <= count <= 256 and offset + size * count <= len(data)
    interpreters, loads = [], []
    for index in range(count):
        kind, flags, file, address, _, filesz, memsz, _ = struct.unpack_from('<IIQQQQQQ', data, offset + index * size)
        assert file + filesz <= len(data)
        if kind == 3:
            value = data[file:file + filesz]
            assert value[-1:] == b'\0' and b'\0' not in value[:-1]
            interpreters.append(value[:-1].decode())
        if kind == 1:
            loads.append(dict(flags=flags, file_offset=file, virtual_address=address,
                              file_size=filesz, memory_size=memsz))
    assert len(interpreters) <= 1
    return dict(interpreter=interpreters[0] if interpreters else None, loads=loads)


def runtime_identity(path, with_elf=False):
    path = Path(path).absolute()
    state = path.stat()
    row = dict(path=str(path), resolved=str(path.resolve(strict=True)), device=state.st_dev,
               inode=state.st_ino, size=state.st_size, sha256=sha(path))
    if with_elf:
        row["elf"] = elf(path)
    return row


def libgcc_symbols(path):
    """Require six defined dynamic functions, each in one executable segment."""
    data = Path(path).read_bytes()
    geometry = elf(path)
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count = struct.unpack_from("<HH", data, 58)
    assert size == 64 and 1 <= count <= 4096 and offset + size * count <= len(data)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * size) for i in range(count)]
    tables = [row for row in sections if row[1] == 11]
    assert len(tables) == 1
    table = tables[0]
    assert table[9] == 24 and table[5] % 24 == 0 and table[5] // 24 <= 65536
    assert 0 <= table[6] < count and table[4] + table[5] <= len(data)
    strings = sections[table[6]]
    assert strings[1] == 3 and strings[4] + strings[5] <= len(data)
    names = data[strings[4]:strings[4] + strings[5]]
    required = {"__register_frame", "_Unwind_Find_FDE", "_Unwind_Backtrace", "_Unwind_GetIPInfo", "_Unwind_GetCFA", "_Unwind_GetGR"}
    result = {}
    for index in range(table[5] // 24):
        name, info, other, section, value, width = struct.unpack_from("<IBBHQQ", data, table[4] + index * 24)
        assert name < len(names)
        stop = names.find(b"\0", name)
        assert stop >= name
        label = names[name:stop].decode("ascii")
        if label not in required:
            continue
        assert label not in result and info & 15 == 2 and info >> 4 in (1, 2)
        assert other & 3 in (0, 3) and 0 < section < count and width > 0
        owners = [s for s in geometry["loads"] if s["flags"] == 5 and s["virtual_address"] <= value
                  and value + width <= s["virtual_address"] + s["file_size"]]
        assert len(owners) == 1
        result[label] = dict(symbol_index=index, value=value, size=width, section=section,
                             file_offset=owners[0]["file_offset"] + value - owners[0]["virtual_address"])
    assert set(result) == required
    return result


def loader_epoch(out):
    """Observe one explicit epoch; no refresh after the runtime plan freezes."""
    cache_path, preload_path = Path("/etc/ld.so.cache"), Path("/etc/ld.so.preload")
    cache = runtime_identity(cache_path) if cache_path.exists() else dict(kind="absent", path=str(cache_path))
    if "sha256" in cache:
        copy_exact(cache_path.resolve(strict=True), out / "snapshots/ld.so.cache")
    if preload_path.exists():
        preload = runtime_identity(preload_path)
        assert preload_path.read_bytes().strip() == b"", "active global preload is outside this fixture"
        preload["kind"] = "inactive-file"
    else:
        preload = dict(kind="absent", path=str(preload_path))
    configuration, directories = {}, {}
    config = Path("/etc/ld.so.conf")
    configuration[str(config)] = runtime_identity(config) if config.exists() else None
    directory = Path("/etc/ld.so.conf.d")
    if directory.exists():
        assert directory.is_dir() and not directory.is_symlink()
        children = sorted(directory.iterdir())
        assert len(children) <= 256 and all(p.is_file() and not p.is_symlink() for p in children)
        directories[str(directory)] = [str(p) for p in children]
        for child in children:
            configuration[str(child)] = runtime_identity(child)
    else:
        configuration[str(directory)] = None
    save(out / "loader-epoch.json", dict(cache=cache, global_preload=preload,
         configuration=configuration, directories=directories,
         semantics="exact observations; no automatic identity refresh or hidden-content claim"))
    return cache, preload, configuration, directories


def runtime(frozen, digest, review, review_sha, admission, admission_sha):
    data = verify(frozen, digest)
    review = regular(Path(review).resolve(strict=True))
    assert review.is_relative_to(ROOT / "ignored") and sha(review) == review_sha
    admission = regular(Path(admission).resolve(strict=True))
    assert sha(admission) == admission_sha
    runtime_admission = read(admission)
    assert runtime_admission["schema"] == "unwind-source-admission-v1"
    assert runtime_admission["status"] == "REVIEWED_SOURCE_FOR_NEW_BUILD"
    assert runtime_admission["source_kind"] == "git_commit"
    assert runtime_admission["tested_revision"] == runtime_admission["base_revision"]
    assert re.fullmatch(r"[0-9a-f]{40}", runtime_admission["tested_revision"])
    assert runtime_admission["clean_tracked"] is True
    assert runtime_admission["tracked_diff_sha256"] == hashlib.sha256(b"").hexdigest()
    assert runtime_admission["source_tree_sha256"] == hashlib.sha256((json.dumps(runtime_admission["source_files"],
        sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()).hexdigest()
    for name, checksum in runtime_admission["source_files"].items():
        assert regular(ROOT / name).is_relative_to(ROOT) and sha(ROOT / name) == checksum
    assert all(runtime_admission["source_files"].get(n) == h for n, h in data["source_files"].items())
    assert sha(runtime_admission["review"]["path"]) == runtime_admission["review"]["sha256"]
    build_dir = frozen / "build"
    build_audit = read(build_dir / "build-audit.json")
    assert build_audit["status"] == "BUILT_REVIEW_REQUIRED_NO_EXECUTION"
    assert build_audit["freeze_sha256"] == digest and build_audit["native_executed"] is False
    assert files(build_dir) == dict(build_audit["files"], **{"build-audit.json": sha(build_dir / "build-audit.json")})
    binding = read(build_dir / "binary-binding.json")
    assert build_audit["binary_binding_sha256"] == sha(build_dir / "binary-binding.json")
    assert binding["freeze_sha256"] == digest and binding["native_executed"] is False
    assert set(binding["binaries"]) == {"consumer-unit-tests", "consumer-main", "consumer-launcher", "consumer-calibrations"}
    assert len(build_audit["steps"]) == 8
    assert [s["name"] for s in build_audit["steps"]] == ["mapping-calibrations", "cargo", "unit", "compile-witness",
        "compile-collector", "compile-consumer-main", "compile-consumer-launcher", "compile-consumer-calibrations"]
    for step in build_audit["steps"]:
        name = step["name"]
        assert step["helper_exit"] == 0
        qp, rp = build_dir / (name + ".request.json"), build_dir / (name + ".receipt.json")
        assert step["request_sha256"] == sha(qp) and step["receipt_sha256"] == sha(rp)
        receipt(qp, rp, data["tools"]["helper"]["sha256"])
        assert (build_dir / (name + ".helper.stdout")).read_bytes() == SUCCESS
        assert (build_dir / (name + ".helper.stderr")).read_bytes() == b""
    recheck_archives(build_dir)
    for row in binding["binaries"].values():
        check_binary(row)
    out = frozen / "runtime"
    out.mkdir()
    (out / "requests").mkdir()
    (out / "snapshots").mkdir()
    for p in sorted((HERE / "runtime").glob("*.py")):
        copy_exact(p, out / p.name)
    copy_exact(HERE / "expected.json", out / "expected.json")
    copy_exact(admission, out / "runtime-source-admission.json")
    save(out / "source-files.json", {p.name: sha(p) for p in sorted(out.glob("*.py"))})
    binaries = {name: runtime_identity(row["path"], True) for name, row in binding["binaries"].items()}
    interpreters = {row["elf"]["interpreter"] for row in binaries.values()}
    assert len(interpreters) == 1 and None not in interpreters
    interpreters = {path: runtime_identity(path, True) for path in interpreters}
    canonical = Path(data["tools"]["libgcc"]["resolved_path"])
    libgcc = runtime_identity(canonical, True)
    alias = runtime_identity("/lib64/libgcc_s.so.1")
    assert alias["resolved"] == libgcc["resolved"]
    snapshot = out / "snapshots/libgcc_s.so.1"
    copy_exact(canonical, snapshot)
    copied = runtime_identity(snapshot)
    assert (copied["device"], copied["inode"]) != (libgcc["device"], libgcc["inode"])
    assert snapshot.read_bytes() == canonical.read_bytes()
    symbols = libgcc_symbols(canonical)
    cache, preload, config, directories = loader_epoch(out)
    refs = {str(ROOT / name): h for name, h in data["source_files"].items()}
    refs.update({str(frozen / "freeze.json"): digest, str(review): review_sha,
                 str(frozen / "toolchain.json"): data["toolchain_sha256"],
                 str(frozen / "source-admission.json"): data["source_admission_sha256"]})
    refs[str(admission)] = admission_sha
    refs[runtime_admission["review"]["path"]] = runtime_admission["review"]["sha256"]
    for name, h in files(build_dir).items():
        refs[str(build_dir / name)] = h
    cargo = read(build_dir / "cargo-binding.json")
    source_identities = [row["original"] for dep in cargo["depfiles"].values() for row in dep["sources"]]
    source_identities += [owner["manifest"] for owner in cargo["package_owners"].values()]
    source_identities += [identity(ROOT / name) for name in data["source_files"]]
    for row in data["cargo_configuration"].values():
        if row is not None and row.get("kind") != "unreadable":
            source_identities.append(row)
    inputs = dict(root=str(ROOT), runtime_directory=str(out), tools=data["tools"], helper=data["tools"]["helper"],
         tool_identities=data["toolchain_files"], source_identities=source_identities,
         source_selection=data["source_files"], public_adapter_directory=str(HERE),
         build_directory=str(build_dir), build_audit_sha256=sha(build_dir / "build-audit.json"),
         binary_binding_sha256=sha(build_dir / "binary-binding.json"), binary=binaries,
         binding_review=dict(path=str(review), sha256=review_sha),
         source_admission=runtime_admission, source_admission_sha256=admission_sha,
         build_source_admission=data["source_admission"], build_source_admission_sha256=data["source_admission_sha256"],
         interpreters=interpreters, libgcc=libgcc,
         libgcc_alias=alias, libgcc_snapshot=copied, libgcc_symbols=symbols,
         global_preload=preload, loader_cache=cache, loader_epoch_sha256=sha(out / "loader-epoch.json"),
         loader_configuration=config, loader_configuration_directories=directories,
         absent_configuration=[p for p, row in data["cargo_configuration"].items() if row is None],
         unreadable_configuration={p: row for p, row in data["cargo_configuration"].items()
                                   if row is not None and row.get("kind") == "unreadable"})
    save(out / "inputs.json", inputs)
    expected = read(out / "expected.json")
    modes = expected["inventory"]["native_modes"]
    assert len(modes) == 6 and len(expected["launcher"]) == 32 and len(expected["shared_calibrations"]) == 26
    names = ["launcher-list", "consumer-models", "full-library", "shared-calibrations"] + [m["cohort"] for m in modes]
    environment = dict(PATH="/usr/bin:/bin", LC_ALL="C", PYTHONDONTWRITEBYTECODE="1", RUST_TEST_THREADS="1")
    steps = []
    for name in names + ["final-audit"]:
        env = dict(environment)
        cohort = next((m for m in modes if m["cohort"] == name), None)
        if name == "launcher-list":
            argv = [binaries["consumer-launcher"]["path"], "--list"]
        elif name == "consumer-models":
            argv = [binaries["consumer-unit-tests"]["path"], "generated_unwind::tests::", "--test-threads=1"]
        elif name == "full-library":
            argv = [binaries["consumer-unit-tests"]["path"], "--test-threads=1"]
        elif name == "shared-calibrations":
            argv = [binaries["consumer-calibrations"]["path"], "--test-threads=1"]
        elif name == "final-audit":
            argv = [data["tools"]["helper_python"]["path"], "-B", str(out / "entry.py"), "audit", sha(out / "source-files.json")]
        else:
            assert cohort is not None
            argv = [binaries["consumer-launcher"]["path"], cohort["test"], "--exact", "--test-threads=1", "--nocapture"]
            env.update(LITEINST_UNWIND_CONSUMER_MAIN_THREAD_DRIVER=binaries["consumer-main"]["path"],
                       LITEINST_UNWIND_CONSUMER_MAIN_THREAD_CAPTURES=str(out / "run/captures" / name),
                       UW_LIBGCC_FILE=libgcc["path"], UW_LIBGCC_SNAPSHOT=copied["path"])
        capture = out / ("audit-output" if name == "final-audit" else "run")
        qp = out / "requests" / (name + ".request.json")
        q = request(argv, capture, name, env, 30 if cohort else 20, 45 if cohort else 30, 16 * 1024 * 1024)
        save(qp, q)
        step = dict(name=name, request=str(qp), request_sha256=sha(qp),
                    receipt=str(capture / (name + ".receipt.json")),
                    helper_stdout=str(capture / (name + ".helper.stdout")),
                    helper_stderr=str(capture / (name + ".helper.stderr")))
        if cohort:
            step.update(cohort)
        steps.append(step)
    save(out / "plan.json", dict(serial=True, output_directory=str(out / "run"), steps=steps[:-1], final_audit=steps[-1],
         qualification_scope="BacktraceOnly; original frameless and frame-pointer rows, two fixed states",
         ordinary_parity="fresh fixed 72-row active-consumer parity remains a separate required gate"))
    assert verify(frozen, digest) == data and sha(review) == review_sha
    for row in binding["binaries"].values():
        check_binary(row)
    assert files(build_dir) == dict(build_audit["files"], **{"build-audit.json": sha(build_dir / "build-audit.json")})
    save(out / "manifest.json", dict(status="FROZEN_PUBLIC_CONSUMER_RUNTIME_REVIEW_REQUIRED", files=files(out),
         references=refs, fixed_commands=10, fixed_native_modes=6, separate_final_audit=True,
         native_executed=False, no_prior_failure_credit=True))
    print("RUNTIME_REVIEW_REQUIRED", sha(out / "manifest.json"), "SOURCE", sha(out / "source-files.json"), flush=True)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="phase", required=True)
    p = sub.add_parser("freeze")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--toolchain", type=Path, required=True)
    p.add_argument("--admission", type=Path, required=True)
    p.add_argument("--admission-sha256", required=True)
    for phase in ("build", "runtime"):
        p = sub.add_parser(phase)
        p.add_argument("--output", type=Path, required=True)
        p.add_argument("--freeze-sha256", required=True)
        if phase == "runtime":
            p.add_argument("--review", type=Path, required=True)
            p.add_argument("--review-sha256", required=True)
            p.add_argument("--admission", type=Path, required=True)
            p.add_argument("--admission-sha256", required=True)
    args = parser.parse_args()
    out = args.output.absolute()
    assert out == out.resolve() and out.is_relative_to(ROOT / "ignored")
    if args.phase == "freeze":
        freeze(out, args.toolchain, args.admission, args.admission_sha256)
    elif args.phase == "build":
        build(out, args.freeze_sha256)
    else:
        runtime(out, args.freeze_sha256, args.review, args.review_sha256, args.admission, args.admission_sha256)


if __name__ == "__main__":
    main()
