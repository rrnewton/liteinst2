#!/usr/bin/env python3
"""Bind active Cargo artifacts to the fixed Word witnesses, in separate phases.

The copied bounded_command helper owns process cleanup. This adapter neither
implements a supervisor nor executes generated machine code itself.
"""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import argparse
import errno
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


def freeze(out, toolchain):
    assert out.is_relative_to(ROOT / "ignored") and not out.exists()
    assert sha(HERE / "bounded_command.py") == HELPER_SHA
    config = read(toolchain)
    assert set(config) == {"tools", "files"}
    expected = {"cargo", "rustc", "gcc", "linker", "assembler", "helper_python", "timeout"}
    assert set(config["tools"]) == expected
    assert 1 <= len(config["files"]) <= 4096
    tools = {name: identity(path) for name, path in config["tools"].items()}
    tools["helper"] = identity(HERE / "bounded_command.py")
    assert Path(tools["cargo"]["resolved_path"]).name == "cargo"
    assert Path(tools["rustc"]["resolved_path"]).name == "rustc"
    assert Path(tools["cargo"]["resolved_path"]).parent == Path(tools["rustc"]["resolved_path"]).parent
    assert Path(tools["linker"]["resolved_path"]).name == "ld.bfd"
    tool_files = [identity(path) for path in config["files"]]
    assert len({r["path"] for r in tool_files}) == len(tool_files)
    assert {r["resolved_path"] for r in tools.values()} - {tools["helper"]["resolved_path"]} <= {r["resolved_path"] for r in tool_files}
    sources = source_files()
    assert "src/patcher/synchronized.rs" in sources and "src/patcher/synchronized/tests.rs" in sources
    out.mkdir()
    (out / "sources").mkdir()
    (out / "tmp").mkdir()
    for name in sources:
        copy_exact(ROOT / name, out / "sources" / name)
    copy_exact(Path(toolchain).resolve(), out / "toolchain.json")
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
               RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="", CARGO_ENCODED_RUSTFLAGS="",
               TMPDIR=str(out / "tmp"), CARGO_PROFILE_DEV_CODEGEN_UNITS="1", CARGO_PROFILE_TEST_CODEGEN_UNITS="1")
    for path, row in configs.items():
        if row is not None and row.get("kind") == "unreadable":
            assert configuration_presence(path) == row, path
    save(out / "freeze.json", dict(status="FROZEN_SOURCE_ONLY_NO_BUILD", root=str(ROOT), adapter=str(HERE),
         source_files=sources, toolchain_sha256=sha(out / "toolchain.json"), tools=tools,
         toolchain_files=tool_files, cargo_configuration=configs, environment=env, target=str(ROOT / "target")))
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


def bind_binary(out, name, source, data):
    path, dep = out / name, out / (name + ".d")
    raw = regular(path).read_bytes()
    assert raw[:7] == b"\x7fELF\x02\x01\x01" and len(raw) > 4096
    assert struct.unpack_from("<H", raw, 18)[0] == 62
    assert struct.unpack_from("<H", raw, 16)[0] in {2, 3}
    rules, environment = dep_rules(dep)
    assert environment == []
    expected = {str(HERE / source)}
    if name != "baseline":
        expected |= {str(HERE / "neighbors.rs")} | {str(ROOT / "tests/support" / n) for n in SUPPORT}
    # rustc may retain literal ../ components. Resolve only source path spelling,
    # not data, machine addresses or architectural-state values.
    nonempty = {t: v for t, v in rules.items() if v}
    empty = {t for t, v in rules.items() if not v}
    assert set(nonempty) == {str(path), str(dep)}
    assert {str(Path(t).resolve()) for t in empty} == expected
    for values in nonempty.values():
        assert len(values) == len(expected) and {str(Path(v).resolve()) for v in values} == expected
    sources = {v: data["source_files"][str(Path(v).relative_to(ROOT))] for v in sorted(expected)}
    path.chmod(0o555)
    return dict(identity(path), source_dependencies=sources, depfile_sha256=sha(dep),
                request_sha256=sha(out / ("compile-" + name + ".request.json")),
                receipt_sha256=sha(out / ("compile-" + name + ".receipt.json")))


def build(frozen, digest):
    data = verify(frozen, digest)
    out = frozen / "build"
    out.mkdir()
    steps = []
    try:
        tools, env = data["tools"], data["environment"]
        argv = [tools["cargo"]["path"], "build", "--offline", "--locked", "--lib", "-p", "liteinst2", "--message-format=json"]
        run_one(frozen, digest, out, "cargo", request(argv, out, "cargo", env, 60, 90, 128 * 1024 * 1024), steps)
        externs = archive_cargo(out, data)
        binaries = {}
        for name, source, test in [("baseline", "baseline.rs", False), ("native", "strict.rs", False), ("calibrations", "strict.rs", True)]:
            for row in read(out / "cargo-binding.json")["archives"].values():
                check_identity(row["copied"])
            argv = [tools["rustc"]["path"], "--edition=2024", "--crate-name", "word_sync_" + name, str(HERE / source),
                    "-D", "warnings", "-D", "unsafe_op_in_unsafe_fn", "-C", "codegen-units=1", "-C", "opt-level=0",
                    "-C", "debuginfo=2", "-C", "debug-assertions=on", "-C", "overflow-checks=on",
                    "-C", "linker=" + tools["gcc"]["path"], "-C", "link-arg=-fuse-ld=bfd",
                    "--extern", "liteinst2=" + externs["liteinst2"], "--extern", "libc=" + externs["libc"],
                    "-L", "dependency=" + str(out / "archives"), "--emit=link,dep-info=" + str(out / (name + ".d")), "-o", str(out / name)]
            if test:
                argv.append("--test")
            run_one(frozen, digest, out, "compile-" + name, request(argv, out, "compile-" + name, env, 60, 90, 128 * 1024 * 1024), steps)
            assert (out / ("compile-" + name + ".stdout")).read_bytes() == b""
            assert (out / ("compile-" + name + ".stderr")).read_bytes() == b""
            for row in read(out / "cargo-binding.json")["archives"].values():
                check_identity(row["copied"])
            binaries[name] = bind_binary(out, name, source, data)
        assert verify(frozen, digest) == data
        save(out / "binary-binding.json", dict(binaries=binaries, freeze_sha256=digest,
             cargo_binding_sha256=sha(out / "cargo-binding.json"), native_executed=False))
        save(out / "build-audit.json", dict(status="BUILT_REVIEW_REQUIRED_NO_EXECUTION", freeze_sha256=digest,
             binaries=binaries, files=files(out), steps=steps, native_executed=False))
        print("BUILT_REVIEW_REQUIRED_NO_EXECUTION", sha(out / "build-audit.json"), flush=True)
    except BaseException as error:
        save(out / "failed-incomplete.json", dict(status="FAILED_INCOMPLETE_NO_BUILD_PASS", error=repr(error),
             steps=steps, cleanup_claimed=False, files=files(out)))
        raise


def runtime(frozen, digest, review, review_sha):
    data = verify(frozen, digest)
    assert sha(review) == review_sha
    build_dir = frozen / "build"
    audit = read(build_dir / "build-audit.json")
    assert audit["status"] == "BUILT_REVIEW_REQUIRED_NO_EXECUTION" and audit["freeze_sha256"] == digest
    assert files(build_dir) == dict(audit["files"], **{"build-audit.json": sha(build_dir / "build-audit.json")})
    binding = read(build_dir / "binary-binding.json")
    assert binding["binaries"] == audit["binaries"]
    for row in binding["binaries"].values():
        assert identity(row["path"]) == {k: row[k] for k in ("path", "resolved_path", "sha256", "stat")}
    out = frozen / "runtime"
    out.mkdir()
    (out / "requests").mkdir()
    for p in sorted((HERE / "runtime").glob("*.py")):
        copy_exact(p, out / p.name)
    for n in ("inventory.json", "baseline-expected.json"):
        copy_exact(HERE / n, out / n)
    save(out / "source-files.json", {p.name: sha(p) for p in sorted(out.glob("*.py"))})
    refs = {str(ROOT / n): h for n, h in data["source_files"].items()}
    refs[str(frozen / "freeze.json")] = digest
    refs[str(build_dir / "cargo-binding.json")] = sha(build_dir / "cargo-binding.json")
    refs[str(frozen / "toolchain.json")] = data["toolchain_sha256"]
    for path, row in data["cargo_configuration"].items():
        if row is not None and row.get("kind") != "unreadable":
            refs[path] = row["sha256"]
    source_identities = [row["original"] for dep in read(build_dir / "cargo-binding.json")["depfiles"].values() for row in dep["sources"]]
    source_identities += [owner["manifest"] for owner in read(build_dir / "cargo-binding.json")["package_owners"].values()]
    inputs = dict(references=refs, absent_configuration=[p for p, row in data["cargo_configuration"].items() if row is None], identities=data["toolchain_files"] + source_identities,
         unreadable_configuration={p: row for p, row in data["cargo_configuration"].items() if row is not None and row.get("kind") == "unreadable"},
         tools=data["tools"], binaries=binding["binaries"], build_audit=str(build_dir / "build-audit.json"),
         build_audit_sha256=sha(build_dir / "build-audit.json"), build_files=audit["files"],
         binary_binding=str(build_dir / "binary-binding.json"), binary_binding_sha256=sha(build_dir / "binary-binding.json"),
         review=dict(path=str(Path(review).resolve()), sha256=review_sha))
    save(out / "inputs.json", inputs)
    env = dict(PATH="/usr/bin:/bin", LC_ALL="C", PYTHONDONTWRITEBYTECODE="1", RUST_TEST_THREADS="1")
    modes = read(out / "inventory.json")["native_modes"]
    names = ["baseline-" + n for n in ["positive", "deny-1", "deny-2", "deny-3"]] + ["auditor-calibrations", "calibration-list", "calibrations"] + [m["name"] for m in modes]
    assert len(names) == len(set(names)) == 20
    rows = {}
    for name in names:
        if name.startswith("baseline-"):
            key = name.removeprefix("baseline-")
            argv = [binding["binaries"]["baseline"]["path"]] + ([] if key == "positive" else [key])
        elif name == "auditor-calibrations":
            argv = [data["tools"]["helper_python"]["path"], "-B", str(out / "entry.py"), name, sha(out / "source-files.json")]
        elif name == "calibration-list":
            argv = [binding["binaries"]["calibrations"]["path"], "--list"]
        elif name == "calibrations":
            argv = [binding["binaries"]["calibrations"]["path"], "--test-threads=1"]
        else:
            argv = [binding["binaries"]["native"]["path"]] + (["neighbors"] if name == "neighbors" else name.split("-"))
        qp = out / "requests" / (name + ".request.json")
        q = request(argv, out / "run", name, env, 20, 30, 1048576)
        save(qp, q)
        rows[name] = dict(request=str(qp.relative_to(out)), request_sha256=sha(qp), receipt=str(out / "run" / (name + ".receipt.json")))
    save(out / "plan.json", dict(cwd=str(ROOT), environment=env, order=names, requests=rows))
    save(out / "manifest.json", dict(status="FROZEN_ACTIVE_RUNTIME_REVIEW_REQUIRED_NOT_EXECUTED", files=files(out)))
    print("RUNTIME_REVIEW_REQUIRED", sha(out / "manifest.json"), "SOURCE", sha(out / "source-files.json"), flush=True)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="phase", required=True)
    p = sub.add_parser("freeze")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--toolchain", type=Path, required=True)
    p = sub.add_parser("build")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--freeze-sha256", required=True)
    p = sub.add_parser("runtime")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--freeze-sha256", required=True)
    p.add_argument("--review", type=Path, required=True)
    p.add_argument("--review-sha256", required=True)
    args = parser.parse_args()
    out = args.output.absolute()
    assert out == out.resolve() and out.is_relative_to(ROOT / "ignored")
    if args.phase == "freeze":
        freeze(out, args.toolchain)
    elif args.phase == "build":
        build(out, args.freeze_sha256)
    else:
        runtime(out, args.freeze_sha256, args.review, args.review_sha256)


if __name__ == "__main__":
    main()
