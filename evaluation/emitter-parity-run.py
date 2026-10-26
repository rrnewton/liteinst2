#!/usr/local/bin/python3
"""Run the finite static emitter comparison; never execute generated images."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import time
import tomllib

BASE = "474094a7355c14c673f794cf34aa63d53566f030"
MATERIALS = "eb60007d14812cca7d01d19cbc7c6b29702c7591f2347fb1ebbb33da9e780172"
PYTHON = "/usr/local/bin/python3"
HELPER_PYTHON = "/usr/bin/python3.9"


def digest(path):
    with Path(path).open("rb") as stream:
        result = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
        return result.hexdigest()


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def identity(path):
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return {"exists": False}
    resolved = path.resolve(strict=True)
    link = path.lstat()
    with resolved.open("rb") as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode)
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
        after = os.fstat(stream.fileno())
    fields = lambda row: [row.st_dev, row.st_ino, row.st_mode, row.st_size,
                          row.st_mtime_ns, row.st_ctime_ns]
    assert fields(before) == fields(after) == fields(resolved.stat())
    return {"exists": True, "resolved": str(resolved), "lstat": fields(link),
            "stat": fields(after), "sha256": value.hexdigest()}


def file_map(directory):
    result = {}
    for path in sorted(directory.rglob("*")):
        assert not path.is_symlink(), path
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = digest(path)
        else:
            assert path.is_dir(), path
    return result


def main():
    if sys.flags.optimize:
        raise SystemExit("Assertions required")
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("raw", "toolchain", "user-home", "cargo-home"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    git = lambda *argv: subprocess.check_output(
        ["/usr/bin/git", "-C", str(repo), *argv], timeout=15)
    assert git("rev-parse", "--show-toplevel").decode().strip() == str(repo)
    revision = git("rev-parse", "HEAD").decode().strip()
    assert re.fullmatch("[0-9a-f]{40}", revision) and revision != BASE
    assert not git("diff", "HEAD", "--"), "exact clean tracked candidate required"
    names = [n for n in git("ls-files", "-z").decode().split("\0") if n]
    assert "evaluation/emitter-parity-run.py" in names
    helper = repo / "tools/unwind-oracle/bounded_command.py"
    materials = repo / "evaluation/emitter-parity"
    assert str(helper.relative_to(repo)) in names
    assert digest(materials / "materials.json") == MATERIALS
    material = json.loads((materials / "materials.json").read_text())
    assert {p.name for p in materials.iterdir()} == set(material) | {"materials.json"}
    for name, expected in material.items():
        assert "evaluation/emitter-parity/" + name in names
        assert (materials / name).is_file() and not (materials / name).is_symlink()
        assert digest(materials / name) == expected
    raw = args.raw
    assert raw.is_absolute() and raw.parent.resolve(strict=True) == raw.parent
    assert raw.is_relative_to(repo / "ignored") and not raw.exists() and not raw.is_symlink()
    for path in (args.toolchain, args.user_home, args.cargo_home):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    raw.mkdir()
    tool = args.toolchain / "bin"
    target = repo / "target"
    runtime = {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
    build = dict(runtime, PATH=str(tool) + ":/usr/bin:/bin", HOME=str(args.user_home),
                 CARGO_HOME=str(args.cargo_home), CARGO_NET_OFFLINE="true",
                 CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="4", CARGO_TARGET_DIR=str(target),
                 RUSTC=str(tool / "rustc"), RUSTDOC=str(tool / "rustdoc"),
                 RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="", RUST_TEST_THREADS="1")
    selected = [tool / n for n in ("cargo", "rustc", "rustdoc")]
    selected += [Path(p) for p in (PYTHON, HELPER_PYTHON, "/usr/bin/git", "/usr/bin/timeout",
                                  "/usr/bin/cc", "/usr/bin/ld", "/etc/ld.so.cache")]
    for lookup in ("git", "cc", "ld"):
        assert not (tool / lookup).exists() and not (tool / lookup).is_symlink()
    configs = {args.cargo_home / name for name in ("config", "config.toml")}
    for owner in [raw, *raw.parents, raw / "prepared", raw / "prepared/old", raw / "prepared/new"]:
        configs.update(owner / ".cargo" / name for name in ("config", "config.toml"))
    selected += sorted(configs)
    source = {n: {"sha256": digest(repo / n), "mode": stat.S_IMODE((repo / n).stat().st_mode)} for n in names}
    tools = {str(p): identity(p) for p in selected}
    save(raw / "source.json", {"revision": revision, "files": source})
    save(raw / "tools-and-configs.json", tools)
    cpu = Path("/proc/cpuinfo").read_text()
    save(raw / "hardware.json", {"cpu_model": next(x.split(":", 1)[1].strip() for x in cpu.splitlines() if x.startswith("model name")),
                                "architecture": platform.machine(), "logical_cpus": os.cpu_count(),
                                "kernel_release": platform.release(), "libc": platform.libc_ver()})
    stages = ["version-rustc", "version-cargo", "version-python", "version-helper-python", "prepare"]
    for side in ("old", "new"):
        stages += [side + "-" + suffix for suffix in
                   ("unit-compile", "list", "capture-58", "capture-current", "library", "link-28", "capture-28")]
    stages += ["compare-28", "compare-58", "compare-current"]
    assert len(stages) == 22
    save(raw / "stage-inventory.json", stages)
    results, archived, prepared = [], {}, None

    def closure():
        assert git("rev-parse", "HEAD").decode().strip() == revision
        assert not git("diff", "HEAD", "--")
        assert [n for n in git("ls-files", "-z").decode().split("\0") if n] == names
        current_source = {n: {"sha256": digest(repo / n), "mode": stat.S_IMODE((repo / n).stat().st_mode)} for n in names}
        current_tools = {str(p): identity(p) for p in selected}
        assert current_source == source and current_tools == tools
        for path, expected in archived.items():
            assert digest(path) == expected, path
        snapshots = {}
        if prepared is not None:
            for side in ("old", "new"):
                snapshots[side] = file_map(Path(prepared[side]["directory"]))
                assert snapshots[side] == prepared[side]["prepared_sha256"]
        return {"revision": revision, "source": current_source, "tools_and_configs": current_tools,
                "prepared": snapshots, "immutable_archives": dict(archived)}

    def execute(name, argv, env, compiler=False):
        assert name == stages[len(results)]
        directory = raw / name
        directory.mkdir()
        (directory / "tmp").mkdir()
        before = closure()
        save(directory / "before.json", before)
        request = dict(argv=argv, cwd=str(repo), env=dict(env, TMPDIR=str(directory / "tmp")),
                       stdout=str(directory / "stdout"), stderr=str(directory / "stderr"),
                       cpu_seconds=60 if compiler else 20, wall_seconds=90 if compiler else 30,
                       file_bytes=(128 if compiler else 16) * 1024 * 1024)
        save(directory / "request.json", request)
        outer = ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s", "100s" if compiler else "40s",
                 HELPER_PYTHON, "-B", str(helper), "--request", str(directory / "request.json"),
                 "--receipt", str(directory / "receipt.json")]
        deadline = 115 if compiler else 55
        save(directory / "outer.json", {"argv": outer, "cwd": str(repo), "env": runtime,
                                        "parent_timeout_seconds": deadline})
        start = time.monotonic()
        with (directory / "helper.stdout").open("xb") as out, (directory / "helper.stderr").open("xb") as err:
            child = subprocess.Popen(outer, cwd=repo, env=runtime, stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=err, start_new_session=True)
            timed_out = False
            try:
                code = child.wait(timeout=deadline)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(child.pid, signal.SIGKILL)
                code = child.wait()
        row = {"name": name, "exit": code, "parent_timeout": timed_out,
               "elapsed_seconds": time.monotonic() - start,
               "request_sha256": digest(directory / "request.json"),
               "outer_sha256": digest(directory / "outer.json")}
        results.append(row)
        save(directory / "result.json", row)
        after = closure()
        save(directory / "after.json", after)
        assert after == before
        assert code == 0 and not timed_out, "failed phase retained; no retry or later stage"
        receipt = json.loads((directory / "receipt.json").read_text())
        assert set(receipt) == {"request_sha256", "helper_sha256", "exit", "wall_timeout",
            "unexpected_descendants", "absence_proof", "stdout_sha256", "stderr_sha256", "elapsed_seconds",
            "cleanup_events", "cleanup_error", "aborted", "inputs_unchanged"}
        assert type(receipt["exit"]) is int and receipt["exit"] == 0
        assert receipt["wall_timeout"] is False and receipt["inputs_unchanged"] is True
        assert type(receipt["elapsed_seconds"]) in (int, float) and math.isfinite(receipt["elapsed_seconds"]) and receipt["elapsed_seconds"] >= 0
        assert receipt["request_sha256"] == row["request_sha256"] and receipt["helper_sha256"] == digest(helper)
        assert receipt["absence_proof"] == "ECHILD" and receipt["unexpected_descendants"] == []
        assert receipt["cleanup_events"] == [] and receipt["cleanup_error"] is None and receipt["aborted"] is None
        expected = {"exit": 0, "wall_timeout": False, "absence_proof": "ECHILD", "descendants": 0, "success": True}
        assert (directory / "helper.stdout").read_text() == json.dumps(expected) + "\n"
        assert not (directory / "helper.stderr").read_bytes()
        for stream in ("stdout", "stderr"):
            assert receipt[stream + "_sha256"] == digest(directory / stream)
        print(name + ": closed", flush=True)
        return directory

    def retain(source_path, destination):
        source_path = Path(source_path)
        assert source_path.is_file() and not source_path.is_symlink()
        before = identity(source_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with source_path.open("rb") as original, destination.open("xb") as copy:
            while block := original.read(1024 * 1024):
                copy.write(block)
        destination.chmod(0o500 if os.access(source_path, os.X_OK) else 0o400)
        assert identity(source_path) == before and digest(destination) == before["sha256"]
        archived[str(destination)] = before["sha256"]
        return {"source": str(source_path), "source_identity": before,
                "copy": str(destination), "sha256": before["sha256"]}

    def cargo_artifacts(directory, side, test):
        rows = [json.loads(line) for line in (directory / "stdout").read_text().splitlines()]
        assert 1 <= len(rows) <= 256 and rows[-1] == {"reason": "build-finished", "success": True}
        assert sum(row["reason"] == "build-finished" for row in rows) == 1
        assert all(row["reason"] in {"compiler-artifact", "build-script-executed", "build-finished"} for row in rows)
        assert not any(re.match(r"(?:warning|error)(?:\[|:)", line) for line in (directory / "stderr").read_text().splitlines())
        source_dir = Path(prepared[side]["directory"])
        name = prepared[side]["library_target"]
        selected_rows = [row for row in rows if row["reason"] == "compiler-artifact" and row["target"]["name"] == name]
        assert len(selected_rows) == 1
        item = selected_rows[0]
        package = tomllib.loads((source_dir / "Cargo.toml").read_text())["package"]
        assert item["manifest_path"] == str(source_dir / "Cargo.toml")
        assert item["package_id"] in {"path+" + source_dir.as_uri() + "#" + package["version"],
                                      "path+" + source_dir.as_uri() + "#liteinst2@" + package["version"]}
        assert item["target"]["src_path"] == str(source_dir / "src/lib.rs")
        assert item["target"]["kind"] == ["lib"] and item["target"]["crate_types"] == ["lib"]
        assert item["target"]["edition"] == "2024" and item["features"] == [] and item["fresh"] is False
        assert item["profile"] == {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
                                   "overflow_checks": True, "test": test}
        archive = raw / "artifacts" / directory.name
        products = {}
        for row in rows:
            if row["reason"] != "compiler-artifact":
                continue
            for filename in row["filenames"]:
                path = Path(filename)
                assert path.is_absolute() and path.resolve(strict=True) == path and path.is_relative_to(target)
                if filename not in products:
                    products[filename] = retain(path, archive / path.relative_to(target))
        if test:
            actual = Path(item["executable"])
            assert item["filenames"] == [str(actual)] and actual.parent == target / "debug/deps"
            assert actual.name.startswith(name + "-")
            depfile = actual.with_suffix(".d")
            selected_product = products[str(actual)]["copy"]
            with actual.open("rb") as stream:
                assert stream.read(5) == b"\x7fELF\x02"
        else:
            assert item["executable"] is None
            libraries = [Path(n) for n in item["filenames"] if n.endswith(".rlib")]
            assert len(libraries) == 1
            actual = libraries[0]
            assert actual.parent == target / "debug/deps" and actual.name.startswith("lib" + name + "-")
            depfile = actual.with_name(actual.name[3:-5] + ".d")
            selected_product = products[str(actual)]["copy"]
            with actual.open("rb") as stream:
                assert stream.read(8) == b"!<arch>\n"
        # The complete depfile is retained, and its first source rule must name
        # this exact fresh crate. Other source dependencies are bound by the
        # complete prepared-tree pre/post hashes, not filename similarity.
        deptext = depfile.read_text()
        escaped = str(source_dir / "src/lib.rs").replace("\\", "\\\\").replace(" ", "\\ ")
        assert escaped in deptext.splitlines()[0] and deptext.endswith("\n")
        depcopy = retain(depfile, archive / depfile.relative_to(target))
        if test:
            assert "src/emitter_parity.rs" in deptext and "src/parity/current_features.rs" in deptext
        iced = [row for row in rows if row["reason"] == "compiler-artifact" and row["target"]["name"] == "iced_x86"]
        assert len(iced) == 1 and iced[0]["target"]["kind"] == ["lib"]
        locked = tomllib.loads((source_dir / "Cargo.lock").read_text())["package"]
        iced_lock = [row for row in locked if row["name"] == "iced-x86"]
        assert len(iced_lock) == 1
        assert iced[0]["package_id"] == iced_lock[0]["source"] + "#iced-x86@" + iced_lock[0]["version"]
        iced_manifest = Path(iced[0]["manifest_path"])
        assert iced_manifest.resolve(strict=True) == iced_manifest and iced_manifest.is_relative_to(args.cargo_home / "registry/src")
        assert iced[0]["target"]["src_path"] == str(iced_manifest.parent / "src/lib.rs")
        assert iced[0]["target"]["crate_types"] == ["lib"] and iced[0]["executable"] is None
        assert iced[0]["features"] == ["block_encoder", "code_asm", "decoder", "encoder", "instr_info", "lazy_static", "std"]
        assert iced[0]["profile"] == {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
                                     "overflow_checks": True, "test": False}
        iced_libs = [n for n in iced[0]["filenames"] if n.endswith(".rlib")]
        assert len(iced_libs) == 1
        iced_library = Path(iced_libs[0])
        assert iced_library.parent == target / "debug/deps" and iced_library.name.startswith("libiced_x86-")
        iced_depfile = iced_library.with_name(iced_library.name[3:-5] + ".d")
        iced_text = iced_depfile.read_text()
        iced_source = str(iced_manifest.parent / "src/lib.rs").replace("\\", "\\\\").replace(" ", "\\ ")
        assert iced_source in iced_text.splitlines()[0] and iced_text.endswith("\n")
        iced_depcopy = retain(iced_depfile, archive / iced_depfile.relative_to(target))
        record = {"core": item, "selected_copy": selected_product, "iced": iced[0],
                  "iced_copy": products[iced_libs[0]]["copy"], "products": products,
                  "depfile": depcopy, "iced_depfile": iced_depcopy,
                  "iced_manifest_identity": identity(iced_manifest)}
        save(directory / "artifacts.json", record)
        return record

    def pin_capture(directory):
        expected = file_map(directory)
        for name, value in expected.items():
            archived[str(directory / name)] = value
        return expected

    try:
        for name, argv in [("rustc", [str(tool / "rustc"), "-vV"]),
                           ("cargo", [str(tool / "cargo"), "-V"]),
                           ("python", [PYTHON, "--version"]),
                           ("helper-python", [HELPER_PYTHON, "--version"])]:
            execute("version-" + name, argv, runtime)
        preparation = execute("prepare", [PYTHON, "-B", str(materials / "prepare.py"), "--repo", str(repo),
                              "--candidate", revision, "--output", str(raw / "prepared")], runtime)
        prepared = json.loads((raw / "prepared/manifest.json").read_text())
        assert prepared["status"] == "PREPARED_NOT_COMPILED_OR_RUN"
        assert prepared["old"]["revision"] == BASE and prepared["new"]["revision"] == revision
        assert prepared["harness_sha256"] == material
        assert json.loads((preparation / "stdout").read_text()) == {
            "manifest": str(raw / "prepared/manifest.json"), "sha256": digest(raw / "prepared/manifest.json")}
        assert not (preparation / "stderr").read_bytes()
        archived[str(raw / "prepared/manifest.json")] = digest(raw / "prepared/manifest.json")
        assert prepared["old"]["library_target"] != prepared["new"]["library_target"]
        products = {}
        for side in ("old", "new"):
            source_dir = Path(prepared[side]["directory"])
            assert source_dir == raw / "prepared" / side
            compiler = [str(tool / "cargo"), "test", "--offline", "--locked", "--manifest-path",
                        str(source_dir / "Cargo.toml"), "--lib", "--no-run", "--message-format=json"]
            compiled = execute(side + "-unit-compile", compiler, build, compiler=True)
            unit = cargo_artifacts(compiled, side, True)
            executable = unit["selected_copy"]
            listed = execute(side + "-list", [executable, "--list"], runtime)
            listing = (listed / "stdout").read_text()
            match = re.fullmatch(r"((?:[^\n]+: test\n)+)\n([0-9]+) tests, 0 benchmarks\n", listing)
            assert match and not (listed / "stderr").read_bytes()
            tests = match[1].splitlines()
            assert len(tests) == int(match[2]) and len(set(tests)) == len(tests)
            for suffix, test_name, message in [
                ("58", "emitter_parity::capture_extended_live_parity", "static capture complete: 58 fixtures, 48 successes, 10 refusals, 56 images, 138 authenticated pointer operands; no generated execution"),
                ("current", "emitter_parity::current_features::capture_current_features", "current-feature static capture complete: 4 chain/grouped cases, 17 frame images, 2 independent refusals; no generated execution")]:
                assert test_name + ": test" in tests
                output = raw / (side + "-" + suffix)
                assert not output.exists() and not output.is_symlink()
                variable = "LITEINST_EXTENDED_PARITY_OUTPUT" if suffix == "58" else "LITEINST_CURRENT_PARITY_OUTPUT"
                captured = execute(side + "-capture-" + suffix,
                    [executable, test_name, "--exact", "--nocapture", "--test-threads=1"], dict(runtime, **{variable: str(output)}))
                expected = "\nrunning 1 test\ntest " + test_name + " ... " + message + "\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; " + str(len(tests) - 1) + " filtered out; finished in "
                assert re.fullmatch(re.escape(expected) + r"[0-9]+\.[0-9]+s\n\n", (captured / "stdout").read_text())
                assert not (captured / "stderr").read_bytes()
                inventory = pin_capture(output)
                assert len(inventory) == (400 if suffix == "58" else 219)
                save(captured / "output-files.json", inventory)
            library = execute(side + "-library", [str(tool / "cargo"), "build", "--offline", "--locked", "--manifest-path",
                              str(source_dir / "Cargo.toml"), "--lib", "--message-format=json"], build, compiler=True)
            ordinary = cargo_artifacts(library, side, False)
            linked = raw / (side + "-28-program")
            # No target writer intervenes between this closure and the link.
            # --extern names are immutable copies; -L retains the original
            # reviewed command coordinate, with every Cargo product rechecked.
            for record in ordinary["products"].values():
                assert identity(record["source"]) == record["source_identity"]
            for record in (ordinary["depfile"], ordinary["iced_depfile"]):
                assert identity(record["source"]) == record["source_identity"]
            execute(side + "-link-28", [str(tool / "rustc"), "--edition=2024", "-Dwarnings", "-Ccodegen-units=1",
                    str(materials / "capture-28.rs"), "--extern", "liteinst2=" + ordinary["selected_copy"],
                    "--extern", "iced_x86=" + ordinary["iced_copy"], "-L", "dependency=" + str(target / "debug/deps"),
                    "-o", str(linked)], build, compiler=True)
            program = retain(linked, raw / "artifacts" / (side + "-28-program"))
            output = raw / (side + "-28")
            assert not output.exists() and not output.is_symlink()
            captured = execute(side + "-capture-28", [program["copy"], str(output)], runtime)
            assert (captured / "stdout").read_text() == "captured 28 fixtures and 33 exact callback operands\n"
            assert not (captured / "stderr").read_bytes()
            inventory = pin_capture(output)
            assert len(inventory) == 114
            save(captured / "output-files.json", inventory)
            if side == "old":
                save(raw / "old-28-manifest.json", {"head": BASE, "harness_path": str(materials / "capture-28.rs"),
                    "harness_sha256": digest(materials / "capture-28.rs"), "rlib_sha256": digest(ordinary["selected_copy"]),
                    "output_sha256": {str(output / n): value for n, value in inventory.items()}})
                archived[str(raw / "old-28-manifest.json")] = digest(raw / "old-28-manifest.json")
            products[side] = {"unit": unit, "ordinary": ordinary, "program28": program}
            if side == "new":
                for kind in ("unit", "ordinary"):
                    assert products["old"][kind]["core"]["package_id"] != products["new"][kind]["core"]["package_id"]
                    assert products["old"][kind]["core"]["target"]["name"] != products["new"][kind]["core"]["target"]["name"]
                    assert digest(products["old"][kind]["selected_copy"]) != digest(products["new"][kind]["selected_copy"])
        comparisons = {}
        for suffix, script in [("28", "compare-28.py"), ("58", "compare.py"), ("current", "compare-current.py")]:
            argv = [PYTHON, "-B", str(materials / script), str(raw / ("old-" + suffix)), str(raw / ("new-" + suffix)),
                    "--manifest", str(raw / "prepared/manifest.json")]
            if suffix == "28":
                argv += ["--old-capture-manifest", str(raw / "old-28-manifest.json")]
            compared = execute("compare-" + suffix, argv, runtime)
            assert not (compared / "stderr").read_bytes()
            comparisons[suffix] = json.loads((compared / "stdout").read_text())
        assert comparisons["28"]["old_head"] == BASE and comparisons["28"]["current_head"] == revision
        assert len(comparisons["28"]["fixtures"]) == 28 and comparisons["28"]["callback_operands"] == 33
        assert comparisons["28"]["all_non_callback_bytes_and_metadata_equal"] is True
        assert comparisons["58"]["status"] == "EXACT_STATIC_PARITY" and comparisons["58"]["fixtures"] == 58
        assert comparisons["58"]["successes"] == 48 and comparisons["58"]["refusals"] == 10
        assert len(comparisons["58"]["images"]) == 56 and comparisons["58"]["authenticated_operands"] == 138
        assert comparisons["58"]["generated_code_executed"] is False
        assert comparisons["current"]["status"] == "EXACT_CURRENT_FEATURE_STATIC_PARITY"
        assert comparisons["current"]["cases"] == 21 and len(comparisons["current"]["images"]) == 34
        assert comparisons["current"]["independent_refusals"] == 2
        assert comparisons["current"]["callback_operands"] == 17 and comparisons["current"]["dispatcher_operands"] == 3 and comparisons["current"]["control_operands"] == 3
        assert comparisons["current"]["generated_code_executed"] is False
        assert len(results) == len(stages)
        save(raw / "final-closure.json", closure())
        save(raw / "products.json", products)
        save(raw / "files.json", file_map(raw))
        save(raw / "complete.json", {"status": "EXACT_STATIC_PARITY", "old_revision": BASE, "candidate_revision": revision,
             "materials_sha256": MATERIALS, "commands": results, "comparisons": comparisons,
             "generated_code_executed": False, "native_qualification": False,
             "selected_tool_closure_only": True, "files_index_sha256": digest(raw / "files.json")})
        print("PASS static emitter parity: 28 historical, 58 extended, 21 current cases; no generated execution")
    except BaseException as error:
        save(raw / "failed-incomplete.json", {"status": "FAILED_OR_STOPPED_NO_RETRY", "candidate_revision": revision,
             "commands": results, "last_launched_stage": results[-1]["name"] if results else None,
             "next_unlaunched_stage": stages[len(results)] if len(results) < len(stages) else None,
             "launched_command_exit_is_not_output_validation": True,
             "error": type(error).__name__ + ": " + str(error), "generated_code_executed": False})
        raise


if __name__ == "__main__":
    main()
