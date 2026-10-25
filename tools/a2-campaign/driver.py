#!/usr/bin/env python3
"""Explicit freeze, review, then run the fixed 544-input campaign.

No action executes on import. Freeze builds artifacts but runs no native test.
Run requires the reviewed manifest SHA-256. Outputs must remain under ignored/.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import sys
import time
import tomllib

if sys.flags.optimize:
    raise SystemExit("Campaign driver requires normal Python; optimized mode is refused.")

BOX = dict(cpu_cores=1, memory_bytes=256 * 1024**2, pids=32,
           cpu_seconds=60, wall_seconds=180, concurrency=2,
           slice_cpu=2, slice_memory_bytes=1024**3, aggregate_wall_seconds=3600)
CALIBRATIONS = sorted([
    "memory_name_calibration::exact_mapping_kind_is_required",
    "oracle::calibration::rejects_fault_address_corruption",
    "oracle::calibration::rejects_gpr_corruption",
    "oracle::calibration::rejects_defined_flag_corruption",
    "oracle::calibration::rejects_simd_corruption",
    "oracle::calibration::rejects_application_memory_corruption",
    "oracle::calibration::rejects_redzone_corruption",
    "oracle::campaign_initialization_calibration::campaign_initializer_keeps_default_memory_and_flags_exact",
    "oracle::campaign_initialization_calibration::campaign_initializer_matches_independent_memory_vectors_and_flags",
])
SOURCES = ("generate.py", "adapt_samples.py", "audit.py", "extract-samples.py",
           "harness.rs", "boxed-worker.py", "check-resource-box.py", "samples-design.md")
INPUTS = ("generated.json", "cases.rs", "sample-runtime.json", "sample-cases.rs",
          "samples.json", "sample-population.json")
CANCELLATION_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
TERMINATING = False
CGROUP_ROOT = Path("/sys/fs/cgroup")
GIT_EXECUTABLE = None


class Failure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def cancellation(signum, _frame):
    """First termination request unwinds through bounded teardown; later ones wait."""
    global TERMINATING
    if not TERMINATING:
        TERMINATING = True
        raise KeyboardInterrupt(f"Received signal {signum}")


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_new(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def load(path):
    return json.loads(Path(path).read_text())


def bind_git(executable, expected_sha256=None):
    """Select and authenticate a Git tool explicitly, avoiding PATH wrappers."""
    global GIT_EXECUTABLE
    path = Path(executable).resolve(strict=True)
    require(path.is_file() and os.access(path, os.X_OK), "Git executable is not runnable")
    actual = digest(path)
    require(expected_sha256 is None or actual == expected_sha256,
            "Frozen Git executable identity changed")
    GIT_EXECUTABLE = str(path)
    return dict(path=str(path), sha256=actual)


def git_bytes(repo, *args):
    require(GIT_EXECUTABLE is not None, "Git tool must be bound before verification")
    return subprocess.check_output(
        [GIT_EXECUTABLE, "--no-optional-locks", "-c", "core.fsmonitor=false",
         "-c", "core.preloadIndex=false", *args], cwd=repo)


def git(repo, *args):
    return git_bytes(repo, *args).decode().strip()


def private_path(repo, path):
    path = Path(path).resolve()
    require(path.is_relative_to(repo / "ignored") and path != repo / "ignored",
            f"Output/input path must be below this repository's ignored/: {path}")
    return path


def fresh_directory(repo, path):
    path = private_path(repo, path)
    require(not path.exists(), f"Refusing to overwrite an existing directory: {path}")
    path.mkdir(parents=True)
    return path


def environment(repo, output):
    env = dict(os.environ)
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                 "RUSTC_WORKSPACE_WRAPPER", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH",
                 "PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE", "BASH_ENV", "ENV"):
        env.pop(name, None)
    temporary = output / "tmp"
    temporary.mkdir(exist_ok=True)
    target = (repo / "target").resolve()
    require(target.is_relative_to(repo), "Cargo target must stay inside the slot")
    env.update(PYTHONDONTWRITEBYTECODE="1", CARGO_INCREMENTAL="0",
               CARGO_BUILD_JOBS="4", CARGO_TARGET_DIR=str(target),
               CARGO_NET_OFFLINE="true", TMPDIR=str(temporary),
               RUST_TEST_THREADS="1", DAGRUN_ENGINE="python",
               CI_HUB_PYTHON=str(Path(sys.executable).resolve()), PYTHONNOUSERSITE="1",
               PYTHONPYCACHEPREFIX=str(output / "python-cache"),
               DAGRUN_PROFILE_DIR=str(output / "dagrun-profiles"))
    return env


def stop_process(process):
    errors = []
    if process.poll() is not None:
        return errors
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError as error:
        errors.append(f"SIGTERM: {error}")
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            errors.append(f"SIGKILL: {error}")
        try:
            process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired) as error:
            errors.append(f"Final wait: {error}")
    except OSError as error:
        errors.append(f"Initial wait: {error}")
    return errors


def command(argv, *, cwd, env, prefix, timeout):
    """Retain command, stdout, stderr, exit and duration even on failure."""
    global TERMINATING
    prefix = Path(prefix)
    stdout = prefix.with_suffix(".stdout")
    stderr = prefix.with_suffix(".stderr")
    receipt = prefix.with_suffix(".command.json")
    require(not receipt.exists(), f"Command already attempted: {receipt}")
    record = dict(argv=list(map(str, argv)), cwd=str(cwd), timeout_seconds=timeout,
                  start_unix=time.time(), exit="incomplete")
    write_new(receipt, record)
    started = time.monotonic()
    process = None
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            # A pending signal is delivered only after the child handle exists,
            # inside this try, so even cancellation during spawn can reap it.
            old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, CANCELLATION_SIGNALS)
            try:
                process = subprocess.Popen(list(map(str, argv)), cwd=cwd, env=env,
                                           stdout=out, stderr=err, start_new_session=True,
                                           # This driver is single-threaded. Do not
                                           # leave the child's termination signals
                                           # blocked when it enters the runner.
                                           preexec_fn=lambda: signal.pthread_sigmask(
                                               signal.SIG_SETMASK, old_mask))
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
            record["exit"] = process.wait(timeout=timeout)
    except BaseException as error:
        TERMINATING = True
        record["exit"] = "timeout" if isinstance(error, subprocess.TimeoutExpired) else "interrupted-or-error"
        record["error"] = f"{type(error).__name__}: {error}"
        if process is not None:
            record["teardown_errors"] = stop_process(process)
        raise
    finally:
        record["seconds"] = time.monotonic() - started
        if stdout.exists():
            record["stdout_sha256"] = digest(stdout)
        if stderr.exists():
            record["stderr_sha256"] = digest(stderr)
        receipt.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return record, stdout, stderr


def successful(argv, **kwargs):
    result = command(argv, **kwargs)
    require(result[0]["exit"] == 0, f"Command failed; retained receipt: {kwargs['prefix']}")
    return result


def repository_hashes(repo):
    require(git(repo, "diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD") == "", "Tracked checkout must be clean")
    names = git_bytes(repo, "ls-files", "-z").split(b"\0")
    result = {}
    for encoded in names:
        if not encoded:
            continue
        name = os.fsdecode(encoded)
        path = repo / name
        require(path.is_file() and not path.is_symlink(), f"Non-regular tracked source: {name}")
        result[name] = digest(path)
    require("BRIEF-li2core.md" not in result, "Task brief must remain untracked")
    return result


def artifact(records, name, package_id, repo, target):
    candidates = []
    for row in records:
        if row.get("reason") != "compiler-artifact":
            continue
        unit = row["target"]
        if unit["name"] != name or "lib" not in unit["kind"]:
            continue
        if row["profile"]["test"]:
            continue
        require(row["package_id"] == package_id,
                f"Unexpected {name} package identity: {row['package_id']}")
        if name == "liteinst2":
            require(Path(unit["src_path"]).resolve() == repo / "src/lib.rs",
                    "liteinst2 artifact did not come from this exact checkout")
        rlibs = [Path(p).resolve() for p in row["filenames"] if p.endswith(".rlib")]
        require(len(rlibs) == 1 and rlibs[0].is_relative_to(target),
                f"Ambiguous/outside-target {name} rlib")
        candidates.append((row, rlibs[0]))
    require(len(candidates) == 1, f"Expected exactly one fresh Cargo JSON artifact for {name}")
    return candidates[0]


def runner_hashes(runner, source_root):
    source_root = Path(source_root).resolve()
    paths = {Path(runner).resolve(), source_root / "py/bin/parallel-experiment-runner"}
    for directory in ("py/dagrun", "py/parallel_experiment_runner"):
        base = source_root / directory
        require(base.is_dir(), f"Expected installed Python runner source: {base}")
        paths.update(base.rglob("*.py"))
    require(all(p.is_file() for p in paths), "Installed runner source inventory is incomplete")
    return {str(p): digest(p) for p in sorted(paths)}


def runner_binding(runner, source_root):
    launcher = Path(runner).absolute()
    root = Path(source_root).resolve()
    require(launcher.name == "parallel-experiment-runner", "Resolver requires the exact tool basename")
    resolved = launcher.resolve()
    require(resolved == root / "common/bin/engine-resolver",
            "Launcher does not belong to the supplied reviewed runner source root")
    entrypoint = root / "py/bin/parallel-experiment-runner"
    require(entrypoint.is_file(), "Reviewed Python entrypoint is absent")
    return dict(launcher=str(launcher), resolved=str(resolved),
                source_root=str(root), entrypoint=str(entrypoint),
                entrypoint_resolved=str(entrypoint.resolve()))


def freeze(args):
    repo = Path(args.repo).resolve()
    source = Path(args.source_dir).resolve()
    inputs = private_path(repo, args.input_dir)
    require(source.is_relative_to(repo), "Campaign source must be inside this checkout")
    require(source.is_dir() and inputs.is_dir(), "Source/input directory is absent")
    git_tool = bind_git(args.git_executable)
    head = git(repo, "rev-parse", "HEAD")
    tracked = repository_hashes(repo)
    output = fresh_directory(repo, args.output_dir)
    payload = output / "payload"
    copied = payload / "input"
    copied.mkdir(parents=True)
    (payload / "bin").mkdir()
    (payload / "artifacts").mkdir()
    logs = output / "build"
    logs.mkdir()
    env = environment(repo, output)
    originals = {}

    def copy(original, destination):
        original = Path(original).resolve()
        require(original.is_file(), f"Missing reviewed input: {original}")
        before = digest(original)
        shutil.copyfile(original, destination)
        require(digest(destination) == before, "Copy changed bytes")
        originals[str(original)] = before

    for name in SOURCES:
        copy(source / name, copied / name)
    for name in INPUTS:
        copy(inputs / name, copied / name)
    copy(Path(__file__), payload / "driver.py")
    helper_path = re.search(r'#\[path = "([^"]+)"\]\s*mod oracle;',
                            (source / "harness.rs").read_text())
    require(helper_path is not None, "Harness must explicitly identify its shared oracle module")
    helper = (source / helper_path.group(1)).resolve()
    require(helper.is_relative_to(repo) and
            digest(helper) == digest(repo / "tests/support/quiescent_oracle.rs"),
            "Harness support is not byte-identical to the active reviewed helper")
    copy(helper, payload / "oracle.rs")
    sample_binary = Path(args.sample_binary).resolve()
    samples = load(copied / "samples.json")
    require(digest(sample_binary) == samples["binary_sha256"],
            "Pinned sample binary identity changed")
    copy(sample_binary, payload / "sample-binary")
    for name in ("README.md", "README-draft.md"):
        if (source / name).is_file():
            copy(source / name, copied / name)
            break

    generated = load(copied / "generated.json")["cases"]
    sampled = load(copied / "sample-runtime.json")
    require([c["id"] for c in generated] == list(range(512)), "Generated inventory changed")
    require([c["id"] for c in sampled] == list(range(512, 544)), "Sample inventory changed")
    successful([sys.executable, copied / "audit.py"], cwd=repo, env=env,
               prefix=logs / "static-audit", timeout=30)
    cargo = shutil.which("cargo")
    rustc = shutil.which("rustc")
    require(cargo and rustc, "Cargo and rustc must be available")
    successful([git_tool["path"], "--version"], cwd=repo, env=env,
               prefix=logs / "git-version", timeout=30)
    successful([rustc, "-Vv"], cwd=repo, env=env, prefix=logs / "rustc-version", timeout=30)
    successful([cargo, "-V"], cwd=repo, env=env, prefix=logs / "cargo-version", timeout=30)
    _, cargo_json, _ = successful(
        [cargo, "build", "--lib", "--package", "liteinst2", "--locked", "--offline",
         "--message-format=json"], cwd=repo, env=env, prefix=logs / "cargo-build", timeout=180)
    records = [json.loads(line) for line in cargo_json.read_text().splitlines() if line.strip()]
    require(any(r.get("reason") == "build-finished" and r["success"] for r in records),
            "Cargo omitted successful build-finished")
    package = tomllib.loads((repo / "Cargo.toml").read_text())["package"]
    lock = tomllib.loads((repo / "Cargo.lock").read_text())
    libc_packages = [p for p in lock["package"] if p["name"] == "libc"]
    require(len(libc_packages) == 1, "Ambiguous locked libc package")
    locked_libc = libc_packages[0]
    require(locked_libc.get("source") == "registry+https://github.com/rust-lang/crates.io-index"
            and re.fullmatch("[0-9a-f]{64}", locked_libc.get("checksum", "")),
            "libc must retain its exact checksummed registry source")
    package_ids = {"liteinst2": f"path+{repo.as_uri()}#liteinst2@{package['version']}",
                   "libc": f"{locked_libc['source']}#libc@{locked_libc['version']}"}
    selected = {}
    for name, package_id in package_ids.items():
        row, path = artifact(records, name, package_id, repo, (repo / "target").resolve())
        destination = payload / "artifacts" / path.name
        copy(path, destination)
        selected[name] = dict(package_id=row["package_id"], target=row["target"],
                              profile=row["profile"], features=row["features"],
                              path=str(path), archived=str(destination.relative_to(output)),
                              sha256=digest(path))
    env["LITEINST_A2_CAMPAIGN_INPUT_DIR"] = str(copied)
    common = [rustc, "--edition=2024", "--crate-name", "a2_campaign", "-D", "warnings",
              "-C", "opt-level=0", "-C", "debug-assertions=yes",
              "-C", "overflow-checks=yes", "-C", "codegen-units=4",
              "-L", f"dependency={repo / 'target/debug/deps'}"]
    for name in ("liteinst2", "libc"):
        common += ["--extern", f"{name}={output / selected[name]['archived']}"]
    for name, extra in (("campaign", []), ("calibrations", ["--test"])):
        successful(common + extra + [source / "harness.rs", "-o", payload / "bin" / name],
                   cwd=repo, env=env, prefix=logs / f"compile-{name}", timeout=180)
    require(git(repo, "rev-parse", "HEAD") == head and repository_hashes(repo) == tracked,
            "Checkout changed during artifact construction")
    require(all(digest(path) == value for path, value in originals.items()),
            "Source/table/artifact changed during freeze")
    binding = runner_binding(args.runner, args.runner_source_root)
    manifest = dict(schema=1, phase="FROZEN_NOT_EXECUTED", repository=str(repo), head=head,
                    tracked_sha256=tracked, original_inputs_sha256=originals,
                    payload_sha256={str(p.relative_to(output)): digest(p)
                                    for p in sorted(payload.rglob("*")) if p.is_file()},
                    build_sha256={str(p.relative_to(output)): digest(p)
                                  for p in sorted(logs.iterdir()) if p.is_file()},
                    driver_sha256=digest(Path(__file__)), git_tool=git_tool,
                    artifacts=selected, locked_libc=locked_libc,
                    runner=binding["launcher"], runner_binding=binding,
                    runner_source_sha256=runner_hashes(args.runner, args.runner_source_root),
                    python=str(Path(sys.executable).resolve()),
                    python_sha256=digest(Path(sys.executable)), python_version=sys.version,
                    box=BOX, expected_calibrations=CALIBRATIONS,
                    case_ids=list(range(544)),
                    input_sha256={str(c["id"]): c["input_sha256"] for c in generated + sampled},
                    calibration_ramp=[[0], [1, 2]], remaining_ids=list(range(3, 544)),
                    estimated_serial_minutes=[10, 30], estimate_is_measured=False)
    write_new(output / "manifest.json", manifest)
    for path in payload.rglob("*"):
        if path.is_file():
            path.chmod(0o555 if path.parent.name == "bin" else 0o444)
    print(json.dumps(dict(freeze=str(output), manifest_sha256=digest(output / "manifest.json"),
                         phase="BUILD_ONLY_NO_NATIVE_EXECUTION"), indent=2))


def verify(frozen, expected):
    frozen = Path(frozen).resolve()
    require(re.fullmatch("[0-9a-f]{64}", expected) is not None, "Require reviewed manifest SHA-256")
    require(digest(frozen / "manifest.json") == expected, "Reviewed manifest hash changed")
    manifest = load(frozen / "manifest.json")
    require(manifest["schema"] == 1 and manifest["box"] == BOX, "Frozen execution contract changed")
    require(manifest["case_ids"] == list(range(544)), "Fixed input denominator changed")
    require(manifest["expected_calibrations"] == CALIBRATIONS, "Calibration set changed")
    require(digest(Path(__file__)) == manifest["driver_sha256"], "Driver differs from frozen source")
    repo = Path(manifest["repository"])
    require(bind_git(manifest["git_tool"]["path"], manifest["git_tool"]["sha256"])
            == manifest["git_tool"], "Git binding differs from frozen identity")
    private_path(repo, frozen)
    require(git(repo, "rev-parse", "HEAD") == manifest["head"], "Library HEAD changed")
    require(repository_hashes(repo) == manifest["tracked_sha256"], "Tracked source identity changed")
    actual = {str(p.relative_to(frozen)) for p in (frozen / "payload").rglob("*") if p.is_file()}
    require(actual == set(manifest["payload_sha256"]), "Frozen payload inventory changed")
    for name, value in manifest["payload_sha256"].items():
        path = (frozen / name).resolve()
        require(path.is_relative_to(frozen / "payload"), "Payload path escaped freeze")
        require(digest(path) == value, f"Frozen payload changed: {name}")
    for name, value in manifest["build_sha256"].items():
        path = (frozen / name).resolve()
        require(path.is_relative_to(frozen / "build"), "Build receipt escaped freeze")
        require(digest(path) == value, f"Frozen build receipt changed: {name}")
    require(runner_binding(manifest["runner"], manifest["runner_binding"]["source_root"])
            == manifest["runner_binding"], "Runner launcher/entrypoint symlink binding changed")
    require(runner_hashes(manifest["runner"], manifest["runner_binding"]["source_root"])
            == manifest["runner_source_sha256"], "Installed runner source bytes/inventory changed")
    require(digest(manifest["python"]) == manifest["python_sha256"], "Python identity changed")
    require(Path(sys.executable).resolve() == Path(manifest["python"]) and
            sys.version == manifest["python_version"], "Driver is not using the frozen Python")
    return manifest


def effective_box():
    line = next(s for s in Path("/proc/self/cgroup").read_text().splitlines() if s.startswith("0::"))
    root = CGROUP_ROOT.resolve()
    group = (root / line[3:].lstrip("/")).resolve()
    require(group.is_relative_to(root) and re.fullmatch(r"step-seed\.\d+", group.name),
            "Worker is not inside its delegated seed cgroup")
    require(re.fullmatch(r"parallel-experiment-.+\.scope", group.parent.name),
            "Worker is not owned by the installed runner scope")
    rows = []
    current = group
    while True:
        row = {"group": str(current)}
        for name in ("cpu.max", "memory.max", "pids.max"):
            path = current / name
            row[name] = path.read_text().strip() if path.exists() else None
        rows.append(row)
        if current == root:
            break
        current = current.parent
    require(any(r["pids.max"] not in (None, "max") and 0 < int(r["pids.max"]) <= BOX["pids"]
                for r in rows), "PID cap absent/too loose")
    require(any(r["memory.max"] not in (None, "max") and
                0 < int(r["memory.max"]) <= BOX["memory_bytes"] for r in rows),
            "Memory cap absent/too loose")
    require(any(r["cpu.max"] and r["cpu.max"].split()[0] != "max" and
                0 < int(r["cpu.max"].split()[0]) <= int(r["cpu.max"].split()[1])
                for r in rows), "CPU quota absent/too loose")
    return rows


def inode_identity(descriptor):
    stat = os.fstat(descriptor)
    return dict(device=stat.st_dev, inode=stat.st_ino)


def cgroup_identity(group):
    """Capture both live directory generations before entering native code."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    scope_fd = os.open(group.parent, flags)
    try:
        group_fd = os.open(group.name, flags, dir_fd=scope_fd)
        try:
            return dict(scope=inode_identity(scope_fd), group=inode_identity(group_fd))
        finally:
            os.close(group_fd)
    finally:
        os.close(scope_fd)


def worker(args):
    frozen = Path(args.freeze_dir).resolve()
    manifest = verify(frozen, args.manifest_sha256)
    output = private_path(Path(manifest["repository"]), args.output_dir)
    require(output.is_dir(), "Run directory must already exist")
    rows = effective_box()
    label = "calibrations" if args.mode == "calibrations" else f"case-{args.seed:04d}"
    require(args.seed == 0 if args.mode == "calibrations" else 0 <= args.seed < 544,
            "Worker ID outside frozen inventory")
    write_new(output / "launches" / f"{label}.json",
              dict(manifest_sha256=args.manifest_sha256, seed=args.seed, mode=args.mode,
                   cgroup=rows[0]["group"],
                   cgroup_identity=cgroup_identity(Path(rows[0]["group"])),
                   effective_resource_rows=rows))
    env = environment(Path(manifest["repository"]), output)
    if args.mode == "case":
        destination = output / "inputs" / f"{args.seed:04d}"
        require(not destination.exists(), "Refusing duplicate native input execution")
        env["LITEINST_A2_CAMPAIGN_REVIEWED"] = "frozen-v1"
        verify(frozen, args.manifest_sha256)
        os.execve(frozen / "payload/bin/campaign",
                  [str(frozen / "payload/bin/campaign"), str(args.seed), str(destination)], env)
    binary = frozen / "payload/bin/calibrations"
    verify(frozen, args.manifest_sha256)
    _, listing, _ = successful([binary, "--list"], cwd=output, env=env,
                              prefix=output / "calibration-list", timeout=15)
    names = sorted(line.removesuffix(": test") for line in listing.read_text().splitlines()
                   if line.endswith(": test"))
    require(names == CALIBRATIONS, "Actual calibration inventory differs from frozen required tests")
    verify(frozen, args.manifest_sha256)
    _, log, _ = successful([binary, "--test-threads=1", "--nocapture"],
                          cwd=output, env=env, prefix=output / "calibration-tests", timeout=170)
    summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
                           r"(\d+) measured; (\d+) filtered out;", log.read_text())
    require(summaries == [(str(len(CALIBRATIONS)), "0", "0", "0", "0")], "Incomplete/ignored/filtered calibrations")
    write_new(output / "calibrations-passed.json",
              dict(names=names, passed=len(CALIBRATIONS), failed=0, ignored=0, manifest=args.manifest_sha256))


def parse_sweep(text):
    decoder = json.JSONDecoder()
    matches = []
    for match in re.finditer(r"(?m)^\{", text):
        try:
            value, used = decoder.raw_decode(text[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "rounds" in value:
            matches.append((value, match.start() + used))
    require(len(matches) == 1, "Runner omitted/duplicated final structured outcome report")
    require(not text[matches[0][1]:].strip(), "Trailing output after runner report")
    return matches[0][0]


def audit_sweep(value, ids, max_width, require_ramp):
    rounds = value["rounds"]
    require(rounds, "Runner reported no rounds")
    seen = []
    for round_ in rounds:
        require(1 <= round_["width"] <= max_width, "Runner width exceeded frozen bound")
        require(round_["reaped_leftovers"] == 0, "Runner found leftover worker processes/cgroups")
        require(0 < len(round_["outcomes"]) <= round_["width"], "Invalid round inventory")
        for outcome in round_["outcomes"]:
            seen.append(outcome["seed"])
            require(outcome["returncode"] == 0 and outcome["status"] == "hit",
                    f"Worker failed despite outer runner status: {outcome}")
            require(not outcome["breach"] and not outcome["resource_report_error"],
                    f"Worker resource breach: {outcome}")
            require(isinstance(outcome["cpu_s"], (int, float)) and
                    math.isfinite(outcome["cpu_s"]) and 0 <= outcome["cpu_s"] <= BOX["cpu_seconds"],
                    "Missing/over-budget CPU measurement")
            require(isinstance(outcome["peak_bytes"], int) and
                    0 < outcome["peak_bytes"] <= BOX["memory_bytes"], "Missing/over-budget memory peak")
            require(isinstance(outcome["wall_s"], (int, float)) and
                    math.isfinite(outcome["wall_s"]) and 0 <= outcome["wall_s"] <= BOX["wall_seconds"],
                    "Missing/over-budget wall measurement")
            require(outcome["tasks_peak"] is None or
                    isinstance(outcome["tasks_peak"], int) and 0 < outcome["tasks_peak"] <= BOX["pids"],
                    "Over-budget task peak")
    require(seen == ids and len(set(seen)) == len(ids), "Missing, duplicate or reordered input")
    if require_ramp:
        require([o["seed"] for o in rounds[0]["outcomes"]] == [0], "Initial calibration is not ID0")
        require(len(rounds) >= 2 and [o["seed"] for o in rounds[1]["outcomes"]] == [1, 2],
                "Required width-two calibration did not run IDs1–2 together")


def populated_at(group_fd):
    try:
        fd = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=group_fd)
    except FileNotFoundError:
        return False  # The authenticated original cgroup was removed.
    with os.fdopen(fd) as stream:
        values = [line.split() for line in stream.read().splitlines()
                  if line.startswith("populated ")]
    require(values in ([["populated", "0"]], [["populated", "1"]]),
            "Missing/malformed cgroup population measurement")
    return values == [["populated", "1"]]


def inspect_leftovers(output):
    """Attempt every receipt; never kill a reused pathname or follow a new link."""
    result = []
    root = CGROUP_ROOT.resolve()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    for receipt in sorted((output / "launches").glob("*.json")):
        record = dict(receipt=receipt.name, populated=False)
        scope_fd = group_fd = None
        try:
            value = load(receipt)
            group = Path(value["cgroup"])
            require(group.is_absolute() and group == group.resolve()
                    and group.is_relative_to(root)
                    and re.fullmatch(r"step-seed\.\d+", group.name)
                    and re.fullmatch(r"parallel-experiment-.+\.scope", group.parent.name),
                    "Unsafe cleanup path in worker receipt")
            record["cgroup"] = str(group)
            try:
                scope_fd = os.open(group.parent, flags)
            except FileNotFoundError:
                record["original_absent"] = True
                continue
            require(inode_identity(scope_fd) == value["cgroup_identity"]["scope"],
                    "Scope pathname was reused; refusing cleanup of another generation")
            try:
                group_fd = os.open(group.name, flags, dir_fd=scope_fd)
            except FileNotFoundError:
                record["original_absent"] = True
                continue
            require(inode_identity(group_fd) == value["cgroup_identity"]["group"],
                    "Seed pathname was reused; refusing cleanup of another generation")
            record["populated"] = populated_at(group_fd)
            if record["populated"]:
                kill_fd = os.open("cgroup.kill", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=group_fd)
                with os.fdopen(kill_fd, "w") as stream:
                    stream.write("1")
                record["killed_owned_subtree"] = True
                deadline = time.monotonic() + 5
                while populated_at(group_fd):
                    require(time.monotonic() < deadline, "Owned subtree did not drain")
                    time.sleep(0.05)
                record["drained"] = True
        except Exception as error:
            # An inaccessible/reused first cgroup must not prevent cleanup of
            # the remaining authenticated owned cgroups in this same run.
            record["error"] = f"{type(error).__name__}: {error}"
        finally:
            for descriptor in (group_fd, scope_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError as error:
                        record["error"] = record.get("error", "") + f" Close: {error}"
            result.append(record)
    return result


def run(args):
    global TERMINATING
    frozen = Path(args.freeze_dir).resolve()
    manifest = verify(frozen, args.manifest_sha256)
    repo = Path(manifest["repository"])
    requested = private_path(repo, args.output_dir)
    require(not requested.is_relative_to(frozen), "Run outputs must be separate from frozen artifacts")
    output = fresh_directory(repo, requested)
    for name in ("launches", "inputs"):
        (output / name).mkdir()
    env = environment(repo, output)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    deadline = time.monotonic() + BOX["aggregate_wall_seconds"]
    write_new(output / "run-start.json",
              dict(manifest=args.manifest_sha256, head=manifest["head"], box=BOX,
                   estimate_serial_minutes=[10, 30], estimate_is_measured=False))
    completed = False
    try:
        for phase, seeds, ceiling in (("calibrations", "0", 1), ("case", "0-543", 2)):
            if phase == "case":
                require((output / "calibrations-passed.json").is_file(),
                        "Full calibration success must precede all campaign inputs")
            work = output / phase
            work.mkdir()
            argv = [manifest["runner"], "run", "--name", f"a2-{phase}-{args.manifest_sha256[:12]}",
                    "--seeds", seeds, "--cpu-cores", "1", "--memory", str(BOX["memory_bytes"]),
                    "--cpu-timeout", "60", "--pids", "32", "--wall-timeout", "180",
                    "--max-concurrency", str(ceiling), "--slice-cpu", "2",
                    "--slice-memory", str(BOX["slice_memory_bytes"]),
                    "--work-dir", str(work), "--log-dir", str(work / "logs"),
                    "--profile-store", str(work / "profile.json"), "--format", "json",
                    "--identity", "backend=ptrace", f"image_id={args.manifest_sha256}",
                    "--", manifest["python"], str(frozen / "payload/input/boxed-worker.py"), "32",
                    manifest["python"], str(frozen / "payload/driver.py"), "_worker",
                    "--freeze-dir", str(frozen), "--manifest-sha256", args.manifest_sha256,
                    "--output-dir", str(output), "--mode", phase, "--seed", "{seed}"]
            verify(frozen, args.manifest_sha256)
            remaining = deadline - time.monotonic()
            require(remaining > 0, "Aggregate campaign wall backstop expired")
            record, log, _ = command(argv, cwd=output, env=env, prefix=work / "runner",
                                     timeout=remaining)
            value = parse_sweep(log.read_text())
            write_new(work / "outcomes.json", value)
            leftovers = inspect_leftovers(output)
            write_new(work / "leftovers.json", leftovers)
            require(not any(r["populated"] or "error" in r for r in leftovers),
                    "Worker left a live descendant or cleanup could not authenticate its absence")
            require(record["exit"] == 0, "Runner exit was nonzero")
            audit_sweep(value, [0] if phase == "calibrations" else list(range(544)),
                        ceiling, phase == "case")
        verify(frozen, args.manifest_sha256)
        remaining = deadline - time.monotonic()
        require(remaining > 0, "Aggregate campaign wall backstop expired before final audit")
        successful([manifest["python"], frozen / "payload/input/audit.py",
                    "--results", output / "inputs"], cwd=output, env=env,
                   prefix=output / "complete-audit", timeout=min(30, remaining))
        require({p.name for p in (output / "inputs").iterdir()} ==
                {f"{i:04d}" for i in range(544)}, "Actual result directory inventory changed")
        write_new(output / "complete.json",
                  dict(manifest=args.manifest_sha256, head=manifest["head"], inputs=544,
                       calibrations=len(CALIBRATIONS), status="ALL_REQUIRED_OUTCOMES_VERIFIED",
                       receipt_sha256={str(p.relative_to(output)): digest(p)
                                       for p in sorted(output.rglob("*")) if p.is_file()}))
        completed = True
    finally:
        if not completed:
            TERMINATING = True
            try:
                cleanup = inspect_leftovers(output)
            except Exception as error:
                cleanup = {"cleanup_error": str(error)}
            write_new(output / "failed-incomplete.json",
                      dict(status="FAILED_OR_INCOMPLETE_NOT_A_PASS", cleanup=cleanup,
                           manifest=args.manifest_sha256))
    print(f"Complete fixed campaign receipt: {output / 'complete.json'}")


def main():
    for signum in CANCELLATION_SIGNALS:
        signal.signal(signum, cancellation)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freezing = commands.add_parser("freeze", help="Build and freeze; executes no native calibration/case")
    freezing.add_argument("--repo", default=".")
    freezing.add_argument("--git-executable", required=True,
                          help="Explicit Git binary without detached helper sidecars")
    freezing.add_argument("--source-dir", required=True)
    freezing.add_argument("--input-dir", required=True)
    freezing.add_argument("--output-dir", required=True)
    freezing.add_argument("--sample-binary", required=True)
    freezing.add_argument("--runner", required=True)
    freezing.add_argument("--runner-source-root", required=True)
    for name in ("run", "_worker"):
        command_parser = commands.add_parser(name)
        command_parser.add_argument("--freeze-dir", required=True)
        command_parser.add_argument("--manifest-sha256", required=True)
        command_parser.add_argument("--output-dir", required=True)
        if name == "_worker":
            command_parser.add_argument("--mode", choices=("case", "calibrations"), required=True)
            command_parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args()
    {"freeze": freeze, "run": run, "_worker": worker}[args.command](args)


if __name__ == "__main__":
    try:
        main()
    except (Failure, OSError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(f"CAMPAIGN_FAILED_OR_INCOMPLETE: {error}", file=sys.stderr)
        raise SystemExit(1)
