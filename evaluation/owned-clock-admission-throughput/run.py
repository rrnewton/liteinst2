"""One release build, twelve fixed admission cohorts, no replacement runs."""
import hashlib, importlib.util, json, os, re, shutil, subprocess, sys
from pathlib import Path

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
assert len(sys.argv) == 5 and re.fullmatch("[0-9a-f]{40}", sys.argv[1]) and re.fullmatch("[0-9a-f]{64}", sys.argv[4])
root = Path.cwd().resolve(); revision = sys.argv[1]; packet = Path(__file__).resolve().parent
out = Path(sys.argv[2]).resolve(); assert out.is_relative_to(root / "ignored") and not out.exists()
out.mkdir(); logs = root / "target/evaluation" / out.name; logs.mkdir(parents=True)
cpus = sorted(os.sched_getaffinity(0)); assert len(cpus) == 3
env = {k: v for k, v in os.environ.items() if not k.startswith(("CARGO", "RUST"))}
env.update(CARGO_BUILD_JOBS="3", RUST_TEST_THREADS="3", CARGO_INCREMENTAL="0", CARGO_NET_OFFLINE="true",
           CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")
scope = ["src", "tools", "crates", "tests", "examples", "Cargo.toml", "Cargo.lock",
         "evaluation/owned-clock-admission-throughput", "evaluation/owned-clock-batch",
         "evaluation/owned-clock-region-throughput/summarize.py", "evaluation/admission/processes.py"]
git = ["/usr/bin/git", "-c", "index.threads=1", "-c", "core.preloadIndex=false"]


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1048576), b""): h.update(chunk)
    return h.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


helper = root / "evaluation/admission/processes.py"; summary = packet / "summarize.py"
assert digest(helper) == "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"
assert digest(summary) == '59b4e30a421672cdf46a4b3c7294f86949e3048218b191ddf2c8b8fd8717a193'
tools = {name: str(Path(shutil.which(name, path=env["PATH"])).absolute()) for name in ("cargo", "rustc", "rustdoc")}
assert all(Path(p).resolve().name == name for name,p in tools.items()), "PATH must select direct pinned toolchain binaries"
env.update(RUSTC=tools["rustc"], RUSTDOC=tools["rustdoc"], CARGO_TARGET_DIR=str(root / "target"))
paths = [Path(__file__).resolve(), helper, summary, Path(sys.executable).resolve(), *map(Path, tools.values()),
         Path("/usr/bin/git"), Path("/usr/bin/taskset"), Path("/usr/bin/prlimit")]
owner = load(helper, "admission_owner"); stats = load(summary, "admission_statistics")
paths.append(stats.COMMON)
prereq = Path(sys.argv[3]).resolve(); assert prereq.is_relative_to(root / "ignored") and digest(prereq) == sys.argv[4]
prior = json.loads(prereq.read_text())
assert prior["status"] == "PASS" and prior["error"] is None and prior["planned"]["revision"] == revision
oracle_recipe = root / "evaluation/owned-clock-batch/reproduce.py"
assert digest(oracle_recipe) == "03f50dd6b12e1ac3b236fe4b508d96a861892933b9e918ed6a1f50085b29c9b8"
assert prior["planned"]["frozen"][str(oracle_recipe)] == digest(oracle_recipe)
assert [r["name"] for r in prior["outcomes"]] == ["release-build", "region-oracle", "region-batch-oracle"]
assert [c["name"] for c in prior["planned"]["commands"]] == [r["name"] for r in prior["outcomes"]]
for r in prior["outcomes"]:
    assert r["status"] == "PASS" and r["source_after"] is True and stats.normal(r["owner"])
    log = prereq.parent / (r["name"] + ".log")
    assert log.is_file() and not log.is_symlink() and log.stat().st_size <= 2097152
    assert digest(log) == r["owner"]["private_log_sha256"]
    paths.append(log)
    if r["name"] == "release-build":
        assert r["compiled_profile"]["opt_level"] == "3" and r["compiled_profile"]["test"] is False
    else:
        artifacts = r["artifacts"]
        folder = prereq.parent / r["name"]
        assert {p.name for p in folder.iterdir()} == set(artifacts["files"])
        for name, expected in artifacts["files"].items():
            path = folder / name
            assert path.is_file() and not path.is_symlink() and path.stat().st_size <= 1048576
            assert dict(bytes=path.stat().st_size, sha256=digest(path)) == expected
            paths.append(path)
        assert json.loads((folder / "summary.json").read_text()) == artifacts["summary"]
        assert artifacts["summary"]["full_state_comparisons"] == 192
        assert artifacts["summary"]["rejection_children"] == 2
        assert artifacts["summary"]["rejection_witnesses"] == 2
        assert artifacts["summary"]["stops"] == (352 if r["name"] == "region-batch-oracle" else 6)
        if r["name"] == "region-batch-oracle":
            assert artifacts["summary"]["fork_entry_children"] == artifacts["summary"]["fork_entry_witnesses"] == 1
paths += [prereq, oracle_recipe]
frozen = {str(p): digest(p) for p in paths}
binary = root / "target/release/liteinst-preempt"; binary_sha = None; source_ok = None


def check():
    global source_ok
    source_ok = False
    assert subprocess.check_output(git + ["rev-parse", "HEAD"], timeout=10).decode().strip() == revision
    assert not subprocess.check_output(git + ["diff", revision, "--", *scope], timeout=10)
    assert not subprocess.check_output(git + ["ls-files", "--others", "--exclude-standard", "--", *scope], timeout=10)
    assert {p: digest(p) for p in frozen} == frozen
    if binary_sha is not None: assert digest(binary) == binary_sha
    source_ok = True


planned = dict(revision=revision, seed=20261101, reserved_cpus=cpus, producer_cpu=cpus[0], frozen=frozen,
    reservation_authority="External caller reserves CPUs; runner records affinity, not an independent live witness.",
    prerequisite=dict(path=str(prereq), sha256=sys.argv[4], binary_sha256=prior["binary_sha256"]),
    environment={k: v for k,v in env.items() if k.startswith(("CARGO", "RUST")) or k in ("PATH", "LANG", "LC_ALL", "LD_PRELOAD", "LD_LIBRARY_PATH")}, python=sys.version, toolchain={n: subprocess.check_output([p, "--version"], env=env, timeout=10).decode().strip() for n,p in tools.items()},
    hardware=dict(architecture=os.uname().machine, logical_cpus=os.cpu_count(), cpu_model=next(x.split(":",1)[1].strip() for x in Path("/proc/cpuinfo").read_text().splitlines() if x.startswith("model name"))),
    load_before=os.getloadavg(), build_wall_seconds=600, child_wall_seconds=90, child_cpu_seconds=60,
    child_file_bytes=1048576, log_cap_bytes=1048576, jobs=3, process_count=12, retries=0)
rows = [dict(index=i, order=order, directory="cohort-%02d" % i, status="UNOBSERVED") for i,order in enumerate(stats.schedule())]
build = dict(status="UNOBSERVED"); error = None; active = None
save(out / "planned.json", planned); save(out / "cohorts.json", rows)
try:
    check(); planned["source_tree"] = subprocess.check_output(git + ["rev-parse", "HEAD^{tree}"], timeout=10).decode().strip(); save(out / "planned.json", planned)
    argv = [tools["cargo"], "build", "--release", "--locked", "--offline", "-j", "3", "--target-dir", str(root / "target"), "--bin", "liteinst-preempt", "--message-format=json-render-diagnostics"]
    log = logs / "release-build.log"; assert not log.exists(); build.update(status="DISPATCHED", argv=argv, log=str(log))
    save(out / "build.json", build)
    result = owner.run_command(argv, env, log, 600, 1048576); build.update(owner=result, status="FAILED"); save(out / "build.json", build)
    assert result["cleanup_complete"], "build ownership poisoned"
    raw = log.read_bytes(); assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == result["private_log_sha256"]
    log = out / "release-build.log"; log.write_bytes(raw); build["log"] = str(log); save(out / "build.json", build)
    check(); assert digest(log) == result["private_log_sha256"] and stats.normal(result)
    messages = [json.loads(line) for line in log.read_text().splitlines() if line.startswith("{")]
    products = [m for m in messages if m.get("reason") == "compiler-artifact" and m.get("target",{}).get("name") == "liteinst-preempt" and m.get("executable")]
    assert len(products) == 1 and Path(products[0]["executable"]).resolve() == binary.resolve()
    assert products[0]["profile"]["opt_level"] == "3" and products[0]["profile"]["test"] is False
    build["compiled_profile"] = products[0]["profile"]
    binary_sha = digest(binary); assert binary_sha == prior["binary_sha256"]; check(); build.update(status="PASS", binary_sha256=binary_sha, load_after=os.getloadavg()); save(out / "build.json", build)
    os.sched_setaffinity(0, {cpus[0]}); assert sorted(os.sched_getaffinity(0)) == cpus[:1]
    for row in rows:
        check(); active = row; target = out / row["directory"]; assert not target.exists()
        log = logs / (row["directory"] + ".log"); assert not log.exists()
        argv = ["/usr/bin/prlimit", "--cpu=60", "--fsize=1048576", "--core=0", "--", "/usr/bin/taskset", "--cpu-list", ",".join(map(str,cpus[1:])), str(binary), "region-admission-bench", row["order"], str(target)]
        row.update(status="DISPATCHED", argv=argv, log=str(log), load_before=os.getloadavg()); save(out / "cohorts.json", rows)
        result = owner.run_command(argv, env, log, 90, 1048576)
        row.update(owner=result, status="FAILED", load_after=os.getloadavg()); save(out / (row["directory"] + "-owner.json"), row); save(out / "cohorts.json", rows)
        if not result["cleanup_complete"]:
            source_ok = None; error = "ownership_poison"; break
        raw = log.read_bytes(); assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == result["private_log_sha256"]
        log = out / (row["directory"] + ".log"); log.write_bytes(raw); row["log"] = str(log)
        save(out / (row["directory"] + "-owner.json"), row); save(out / "cohorts.json", rows)
        check(); row["source_after"] = True
        assert sorted(os.sched_getaffinity(0)) == cpus[:1] and digest(log) == result["private_log_sha256"]
        try:
            row["artifacts"] = stats.artifacts(target)
            if stats.normal(result):
                assert {p.name for p in target.iterdir()} == set(row["artifacts"]) == set(stats.FILES)
                stats.cohort(target, row["order"], cpus[1:])
                assert stats.artifacts(target) == row["artifacts"]
                assert log.read_text().splitlines() == ["preemption:region-admission-bench:3-qualified:9-warmups:192-measured:no-outlier-filter"]
                row["status"] = "PASS"
        except Exception as failure: row["validation_error"] = type(failure).__name__ + ": " + str(failure)
        save(out / "cohorts.json", rows); active = None
        if result["termination"] in ("interrupted", "ownership_refused"):
            error = result["termination"]; break
    if source_ok is True: check()
except BaseException as failure:
    error = type(failure).__name__ + ": " + str(failure)
    if active is not None: active["status"] = "FAILED"
finally:
    passed = error is None and source_ok is True and build["status"] == "PASS" and all(r["status"] == "PASS" for r in rows)
    closed = dict(status="PASS" if passed else "FAILED", planned=planned, build=build, cohorts=rows,
                  binary_sha256=binary_sha, source_unchanged=source_ok, error=error, load_after=os.getloadavg())
    save(out / "cohorts.json", rows); save(out / "closed.json", closed)
if passed:
    try: stats.summarize(out, digest(out / "closed.json"))
    except BaseException as failure:
        save(out / "statistics-failed.json", dict(error=type(failure).__name__ + ": " + str(failure))); raise
raise SystemExit(0 if passed else 1)
