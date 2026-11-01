"""One release build, twelve fixed disabled-point cohorts, no replacement runs."""
import hashlib, importlib.util, json, os, re, shutil, subprocess, sys
from pathlib import Path

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
assert len(sys.argv) == 7 and re.fullmatch("[0-9a-f]{40}", sys.argv[1])
assert all(re.fullmatch("[0-9a-f]{64}", sys.argv[i]) for i in (4, 6))
root = Path.cwd().resolve(); revision = sys.argv[1]; packet = Path(__file__).resolve().parent
assert packet == root / "evaluation/early-point-throughput"
out = Path(sys.argv[2]).resolve(); assert out.is_relative_to(root / "ignored") and not out.exists()
out.mkdir(); logs = root / "target/evaluation" / out.name; logs.mkdir(parents=True, exist_ok=False)
cpus = sorted(os.sched_getaffinity(0)); assert len(cpus) == 2
env = {k: v for k, v in os.environ.items() if not k.startswith(("CARGO", "RUST"))}
assert not any(env.get(k) for k in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"))
env.update(CARGO_BUILD_JOBS="2", RUST_TEST_THREADS="2", CARGO_INCREMENTAL="0", CARGO_NET_OFFLINE="true",
    CARGO_PROFILE_RELEASE_OPT_LEVEL="3", CARGO_PROFILE_RELEASE_DEBUG="0",
    CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS="false", CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS="false")
scope = ["src", "tools", "crates", "tests", "examples", "Cargo.toml", "Cargo.lock", "build.rs", ".cargo",
    "rust-toolchain", "rust-toolchain.toml", "evaluation/early-point-throughput", "evaluation/early-controlled-point",
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
assert digest(summary) == "10f9b2d57118ffb007ede6b23f327e2c8d39650b03f598ed0059ccb8cfb7156b"
tools = {name: str(Path(shutil.which(name, path=env["PATH"])).resolve()) for name in ("cargo", "rustc", "rustdoc")}
assert all(Path(p).name == name for name, p in tools.items()), "PATH must select direct toolchain binaries"
env.update(RUSTC=tools["rustc"], RUSTDOC=tools["rustdoc"], CARGO_TARGET_DIR=str(root / "target"))
paths = [Path(__file__).resolve(), helper, summary, Path(sys.executable).resolve(), *map(Path, tools.values()),
    Path("/usr/bin/git"), Path("/usr/bin/taskset"), Path("/usr/bin/prlimit"), Path("/usr/bin/du")]
owner = load(helper, "point_owner"); stats = load(summary, "point_statistics"); paths.append(stats.COMMON)
expected = {"core": [9], "planning": [2], "static-oracle": [1, 1, 1, 1, 37], "race-oracle": [1, 1, 1, 1, 36], "profiler": [2]}
# Exact original commands, filters, wall limits and census. Release adds only
# the declared Cargo profile switch; it does not replace the original cohort.
correctness_commands = [
    ["core", ["cargo", "test", "--locked", "--offline", "-j", "12", "-p", "liteinst2", "--lib", "early_control", "--", "--nocapture"], 180],
    ["planning", ["cargo", "test", "--locked", "--offline", "-j", "12", "-p", "liteinst2", "--test", "early_control_planning", "--", "--nocapture"], 180],
    ["static-oracle", ["cargo", "test", "--locked", "--offline", "-j", "12", "-p", "liteinst2", "--test", "early_control_oracle", "--", "--nocapture"], 240],
    ["race-oracle", ["cargo", "test", "--locked", "--offline", "-j", "12", "-p", "liteinst2", "--test", "early_control_race_oracle", "--", "--nocapture"], 120],
    ["profiler", ["cargo", "test", "--locked", "--offline", "-j", "12", "-p", "rapid-profiler", "--lib", "data_flag::tests::", "--", "--nocapture"], 180],
]
prerequisites = {}
assert Path(sys.argv[3]).resolve() != Path(sys.argv[5]).resolve()
for mode, argument, recipe, recipe_sha in (
        ("development", 3, root / "evaluation/early-controlled-point/reproduce.py", "f3df0b571afa66f6300e09d28956727732ad93fdea21fc8a63d54ef5858cf559"),
        ("release", 5, packet / "release_correctness.py", "090b6921f87260f5f66df929a2fbc4db8094549b335ad022e5ffea821546da2b")):
    prereq = Path(sys.argv[argument]).resolve()
    assert prereq.is_relative_to(root / "ignored") and prereq.is_file() and not prereq.is_symlink() and prereq.stat().st_size <= 262144
    assert digest(prereq) == sys.argv[argument + 1]
    prior = json.loads(prereq.read_text()); prior_plan = prereq.parent / "planned.json"
    assert prior_plan.is_file() and not prior_plan.is_symlink() and prior_plan.stat().st_size <= 262144
    plan = json.loads(prior_plan.read_text())
    assert prior["status"] == "PASS" and prior["error"] is None and prior["undispatched"] == []
    assert plan["planned"] == prior["planned"] and prior["planned"]["revision"] == revision
    assert prior["planned"]["source_tree"] == subprocess.check_output(git + ["rev-parse", "HEAD^{tree}"], timeout=10).decode().strip()
    assert digest(recipe) == recipe_sha
    assert prior["planned"]["script_sha256"] == digest(recipe)
    assert plan["frozen"][str(recipe)] == digest(recipe)
    assert plan["frozen"][str(helper)] == digest(helper)
    assert all(plan["frozen"][p] == digest(p) for p in tools.values())
    assert prior["planned"]["expected_harness_passes"] == expected
    assert [r["name"] for r in prior["results"]] == list(expected)
    assert [c[0] for c in prior["planned"]["commands"]] == list(expected)
    commands = [[name, argv[:2] + (["--release"] if mode == "release" else []) + argv[2:], wall]
                for name, argv, wall in correctness_commands]
    assert prior["planned"]["commands"] == commands
    assert prior["planned"]["attempts"] == 1 and prior["planned"]["jobs"] == prior["planned"]["test_threads"] == 12
    assert prior["planned"]["capture_limit"] == 2097152
    if mode == "release":
        assert prior["planned"]["profile"] == "matching-release-correctness-v1"
        assert prior["planned"]["release_environment"] == {key: env[key] for key in (
            "CARGO_PROFILE_RELEASE_OPT_LEVEL", "CARGO_PROFILE_RELEASE_DEBUG",
            "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS", "CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS")}
    for row, (name, argv, wall) in zip(prior["results"], commands):
        assert stats.normal(row["result"])
        if mode == "release":
            assert row["argv"] == [tools["cargo"], *argv[1:]]
            assert row["wall_seconds"] == wall and row["capture_limit"] == 2097152
        summaries = row["harness_summaries"]
        assert sorted(s["passed"] for s in summaries) == expected[row["name"]]
        assert all(s["outcome"] == "ok" and s["failed"] == s["ignored"] == s["measured"] == 0 for s in summaries)
        log = prereq.parent / (row["name"] + ".log")
        assert log.is_file() and not log.is_symlink() and log.stat().st_size <= 2097152
        assert digest(log) == row["result"]["private_log_sha256"]
        paths.append(log)
    paths += [prereq, prior_plan, recipe]
    prerequisites[mode] = dict(path=str(prereq), sha256=sys.argv[argument + 1], status=prior["status"],
        profile=mode, commands=commands, recipe_sha256=recipe_sha,
        release_environment=prior["planned"].get("release_environment"))
frozen = {str(p): digest(p) for p in paths}
binary = root / "target/release/point-throughput"; binary_sha = None; source_ok = None


def check():
    global source_ok
    source_ok = False
    assert subprocess.check_output(git + ["rev-parse", "HEAD"], timeout=10).decode().strip() == revision
    assert not subprocess.check_output(git + ["diff", revision, "--", *scope], timeout=10)
    assert not subprocess.check_output(git + ["ls-files", "--others", "--exclude-standard", "--", *scope], timeout=10)
    assert {p: digest(p) for p in frozen} == frozen
    if binary_sha is not None: assert digest(binary) == binary_sha
    source_ok = True


capacity_rows = []
def capacity(label, reserve):
    check()
    row = dict(label=label, reserve_bytes=reserve, status="DISPATCHED", queries=[])
    capacity_rows.append(row); save(out / "capacity.json", capacity_rows)
    for apparent in (False, True):
        log = logs / (label + ("-apparent.log" if apparent else "-allocated.log"))
        assert not log.exists()
        targets = [root, root / "ignored", root / "target"]
        argv = ["/usr/bin/prlimit", "--cpu=30", "--as=268435456", "--fsize=65536", "--core=0", "--",
            "/usr/bin/du", "--summarize", "--block-size=1", "--count-links"]
        if apparent: argv.append("--apparent-size")
        argv += list(map(str, targets))
        result = owner.run_command(argv, env, log, 60, 65536)
        query = dict(apparent=apparent, argv=argv, owner=result); row["queries"].append(query); row["status"] = "FAILED"
        save(out / "capacity.json", capacity_rows)
        assert result["cleanup_complete"], "capacity ownership poisoned"
        raw = log.read_bytes(); assert len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == result["private_log_sha256"]
        (out / log.name).write_bytes(raw)
        assert stats.normal(result)
        entries = [line.split("\t") for line in raw.decode().splitlines()]
        assert len(entries) == 3 and [x[1] for x in entries] == list(map(str, targets))
        sizes = [int(x[0]) for x in entries]; assert all(n >= 0 for n in sizes)
        query["bytes"] = dict(zip(("slot", "ignored", "target"), sizes))
        assert sizes[0] + reserve <= 20_000_000_000
    check(); row["status"] = "PASS"; save(out / "capacity.json", capacity_rows)


planned = dict(revision=revision, seed=20261101, reserved_cpus=cpus, producer_cpu=cpus[0], worker_cpu=cpus[1], frozen=frozen,
    reservation_authority="External caller reserves two CPUs; runner records affinity, not an independent live witness.",
    prerequisite=prerequisites["development"], release_prerequisite=prerequisites["release"],
    environment={k: v for k, v in env.items() if k.startswith(("CARGO", "RUST")) or k in ("PATH", "LANG", "LC_ALL")}, python=sys.version,
    toolchain={n: subprocess.check_output([p, "--version"], env=env, timeout=10).decode().strip() for n, p in tools.items()},
    hardware=dict(label="AMD EPYC Zen 5 dev host", architecture=os.uname().machine, logical_cpus=os.cpu_count(), cpu_model=next(x.split(":", 1)[1].strip() for x in Path("/proc/cpuinfo").read_text().splitlines() if x.startswith("model name"))),
    load_before=os.getloadavg(), build_wall_seconds=600, child_wall_seconds=90, child_cpu_seconds=60,
    child_file_bytes=1048576, log_cap_bytes=1048576, jobs=2, process_count=12, rows_per_process=206, retries=0,
    slot_limit_bytes=20_000_000_000, initial_reserve_bytes=2**31 + 2**26, campaign_reserve_bytes=2**26)
rows = [dict(index=i, order=order, directory="cohort-%02d" % i, status="UNOBSERVED") for i, order in enumerate(stats.schedule())]
build = dict(status="UNOBSERVED"); error = None; active = None
save(out / "planned.json", planned); save(out / "cohorts.json", rows)
try:
    check(); planned["source_tree"] = subprocess.check_output(git + ["rev-parse", "HEAD^{tree}"], timeout=10).decode().strip(); save(out / "planned.json", planned)
    capacity("before-build", 2**31 + 2**26)
    argv = [tools["cargo"], "build", "--release", "--locked", "--offline", "-j", "2", "--target-dir", str(root / "target"), "-p", "rapid-profiler", "--bin", "point-throughput", "--message-format=json-render-diagnostics"]
    log = logs / "release-build.log"; assert not log.exists(); build.update(status="DISPATCHED", argv=argv, log=str(log)); save(out / "build.json", build)
    result = owner.run_command(argv, env, log, 600, 1048576); build.update(owner=result, status="FAILED"); save(out / "build.json", build)
    assert result["cleanup_complete"], "build ownership poisoned"
    raw = log.read_bytes(); assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == result["private_log_sha256"]
    log = out / "release-build.log"; log.write_bytes(raw); build["log"] = str(log); save(out / "build.json", build)
    check(); assert stats.normal(result)
    messages = [json.loads(line) for line in log.read_text().splitlines() if line.startswith("{")]
    products = [m for m in messages if m.get("reason") == "compiler-artifact" and m.get("target", {}).get("name") == "point-throughput" and m.get("executable")]
    assert len(products) == 1 and Path(products[0]["executable"]).resolve() == binary.resolve()
    profile = products[0]["profile"]
    assert profile["opt_level"] == "3" and profile["debuginfo"] == 0 and profile["test"] is False
    assert profile["debug_assertions"] is False and profile["overflow_checks"] is False
    build["compiled_profile"] = profile; binary_sha = digest(binary); check()
    build.update(status="PASS", binary_sha256=binary_sha, load_after=os.getloadavg()); save(out / "build.json", build)
    capacity("before-campaign", 2**26)
    os.sched_setaffinity(0, {cpus[0]}); assert sorted(os.sched_getaffinity(0)) == cpus[:1]
    for row in rows:
        check(); active = row; target = out / row["directory"]; assert not target.exists()
        log = logs / (row["directory"] + ".log"); assert not log.exists()
        argv = ["/usr/bin/prlimit", "--cpu=60", "--fsize=1048576", "--core=0", "--", "/usr/bin/taskset", "--cpu-list", str(cpus[1]), str(binary), row["order"], str(target)]
        row.update(status="DISPATCHED", argv=argv, log=str(log), load_before=os.getloadavg()); save(out / "cohorts.json", rows)
        result = owner.run_command(argv, env, log, 90, 1048576)
        row.update(owner=result, status="FAILED", load_after=os.getloadavg()); save(out / (row["directory"] + "-owner.json"), row); save(out / "cohorts.json", rows)
        if not result["cleanup_complete"]:
            source_ok = None; error = "ownership_poison"; break
        raw = log.read_bytes(); assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == result["private_log_sha256"]
        log = out / (row["directory"] + ".log"); log.write_bytes(raw); row["log"] = str(log)
        save(out / (row["directory"] + "-owner.json"), row); save(out / "cohorts.json", rows)
        check(); row["source_after"] = True
        assert sorted(os.sched_getaffinity(0)) == cpus[:1]
        try:
            row["artifacts"] = stats.artifacts(target)
            if stats.normal(result):
                assert {p.name for p in target.iterdir()} == set(row["artifacts"]) == set(stats.FILES)
                stats.cohort(target, row["order"], cpus[1]); assert stats.artifacts(target) == row["artifacts"]
                assert log.read_text().splitlines() == [stats.MARKER]
                row["status"] = "PASS"
        except Exception as failure: row["validation_error"] = type(failure).__name__ + ": " + str(failure)
        save(out / "cohorts.json", rows); active = None
        if result["termination"] in ("interrupted", "ownership_refused") or result["reaped_descendants"] != 0:
            error = result["termination"] or "rescued_descendants"; break
    if source_ok is True: check(); capacity("after-campaign", 0)
except BaseException as failure:
    error = type(failure).__name__ + ": " + str(failure)
    if active is not None: active["status"] = "FAILED"
finally:
    passed = error is None and source_ok is True and build["status"] == "PASS" and all(r["status"] == "PASS" for r in rows)
    closed = dict(status="PASS" if passed else "FAILED", planned=planned, build=build, cohorts=rows,
        capacity=capacity_rows, binary_sha256=binary_sha, source_unchanged=source_ok, error=error, load_after=os.getloadavg())
    save(out / "cohorts.json", rows); save(out / "closed.json", closed)
if passed:
    try: stats.summarize(out, digest(out / "closed.json"))
    except BaseException as failure:
        save(out / "statistics-failed.json", dict(error=type(failure).__name__ + ": " + str(failure))); raise
raise SystemExit(0 if passed else 1)
