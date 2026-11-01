"""One release build, twelve fixed sequential processes, no replacement runs."""
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
scope = ["src", "tools", "crates", "Cargo.toml", "Cargo.lock"]
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
assert digest(summary) == '45c89e7f3640f1c469e71a4730cd6c0776d6238a3179964af3c8bc54483dd5d3'
tools = {name: str(Path(shutil.which(name, path=env["PATH"])).absolute()) for name in ("cargo", "rustc", "rustdoc")}
assert all(Path(p).resolve().name == name for name,p in tools.items()), "PATH must select direct pinned toolchain binaries"
env.update(RUSTC=tools["rustc"], RUSTDOC=tools["rustdoc"])
paths = [Path(__file__).resolve(), helper, summary, Path(sys.executable).resolve(), *map(Path, tools.values()),
         Path("/usr/bin/git"), Path("/usr/bin/taskset"), Path("/usr/bin/prlimit")]
owner = load(helper, "region_owner"); stats = load(summary, "region_statistics")
prereq = Path(sys.argv[3]).resolve(); assert prereq.is_relative_to(root / "ignored") and digest(prereq) == sys.argv[4]
prior = json.loads(prereq.read_text()); assert prior["status"] == "PASS" and prior["error"] is None and prior["undispatched"] == []
assert prior["planned"]["revision"] == revision and prior["planned"]["script_sha256"] == "04460d748b718978feb853b7bcf77d98a5373a1c2608e9930aec36d3bd810627"
assert [r["name"] for r in prior["results"]] == ["release-build", "native-oracle"] and all(stats.normal(r["result"]) for r in prior["results"])
for r in prior["results"]:
    log = prereq.parent / (r["name"] + ".log"); assert log.stat().st_size <= 2097152 and digest(log) == r["result"]["private_log_sha256"]; paths.append(log)
assert (prereq.parent / "native-oracle.log").read_text().splitlines() == ["preemption:region-gates:6-pairs:12-children:192-full-state-comparisons", "preemption:region-rejections:2-children:2-first-stop-witnesses:2-exit123-echild", "preemption:region-stops:3-quanta:15-encounters:11-taken:6-stops:6-parked-checks"]
oracle = prereq.parent / "oracle"
assert json.loads((oracle / "summary.json").read_text()) == dict(status="PASS", profile="owned-two-backedge-region-oracle-v1", gate_pairs=6, gate_children=12, full_state_comparisons=192, stop_quanta=[2,11,12], stops=6, parked_checks=6, rejection_children=2, rejection_witnesses=2, publisher_validation=False, full_state_after_callback=False, performance_qualification=False)
for name in ("summary.json", "region-gates.csv", "region-stops.csv", "region-events.csv", "region-rejections.csv", "region-rejection-wrong-site.bin", "region-rejection-wrong-count.bin"):
    path = oracle / name; assert path.is_file() and not path.is_symlink() and path.stat().st_size <= 1048576; paths.append(path)
paths += [prereq, root / "evaluation/owned-clock-region/reproduce.py"]
assert digest(paths[-1]) == prior["planned"]["script_sha256"]
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
    prerequisite=dict(path=str(prereq), sha256=sys.argv[4], binary_sha256=prior["binary_sha256"]),
    environment={k: v for k,v in env.items() if k.startswith(("CARGO", "RUST")) or k in ("PATH", "LD_PRELOAD", "LD_LIBRARY_PATH")}, python=sys.version, toolchain={n: subprocess.check_output([p, "--version"], env=env, timeout=10).decode().strip() for n,p in tools.items()},
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
    check(); assert digest(log) == result["private_log_sha256"] and stats.normal(result)
    messages = [json.loads(line) for line in log.read_text().splitlines() if line.startswith("{")]
    products = [m for m in messages if m.get("reason") == "compiler-artifact" and m.get("target",{}).get("name") == "liteinst-preempt" and m.get("executable")]
    assert len(products) == 1 and Path(products[0]["executable"]).resolve() == binary.resolve()
    binary_sha = digest(binary); assert binary_sha == prior["binary_sha256"]; check(); build.update(status="PASS", binary_sha256=binary_sha, load_after=os.getloadavg()); save(out / "build.json", build)
    os.sched_setaffinity(0, {cpus[0]}); assert sorted(os.sched_getaffinity(0)) == cpus[:1]
    for row in rows:
        check(); active = row; target = out / row["directory"]; assert not target.exists()
        log = logs / (row["directory"] + ".log"); assert not log.exists()
        argv = ["/usr/bin/prlimit", "--cpu=60", "--fsize=1048576", "--core=0", "--", "/usr/bin/taskset", "--cpu-list", ",".join(map(str,cpus[1:])), str(binary), "region-bench", row["order"], str(target)]
        row.update(status="DISPATCHED", argv=argv, log=str(log), load_before=os.getloadavg()); save(out / "cohorts.json", rows)
        result = owner.run_command(argv, env, log, 90, 1048576)
        row.update(owner=result, status="FAILED", load_after=os.getloadavg()); save(out / (row["directory"] + "-owner.json"), row); save(out / "cohorts.json", rows)
        if not result["cleanup_complete"]:
            source_ok = None; error = "ownership_poison"; break
        check(); row["source_after"] = True
        assert sorted(os.sched_getaffinity(0)) == cpus[:1] and digest(log) == result["private_log_sha256"]
        try:
            row["artifacts"] = stats.artifacts(target)
            if stats.normal(result):
                assert set(row["artifacts"]) == set(stats.FILES)
                stats.cohort(target, row["order"], cpus[1:])
                assert stats.artifacts(target) == row["artifacts"]
                assert log.read_text().splitlines() == ["preemption:region-bench-rejections:2-children:2-before-refill-witnesses:2-exit123-echild", "preemption:region-bench:3-qualified:9-warmups:192-measured:no-outlier-filter"]
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
