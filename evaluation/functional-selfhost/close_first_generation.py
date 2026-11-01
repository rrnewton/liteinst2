#!/usr/bin/env python3
"""Authenticate a CLOSED fresh --cases all producer; no native dispatch."""
import argparse
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import sys

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
ROOT, SELF = Path.cwd().resolve(), Path(__file__).resolve()
M = 1024**2
REV = "10a778d6415e51c66dfdc122d1e019e5c8c94c3c"
HELPER = "69c7d87ecf8d249a0a7b325db78f05d770fad993994eba97a40bb8338c0c4f6a"
DRIVER = "561c661da5ea02079d1783d953305cde24f5031cb0527383f473ca5f18a083c9"
FRESH_OWNER = "707bb71f96381a5ad0375157e088e4c86eef66837a14253309f617a395aea8b5"
CANONICAL = "43ce9ab04259b8bc551cd2ec2c093206710b60258b3e9e73ac351ddb7ea77733"


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def source(path, digest):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_size <= M
    data = path.read_bytes()
    after = path.lstat()
    assert identity(before) == identity(after) and before.st_nlink == after.st_nlink
    assert hashlib.sha256(data).hexdigest() == digest
    spec = importlib.util.spec_from_file_location("fresh_corpus_helpers", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    assert path.read_bytes() == data
    return module


def scope(cgroup):
    value = cgroup.strip()
    assert value.startswith("0::/") and "\n" not in value and ".." not in Path(value[3:]).parts
    return Path("/sys/fs/cgroup")/value[4:]


def gone(identity):
    assert type(identity["pid"]) is int and identity["pid"] > 1
    old = identity["stat"].rsplit(")", 1)[1].split()[19]
    try:
        now = (Path("/proc")/str(identity["pid"])/"stat").read_text()
    except FileNotFoundError:
        now = None
    assert now is None or now.rsplit(")", 1)[1].split()[19] != old
    assert not scope(identity["cgroup"]).exists()


def main():
    for key, value in ((resource.RLIMIT_CPU, 60), (resource.RLIMIT_AS, 256*M),
                       (resource.RLIMIT_FSIZE, M), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(key, (value, value))
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    p.add_argument("--first-generation", type=Path, required=True)
    p.add_argument("--corpus-scripts", type=Path, required=True)
    p.add_argument("--receipt-sha", required=True)
    p.add_argument("--owner-live-sha", required=True)
    p.add_argument("--owner-closed-sha", required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    run, scripts, destination = a.first_generation.absolute(), a.corpus_scripts.absolute(), a.out.absolute()
    assert run == run.resolve() and run.parent == ROOT/"ignored/a3" and run.is_dir()
    assert scripts == scripts.resolve() and destination == destination.resolve() and not destination.exists()
    assert destination.parent == ROOT/"ignored/a3" and len(os.sched_getaffinity(0)) == 1
    h = source(scripts/"run.py", HELPER)
    manifest = SELF.with_name("inputs.json")
    assert h.pin(manifest, M)["sha256"] == CANONICAL
    canonical = json.loads(manifest.read_text())
    meta = run.with_name(run.name+"-owner")
    frozen = {}

    def pin(path, expected=None, cap=512*M):
        got = h.pin(path, cap)
        if expected is not None:
            assert got == expected
        frozen[str(path)] = got
        return got

    def read(path, digest):
        got = pin(path, cap=M)
        assert got["sha256"] == digest
        value = json.loads(path.read_text())
        assert h.pin(path, M) == got
        return value

    def closed(result, exit_code):
        assert result["cleanup_complete"] is True and result["reaped_descendants"] == 0
        assert result["termination"] is None and result["exit_code"] == exit_code
        assert result["child_discovery_strategy"] == "pidfd_authenticated_proc_candidates"

    # These three hashes are NEW producer records, supplied after that owner exits.
    # Reading CLOSED metadata precedes any output or log payload access.
    outer = read(meta/"closed.json", a.owner_closed_sha)
    closed(outer, 1)
    live = read(meta/"live.json", a.owner_live_sha)
    source_paths = {str(SELF.with_name("fresh-owner.py")), str(ROOT/"evaluation/admission/processes.py")}
    assert set(live["source_pins"]) == source_paths
    assert outer["source_pins"] == live["source_pins"] and outer["source_unchanged"] is True
    for path, expected in live["source_pins"].items():
        pin(Path(path), expected, M)
    assert frozen[str(SELF.with_name("fresh-owner.py"))]["sha256"] == FRESH_OWNER
    helper_pin = frozen[str(ROOT/"evaluation/admission/processes.py")]
    assert (helper_pin["bytes"], helper_pin["sha256"]) == h.TOOLS["evaluation/admission/processes.py"]
    receipt = read(run/"receipt.json", a.receipt_sha)
    assert receipt["revision"] == REV and receipt["case_set"] == "all"
    assert receipt["source_unchanged"] is True and receipt["status"] == "FAILED_OUTCOME_RETAINED"
    assert "error" not in receipt and receipt["qualification_complete"] is False
    assert receipt["performance_qualified"] is False
    assert len(live["cpus"]) == 1 and type(live["cpus"][0]) is int
    assert receipt["before"]["root_identity"] == [ROOT.stat().st_dev, ROOT.stat().st_ino]
    worker = receipt["before"]; gone(live); gone(worker)
    cpu = live["cpus"][0]
    unit = scope(worker["cgroup"]).name
    assert unit.startswith("li2core-functional-repro-") and unit.endswith(".scope")
    unit = unit[:-6]
    command = ["/usr/bin/systemd-run", "--user", "--scope", "--collect", "--quiet", "--unit="+unit,
               "-p", "AllowedCPUs="+str(cpu), "-p", "CPUQuota=100%", "-p", "MemoryMax=1073741824",
               "-p", "MemorySwapMax=0", "-p", "TasksMax=64", "--", "/usr/bin/python3.9", "-I", "-B",
               str(SELF.with_name("first_generation.py")), "--corpus-scripts", str(scripts),
               "--cpu", str(cpu), "--unit", unit, "--out", str(run)]
    assert live["command"] == command
    driver = SELF.with_name("first_generation.py")
    assert pin(driver, cap=M)["sha256"] == DRIVER
    wrapper_path = run/"first-generation-wrapper-closed.json"
    wrapper_pin = pin(wrapper_path, cap=M)
    wrapper = json.loads(wrapper_path.read_text()); assert h.pin(wrapper_path, M) == wrapper_pin
    assert wrapper["revision"] == REV and wrapper["child_source_revision"] == h.REV
    assert wrapper["result"] == 1 and wrapper["source_unchanged"] is True
    assert wrapper["revision_override_only"] is True and wrapper["case_set"] == "all" and wrapper["attempts"] == 1
    assert wrapper["driver"] == frozen[str(driver)] and wrapper["receipt"] == frozen[str(run/"receipt.json")]
    assert wrapper["command"] == command[command.index("--")+1:]
    assert wrapper["child_script"] == h.pin(scripts/"run.py")
    # Close every actual producer before reading any request/product/log payload.
    pre_dispatches = [row for case in receipt["cases"]
                      for row in [case["generation"], *[case["arms"][r] for r in h.ROLES]]]
    assert len(pre_dispatches) == 40 and pre_dispatches == receipt["dispatch_attempts"]
    for row in pre_dispatches:
        closed(row["owner"], 0)
    for index, row in enumerate(pre_dispatches):
        assert row["command"][0:4] == ["/usr/bin/python3.9", "-I", "-B", str(scripts/"run.py")]
        assert row["command"][-1] == str(cpu)
        assert row["log"]["sha256"] == row["owner"]["private_log_sha256"]
        assert row["before"]["cgroup"] == worker["cgroup"] == row["after"]["cgroup"]
        assert row["retained_log"] == str(run/"logs"/(str(index)+".log"))
        cap = 8*M*(4 if row["command"][5] == "e9tool" else 1)
        actual = pin(Path(row["retained_log"]), cap=cap)
        assert all(actual[k] == row["log"][k] for k in ("bytes", "sha256"))
        pin(ROOT/"target/evaluation"/run.name/(str(index)+".log"), row["log"], cap)
    assert worker["cgroup"] == receipt["after"]["cgroup"]
    assert worker["properties"] == receipt["after"]["properties"]
    properties = worker["properties"]
    assert [properties[k] for k in ("memory.max", "memory.swap.max", "pids.max", "cpuset.cpus.effective")] == [str(1024*M), "0", "64", str(cpu)]
    quota, period = map(int, properties["cpu.max"].split()); assert quota == period and period > 0
    pin(SELF); pin(manifest); pin(scripts/"run.py")
    for path, expected in receipt["inputs"].items():
        pin(Path(path), expected)
    assert frozen[str(scripts/"run.py")]["sha256"] == HELPER
    for name, expected in h.SIBLINGS.items():
        got = pin(scripts/name)
        assert (got["bytes"], got["sha256"]) == expected
    for log in (meta/"outer.log", ROOT/"target/evaluation"/meta.name/"outer.log"):
        assert pin(log, cap=8*M)["sha256"] == outer["private_log_sha256"]
    for query in receipt["capacity_queries"]:
        closed(query["owner"], 0)
        assert query["log"]["sha256"] == query["owner"]["private_log_sha256"]
        apparent = "--apparent-size" in query["command"]
        pin(ROOT/"target/evaluation"/run.name/("baseline-"+str(int(apparent))+".log"), query["log"], 65536)
    assert len(receipt["capacity_queries"]) == 2 and receipt["capacity"]["charged"] <= 2048*M
    assert receipt["baseline_slot"]+2048*M+64*M <= 20_000_000_000
    expected_cases = [(str(i)+"-"+name, name, action) for i, action in enumerate(h.ACTIONS)
                      for name in ("e9tool", "e9patch")]
    assert [(c["id"], c["source"], c["action"]) for c in receipt["cases"]] == expected_cases
    dispatches = []
    selected = {}
    definitions = json.loads((scripts/"definitions.json").read_text())
    canonical_receipt = ROOT/"evaluation/functional-corpus/receipt.json"
    canonical_csv = ROOT/"evaluation/functional-corpus/results.csv"
    assert pin(canonical_receipt, cap=M)["sha256"] == "1e9e90d8fe9493c2dc071ca8126e5d2c4c616b0f83f04725f30b086705e3f184"
    assert pin(canonical_csv, cap=M)["sha256"] == "50ffd9b52ea51b4e6ffa18ef635afdcc6a792890033745554b17a4644de83aa3"
    expected_rows = {r["case"]:r for r in json.loads(canonical_receipt.read_text())["cases"]}
    with canonical_csv.open(newline="") as f:
        expected_tactics = {r["case"]:{k:int(r[k]) for k in ("B1","B2","T1","T2","T3")}
                            for r in csv.DictReader(f) if r["arm"] == "original"}
    assert len(expected_rows) == len(expected_tactics) == 10
    for case in receipt["cases"]:
        assert case["execution"] == "CURRENT" and "generation_error" not in case and "error" not in case
        name, action = case["source"], case["action"]
        expected = expected_rows[case["id"]]
        assert expected["source"] == name and expected["action"] == action
        request = run/case["id"]/"generate/request.jsonl"
        got = pin(request, case["request"]["pin"])
        assert (got["bytes"], got["sha256"]) == (expected["rpc"]["bytes"], expected["rpc"]["sha256"])
        info, lengths = h.request(request, name, action, definitions); info["source"] = name
        assert info == case["request"] and info["messages"] == expected["messages"]
        assert info["requested"] == expected["requested"]
        gen = case["generation"]
        assert gen["status"] == "CLOSED"
        assert gen["command"] == ["/usr/bin/python3.9", "-I", "-B", str(scripts/"run.py"),
                                  "--generate", name, action, "none", str(run/case["id"]/"generate"),
                                  str(run/"inputs"), str(request), str(case["rpc_limit"]), "none", str(cpu)]
        assert not Path(gen["retained_log"]).read_bytes()
        dispatches.append(gen)
        assert set(case["arms"]) == set(h.ROLES)
        for role in h.ROLES:
            arm = case["arms"][role]; dispatches.append(arm)
            assert arm["valid_elf"] is True and "analysis_error" not in arm
            assert arm["status"] == "FAILED_OUTCOME_RETAINED"
            assert arm["strict_full"] is False and arm["statistics"]["strict_full"] is False
            assert arm["command"] == ["/usr/bin/python3.9", "-I", "-B", str(scripts/"run.py"),
                                      "--backend", name, action, role, str(run/case["id"]/role),
                                      str(run/"inputs"), str(request), str(got["bytes"]), got["sha256"], str(cpu)]
            assert pin(run/case["id"]/role/"a.out", arm["output"]) == arm["output"]
            assert h.product(run/case["id"]/role/"a.out") == arm["output"]
            assert (arm["output"]["bytes"], arm["output"]["sha256"]) == (expected["output"]["bytes"], expected["output"]["sha256"])
            actual = h.statistics(Path(arm["retained_log"]), info, lengths, arm["output"]["bytes"])
            assert actual == arm["statistics"]
            assert all(actual[k] == expected[k] for k in ("requested", "successful", "failed"))
            assert actual["tactics"] == expected_tactics[case["id"]]
            # The old first-case report used four fields. The measured self-host
            # manifest binds its already-normalized three-field comparator.
            outcomes = (canonical["expected_outcomes"][name]["complete_ordered_outcomes_sha256"]
                        if case["id"] == "0-e9patch" else expected["complete_ordered_outcomes_sha256"])
            assert actual["complete_ordered_outcomes_sha256"] == outcomes
        assert case["strict_pass"] is False and case["status"] == "FAILED_OUTCOME_RETAINED"
        assert case["descriptive_byte_equal"] == {"li2":True, "e9":True}
        assert case["descriptive_outcomes_equal"] == {"li2":True, "e9":True}
        assert all(h.equal(run/case["id"]/"original/a.out", run/case["id"]/role/"a.out") for role in ("li2", "e9"))
        if case["id"].startswith("0-"):
            canonical_request = canonical["requests"][name]
            assert (got["bytes"], got["sha256"]) == (canonical_request["bytes"], canonical_request["sha256"])
            for role in h.ROLES:
                arm = case["arms"][role]
                product = canonical["products"][role][name]
                assert (arm["output"]["bytes"], arm["output"]["sha256"]) == (product["bytes"], product["sha256"])
                assert all(arm["statistics"][k] == v for k, v in canonical["expected_outcomes"][name].items())
            selected[name] = dict(request=got, products={r:case["arms"][r]["output"] for r in h.ROLES},
                                  expected_outcomes=canonical["expected_outcomes"][name])
    assert len(dispatches) == 40 and dispatches == receipt["dispatch_attempts"]
    assert set(selected) == {"e9tool", "e9patch"}
    assert all(h.pin(Path(path)) == got for path, got in frozen.items())
    result = dict(schema=1, status="FRESH_FIRST_GENERATION_CLOSED", producer_revision=REV,
                  first_generation=str(run), owner_directory=str(meta), producer_command=command,
                  outer=outer, receipt=frozen[str(run/"receipt.json")],
                  owner_live=frozen[str(meta/"live.json")], owner_closed=frozen[str(meta/"closed.json")],
                  wrapper_closed=frozen[str(wrapper_path)],
                  source_unchanged=True, parent_and_worker_and_scopes_gone=True, cases=10, dispatches=40,
                  strict_status="FAILED_OUTCOME_RETAINED", selected=selected,
                  native_dispatches=0, independent_live_witness=False,
                  closure_script=frozen[str(SELF)], frozen=frozen)
    with destination.open("x") as f:
        json.dump(result, f, separators=(",", ":")); f.write("\n"); f.flush(); os.fsync(f.fileno())
    print(json.dumps(h.pin(destination, M)), flush=True)


if __name__ == "__main__":
    main()
