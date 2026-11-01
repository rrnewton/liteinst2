"""Exact disabled-point cohort schema; existing twelve-process paired statistics."""
import csv
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import random
import sys

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "evaluation/owned-clock-region-throughput/summarize.py"
COMMON_SHA = "45c89e7f3640f1c469e71a4730cd6c0776d6238a3179964af3c8bc54483dd5d3"
assert hashlib.sha256(COMMON.read_bytes()).hexdigest() == COMMON_SHA
spec = importlib.util.spec_from_file_location("point_statistics_common", COMMON)
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)
digest, normal, interval = common.digest, common.normal, common.interval
ARMS = ("native", "ordinary-disabled", "early-disabled")
HEADER = "pid,worker_tid,worker_cpu,arm,phase,batch,status,calls,elapsed_ns,checksum,callbacks,records,refusals".split(",")
FILES = ("measurements.csv", "summary.json")
MARKER = "early-point:2-enabled:3-qualified:9-warmups:192-measured:no-outlier-filter"


def schedule():
    orders = [",".join(x) for x in itertools.permutations(ARMS)] * 2
    random.Random(20261101).shuffle(orders)
    return orders


def artifacts(path):
    found = {}
    for name in FILES:
        p = path / name
        if p.exists():
            assert p.is_file() and not p.is_symlink() and p.stat().st_size <= 1048576
            found[name] = {"bytes": p.stat().st_size, "sha256": digest(p)}
    return found


def cohort(path, order, worker):
    assert order in schedule() and type(worker) is int and worker >= 0
    summary = json.loads((path / "summary.json").read_text())
    pid = summary["pid"]
    assert type(pid) is int and pid > 0
    assert all(type(summary[k]) is int for k in ("worker_tid", "worker_cpu", "source_bytes",
        "enabled_controls", "qualification_rows", "warmup_rows", "measured_rows", "calls_per_batch",
        "checksum_per_batch", "total_calls", "enabled_callbacks", "retained_records", "timed_callbacks"))
    assert summary["performance_threshold"] is False
    assert summary == dict(status="PASS", profile="early-point-throughput-v1", order=order,
        pid=pid, worker_tid=pid, worker_cpu=worker, source_bytes=7, enabled_controls=2,
        qualification_rows=3, warmup_rows=9, measured_rows=192, calls_per_batch=2048,
        checksum_per_batch=6296576, total_calls=417794, enabled_callbacks=2,
        retained_records=2, timed_callbacks=0, publication="direct-generated-entry", performance_threshold=False)
    with (path / "measurements.csv").open(newline="") as stream:
        reader = csv.DictReader(stream); rows = list(reader); assert reader.fieldnames == HEADER
    roster = [("ordinary-enabled", "enabled-control", 0), ("early-enabled", "enabled-control", 0)]
    roster += [(a, "qualification", 0) for a in ARMS]
    roster += [(a, "warmup" if i < 3 else "measured", i if i < 3 else i - 3)
               for a in order.split(",") for i in range(67)]
    assert len(rows) == len(roster) == 206
    totals = {a: [] for a in ARMS}
    for row, (arm, phase, index) in zip(rows, roster):
        assert set(row) == set(HEADER)
        assert [row[k] for k in ("pid", "worker_tid", "worker_cpu")] == [str(pid), str(pid), str(worker)]
        assert (row["arm"], row["phase"], row["batch"], row["status"]) == (arm, phase, str(index), "PASS")
        expected = ["1", "18", "1", "1", "0"] if phase == "enabled-control" else ["2048", "6296576", "0", "0", "0"]
        assert [row[k] for k in ("calls", "checksum", "callbacks", "records", "refusals")] == expected
        if phase in ("enabled-control", "qualification"):
            assert row["elapsed_ns"] == ""
        else:
            ns = int(row["elapsed_ns"])
            assert str(ns) == row["elapsed_ns"] and 0 < ns <= 90000000000
            if phase == "measured": totals[arm].append(ns)
    assert all(len(v) == 64 for v in totals.values())
    return {arm: sum(values) / (64 * 2048) for arm, values in totals.items()}


def summarize(path, expected_sha):
    assert digest(path / "closed.json") == expected_sha
    closed = json.loads((path / "closed.json").read_text())
    assert closed["status"] == "PASS" and closed["source_unchanged"] is True and normal(closed["build"]["owner"])
    assert digest(Path(__file__)) == closed["planned"]["frozen"][str(Path(__file__).resolve())]
    assert closed["planned"]["frozen"][str(COMMON)] == COMMON_SHA
    assert closed["planned"]["prerequisite"]["status"] == "PASS"
    assert closed["planned"]["release_prerequisite"]["status"] == "PASS"
    assert closed["planned"]["release_prerequisite"]["profile"] == "release"
    assert len(closed["cohorts"]) == 12 and [r["order"] for r in closed["cohorts"]] == schedule()
    assert digest(Path(closed["build"]["log"])) == closed["build"]["owner"]["private_log_sha256"]
    assert [(r["index"], r["directory"]) for r in closed["cohorts"]] == [(i, "cohort-%02d" % i) for i in range(12)]
    means = []
    for row in closed["cohorts"]:
        assert row["status"] == "PASS" and normal(row["owner"]) and row["source_after"] is True
        assert digest(Path(row["log"])) == row["owner"]["private_log_sha256"]
        assert Path(row["log"]).read_text().splitlines() == [MARKER]
        folder = path / row["directory"]
        assert {p.name for p in folder.iterdir()} == set(FILES)
        assert artifacts(folder) == row["artifacts"] and set(row["artifacts"]) == set(FILES)
        means.append(cohort(folder, row["order"], closed["planned"]["worker_cpu"]))
        assert artifacts(folder) == row["artifacts"]
    pairs = [(ARMS[1], ARMS[0]), (ARMS[2], ARMS[0]), (ARMS[2], ARMS[1])]
    result = dict(status="PASS_COMPLETE_COHORT", processes=12, degrees_of_freedom=11, t_critical=common.T,
        total_rows=2472, enabled_controls=24, qualifications=36, warmups=108, measured_batches=2304,
        process_means_ns_per_call=means, absolute={a: interval([m[a] for m in means]) for a in ARMS},
        paired_geometric_ratios={a+"/"+b: interval([m[a]/m[b] for m in means], True) for a,b in pairs},
        primary_ratio=ARMS[2]+"/"+ARMS[1], closed_sha256=expected_sha,
        scope="One stable disabled managed point and identical tiny add work; includes indirect calls and bookkeeping. No isolated load cost, enabled throughput, visibility/drainage, application or publication claim. No outliers removed.")
    with (path / "statistics.json").open("x") as stream:
        json.dump(result, stream, indent=2); stream.write("\n")


if __name__ == "__main__":
    assert len(sys.argv) == 3
    summarize(Path(sys.argv[1]).resolve(), sys.argv[2])
