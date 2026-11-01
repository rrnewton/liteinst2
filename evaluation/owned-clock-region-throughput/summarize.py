"""Closed-only validation and twelve-process paired statistics; no filtering."""
import csv, hashlib, itertools, json, math, random, statistics, struct, sys
from pathlib import Path

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
ARMS = ("native", "counter", "stop")
HEADER = "pid,worker_tid,arm,phase,batch,status,calls,expected_encounters,expected_taken,elapsed_ns,checksum,clock_encounters,clock_taken,stops,remaining".split(",")
FILES = ("measurements.csv", "summary.json", "rejections.csv", "rejection-1.bin", "rejection-2.bin")
T = 2.200985160


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1048576), b""): h.update(chunk)
    return h.hexdigest()


def schedule():
    orders = [",".join(x) for x in itertools.permutations(ARMS)] * 2
    random.Random(20261101).shuffle(orders)
    return orders


def normal(result):
    return result["exit_code"] == 0 and result["termination"] is None and result["cleanup_complete"] and result["reaped_descendants"] == 0


def artifacts(path):
    found = {}
    for name in FILES:
        p = path / name
        if p.exists():
            assert p.is_file() and not p.is_symlink() and p.stat().st_size <= 1048576
            found[name] = {"bytes": p.stat().st_size, "sha256": digest(p)}
    return found


def cohort(path, order, cpus):
    summary = json.loads((path / "summary.json").read_text())
    assert summary == dict(status="PASS", profile="owned-two-backedge-throughput-v1", order=order,
        controller_cpu=cpus[0], worker_cpu=cpus[1], qualification_rows=3, rejection_children=2,
        rejection_witnesses=2, warmup_rows=9, measured_rows=192, calls_per_batch=2048,
        encounters_per_lease=30720, quantum=64, stop_handoffs_per_batch=352,
        publisher_validation=False, full_state_after_callback=False, performance_threshold=False)
    with (path / "measurements.csv").open(newline="") as stream:
        reader = csv.DictReader(stream); rows = list(reader); assert reader.fieldnames == HEADER
    roster = [(a, "qualification", 0) for a in ARMS]
    roster += [(a, "warmup" if i < 3 else "measured", i if i < 3 else i-3) for a in order.split(",") for i in range(67)]
    assert len(rows) == len(roster) == 204
    totals = {a: [] for a in ARMS}; pids = set()
    for row, (arm, phase, index) in zip(rows, roster):
        assert set(row) == set(HEADER) and (row["arm"], row["phase"], row["batch"], row["status"]) == (arm, phase, str(index), "PASS")
        assert [row[k] for k in ("calls", "expected_encounters", "expected_taken", "checksum")] == ["2048", "30720", "22528", "24576"]
        pid, tid = int(row["pid"]), int(row["worker_tid"]); assert pid > 0 and tid > 0 and pid != tid; pids.add(pid)
        assert [row[k] for k in ("clock_encounters", "clock_taken", "stops", "remaining")] == (["", "", "0", ""] if arm == "native" else ["30720", "22528", "352" if arm == "stop" else "0", "64"])
        if phase == "qualification": assert row["elapsed_ns"] == ""
        else:
            ns = int(row["elapsed_ns"]); assert str(ns) == row["elapsed_ns"] and 0 < ns <= 90000000000
            if phase == "measured": totals[arm].append(ns)
    assert len(pids) == 1 and all(len(v) == 64 for v in totals.values())
    with (path / "rejections.csv").open(newline="") as stream:
        reader = csv.DictReader(stream); rejects = list(reader)
        assert reader.fieldnames == "fault,pid,tid,site,count,reply_site,reply_count,exit,result".split(",")
    assert len(rejects) == 2
    for cause, row in enumerate(rejects, 1):
        reply = (21, 64) if cause == 1 else (20, 65)
        assert row == dict(fault=str(cause), pid=row["pid"], tid=row["tid"], site="20", count="64", reply_site=str(reply[0]), reply_count=str(reply[1]), exit="123", result="PASS")
        raw = (path / ("rejection-%d.bin" % cause)).read_bytes(); assert len(raw) == 248 and raw[:8] == b"LI2RBQ64"
        w = struct.unpack("<30Q", raw[8:]); assert w[:3] == (cause, int(row["pid"]), int(row["tid"]))
        assert w[1] > 0 and w[2] > 0 and w[1] != w[2] and w[1] not in pids and w[3] > 0
        assert w[4:12] == (20, 64, *reply, 3, 86, 64, 0) and w[12] == w[3]+20 and w[13] > 0
        assert (w[21], w[27], w[28]) == (1, 3, 9) and w[29] & 64 == 0
    return {arm: sum(values) / (64 * 2048) for arm, values in totals.items()}


def interval(values, logarithmic=False):
    assert len(values) == 12 and all(math.isfinite(v) and v > 0 for v in values)
    data = list(map(math.log, values)) if logarithmic else values
    mean = statistics.mean(data); half = T * statistics.stdev(data) / math.sqrt(12)
    transform = math.exp if logarithmic else lambda x: x
    return dict(estimate=transform(mean), lower95=transform(mean-half), upper95=transform(mean+half))


def summarize(path, expected_sha):
    assert digest(path / "closed.json") == expected_sha
    closed = json.loads((path / "closed.json").read_text())
    assert closed["status"] == "PASS" and closed["source_unchanged"] is True and normal(closed["build"]["owner"])
    assert digest(Path(__file__)) == closed["planned"]["frozen"][str(Path(__file__).resolve())]
    assert len(closed["cohorts"]) == 12 and [r["order"] for r in closed["cohorts"]] == schedule()
    assert digest(Path(closed["build"]["log"])) == closed["build"]["owner"]["private_log_sha256"]
    assert [(r["index"],r["directory"]) for r in closed["cohorts"]] == [(i,"cohort-%02d" % i) for i in range(12)]
    means = []
    for row in closed["cohorts"]:
        assert row["status"] == "PASS" and normal(row["owner"]) and row["source_after"] is True
        assert digest(Path(row["log"])) == row["owner"]["private_log_sha256"]
        folder = path / row["directory"]; assert artifacts(folder) == row["artifacts"] and set(row["artifacts"]) == set(FILES)
        means.append(cohort(folder, row["order"], closed["planned"]["reserved_cpus"][1:]))
        assert artifacts(folder) == row["artifacts"]
    result = dict(status="PASS_COMPLETE_COHORT", processes=12, degrees_of_freedom=11, t_critical=T,
        process_means_ns_per_call=means, absolute={a: interval([m[a] for m in means]) for a in ARMS},
        paired_geometric_ratios={a+"/native": interval([m[a]/m["native"] for m in means], True) for a in ARMS[1:]},
        closed_sha256=expected_sha, scope="Includes per-call guards and real handoff/check/scheduling cost; not isolated gate cost, a performance threshold, or publisher qualification. No outliers removed.")
    with (path / "statistics.json").open("x") as stream: json.dump(result, stream, indent=2); stream.write("\n")


if __name__ == "__main__":
    assert len(sys.argv) == 3
    summarize(Path(sys.argv[1]).resolve(), sys.argv[2])
