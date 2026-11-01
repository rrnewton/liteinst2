"""One CLOSED-only metadata analysis; never execute an input or generated ELF."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import struct
import sys
import time
import traceback

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use Python -I -B with assertions")
SELF = Path(__file__).resolve()
ROOT, OUT = SELF.parents[3], SELF.parent
RUN = ROOT / "ignored/a3/functional-corpus-remaining-v1"
OWNER = ROOT / "ignored/a3/functional-corpus-remaining-owner-v1"
PROPOSAL = ROOT / "ignored/a3/functional-corpus-proposal-v1"
ROLES = ("original", "li2", "e9")
TACTICS = ("B1", "B2", "T1", "T2", "T3")
ACTIONS = ("=.*:passthru", "=.*:call entry@nop", "=.*:call[naked,after] entry@nop",
           "=.*:call entry(instrAsmStr,instrBytes,rflags,rdi,rip,instrAddr)@nop", "=.*:print")
REV = "438954e0e1372fdb428b3446d69aca804ccd29ea"
M = 1024**2
BEGIN = time.monotonic()


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def expected(pin):
    return {k: pin[k] for k in ("bytes", "sha256")}


class AuthenticatedFile:
    def __init__(self, path, bound, wanted):
        self.path, self.wanted = path, expected(wanted)
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        self.file = os.fdopen(fd, "rb")
        self.before = os.fstat(fd)
        assert stat.S_ISREG(self.before.st_mode) and self.before.st_size == wanted["bytes"] <= bound
        self.hash, self.count = hashlib.sha256(), 0

    def add(self, data):
        self.count += len(data)
        assert self.count <= self.before.st_size
        self.hash.update(data)
        return data

    def finish(self):
        actual = dict(bytes=self.count, sha256=self.hash.hexdigest())
        assert actual == self.wanted
        assert identity(self.before) == identity(os.fstat(self.file.fileno())) == identity(self.path.lstat())
        self.file.close()
        return actual


def read(path, bound, wanted):
    f = AuthenticatedFile(path, bound, wanted)
    data = f.add(f.file.read(bound + 1))
    return data, f.finish()


def load(path, bound, wanted):
    raw, pin = read(path, bound, wanted)
    return json.loads(raw), pin


def digest(value):
    return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


def normal(owner, code):
    assert owner["exit_code"] == code and owner["termination"] is None
    assert owner["cleanup_complete"] is True and owner["reaped_descendants"] == 0


def one(pattern, raw):
    values = re.findall(pattern, raw, re.MULTILINE)
    assert len(values) == 1, pattern
    return values[0]


def source_text(data):
    h = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    assert h[0][:6] == b"\x7fELF\x02\x01" and h[2] == 62 and h[11] == 64
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, h[6] + i * 64) for i in range(h[12])]
    strings_section = sections[h[13]]
    strings = data[strings_section[4]:strings_section[4] + strings_section[5]]
    rows = [s for s in sections if strings[s[0]:].split(b"\0", 1)[0] == b".text"]
    assert len(rows) == 1 and rows[0][1] == 1 and rows[0][2] & 6 == 6
    address, offset, size = rows[0][3:6]
    assert offset + size <= len(data)
    return address, offset, size


def request(case, text):
    path = RUN / case["id"] / "generate/request.jsonl"
    f = AuthenticatedFile(path, 203238400, case["request"]["pin"])
    address, offset, size = text
    declarations, patches, methods = {}, [], {}
    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result
            result[key] = value
        return result
    i = -1
    for i, raw in enumerate(iter(lambda: f.file.readline(M + 1), b"")):
        f.add(raw); assert len(raw) <= M and raw.endswith(b"\n")
        row = json.loads(raw, object_pairs_hook=unique)
        assert set(row) == {"id", "jsonrpc", "method", "params"}
        assert type(row["id"]) is int and row["id"] == i and row["jsonrpc"] == "2.0"
        method, p = row["method"], row["params"]
        methods[method] = methods.get(method, 0) + 1
        if method == "instruction":
            assert set(p) == {"address", "offset", "length"} and all(type(v) is int for v in p.values())
            a, o, n = p["address"], p["offset"], p["length"]
            assert o not in declarations and offset <= o < o + n <= offset + size and 1 <= n <= 15
            assert a - address == o - offset
            declarations[o] = (a, o, n)
        elif method == "patch":
            assert type(p["offset"]) is int and p["offset"] in declarations
            patches.append(p["offset"])
        elif method == "binary":
            assert i == 0 and p == dict(filename="/proc/self/fd/3", mode="exe")
        elif method == "emit":
            assert p == dict(filename="a.out", format="binary", mapping_size=32768)
            assert not f.file.read(1)
        else:
            assert method in ("trampoline", "reserve")
    pin = f.finish()
    assert method == "emit"
    ordered = sorted(declarations)
    cursor = offset
    for o in ordered:
        assert o == cursor
        cursor += declarations[o][2]
    assert cursor == offset + size and patches == list(reversed(ordered))
    n = len(ordered)
    census = dict(binary=1, trampoline=1, instruction=n, patch=n, emit=1)
    if "call" in case["action"]: census["reserve"] = 4
    assert methods == census and i + 1 == case["request"]["messages"]
    assert n == case["request"]["requested"] and list(text) == case["request"]["text"]
    roster = [(declarations[o][0], declarations[o][2]) for o in patches]
    return roster, dict(pin=pin, messages=i + 1, requested=n, text=list(text), ordered_heads_sha256=digest(roster))


ADDRESS = rb"(?:\[absolute\] )?-?0x[0-9a-f]+"
EVENT = re.compile(
    rb"debug: (?:patched instruction 0x([0-9a-f]+) \[size=([0-9]+), tactic=(B1|B2|T1|T2|T3), trampoline="
    + ADDRESS + rb"\.\." + ADDRESS + rb"\]|failed to patch instruction at address 0x([0-9a-f]+) \(([0-9]+)\))")


def parse_log(case, role, roster, input_size):
    arm = case["arms"][role]
    normal(arm["owner"], 0)
    assert arm["valid_elf"] and arm["strict_full"] is False and arm["status"] == "FAILED_OUTCOME_RETAINED"
    path = Path(arm["retained_log"])
    assert path.parent == RUN / "logs" and path.name.endswith(".log")
    raw, pin = read(path, case["backend"]["log_bytes"], arm["log"])
    assert pin["sha256"] == arm["owner"]["private_log_sha256"]
    outcomes, failures, histogram = [], [], dict.fromkeys(TACTICS, 0)
    for m in EVENT.finditer(raw):
        if m[1] is not None:
            a, length, tactic = int(m[1], 16), int(m[2]), m[3].decode()
            histogram[tactic] += 1
        else:
            a, length, tactic = int(m[4], 16), int(m[5]), "FAILED"
            failures.append((a, length))
        outcomes.append((a, length, tactic))
    successful, n = sum(histogram.values()), len(roster)
    assert raw.count(b"debug: patched instruction ") == successful
    assert raw.count(b"debug: failed to patch instruction") == len(failures)
    assert [(a, length) for a, length, tactic in outcomes] == roster
    total = one(rb"^num_patched + = ([0-9]+) / ([0-9]+) \((?:[0-9]+\.[0-9]{2}|~100\.00)%\)$", raw)
    assert tuple(map(int, total)) == (successful, n) and successful + len(failures) == n
    for tactic, count in histogram.items():
        line = one(rb"^num_patched_" + tactic.encode() + rb" + = ([0-9]+) / ([0-9]+) \([0-9]+\.[0-9]{2}%\)$", raw)
        assert tuple(map(int, line)) == (count, n)
    assert one(rb"^input_binary + = (.+)$", raw) == b"/proc/self/fd/3"
    assert one(rb"^input_mode + = (.+)$", raw) == b"EXECUTABLE"
    assert int(one(rb"^input_file_size + = ([0-9]+)$", raw)) == input_size
    assert int(one(rb"^output_file_size + = ([0-9]+) \([0-9]+\.[0-9]{2}%\)$", raw)) == arm["output"]["bytes"]
    actual = dict(strict_full=successful == n, successful=successful, requested=n, failed=len(failures),
                  tactics=histogram, failed_tuples_sha256=digest(failures),
                  complete_ordered_outcomes_sha256=digest(outcomes), ordered_coverage_sha256=digest(roster))
    assert actual == arm["statistics"]
    return outcomes, actual, pin


def outputs(case):
    handles = {r: AuthenticatedFile(RUN / case["id"] / r / "a.out", 512 * M, case["arms"][r]["output"]) for r in ROLES}
    equal = dict(li2=True, e9=True)
    first = True
    while True:
        blocks = {r: f.add(f.file.read(M)) for r, f in handles.items()}
        if first:
            assert all(b[:6] == b"\x7fELF\x02\x01" for b in blocks.values())
            first = False
        for r in equal: equal[r] = equal[r] and blocks[r] == blocks["original"]
        if not any(blocks.values()): break
    return equal, {r: f.finish() for r, f in handles.items()}


def save(name, value):
    data = (json.dumps(value, indent=2) + "\n").encode()
    assert len(data) <= M
    with (OUT / name).open("xb") as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def main():
    assert Path.cwd() == ROOT and len(os.sched_getaffinity(0)) == 1
    limits = {name: resource.getrlimit(key) for name, key in (("cpu", resource.RLIMIT_CPU), ("as", resource.RLIMIT_AS), ("file", resource.RLIMIT_FSIZE), ("core", resource.RLIMIT_CORE))}
    assert limits == dict(cpu=(60, 60), **{"as": (256 * M, 256 * M)}, file=(M, M), core=(0, 0))
    root, rootpin = load(OWNER / "root-closed.json", 8192, dict(bytes=1409, sha256="b6deb0100b59ed044c1a120d191ed6a9453fef7f550d50d019e6b850381691ff"))
    assert root["status"] == "CLOSED_AUTHENTICATED" and root["source_unchanged"] and root["pid_and_both_scopes_gone"]
    normal(root["outer"], 1)
    closed, closedpin = load(OWNER / "closed.json", 8192, root["owner"])
    assert closed["normal"] and not closed["passed"] and closed["source_unchanged"] and closed["attempts"] == 1
    assert closed["result"] == root["outer"] and expected(closed["receipt"]) == expected(root["receipt"])
    receipt, receiptpin = load(RUN / "receipt.json", M, root["receipt"])
    assert receipt["revision"] == REV and receipt["case_set"] == "remaining-nine" and receipt["source_unchanged"]
    assert receipt["status"] == closed["status"] == "FAILED_OUTCOME_RETAINED"
    assert receipt["qualification_complete"] is False and receipt["performance_qualified"] is False
    assert len(receipt["cases"]) == 10 and len(receipt["dispatch_attempts"]) == root["dispatches"] == 36
    history, historypin = load(PROPOSAL / "first-case.json", 16384, dict(bytes=7639, sha256="1fd8e3cfe208becf992f8edbc990a0e6acdca45fef3a26c3a49cfc6e06652c0d"))
    assert history["status"] == "FAILED_OUTCOME_RETAINED" and history["case"] == "e9patch:passthru"
    prior, priorpin = load(ROOT / "ignored/a3/overlapping-neighbor-functional-analysis-v1/phase-report.json", 16384, history["raw_pins"]["analysis"])
    assert prior["official_gate"] == "FAILED_OUTCOME_RETAINED" and prior["official_byte_equal"] == dict(li2=None, e9=None)
    sources = {}
    for source in ("e9tool", "e9patch"):
        wanted = receipt["inputs"][str(RUN / "inputs" / source)]
        data, pin = read(RUN / "inputs" / source, 4 * M, wanted)
        sources[source] = dict(pin=pin, text=source_text(data))
    totals = {r: dict(requested=0, successful=0, refused=0, tactics=dict.fromkeys(TACTICS, 0)) for r in ROLES}
    rows, joined_dispatches = [], []
    for i, case in enumerate(receipt["cases"]):
        action, source = ACTIONS[i // 2], ("e9tool", "e9patch")[i % 2]
        assert case["id"] == str(i // 2) + "-" + source and case["source"] == source and case["action"] == action
        assert case["status"] == "FAILED_OUTCOME_RETAINED" and case["strict_pass"] is False
        row = dict(id=case["id"], source=source, action=action, strict_status=case["status"])
        if case["execution"] == "HISTORICAL":
            assert case["id"] == "0-e9patch" and case["new_backend_attempts"] == 0 and case["arms"] == {}
            assert expected(case["history"]) == historypin
            stats = {r: history["comparison"]["arms"][r] for r in ROLES}
            for r in ROLES:
                normal(stats[r]["owner"], 0)
                assert stats[r]["requested"] == prior["denominator"]
                assert stats[r]["successful"] == prior["outcomes"][r]["successful"] and stats[r]["refused"] == prior["outcomes"][r]["refused"]
                assert stats[r]["tactics"] == prior["outcomes"][r]["tactics"]
                assert stats[r]["log"] == prior["outcomes"][r]["log"] and stats[r]["output"] == prior["outcomes"][r]["output"]
            row.update(evidence="CARRIED_CLOSED_FIRST_CASE", request=history["preparation"]["request"],
                       descriptive_byte_equal=history["closed_analysis"]["descriptive_output_byte_equal"],
                       complete_outcomes_equal=history["closed_analysis"]["complete_ordered_outcomes_equal"],
                       arms={r: {k: stats[r][k] for k in ("requested", "successful", "refused", "tactics", "log", "output", "complete_ordered_outcomes_sha256")} for r in ROLES})
        else:
            assert case["execution"] == "CURRENT" and tuple(case["arms"]) == ROLES
            normal(case["generation"]["owner"], 0)
            joined_dispatches.append(case["generation"])
            roster, req = request(case, sources[source]["text"])
            populations, stats, pins = {}, {}, {}
            for r in ROLES:
                populations[r], stats[r], pins[r] = parse_log(case, r, roster, sources[source]["pin"]["bytes"])
                joined_dispatches.append(case["arms"][r])
            same_bytes, products = outputs(case)
            same_outcomes = {r: populations[r] == populations["original"] for r in ROLES[1:]}
            assert same_bytes == case["descriptive_byte_equal"] and same_outcomes == case["descriptive_outcomes_equal"]
            row.update(evidence="INDEPENDENT_CURRENT_REQUEST_LOG_AND_BYTE_READBACK", request=req,
                       descriptive_byte_equal=same_bytes, complete_outcomes_equal=same_outcomes,
                       arms={r: dict(requested=stats[r]["requested"], successful=stats[r]["successful"], refused=stats[r]["failed"],
                           tactics=stats[r]["tactics"], log=pins[r], output=products[r],
                           failed_tuples_sha256=stats[r]["failed_tuples_sha256"],
                           complete_ordered_outcomes_sha256=stats[r]["complete_ordered_outcomes_sha256"]) for r in ROLES})
        for r, values in row["arms"].items():
            for key in ("requested", "successful", "refused"): totals[r][key] += values[key]
            for tactic in TACTICS: totals[r]["tactics"][tactic] += values["tactics"][tactic]
        rows.append(row)
    assert len(joined_dispatches) == 36
    for actual, claimed in zip(joined_dispatches, receipt["dispatch_attempts"]):
        for key in ("command", "owner", "log", "retained_log", "before", "after", "admission"):
            assert actual[key] == claimed[key]
    for values in totals.values():
        assert values["successful"] + values["refused"] == values["requested"]
        assert sum(values["tactics"].values()) == values["successful"]
    script = SELF.read_bytes()
    report = dict(status="INDEPENDENT_DIAGNOSTIC_COMPLETE_STRICT_FAILED", revision=REV,
                  authorities=dict(root=rootpin, owner=closedpin, receipt=receiptpin, historical_first_case=historypin, prior_analysis=priorpin),
                  cases=rows, totals_per_arm=totals, current_cases_read=9, carried_cases=1,
                  current_backend_attempts=27, historical_backend_attempts=3,
                  root_reported_totals_match=all(v["requested"] == 296245 and v["refused"] == 1035 for v in totals.values()),
                  strict_pass_cases=0, strict_status="FAILED_OUTCOME_RETAINED", qualification_complete=False, performance_qualified=False,
                  interpretation="Direct bytes and complete ordered outcomes are descriptive. All partial cases remain strict failures. First case is carried from authenticated prior independent readback, not rerun. No generated product execution or patched-frontend second round.",
                  execution=dict(cpus=sorted(os.sched_getaffinity(0)), limits=limits, seconds=time.monotonic()-BEGIN,
                      script=dict(bytes=len(script), sha256=hashlib.sha256(script).hexdigest()), independent_live_witness=False))
    pin = save("report.json", report)
    print(json.dumps(dict(report=pin, totals_per_arm=totals, root_reported_totals_match=report["root_reported_totals_match"], strict_status=report["strict_status"])))


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        save("error.json", dict(status="METADATA_ANALYSIS_FAILED", type=type(error).__name__, message=str(error), traceback=traceback.format_exc()[-16000:], native_gate_status="FAILED_OUTCOME_RETAINED"))
        raise
