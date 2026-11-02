#!/usr/bin/env python3
"""Bounded, read-only attribution of one CLOSED strict failure; never executes ELF."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import struct
import sys

MIB = 1 << 20
READS = []


def require(ok, message):
    if not ok:
        raise ValueError(message)


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read(path, cap, expected=None, keep=True, remember=True):
    path = Path(path).absolute()
    before = os.lstat(path)
    require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap,
            "not a bounded regular file: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    chunks, count, digest = [], 0, hashlib.sha256()
    try:
        require(identity(os.fstat(fd)) == identity(before), "open identity changed")
        while True:
            chunk = os.read(fd, min(65536, before.st_size - count + 1))
            if not chunk:
                break
            count += len(chunk)
            require(count <= before.st_size <= cap, "file grew during read")
            digest.update(chunk)
            if keep:
                chunks.append(chunk)
        require(count == before.st_size, "short file read")
        require(identity(os.fstat(fd)) == identity(before), "fd identity changed")
    finally:
        os.close(fd)
    require(identity(os.lstat(path)) == identity(before), "path identity changed")
    pin = dict(bytes=count, sha256=digest.hexdigest())
    if expected is not None:
        require(pin == expected, "pin mismatch: " + str(path))
    if remember:
        READS.append((path, cap, pin, identity(before)))
    return b"".join(chunks), pin


def metadata(path, digest, cap=2 * MIB):
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "bad SHA256")
    data, pin = read(path, cap)
    require(pin["sha256"] == digest, "metadata pin mismatch: " + str(path))
    return json.loads(data), pin


def owner(value, exit_code):
    require(value["cleanup_complete"] is True and value["reaped_descendants"] == 0
            and value["termination"] is None and value["exit_code"] == exit_code,
            "owner did not close with required cleanup/exit")


def span(offset, length, limit):
    require(0 <= offset <= limit and 0 <= length <= limit - offset, "ELF range")


def elf_tables(data):
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "ELF64 LE required")
    h = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    kind, machine, version, _, phoff, shoff, _, ehsize, phsize, phnum, shsize, shnum, shnames = h
    require((kind, machine, version, ehsize) == (3, 62, 1, 64), "x86-64 ET_DYN required")
    require(phsize == 56 and 0 < phnum <= 128 and shsize == 64
            and 0 < shnum <= 4096 and 0 < shnames < shnum, "ELF table limits")
    span(phoff, phsize * phnum, len(data)); span(shoff, shsize * shnum, len(data))
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * 64) for i in range(shnum)]
    loads = []
    for i in range(phnum):
        typ, flags, offset, address, _, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", data, phoff + i * 56)
        if typ == 1:
            span(offset, filesz, len(data)); span(address, memsz, 1 << 64)
            require(filesz <= memsz and (align in (0, 1) or align & (align - 1) == 0), "bad LOAD")
            require(align in (0, 1) or (address - offset) % align == 0, "LOAD alignment mismatch")
            loads.append(dict(start=address, end=address + memsz, flags=flags, offset=offset))
    rx = [s for s in loads if s["flags"] & 5 == 5]
    require(rx and all(not s["flags"] & 2 for s in rx), "no read-execute LOAD or writable RX")

    def strings(section):
        require(section[1] == 3, "string section type")
        span(section[4], section[5], len(data))
        return data[section[4]:section[4] + section[5]]

    def name(table, at):
        require(0 <= at < len(table), "string offset")
        end = table.find(b"\0", at, min(len(table), at + 4097))
        require(end >= at, "unterminated/oversize symbol name")
        return table[at:end].decode("ascii")

    section_names = strings(sections[shnames])
    tables = [s for s in sections if s[1] == 2]
    require(len(tables) == 1, "unique complete SHT_SYMTAB required")
    table = tables[0]
    require(name(section_names, table[0]) == ".symtab" and table[9] == 24
            and table[5] % 24 == 0 and 0 < table[5] // 24 <= 200000
            and 0 < table[6] < shnum, "symbol table limits")
    span(table[4], table[5], len(data))
    string_section = sections[table[6]]
    require(name(section_names, string_section[0]) == ".strtab", "symtab string link")
    names = strings(string_section)
    functions = []
    undefined = 0
    for at in range(table[4], table[4] + table[5], 24):
        ni, info, _, section, address, extent = struct.unpack_from("<IBBHQQ", data, at)
        if info & 15 not in (2, 10):
            continue
        raw = name(names, ni)
        if section == 0:
            undefined += 1
            continue
        require(0 < section < shnum, "unsupported defined function section")
        s = sections[section]
        require(s[2] & 4 and s[1] != 8, "defined function outside executable section")
        relative = address - s[3]
        span(relative, extent, s[5]); span(s[4] + relative, extent, len(data))
        require(any(r["start"] <= address and address + max(1, extent) <= r["end"] for r in rx),
                "function outside RX LOAD")
        functions.append(dict(name=raw, start=address, end=address + extent))
    return loads, rx, functions, undefined, table[5] // 24


def unique(functions, pattern):
    matches = [s for s in functions if re.fullmatch(pattern, s["name"]) and s["end"] > s["start"]]
    require(len(matches) == 1, "missing/ambiguous exact anchor: " + pattern)
    return matches[0]


def run(args, source_pin):
    require(__debug__ and sys.flags.isolated and sys.dont_write_bytecode, "use python -I -B without -O")
    require(len(os.sched_getaffinity(0)) == 1, "one reserved CPU required")
    for key, value in [(resource.RLIMIT_CPU, 10), (resource.RLIMIT_AS, 256 * MIB),
                       (resource.RLIMIT_FSIZE, MIB), (resource.RLIMIT_CORE, 0)]:
        require(resource.getrlimit(key) == (value, value), "external resource bounds required")
    result, result_pin = metadata(args.result, args.result_sha256)
    outer, outer_pin = metadata(args.closed, args.closed_sha256, 128 * 1024)
    build, build_pin = metadata(args.build_closed, args.build_closed_sha256, 128 * 1024)
    artifact, artifact_pin = metadata(args.artifact, args.artifact_sha256, 128 * 1024)
    revision = result["revision"]
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None and
            revision == outer["revision"] == build["revision"] == artifact["revision"], "revision join")
    require(result["tree"] == build["tree"] and result["status"] == outer["status"] == "FAILED"
            and result["profile"] == "qualification-feature-v1" and result["cleanup_complete"] is True,
            "not a CLOSED strict failure")
    require(1 <= result["native_attempts"] <= 12 and len(result["cases"]) == 12 and len(result["stages"]) == 37,
            "unexpected strict attempt/preparation denominator")
    require(all(result[k] is False for k in ("A5_qualified", "default_profile_qualified", "performance_qualified")),
            "failure must remain unqualified")
    require(len(outer["owners"]) == 5 and [v["name"] for v in outer["owners"]].count("campaign") == 1,
            "outer owner denominator")
    for entry in outer["owners"]:
        owner(entry["result"], 1 if entry["name"] == "campaign" else 0)
    for entry in result["stages"]:
        require(entry["status"] == "CLOSED_EXIT_ZERO", "preparation not closed")
        owner(entry["closed"], 0)
    roster = [("order" + order + "-k" + str(k) + "-" + mode, k, mode)
              for order in ("01", "10") for k in (10, 1000) for mode in ("enabled", "bypass", "scheduled")]
    require([(c["case"], c["k"], c["mode"]) for c in result["cases"]] == roster, "fixed cohort roster")
    failed = [i for i, c in enumerate(result["cases"]) if c["status"] == "FAILED"]
    require(len(failed) == 1 and result["native_attempts"] == failed[0] + 1, "one stopped failure required")
    for i, c in enumerate(result["cases"]):
        expected = "PASS" if i < failed[0] else "FAILED" if i == failed[0] else "UNOBSERVED"
        require(c["status"] == expected and c["attempts"] == int(i <= failed[0]), "case outcome/attempt order")
        if i <= failed[0]:
            owner(c["closed"], 101 if i == failed[0] else 0)
    case = result["cases"][failed[0]]
    require(build["status"] == "RELEASE_BUILD_PASS", "build not closed PASS")
    owner(build["owner"], 0)
    receipt = build["receipt"]
    require(receipt["exit"] == 0 and receipt["absence_proof"] == "ECHILD" and receipt["inputs_unchanged"] is True
            and receipt["wall_timeout"] is False and receipt["aborted"] is None and receipt["cleanup_error"] is None
            and receipt["unexpected_descendants"] == receipt["cleanup_events"] == [], "build receipt closure")

    # Only now read owned capture bytes. Pinned result/build are the source-claim authorities.
    raw = Path(args.result).absolute().parent
    native = raw / ("native-" + case["case"])
    request_bytes, _ = read(native / "request.json", 2 * MIB, case["request"])
    request = json.loads(request_bytes)
    require(request["argv"][1:4] == ["normal-early-entry-state", case["mode"], str(case["k"])],
            "strict native command/profile join")
    require(json.loads(read(native / "closed.json", 128 * 1024)[0]) == case["closed"], "native owner join")
    executable = Path(args.elf).absolute()
    expected_elf = dict(bytes=args.elf_bytes, sha256=args.elf_sha256)
    require(re.fullmatch(r"[0-9a-f]{64}", args.elf_sha256) is not None and 64 <= args.elf_bytes <= 16 * MIB,
            "explicit bounded ELF pin required")
    require(artifact["binary"] == expected_elf == result["retained"][str(executable)]
            == request["pins"][str(executable)] and request["argv"][0] == str(executable), "same exact ELF join")
    product = artifact["product"]
    require(product["executable"] == str(executable) and product["features"] == ["frontend-native-qualification"]
            and product["target"]["name"] == "frontend-native-oracle" and product["target"]["kind"] == ["bin"]
            and product["profile"] == dict(opt_level="3", debuginfo=0, debug_assertions=False,
                                           overflow_checks=False, test=False), "qualification build product")
    build_dir = Path(args.build_closed).absolute().parent
    cargo_bytes, cargo_pin = read(build_dir / "stdout.txt", 8 * MIB)
    require(cargo_pin["sha256"] == receipt["stdout_sha256"], "Cargo capture hash")
    require(sum(json.loads(line) == product for line in cargo_bytes.splitlines() if line.startswith(b"{")) == 1,
            "Cargo product not uniquely present")
    stderr_path = native / "stderr.txt"
    stderr_bytes, stderr_pin = read(stderr_path, MIB, result["retained"][str(stderr_path)])
    stderr = stderr_bytes.decode("utf-8")
    guard = re.findall(r"whole ordinary child 20000-step budget: phase=normal candidate steps=(\d+) rip=(0x[0-9a-f]+) pid=\d+ step_anchor=(0x[0-9a-f]+)", stderr)
    require(len(guard) == 1 and int(guard[0][0]) == 20000, "exact strict20k guard diagnostic required")
    failure_pc, runtime_anchor = (int(x, 16) for x in guard[0][1:])
    hist = re.findall(r"early-entry code-pages: page_bytes=4096 first_observed_step=Some\((\d+)\) completed_single_steps=(\d+) recorded_completed_steps=(\d+) dropped_completed_steps=(\d+) unpaired_observations=(\d+) records=(\d+)", stderr)
    require(len(hist) == 1, "unique complete histogram header required")
    first, completed, recorded, dropped, unpaired, count = map(int, hist[0])
    rows = re.findall(r"early-entry code-page: page=(0x[0-9a-f]+) completed_single_steps=(\d+) first_completed_step=(\d+) last_completed_step=(\d+)", stderr)
    require(0 < len(rows) == count <= 128 and len({p for p, _, _, _ in rows}) == count
            and sum(line.startswith("early-entry code-page:") for line in stderr.splitlines()) == count,
            "histogram row census")
    require(sum(int(n) for _, n, _, _ in rows) == recorded and recorded + dropped == completed
            and 0 <= first <= 20000 and completed <= 20000 - first, "histogram conservation")
    if unpaired == 0:
        require(completed == 20000 - first, "missing completed transitions")
    data, elf_pin = read(executable, 16 * MIB, expected_elf)
    loads, rx, functions, undefined, entries = elf_tables(data)
    walk = unique(functions, r"_RNvM.*15native_ordinary.*4Walk4step")
    bias = runtime_anchor - walk["start"]
    require(0 <= bias < (1 << 64) and bias % 4096 == 0, "invalid page-aligned load bias")
    markers = [int(s, 16) for s in re.findall(r"early-entry boundary: kind=snapshot_marker_pc step=\d+ pc=(0x[0-9a-f]+) ordinal=\d+", stderr)]
    marker = None
    if markers:
        marker = unique(functions, r"_RNv.*6normal6module11early_entry14snapshot_ready")
        require(all(p == bias + marker["start"] for p in markers), "independent marker bias mismatch")

    selected, table = {}, []
    def references(start, end):
        ids = []
        for s in functions:
            overlaps = (s["start"] < end and start < s["end"]) if s["end"] > s["start"] else start <= s["start"] < end
            if overlaps:
                key = (s["name"], s["start"], s["end"])
                if key not in selected:
                    require(len(table) < 4096, "output symbol limit; refuse, never truncate")
                    selected[key] = len(table)
                    table.append(dict(name=s["name"], start=hex(s["start"]), end=hex(s["end"])))
                ids.append(selected[key])
        return sorted(set(ids))
    output_rows = []
    for p, n, a, b in rows:
        page, n, a, b = int(p, 16), int(n), int(a), int(b)
        require(page % 4096 == 0 and n > 0 and first < a <= b <= 20000, "invalid page row")
        lo, hi = page - bias, page - bias + 4096
        segments = [i for i, s in enumerate(rx) if lo < s["end"] and s["start"] < hi]
        ids = references(lo, hi) if segments else []
        classification = "PINNED_ELF_RX" if segments else "PINNED_ELF_LOAD_OUTSIDE_RX" if any(
            lo < s["end"] and s["start"] < hi for s in loads) else "OUTSIDE_PINNED_ELF_LOADS_UNRESOLVED"
        output_rows.append(dict(runtime_page=hex(page), completed_steps=n, first_step=a, last_step=b,
                                elf_page=hex(lo) if segments else None, rx_segments=segments, symbols=ids,
                                classification=classification))
    pc = failure_pc - bias
    failure_in_rx = any(s["start"] <= pc < s["end"] for s in rx)
    failure_symbols = references(pc, pc + 1) if failure_in_rx else []
    # Re-read/hash every exact input, streaming the ELF; no second full image allocation.
    for path, cap, pin, old_identity in READS:
        read(path, cap, pin, keep=False, remember=False)
        require(identity(os.lstat(path)) == old_identity, "input identity changed after analysis")
    return dict(status="STATIC_PAGE_MAPPING_ONLY", source=source_pin, revision=revision, strict_status="FAILED",
                failed_cohort=case["case"], native_attempts=result["native_attempts"],
                authorities=dict(result=result_pin, outer=outer_pin, build=build_pin, artifact=artifact_pin,
                                 stderr=stderr_pin, elf=elf_pin), load_bias=hex(bias), walk_anchor=walk,
                independent_marker=marker, marker_observations=len(markers), rx_loads=rx,
                symtab_entries=entries, defined_function_symbols=len(functions), undefined_functions=undefined,
                histogram=dict(first_observed_step=first, completed_steps=completed, recorded_steps=recorded,
                               dropped_steps=dropped, unpaired_observations=unpaired, pages=output_rows),
                failure=dict(runtime_pc=hex(failure_pc), elf_pc=hex(pc) if failure_in_rx else None,
                             classification="PINNED_ELF_RX" if failure_in_rx else "OUTSIDE_PINNED_ELF_RX_UNRESOLVED",
                             overlapping_symbols=failure_symbols),
                symbols=table,
                limitations=["Page counts are never assigned to individual functions; overlaps include aliases and zero-size entries.",
                             "Outside-main-RX pages may be libraries, generated code, padding or unmapped; no process maps were read.",
                             "Counts cover only the reported partial prefix. Failure PC is the next unexecuted instruction.",
                             "Fork-without-exec mapping premise is source-reviewed; marker equality is an independent check when present.",
                             "Pinned CLOSED result/build authorities supply provenance; this reader does not repeat source or qualification audits.",
                             "No timing, full-path, runtime improvement, strict20k pass or changed witness/budget claim."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("result", "closed", "build-closed", "artifact"):
        parser.add_argument("--" + name, required=True)
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--elf", required=True)
    parser.add_argument("--elf-sha256", required=True)
    parser.add_argument("--elf-bytes", required=True, type=int)
    args = parser.parse_args()
    _, source_pin = read(__file__, 64 * 1024)
    try:
        result = run(args, source_pin)
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
        require(len(encoded.encode()) <= MIB, "complete JSON exceeds bound; refuse without filtering")
    except Exception as error:
        print(json.dumps(dict(status="REFUSED", source=source_pin, error=type(error).__name__ + ": " + str(error)), sort_keys=True))
        return 1
    sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
