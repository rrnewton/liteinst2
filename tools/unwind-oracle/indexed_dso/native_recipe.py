#!/usr/bin/env python3
"""Fixed three-cell recipe; only existing owners execute children.

Run inside ONE retained cpuset-alloc --cores 1 lease and the existing 1200 s
outer owner. A reviewed, frozen admission JSON is mandatory; this program does
not manufacture compiler/CRT/callback semantic authority from its hashes.
"""
import sys
if sys.flags.optimize:
    raise SystemExit("assertions required")
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import stat
import struct
import subprocess

ROOT = Path.cwd().resolve()
HERE = Path(__file__).resolve().parent
MODES = ("original", "intact", "lookup-negative")
HELPER = ROOT / "tools/unwind-oracle/bounded_command.py"
HELPER_SHA = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
OWNER = ROOT / "evaluation/admission/processes.py"
OWNER_SHA = "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"
CONSUMER_SHA = "3d144b557008c93e4e67567d5dc98cb81cf55187a698d1b4872ce84ba8a26bed"
CAP, READ_CAP, LOG_CAP = 128 * 1024**2, 16 * 1024**2, 8 * 1024**2
STAGES = ("gcc-version", "assembler-version", "linker-version", "resolve-cc1",
          "resolve-assembler", "resolve-collect2", "resolve-linker", "resolve-libgcc",
          "compile-subject", "compile-collector", "compile-caller", "link-subject", "link-caller")


def capture(path, keep=False, cap=CAP):
    path = Path(path)
    assert path.is_absolute() and path.resolve(strict=True) == path
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        a = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_mtime_ns, s.st_ctime_ns)
        assert stat.S_ISREG(a.st_mode) and a.st_size <= cap
        h, chunks, n = hashlib.sha256(), [], 0
        while True:
            b = os.read(fd, min(524288, cap + 1 - n))
            if not b:
                break
            n += len(b)
            assert n <= cap
            h.update(b)
            if keep:
                chunks.append(b)
        assert n == a.st_size and fields(a) == fields(os.fstat(fd)) == fields(path.lstat())
        return dict(path=str(path), bytes=n, sha256=h.hexdigest()), b"".join(chunks)
    finally:
        os.close(fd)


def check(pin):
    actual, _ = capture(pin["path"])
    assert all(actual[k] == pin[k] for k in ("path", "bytes", "sha256"))
    return actual


def unique(pairs):
    value = dict(pairs)
    assert len(value) == len(pairs), "duplicate JSON key"
    return value


def load(path, digest=None):
    pin, raw = capture(path, True, READ_CAP)
    assert digest is None or pin["sha256"] == digest
    return json.loads(raw, object_pairs_hook=unique)


def save(path, value):
    temp = path.with_suffix(path.suffix + ".pending")
    with temp.open("x") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def ordinary_closed(row):
    return (row["exit_code"] == 0 and row["termination"] is None
            and row["cleanup_complete"] is True and row["reaped_descendants"] == 0)


def helper_custody(row):
    return (row["absence_proof"] == "ECHILD" and row["unexpected_descendants"] == []
            and row["cleanup_events"] == [] and row["cleanup_error"] is None
            and row["aborted"] is None and row["inputs_unchanged"] is True)


def all_pins(value, result=None):
    if result is None:
        result = {}
    if isinstance(value, dict):
        if {"path", "bytes", "sha256"} <= value.keys():
            p = {k: value[k] for k in ("path", "bytes", "sha256")}
            assert p["path"] not in result or result[p["path"]] == p
            result[p["path"]] = p
            assert len(result) <= 4096
        for child in value.values():
            all_pins(child, result)
    elif isinstance(value, list):
        for child in value:
            all_pins(child, result)
    return result


def source():
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, timeout=10).decode().splitlines()
    paths = set(git("ls-files", "--modified", "--others", "--exclude-standard"))
    paths.update(git("diff", "--cached", "--name-only"))
    assert git("ls-files", "--", "BRIEF-li2core.md") == []
    paths.discard("BRIEF-li2core.md")  # expressly untracked coordinator brief only
    return dict(base=git("rev-parse", "HEAD")[0], working_source_sha256={
        p: capture(ROOT / p)[0]["sha256"] if (ROOT / p).is_file() else None for p in sorted(paths)})


def reservation(admission):
    ledger = load(Path(admission["reservation_ledger"]))
    rows = [r for r in ledger["reservations"] if r["tag"] == admission["reservation_tag"]]
    assert len(rows) == 1
    row = rows[0]
    cpus = sorted(os.sched_getaffinity(0))
    assert len(cpus) == 1 and row["cores"] == cpus
    pid, ancestors = os.getpid(), {}
    for _ in range(64):
        data = Path(f"/proc/{pid}/stat").read_bytes()
        assert len(data) <= 4096
        tail = data[data.rfind(b")") + 2:].split()
        ancestors[pid] = int(tail[19])
        pid = int(tail[1])
        if pid == 0:
            break
    assert ancestors.get(row["pid"]) == row["starttime"] and row["starttime"] > 0
    groups = Path("/proc/self/cgroup").read_text().splitlines()
    assert len(groups) == 1 and groups[0].startswith("0::/")
    group = groups[0][3:]
    unit = "cpuset-alloc-" + "".join(c if c.isalnum() else "-" for c in row["tag"])[:48] + "-" + str(row["pid"])
    assert unit + ".scope" in group.split("/")
    effective = (Path("/sys/fs/cgroup") / group.lstrip("/") / "cpuset.cpus.effective").read_text().strip()
    assert effective == str(cpus[0])
    return {k: row[k] for k in ("pid", "starttime", "cores", "tag")}


def population(mode, raw):
    lines = [json.loads(line, object_pairs_hook=unique) for line in raw.splitlines()]
    assert 1 <= len(lines) <= 21
    completes = [r for r in lines if r.get("kind") == "complete"]
    assert len(completes) == 1 and lines[-1] == completes[0]
    end = completes[0]
    assert set(end) == {"kind", "mode", "lookups", "calls"}
    assert end["mode"] == {"original": "Original", "intact": "Intact", "lookup-negative": "lookup-negative"}[mode]
    assert type(end["lookups"]) is int
    # Original owns only original subject/caller coordinates. Generated ranges
    # belong to intact/negative, whose complete point sets must agree below.
    assert end["lookups"] == 38 if mode == "original" else end["lookups"] > 38
    calls = [r for r in lines if r.get("kind") == "call"]
    frames = [r for r in lines if r.get("kind") == "frame"]
    assert len(lines) == len(calls) + len(frames) + 1
    cases = ("MixedBytes", "TextAndZeros")
    expected = [] if mode == "lookup-negative" else [(m, c) for c in cases for m in
        ("Reference", "OriginalWork" if mode == "original" else "CandidateWork")]
    assert [(r["mode"], r["case"]) for r in calls] == expected
    assert end["calls"] == len(expected)
    for r in calls:
        assert set(r) == {"kind", "mode", "case", "returned", "rsp_pre", "rsp_raw", "result", "output", "callee"}
        assert r["returned"] == 1 and r["rsp_pre"] == r["rsp_raw"]
        assert r["callee"] == [0x13579bdf2468ace1, 0x2468ace113579bdf, 0x3141592653589793,
                               0x2718281828459045, 0x55aa33cc77ee1199, 0xaa55cc33ee779911]
        data, seed = ((bytes([0, 1, 2, 3, 127, 128, 254, 255]), 0x0123456789abcdef)
                      if r["case"] == "MixedBytes" else (b"LiteInst indexed DSO\0\xff", 0xfedcba9876543210))
        value = seed
        for byte in data:
            value = ((value * 33) & ((1 << 64) - 1)) ^ byte
        result, output = ((seed ^ 0x5245464552454e43, 0xc3c35a5a96966969)
                          if r["mode"] == "Reference" else (value, value ^ len(data)))
        assert (r["result"], r["output"]) == (result, output)
    frame_keys = [(m, c) for m, c in expected if m != "OriginalWork"]
    for m, c in frame_keys:
        group = [r for r in frames if (r["mode"], r["case"]) == (m, c)]
        assert len(group) == 4 and [r["index"] for r in group] == [0, 1, 2, 3]
        assert all(set(r) == {"kind", "mode", "case", "index", "ip", "cfa", "before_instruction", "owned", "callee"} for r in group)
    assert all((r["mode"], r["case"]) in frame_keys for r in frames)
    expected_order = []
    for m, c in expected:
        if m != "OriginalWork":
            expected_order.extend(("frame", m, c, i) for i in range(4))
        expected_order.append(("call", m, c, None))
    assert [(r["kind"], r["mode"], r["case"], r.get("index")) for r in lines[:-1]] == expected_order
    # Exact frame-address/CFI admission is in the reviewed frozen executable; these
    # are a complete output census, never an independent semantic qualification.
    return dict(calls=len(calls), frames=len(frames), lookups=end["lookups"])


def elf_programs(raw):
    assert len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01"
    assert struct.unpack_from("<H", raw, 18)[0] == 62
    first = struct.unpack_from("<Q", raw, 32)[0]
    size, count = struct.unpack_from("<HH", raw, 54)
    assert size == 56 and 1 <= count <= 256 and first + count * 56 <= len(raw)
    return [struct.unpack_from("<IIQQQQQQ", raw, first + i * 56) for i in range(count)]


def diagnostic_inputs(binary, libgcc, pins):
    # Only the loader path and executable-segment count are projected from ELF;
    # all CFI/consumer/mapping authority remains in the reviewed Rust driver.
    check(binary)
    main = capture(binary["path"], True)[1]
    interpreters = []
    for p in elf_programs(main):
        if p[0] == 3:
            assert 2 <= p[5] <= 4096 and p[2] + p[5] <= len(main)
            name = main[p[2]:p[2] + p[5]]
            assert name[-1:] == b"\0" and b"\0" not in name[:-1]
            path = Path(os.fsdecode(name[:-1]))
            assert path.is_absolute()
            interpreters.append(str(path.resolve(strict=True)))
    assert len(interpreters) == 1 and interpreters[0] in pins
    interpreter = pins[interpreters[0]]
    expected = {}
    for role, pin in (("main", binary), ("interpreter", interpreter), ("libgcc", libgcc)):
        check(pin)
        st = Path(pin["path"]).stat()
        assert stat.S_ISREG(st.st_mode) and st.st_size == pin["bytes"]
        expected[role] = dict(path=pin["path"], stat_dev=st.st_dev, inode=st.st_ino, bytes=st.st_size)
    consumer = capture(libgcc["path"], True, READ_CAP)[1]
    executable = [p for p in elf_programs(consumer) if p[0] == 1 and p[1] & 1]
    assert executable and all(p[1] == 5 and p[5] > 0 and p[2] + p[5] <= len(consumer) for p in executable)
    expected["executable_segments"] = len(executable)
    mounts = Path("/proc/self/mountinfo").read_bytes()
    assert len(mounts) < 2 * 1024**2
    expected["mount_lines"] = mounts.splitlines()
    return expected


def diagnostics(mode, raw, expected):
    # One revalidate is main/interpreter/libgcc backing, then consumer identity.
    # 11 = qualify + postlookup + before/after four calls + final; negative = 2.
    groups = 2 if mode == "lookup-negative" else 11
    assert raw.endswith(b"\n")
    lines = raw[:-1].split(b"\n")
    assert len(lines) == groups * 4
    number = r"(0|[1-9][0-9]{0,19})"
    path = r"([^\x00-\x20\x7f]+)"
    hexed = r"([0-9a-f]+)"
    backing = (r"consumer_backing role=(main|interpreter|libgcc) fd=" + number +
        r" stat_dev=" + number + r" inode=" + number + r" bytes=" + number +
        r" mount_major=" + number + r" mount_minor=" + number + r" mount_id=" + number +
        r" path=" + path + r" fdinfo_hex=" + hexed + r" mountinfo_hex=" + hexed +
        r" fd_path_hex=" + hexed + r" whole_file_bytes_exact=true")
    identity = (r"consumer_identity path=" + path + r" base=(0x[1-9a-f][0-9a-f]*) bytes=" + number +
        r" exported_symbols=5 executable_segments=" + number + r" file_mapping_bytes_exact=true")
    first = lines[:4]
    for group in range(groups):
        chunk = lines[group * 4:group * 4 + 4]
        assert chunk == first  # retained fds, identity and one loaded base never change
        fds = []
        for role, line in zip(("main", "interpreter", "libgcc"), chunk[:3]):
            m = re.fullmatch(backing, line.decode("utf-8"))
            assert m is not None
            found, fd, dev, ino, size, major, minor, mount_id, name, info, mount, fdpath = m.groups()
            fd, dev, ino, size, major, minor, mount_id = map(int, (fd, dev, ino, size, major, minor, mount_id))
            assert found == role and 0 <= fd < 2**31 and ino > 0 and mount_id > 0
            assert max(dev, ino, size, major, minor, mount_id) < 2**64
            assert dict(path=name, stat_dev=dev, inode=ino, bytes=size) == expected[role]
            fds.append(fd)
            assert len(info) % 2 == len(mount) % 2 == len(fdpath) % 2 == 0
            info, mount, fdpath = map(bytes.fromhex, (info, mount, fdpath))
            assert len(info) < 16 * 1024 and len(mount) < 2 * 1024**2
            assert fdpath == os.fsencode(name)
            entries = {}
            for row in info.decode("ascii").splitlines():
                key, value = row.split(":", 1)
                assert key not in entries
                entries[key] = value.strip()
            assert all(re.fullmatch(number, entries[key]) for key in ("ino", "mnt_id", "pos"))
            assert re.fullmatch(r"[0-7]{1,22}", entries["flags"])
            assert int(entries["ino"]) == ino and int(entries["mnt_id"]) == mount_id
            assert int(entries["pos"]) == 0 and 0 <= int(entries["flags"], 8) < 2**64
            assert int(entries["flags"], 8) & os.O_ACCMODE == 0
            assert mount in expected["mount_lines"]
            fields = mount.split()
            assert fields.count(b"-") == 1
            separator = fields.index(b"-")
            assert separator >= 6 and len(fields) == separator + 4
            assert int(fields[0]) == mount_id and int(fields[1]) > 0
            assert fields[2] == f"{major}:{minor}".encode()
            assert all(f.startswith(b"/") and b"\\" not in f for f in fields[3:5])
            assert Path(name).is_relative_to(Path(os.fsdecode(fields[4])))
        assert len(set(fds)) == 3
        m = re.fullmatch(identity, chunk[3].decode("utf-8"))
        assert m is not None
        name, base, size, segments = m.groups()
        assert name == expected["libgcc"]["path"] and 0 < int(base, 16) < 2**64
        assert int(size) == expected["libgcc"]["bytes"]
        assert int(segments) == expected["executable_segments"]
    return dict(consumer_revalidations=groups, consumer_backing_rows=groups * 3,
                consumer_identity_rows=groups, consumer_exported_symbols=5,
                consumer_executable_segments=expected["executable_segments"])


def hardware_metadata(label):
    assert isinstance(label, str) and re.fullmatch(r"(?:AMD|Intel) [A-Za-z0-9()+ -]{1,90}", label)
    with Path("/proc/cpuinfo").open("rb") as stream:
        raw = stream.read(2 * 1024**2 + 1)
    assert len(raw) <= 2 * 1024**2
    models = {line.split(b":", 1)[1].strip().decode("ascii") for line in raw.splitlines()
              if line.split(b":", 1)[0].strip() == b"model name"}
    assert len(models) == 1
    model = models.pop()
    assert re.fullmatch(r"[A-Za-z0-9()@.+ _-]{1,160}", model)
    return dict(hardware=label, cpu_model=model)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--admission", type=Path, required=True)
    parser.add_argument("--admission-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    args = parser.parse_args()
    BUILD = args.build_root.absolute()
    assert BUILD.resolve(strict=True) == BUILD and BUILD.is_dir() and BUILD.is_relative_to(ROOT / "ignored")
    out = args.out.absolute()
    assert out.resolve() == out and out.is_relative_to(ROOT / "ignored")
    out.mkdir()  # never resume or overwrite an attempt
    rows = [dict(mode=m, status="UNRUN", attempts=0) for m in MODES]
    receipt = dict(schema="indexed-dso-native-three-v1", hardware=None,
                   status="PREPARING", native_qualification=False, cells=rows,
                   bounds=dict(cpu_seconds=60, wall_seconds=90, file_bytes=CAP,
                               helper_owner_wall_seconds=120, helper_log_bytes=LOG_CAP),
                   reservation_release="PENDING_OUTER_CLOSURE")
    dest = out / "summary.json"
    save(dest, receipt)
    stage = "preflight"
    try:
        a = load(args.admission.resolve(), args.admission_sha256)
        assert a["schema"] == "indexed-dso-native-admission-v1"
        receipt["admission_sha256"] = args.admission_sha256
        receipt.update(hardware_metadata(a["hardware"]))
        assert 1 <= len(a["historical_reviews"]) <= 32
        assert all(set(p) == {"path", "bytes", "sha256"} for p in a["historical_reviews"])
        # Read outer closure BEFORE the build manifest or any retained outputs.
        for key, path in (("c_build_owner", BUILD.parent / "closed.json"),
                          ("c_build_manifest", BUILD / "manifest.json")):
            assert set(a[key]) == {"path", "bytes", "sha256"}
            assert a[key]["path"] == str(path)
        check(a["c_build_owner"])
        build_sha = a["c_build_manifest"]["sha256"]
        build_owner_sha = a["c_build_owner"]["sha256"]
        outer = load(BUILD.parent / "closed.json", build_owner_sha)
        assert ordinary_closed(outer["closed"]) and outer["source_unchanged"] is True
        check(a["c_build_manifest"])
        manifest = load(BUILD / "manifest.json", build_sha)
        assert manifest["status"] == "BUILD_ONLY_REVIEW_REQUIRED"
        assert [r["name"] for r in manifest["stages"]] == list(STAGES)
        for row in manifest["stages"]:
            check(row["receipt"])
            closed = load(Path(row["receipt"]["path"]))
            assert closed == row["owner"] and helper_custody(closed)
            assert row["attempts"] == 1 and row["status"] == "PASS" and row["helper_exit"] == 0
            assert closed["exit"] == 0 and closed["wall_timeout"] is False
            assert closed["helper_sha256"] == HELPER_SHA
            assert closed["request_sha256"] == row["request"]["sha256"]
        assert len(manifest["toolchain_files"]) == 79 and len(manifest["sources"]) == 8
        pins = all_pins(manifest)
        assert a["execution_tools"] and len(a["execution_tools"]) <= 128
        for key, value in all_pins(a).items():
            assert key not in pins or pins[key] == value
            pins[key] = value
        for p in pins.values():
            check(p)
        assert capture(HELPER)[0]["sha256"] == HELPER_SHA
        assert capture(OWNER)[0]["sha256"] == OWNER_SHA
        built = load(Path(a["native_build_owner"]["path"]))
        assert ordinary_closed(built["closed"]) and built["source_unchanged"] is True
        wanted_source = {k: built[k] for k in ("base", "working_source_sha256")}
        assert source() == wanted_source == a["source"]
        inspected = load(Path(a["inspection_owner"]["path"]))
        assert ordinary_closed(inspected["closed"]) and inspected["source_unchanged"] is True
        assert {k: inspected[k] for k in wanted_source} == wanted_source
        for key in ("semantic_review", "native_review", "native_binary", "native_build_owner", "inspection_owner"):
            assert set(a[key]) == {"path", "bytes", "sha256"}
            check(a[key])  # reviews are external semantic premises, not inferred authority
        subject, caller = [manifest["links"][n]["elf"] for n in ("subject", "caller")]
        for name, row in (("subject", subject), ("caller", caller)):
            assert set(a[name + "_elf"]) == {"path", "bytes", "sha256"}
            assert a[name + "_elf"] == {k: row[k] for k in ("path", "bytes", "sha256")}
            assert row["path"] == str(BUILD / ("libli2_uw_" + name + ".so"))
        libgcc = manifest["tools"]["libgcc"]
        assert libgcc["sha256"] == CONSUMER_SHA
        assert inspected["command"] == [a["native_binary"]["path"], "inspect", subject["path"], subject["sha256"],
            caller["path"], caller["sha256"], str(BUILD / "manifest.json"), build_sha, libgcc["path"],
            str(BUILD / "inputs" / CONSUMER_SHA), a["inspection_out"]]
        snapshot = BUILD / "inputs" / CONSUMER_SHA
        assert capture(snapshot)[0]["sha256"] == CONSUMER_SHA
        lease = reservation(a)
        receipt.update(status="RUNNING", source_base=a["source"]["base"],
                       build_sha256=build_sha, binary_sha256=a["native_binary"]["sha256"],
                       consumer_sha256=CONSUMER_SHA, cpu=lease["cores"][0],
                       subject_sha256=subject["sha256"], caller_sha256=caller["sha256"],
                       build_owner_sha256=build_owner_sha,
                       native_build_owner_sha256=a["native_build_owner"]["sha256"],
                       inspection_owner_sha256=a["inspection_owner"]["sha256"],
                       semantic_review_sha256=a["semantic_review"]["sha256"],
                       native_review_sha256=a["native_review"]["sha256"],
                       source_overlay_sha256=hashlib.sha256(json.dumps(a["source"], sort_keys=True).encode()).hexdigest(),
                       runner_sha256=capture(Path(__file__).resolve())[0]["sha256"])
        save(dest, receipt)
        spec = importlib.util.spec_from_file_location("indexed_native_owner", OWNER)
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        environment = dict(PATH="/usr/bin:/bin", LANG="C", LC_ALL="C", PYTHONDONTWRITEBYTECODE="1")
        logs = ROOT / "target/evaluation" / ("indexed-native-" + hashlib.sha256(str(out).encode()).hexdigest())
        logs.mkdir(exist_ok=False)
        recipe_pin = capture(Path(__file__).resolve())[0]
        pins[str(HELPER)] = capture(HELPER)[0]
        pins[str(OWNER)] = capture(OWNER)[0]
        pins[str(BUILD / "manifest.json")] = capture(BUILD / "manifest.json")[0]
        pins[str(BUILD.parent / "closed.json")] = capture(BUILD.parent / "closed.json")[0]
        def unchanged():
            assert source() == wanted_source and reservation(a) == lease
            check(recipe_pin)
            assert load(args.admission.resolve(), args.admission_sha256) == a
            for p in pins.values():
                check(p)
        for row in rows:
            stage = row["mode"]
            unchanged()
            diagnostic_expected = diagnostic_inputs(a["native_binary"], libgcc, pins)
            cell = out / stage
            cell.mkdir()
            argv = [a["native_binary"]["path"], stage, subject["path"], subject["sha256"],
                    caller["path"], caller["sha256"], str(BUILD / "manifest.json"), build_sha,
                    libgcc["path"], str(snapshot), str(cell)]
            request = dict(argv=argv, cwd=str(ROOT), env=environment,
                           stdout=str(cell / "stdout"), stderr=str(cell / "stderr"),
                           cpu_seconds=60, wall_seconds=90, file_bytes=CAP)
            save(cell / "request.json", request)
            row.update(status="DISPATCHED_UNRESOLVED", attempts=1,
                       load_before=Path("/proc/loadavg").read_text().split()[:3], cpu=lease["cores"][0])
            save(dest, receipt)  # durable before dispatch; never rerun unknown work
            command = [manifest["tools"]["helper_python"]["path"], "-B", str(HELPER),
                       "--request", str(cell / "request.json"), "--receipt", str(cell / "owner.json")]
            closed = owner.run_command(command, environment, logs / (stage + ".log"), 120, LOG_CAP)
            save(cell / "outer.json", closed)  # retain closed row before any later assertion
            row.update(status="CLOSED_UNCHECKED", seconds=closed["seconds"], exit=closed["exit_code"],
                       load_after=Path("/proc/loadavg").read_text().split()[:3])
            save(dest, receipt)
            assert closed["cleanup_complete"] is True and closed["reaped_descendants"] == 0
            private = capture(logs / (stage + ".log"), True, LOG_CAP)
            assert private[0]["sha256"] == closed["private_log_sha256"]
            (cell / "helper.log").write_bytes(private[1])
            assert (cell / "owner.json").is_file(), "missing child closure; stop remaining cells"
            inner = load(cell / "owner.json")  # owner FIRST, then stdout/stderr
            row.update(native_exit=inner["exit"], wall_timeout=inner["wall_timeout"],
                       stdout_sha256=inner["stdout_sha256"], stderr_sha256=inner["stderr_sha256"])
            save(dest, receipt)
            assert helper_custody(inner)
            assert inner["helper_sha256"] == HELPER_SHA
            assert inner["request_sha256"] == capture(cell / "request.json")[0]["sha256"]
            unchanged()
            stdout = capture(cell / "stdout", True, READ_CAP)
            stderr = capture(cell / "stderr", True, CAP)
            assert stdout[0]["sha256"] == inner["stdout_sha256"] and stderr[0]["sha256"] == inner["stderr_sha256"]
            row["status"] = "FAILED"
            save(dest, receipt)
            if ordinary_closed(closed) and inner["exit"] == 0 and inner["wall_timeout"] is False:
                try:
                    row.update(population(stage, stdout[1]))
                    after = diagnostic_inputs(a["native_binary"], libgcc, pins)
                    assert {k: v for k, v in after.items() if k != "mount_lines"} == {
                        k: v for k, v in diagnostic_expected.items() if k != "mount_lines"}
                    diagnostic_expected["mount_lines"] = [line for line in diagnostic_expected["mount_lines"]
                        if line in after["mount_lines"]]
                    row.update(diagnostics(stage, stderr[1], diagnostic_expected))
                    row["status"] = "PASS_FINITE_CHECKS"
                except (AssertionError, ValueError, KeyError, TypeError):
                    row["reason"] = "output_census_refused"
            save(dest, receipt)
        unchanged()
        if all(r["status"] == "PASS_FINITE_CHECKS" for r in rows):
            assert rows[0]["lookups"] == 38
            assert rows[1]["lookups"] == rows[2]["lookups"]
            receipt["status"] = "PASS_FINITE_CHECKS"
        else:
            receipt["status"] = "FAILED"
    except BaseException as error:
        receipt.update(status="REFUSED_OR_INCOMPLETE", refusal_stage=stage, error_type=type(error).__name__)
        # Every earlier outcome remains. Unknown custody blocks all later cells.
        save(dest, receipt)
        raise
    save(dest, receipt)
    return 0 if receipt["status"] == "PASS_FINITE_CHECKS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
