#!/usr/bin/env python3
"""One pinned backend generation attempt inside an externally owned bounded scope.

Run from a clean exact checkout with Python -I -B. The caller retains one HARD
CPU lease and bounds/owns the systemd scope; this script never runs a candidate.
Only the RPC binary filename is relocated after complete request authentication.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")
ROOT = Path.cwd().resolve()
AS_LIMIT, MEMORY, FILE_LIMIT = 36 * 1024**3, 1024**3, 512 * 1024**2
ORIGINAL = "890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb"
CANONICAL_RPC = "d717bf1bc9536c21b9cf079bd05e952c3d6ca10330d4f0134a827134654b8eeb"
PINS = {
    "evaluation/admission/processes.py": "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f",
    "/usr/bin/prlimit": "942bcd8596c242d4d33dca657372a83e1f55908afd59b525389362cd6d282933",
    "/usr/bin/env": "1caef498bf8afe1633c37cbe6ec6e10908cfdf032505d85c0b14ce906bae489f",
}
p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
p.add_argument("--revision", required=True)
p.add_argument("--cpu", type=int, required=True)
p.add_argument("--unit", required=True)
p.add_argument("--out", type=Path, required=True)
p.add_argument("--original", type=Path, required=True)
p.add_argument("--rpc", type=Path, required=True)
a = p.parse_args()
assert len(a.revision) == 40 and all(c in "0123456789abcdef" for c in a.revision)
assert a.unit.startswith("li2core-e9-backend-36g-") and all(c.isascii() and (c.isalnum() or c == "-") for c in a.unit)
out = a.out.absolute()
assert out == out.resolve() and out.parent == ROOT / "target/evaluation" and not out.exists()
out.mkdir(mode=0o700)
(out / "e9").mkdir(); (out / "tmp").mkdir()
record = dict(profile="pinned-pldi2020-full-rpc-36g-as-1g-memory-portable-v1", status="PREFLIGHT", attempts=0,
              qualification_complete=False, candidate_executions=0, revision=a.revision)

def save():
    with (out / "receipt.tmp").open("w") as f:
        json.dump(record, f, indent=2, sort_keys=True); f.write("\n"); f.flush(); os.fsync(f.fileno())
    os.replace(out / "receipt.tmp", out / "receipt.json")

def pin(path):
    path = Path(path).resolve(strict=True)
    before = path.stat(); assert path.is_file() and before.st_size <= FILE_LIMIT
    digest = hashlib.sha256(); size = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024**2), b""):
            size += len(chunk); assert size <= FILE_LIMIT; digest.update(chunk)
    stamp = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    assert size == before.st_size and stamp(before) == stamp(path.stat())
    return dict(bytes=size, sha256=digest.hexdigest(), stat=stamp(before))

def ready():
    assert subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], timeout=10).decode().strip() == a.revision
    assert not subprocess.check_output(["/usr/bin/git", "status", "--porcelain", "--untracked-files=no"], timeout=10)
    assert os.sched_getaffinity(0) == {a.cpu}
    line = Path("/proc/self/cgroup").read_text().strip()
    assert line.startswith("0::/") and "\n" not in line and ".." not in Path(line[3:]).parts
    assert line.endswith("/" + a.unit + ".scope")
    cg = Path("/sys/fs/cgroup") / line[4:]
    fields = {n: (cg / n).read_text().strip() for n in (
        "memory.max", "memory.swap.max", "pids.max", "cpu.max", "cpuset.cpus.effective")}
    assert fields["memory.max"] == str(MEMORY) and fields["memory.swap.max"] == "0"
    assert fields["pids.max"] == "64" and fields["cpuset.cpus.effective"] == str(a.cpu)
    quota, period = map(int, fields["cpu.max"].split()); assert quota == period and period > 0
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    assert hard == resource.RLIM_INFINITY or hard >= AS_LIMIT, "inherited hard AS cannot admit fixed reservation"
    return dict(cgroup=str(cg), properties=fields, inherited_as=[soft, hard],
                memory_events=(cg / "memory.events").read_text(), memory_peak=(cg / "memory.peak").read_text().strip())

def relocate_rpc(wire, original):
    assert len(wire) <= 16 * 1024**2
    lines = wire.splitlines(keepends=True)
    assert len(lines) == 14997
    messages = [json.loads(line) for line in lines]
    assert sum(row.get("method") == "binary" for row in messages) == 1
    head = messages[0]
    filename = head["params"]["filename"]
    assert isinstance(filename, str) and head == dict(
        jsonrpc="2.0", method="binary", params=dict(filename=filename, mode="exe"), id=0)
    encode = lambda row: (json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    assert lines[0] == encode(head)  # Also refuses duplicate keys/noncanonical first rows.
    tail = b"".join(lines[1:])
    head["params"]["filename"] = "$ORIGINAL"
    assert hashlib.sha256(encode(head) + tail).hexdigest() == CANONICAL_RPC
    head["params"]["filename"] = str(original)
    return encode(head) + tail

try:
    save()
    original, source_rpc = a.original.resolve(strict=True), a.rpc.resolve(strict=True)
    assert source_rpc.stat().st_size <= 16 * 1024**2
    frozen = {str((ROOT / name).resolve()): pin(ROOT / name) for name in PINS}
    for name, digest in PINS.items():
        assert frozen[str((ROOT / name).resolve())]["sha256"] == digest, name
    for name in (Path(__file__).resolve(), Path(sys.executable).resolve(), Path("/usr/bin/systemd-run"), original, source_rpc):
        frozen[str(name)] = pin(name)
    assert frozen[str(original)]["sha256"] == ORIGINAL
    record.update(inputs=frozen, readiness_before=ready(), load_before=os.getloadavg(),
                  utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    rpc = out / "request.jsonl"
    relocated = relocate_rpc(source_rpc.read_bytes(), original)
    with rpc.open("xb") as f:
        f.write(relocated); f.flush(); os.fsync(f.fileno())
    frozen[str(rpc)] = pin(rpc)
    record["rpc_identity"] = dict(source_sha256=frozen[str(source_rpc)]["sha256"],
        canonical_sha256=CANONICAL_RPC, executed_sha256=frozen[str(rpc)]["sha256"],
        normalization="Only binary.params.filename; all remaining wire lines unchanged")
    argv = ["/usr/bin/prlimit", "--cpu=60", "--as=" + str(AS_LIMIT), "--fsize=" + str(FILE_LIMIT), "--core=0", "--",
            "/usr/bin/env", "--chdir=" + str(out / "e9"), "--", str(original), "--debug", "--input", str(rpc)]
    env = dict(PATH="/usr/bin:/bin", LANG="C", LC_ALL="C", PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(out / "tmp"))
    spec = importlib.util.spec_from_file_location("backend_owner", ROOT / "evaluation/admission/processes.py")
    owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
    record.update(status="DISPATCHED_UNRESOLVED", attempts=1, argv=argv, environment=env,
                  cpu_seconds=60, wall_seconds=90, file_bytes=FILE_LIMIT, capture_bytes=8 * 1024**2)
    save()
    record["owner"] = owner.run_command(argv, env, out / "backend.log", 90, 8 * 1024**2)
    save()
    result = record["owner"]
    assert result["cleanup_complete"], "ownership unresolved: do not inspect output"
    record["log"] = pin(out / "backend.log")
    assert record["log"]["sha256"] == result["private_log_sha256"]
    assert result["reaped_descendants"] == 0
    record.update(readiness_after=ready(), load_after=os.getloadavg())
    assert all(pin(Path(path)) == value for path, value in frozen.items())
    assert all(not x.is_symlink() and x.is_file() for x in (out / "e9").iterdir())
    record["products"] = {x.name: pin(x) for x in (out / "e9").iterdir()}
    record["status"] = "EXIT_ZERO_UNQUALIFIED" if result["exit_code"] == 0 and result["termination"] is None else "FAILED_OUTCOME_RETAINED"
    save()
except BaseException as error:
    record.update(status="FAILED", error=dict(type=type(error).__name__, message=str(error)))
    save(); raise
print(json.dumps(dict(status=record["status"], receipt=str(out / "receipt.json"))))
