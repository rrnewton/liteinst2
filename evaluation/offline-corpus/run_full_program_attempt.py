#!/usr/bin/env python3
"""One fixed whole-program material/planner/backend attempt; never run a candidate.

Use Python -I -B from the clean exact repository revision under one externally
reserved CPU. The caller binds the two release binaries to that revision using
the supplied, separately reviewed build receipt. This script does not build.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python with -I -B")

ORIGINAL = "890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb"
CSV = "591845048470e947952fe064286d61f4a06413e5d01ae80c8504597e6c089562"
LEDGER = "727d43acbbb31ac419ba2a87f75433a495c2b838fa9d6d08a138d16c6e52e60d"
OWNER = "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"
PRLIMIT = "942bcd8596c242d4d33dca657372a83e1f55908afd59b525389362cd6d282933"
ENV_CHDIR = "1caef498bf8afe1633c37cbe6ec6e10908cfdf032505d85c0b14ce906bae489f"
POLICY_16M = "d097e98b33b96421657e70bbbca4aa7fe48335adb6908746a04efc76d662f672"
POLICY_2G = "ef09bcd4c78949ff4b93a928c59e04b545081f9e56c2056f2cfcdfe068604cce"
MIB = 1024**2
root = Path.cwd().resolve()
p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
for name in ("revision", "bridge-sha256", "planner-sha256", "build-receipt-sha256"):
    p.add_argument("--" + name, required=True)
for name in ("out", "bridge", "planner", "build-receipt", "original", "csv", "policy-16m", "policy-2g"):
    p.add_argument("--" + name, type=Path, required=True)
a = p.parse_args()
for name in ("bridge", "planner", "build_receipt", "original", "csv", "policy_16m", "policy_2g"):
    setattr(a, name, getattr(a, name).resolve(strict=True))
out = a.out.absolute()
if out.resolve() != out or out.parent != root / "target/evaluation" or out.exists():
    raise SystemExit("--out must be a fresh direct child of target/evaluation")
out.mkdir(mode=0o700, parents=True)
(out / "tmp").mkdir()
(out / "e9").mkdir()
rows = [dict(name=n, attempts=0, status="UNRUN")
        for n in ("materials", "li2-16m", "li2-2g", "e9-backend")]
record = dict(status="INCOMPLETE", stages=rows, native_attempts=0,
              qualification_complete=False, execution_revision=a.revision)

def save():
    with (out / "receipt.tmp").open("w") as f:
        json.dump(record, f, sort_keys=True, indent=2)
        f.write("\n"); f.flush(); os.fsync(f.fileno())
    os.replace(out / "receipt.tmp", out / "receipt.json")

def pin(path):
    path = path.resolve(strict=True)
    before = path.stat()
    assert path.is_file() and before.st_size <= 512 * MIB, str(path)
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            size += len(chunk); digest.update(chunk)
            assert size <= 512 * MIB, str(path)
    stamp = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert stamp(before) == stamp(path.stat()) and size == before.st_size, str(path)
    return dict(path=str(path), bytes=size, sha256=digest.hexdigest(), stat=stamp(before))

def git(*args):
    return subprocess.check_output(["/usr/bin/git", "-C", str(root), *args], timeout=10)

def unchanged():
    assert git("rev-parse", "HEAD").decode().strip() == a.revision
    assert not git("status", "--porcelain", "--untracked-files=no")
    assert sorted(os.sched_getaffinity(0)) == record["cpus"]
    for path, expected in frozen.items():
        assert pin(Path(path)) == expected, path

def storage():
    entries = list(out.rglob("*"))
    assert all(not x.is_symlink() for x in entries)
    files = [x for x in entries if not x.is_dir()]
    assert all(x.is_file() for x in files)
    return dict(files=len(files), apparent=sum(x.stat().st_size for x in files),
                allocated=sum(x.stat().st_blocks * 512 for x in files))

try:
    for field in ("revision", "bridge_sha256", "planner_sha256", "build_receipt_sha256"):
        value = getattr(a, field)
        assert len(value) == (40 if field == "revision" else 64)
        assert all(c in "0123456789abcdef" for c in value)
    owned = root / "evaluation/admission/processes.py"
    limits = Path("/usr/bin/prlimit")
    chdir_tool = Path("/usr/bin/env")
    inputs = [Path(__file__), owned, limits, chdir_tool, Path(sys.executable), a.bridge, a.planner,
              a.build_receipt, a.original, a.csv, a.policy_16m, a.policy_2g]
    frozen = {str(x.resolve(strict=True)): pin(x) for x in inputs}
    def require(path, digest):
        assert frozen[str(path.resolve(strict=True))]["sha256"] == digest, str(path)
    for path, digest in ((owned, OWNER), (limits, PRLIMIT), (chdir_tool, ENV_CHDIR), (a.original, ORIGINAL), (a.csv, CSV),
                         (a.bridge, a.bridge_sha256), (a.planner, a.planner_sha256),
                         (a.build_receipt, a.build_receipt_sha256),
                         (a.policy_16m, POLICY_16M), (a.policy_2g, POLICY_2G)):
        require(path, digest)
    script = Path(__file__).resolve().relative_to(root)
    assert git("ls-files", "--error-unmatch", str(script)).decode().strip() == str(script)
    record.update(inputs=frozen, cpus=sorted(os.sched_getaffinity(0)), python_version=sys.version,
        start_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        external_cpu_lease="Caller must retain one HARD CPU and lane CPUQuota <=1200%; affinity checked here",
        trusted_premises=["Caller-reviewed exact-revision build/toolchain receipt; a receipt hash is provenance only",
            "Trusted complete-code/no-overlap/no-code-as-data/private-image premise, including the two RX gaps"],
        limits=dict(post_stage_workspace_bytes=2048 * MIB, per_file_bytes=512 * MIB,
                    capture_and_rpc_bytes=16 * MIB, concurrent_children=1),
        denominator=dict(heads=13143, selected_jumps=2053, rpc_messages=14997),
        policy_profiles=["full-e9patch-packed-source-whole-resources-16m-v1",
                         "full-e9patch-packed-source-whole-resources-2g-v1"],
        scope="Offline artifacts only; existing E9 producer adapter and PIE execution remain unqualified")
    assert len(record["cpus"]) == 1
    unchanged(); save()
    spec = importlib.util.spec_from_file_location("full_program_owner", owned)
    owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
    env = dict(PATH="/usr/bin:/bin", LANG="C", LC_ALL="C", TMPDIR=str(out / "tmp"),
               PYTHONDONTWRITEBYTECODE="1")
    materials = out / "materials"
    bridge, planner, original, csv_path = (str(x.resolve()) for x in (a.bridge, a.planner, a.original, a.csv))
    commands = [(30, 45, 512 * MIB, root,
        [bridge, "--whole-program-4096", "--trusted-complete-code", original, csv_path, CSV, str(materials)])]
    for name, policy, digest in (("li2-16m", a.policy_16m, POLICY_16M),
                                 ("li2-2g", a.policy_2g, POLICY_2G)):
        commands.append((180, 240, 3 * 1024**3, root,
            [planner, "--whole-program-4096", original, str(materials / "ledger.txt"), LEDGER,
             str(policy.resolve()), digest, str(out / name)]))
    commands.append((60, 90, 1024**3, out / "e9",
                     [str(chdir_tool), "--chdir=" + str(out / "e9"), "--",
                      original, "--debug", "--input", str(materials / "request.jsonl")]))
    record["environment"] = env
    for row, (cpu, wall, memory, cwd, argv) in zip(rows, commands):
        unchanged()
        row.update(status="DISPATCHED_UNRESOLVED", attempts=1, cwd=str(cwd),
            cpu_seconds=cpu, wall_seconds=wall, address_space_bytes=memory,
            argv=[str(limits), "--cpu=" + str(cpu), "--as=" + str(memory),
                  "--fsize=" + str(512 * MIB), "--core=0", "--", *argv], load_before=os.getloadavg())
        save()
        log = out / (row["name"] + ".log")
        # The owner starts at ROOT. Only the bounded child wrapper changes cwd.
        row["owner"] = owner.run_command(row["argv"], env, log, wall, 8 * MIB)
        row.update(status="CLOSED", load_after=os.getloadavg()); save()
        closed = row["owner"]
        assert closed["cleanup_complete"], "custody unresolved; do not inspect child outputs"
        row["log"] = pin(log)
        assert row["log"]["sha256"] == closed["private_log_sha256"]
        row["storage"] = storage(); unchanged(); save()
        assert max(row["storage"]["apparent"], row["storage"]["allocated"]) <= 2048 * MIB
        assert closed["reaped_descendants"] == 0, "unexpected adopted descendant; stop"
        row["status"] = "EXIT_ZERO_UNQUALIFIED" if closed["exit_code"] == 0 and closed["termination"] is None else "FAILED_OR_REFUSED"
        product_dir = materials if row["name"] == "materials" else out / ("e9" if row["name"] == "e9-backend" else row["name"])
        if product_dir.exists():
            names = ("COMPLETE", "ledger.txt", "sites.tsv", "regions.tsv", "request.jsonl") if row["name"] == "materials" else (
                "COMPLETE", "bundle-index.tsv", "report.tsv", "ledger.tsv", "plan-ledger.tsv", "candidate.elf", "program-failure.tsv", "a.out")
            row["products"] = {n: pin(product_dir / n) for n in names if (product_dir / n).is_file()}
        save()
        if row["name"] == "materials":
            if row["status"] != "EXIT_ZERO_UNQUALIFIED":
                break
            assert pin(materials / "ledger.txt")["sha256"] == LEDGER
            wire = (materials / "request.jsonl").read_bytes()
            assert len(wire) <= 16 * MIB and len(wire.splitlines()) == 14997
            record["materials"] = {x.name: pin(x) for x in sorted(materials.iterdir())}
            frozen.update({str(x.resolve()): pin(x) for x in materials.iterdir()})
            save()
    record["status"] = "ALL_TOOLS_EXITED_ZERO_UNQUALIFIED" if all(r["status"] == "EXIT_ZERO_UNQUALIFIED" for r in rows) else "FAILED_OR_REFUSED_OUTCOMES_RETAINED"
except BaseException as error:
    record.update(status="FAILED", failure=dict(type=type(error).__name__, message=str(error)))
    save(); raise
else:
    record["storage_final"] = storage(); save()
    print(json.dumps(dict(status=record["status"], receipt=str(out / "receipt.json"))))
