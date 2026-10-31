#!/usr/bin/env python3
"""Build the pinned modern CSV provider offline; capture only, never run the subject.
Run from the repository root with python3.9 -I -B, under one externally leased CPU.
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
SOURCE = "5e098f7920b5b5535f553de599c94ee980e97e29"
ORIGINAL = "890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb"
OWNER = "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"
TOOL_SHA = dict(make="d63f759752b1c19363744c8224cc108c73458e2cb7efa4ca0acd489752e64ec0",
    gcc="546023eae5ff58287b1d987e059d38e2733dfe49eda827282d6942707c4c25d0",
    gxx="8b58cbb443f9f3af9a6dfb333fae55ef8808ed10a78d2a343885ccd06e016e59",
    ar="e4b206f523c501897b356f48f5a770626bf07e63cb88697ebda00a188959276c",
    ld="ac6bbc7393b95278ffa294cbdf18c65b5003d4e15dc805ce24a8146a8a154c42",
    prlimit="942bcd8596c242d4d33dca657372a83e1f55908afd59b525389362cd6d282933")
TOOLS = {k: Path("/usr/bin") / ("g++" if k == "gxx" else k) for k in TOOL_SHA}
FILE_LIMIT, STORAGE_LIMIT = 16 * 1024**2, 128 * 1024**2
root = Path.cwd().resolve()
parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--source", type=Path, default=Path("ignored/a3/upstream/e9patch"))
parser.add_argument("--original", type=Path, default=Path("ignored/a3/upstream/e9patch-pldi2020/e9patch"))
args = parser.parse_args()
out, source, original = args.out.absolute(), args.source.resolve(strict=True), args.original.resolve(strict=True)
if out.resolve() != out or out.parent != root / "target/evaluation" or out.exists():
    raise SystemExit("--out must be one fresh direct child of target/evaluation")
out.mkdir(mode=0o700, parents=True)
rows = [dict(name=n, status="UNRUN", attempts=0) for n in ("versions", "zydis", "e9tool", "capture")]
record = dict(status="INCOMPLETE", stages=rows, native_attempts=0, qualification_complete=False)

def save():
    with (out / "receipt.tmp").open("w") as f:
        json.dump(record, f, indent=2, sort_keys=True); f.write("\n"); f.flush(); os.fsync(f.fileno())
    os.replace(out / "receipt.tmp", out / "receipt.json")

def pin(path):
    resolved = path.resolve(strict=True); before = resolved.stat()
    assert resolved.is_file() and before.st_size <= FILE_LIMIT, str(path)
    data = resolved.read_bytes()
    stamp = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert stamp(resolved.stat()) == stamp(before) and path.resolve(strict=True) == resolved, str(path)
    return dict(path=str(path), resolved=str(resolved), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def git(where, *words):
    return subprocess.check_output(["/usr/bin/git", "-C", str(where), *words], timeout=10)

def storage():
    entries = list(out.rglob("*")); assert all(not p.is_symlink() for p in entries)
    files = [p for p in entries if not p.is_dir()]; assert all(p.is_file() for p in files)
    return dict(files=len(files), apparent=sum(p.stat().st_size for p in files),
                allocated=sum(p.stat().st_blocks * 512 for p in files))

def unchanged():
    assert git(root, "rev-parse", "HEAD").decode().strip() == record["revision"]
    assert not git(root, "status", "--porcelain", "--untracked-files=no")
    assert git(source, "rev-parse", "HEAD").decode().strip() == SOURCE
    assert not git(source, "status", "--porcelain", "--untracked-files=no")
    assert sorted(os.sched_getaffinity(0)) == record["cpus"]
    for path, expected in frozen.items():
        assert pin(Path(path)) == expected, path
    for path, digest in copied.items():
        assert pin(work / path)["sha256"] == digest, path

try:
    record.update(revision=git(root, "rev-parse", "HEAD").decode().strip(), cpus=sorted(os.sched_getaffinity(0)),
        source_revision=SOURCE, source_tree=git(source, "rev-parse", "HEAD^{tree}").decode().strip(),
        python_version=sys.version, start_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        external_cpu_lease="required from caller; affinity checked, allocator not reimplemented",
        limits=dict(per_file=FILE_LIMIT, post_stage_storage=STORAGE_LIMIT, log_bytes=1024**2),
        scope="Provider build/capture only; no full-code premise, bridge admission or backend execution")
    save()
    assert len(record["cpus"]) == 1
    assert git(source, "rev-parse", "HEAD").decode().strip() == SOURCE
    assert not git(source, "status", "--porcelain", "--untracked-files=no")
    owned = root / "evaluation/admission/processes.py"
    dependencies = [Path(p) for p in ("/usr/lib64/libdw.so", "/usr/lib64/libelf.so", "/usr/lib64/libz.so",
        "/usr/include/elfutils/libdw.h", "/usr/include/zlib.h")]
    frozen = {str(p): pin(p) for p in [Path(__file__).resolve(), owned, original, Path(sys.executable), *TOOLS.values(), *dependencies]}
    assert frozen[str(owned)]["sha256"] == OWNER
    assert frozen[str(original)]["sha256"] == ORIGINAL and frozen[str(original)]["bytes"] == 93520
    assert all(frozen[str(p)]["sha256"] == TOOL_SHA[k] for k, p in TOOLS.items())
    work = out / "source"; work.mkdir(); (out / "tmp").mkdir(); (out / "capture").mkdir()
    copied, identities = {}, []
    for row in git(source, "ls-tree", "-rz", "HEAD").split(b"\0"):
        if not row: continue
        meta, name = row.split(b"\t"); mode, kind, blob = meta.decode().split(); name = name.decode()
        if name not in ("Makefile", "VERSION", "src/e9patch/e9loader.h") and not name.startswith(("src/e9tool/", "contrib/zydis/")): continue
        assert mode in ("100644", "100755") and kind == "blob"
        p = source / name; before = pin(p); data = p.read_bytes(); assert pin(p) == before
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == blob
        dest = work / name; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(data); dest.chmod(int(mode, 8) & 0o777)
        copied[name] = before["sha256"]; identities.append([name, mode, blob, len(data), copied[name]])
        frozen[str(p)] = before
    assert len(copied) == 133 and sum(r[3] for r in identities) == 13059771
    record.update(inputs={k: v for k, v in frozen.items() if not Path(k).is_relative_to(source)},
        provider_build_version="1.0.0", source_files=len(copied), source_bytes=sum(r[3] for r in identities),
        source_manifest_sha256=hashlib.sha256(json.dumps(identities, separators=(",", ":")).encode()).hexdigest())
    spec = importlib.util.spec_from_file_location("provider_owner", owned)
    owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
    env = dict(PATH="/usr/bin:/bin", LANG="C", LC_ALL="C", TMPDIR=str(out / "tmp"), PYTHONDONTWRITEBYTECODE="1")
    version_code = "import json,subprocess,sys\nfor p in sys.argv[1:]:\n r=subprocess.run([p,'--version'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=5)\n print(json.dumps(dict(tool=p,exit_code=r.returncode,text=r.stdout.decode())),flush=True)\n if r.returncode: raise SystemExit(r.returncode)\n"
    flags = "-O2 -std=c++11 -Wall -Wno-reorder -fPIC -pie -DVERSION=1.0.0 -DSYSTEM_LIBDW -Isrc/e9tool -Wno-unused-function -Icontrib/zydis/include -Icontrib/zydis/dependencies/zycore/include"
    commands = [(30, [sys.executable, "-I", "-B", "-c", version_code, *map(str, TOOLS.values())]),
        (180, [str(TOOLS["make"]), "-C", str(work), "-j1", "contrib/zydis/libZydis.a", "CC=/usr/bin/gcc"]),
        (180, [str(TOOLS["make"]), "-C", str(work), "-j1", "e9tool", "CXX=/usr/bin/g++", "CXXFLAGS=" + flags,
               "E9TOOL_LIBS=contrib/zydis/libZydis.a", "E9TOOL_LDLIBS=-ldl -lz -ldw"]),
        (30, [str(work / "e9tool"), "--format=json", "--dump-all", "--plt", "-o", str(out / "capture/provider"), str(original)])]
    record["environment"] = env
    for row, (wall, argv) in zip(rows, commands):
        unchanged(); row.update(status="DISPATCHED_UNRESOLVED", attempts=1, wall_seconds=wall,
            argv=[str(TOOLS["prlimit"]), "--cpu=" + str(wall), "--fsize=" + str(FILE_LIMIT), "--core=0", "--", *argv], load_before=os.getloadavg()); save()
        log = out / (row["name"] + ".log"); assert not log.exists()
        row["owner"] = owner.run_command(row["argv"], env, log, wall, 1024**2)
        row.update(status="CLOSED", load_after=os.getloadavg()); save()
        closed = row["owner"]; assert closed["cleanup_complete"], "custody unresolved; stop without reading child output"
        row["log"] = pin(log); assert row["log"]["sha256"] == closed["private_log_sha256"]
        row["storage"] = storage(); unchanged(); save()
        assert closed["exit_code"] == 0 and closed["termination"] is None and closed["reaped_descendants"] == 0
        assert max(row["storage"]["apparent"], row["storage"]["allocated"]) <= STORAGE_LIMIT
        if row["name"] == "versions": record["tool_versions"] = [json.loads(s) for s in log.read_text().splitlines()]
        if row["name"] == "e9tool": frozen[str(work / "e9tool")] = pin(work / "e9tool"); record["provider"] = frozen[str(work / "e9tool")]
        row["status"] = "PASS"; save()
    record["capture"] = {p.name: pin(p) for p in sorted((out / "capture").iterdir())}
    csv = out / "capture/provider.DISASM.csv"; data = csv.read_bytes()
    assert len(data) <= 1024**2 and data.startswith(b"address,offset,size\n") and data.endswith(b"\n")
    record.update(status="CSV_CAPTURED_UNVALIDATED", csv_rows=len(data.splitlines()) - 1, load_after=os.getloadavg())
except BaseException as error:
    record.update(status="FAILED", failure=dict(type=type(error).__name__, message=str(error)))
    save(); raise
else:
    save(); print(json.dumps(dict(status=record["status"], csv_rows=record["csv_rows"], receipt=str(out / "receipt.json"))))
