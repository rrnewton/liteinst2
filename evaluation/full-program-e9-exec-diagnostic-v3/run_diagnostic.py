"""One future bounded GDB observation of the unchanged E9 help exec-arm child."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import types

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")

ROOT = Path.cwd().resolve()
HERE = Path(__file__).resolve().parent
ENV = dict(PATH="/usr/bin:/bin", LANG="C", LC_ALL="C", TZ="UTC")
PINS = {
    "evaluation/admission/processes.py": "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f",
    "evaluation/offline-corpus/run_e9_help_parity.py": "a3a17f093c79774781247e767fb97687c51ed03cbbe576ce4e721e2e26b5bf88",
    "/usr/libexec/gdb": "cf8ae9d5192667cf681eabedf50ef39ecd11fac784c15cea6e3961880d3a16ed",
    "/usr/bin/python3.9": "9cfdf1a01d07dadb394dd2dc9fd8316254c36764076d23dc2c895c8401735576",
    "/usr/bin/prlimit": "942bcd8596c242d4d33dca657372a83e1f55908afd59b525389362cd6d282933",
    "/usr/share/gdb/syscalls/amd64-linux.xml": "a7a04515a1ad8bdf6d1cc2dbf3b5aba3063cfb76c6b8c5cbc0abc80b3a93d1bc",
}
CANDIDATE = "eabf1d463a75d5644ec114bed7b66ace8c7a00f6a64892a4600e8a5661547afc"
PROTOCOL_SHA256 = '35d0d6a71507d9381cb22003acab514a2f9bc7ffbbec5f727bf3e953f36e6373'


def pin(path):
    path = path.resolve(strict=True)
    a = path.stat(); data = path.read_bytes(); b = path.stat()
    fields = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    assert fields(a) == fields(b) and len(data) == a.st_size <= 64 * 1024**2
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), stat=fields(a))


def main():
    p = argparse.ArgumentParser(allow_abbrev=False)
    p.add_argument("--revision", required=True)
    p.add_argument("--cpu", type=int, required=True)
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    assert len(a.revision) == 40 and all(x in "0123456789abcdef" for x in a.revision)
    assert os.sched_getaffinity(0) == {a.cpu}
    def ready():
        assert subprocess.check_output(["/usr/bin/git", "--no-optional-locks", "rev-parse", "HEAD"], timeout=5).decode().strip() == a.revision
        assert not subprocess.check_output(["/usr/bin/git", "--no-optional-locks", "status", "--porcelain", "--untracked-files=no"], timeout=5)
        assert os.sched_getaffinity(0) == {a.cpu}
    ready()
    out = a.out.absolute()
    assert out == out.resolve() and out.parent == ROOT / "target/evaluation" and not out.exists()
    candidate = a.candidate.resolve(strict=True)
    files = [ROOT / name for name in PINS] + [Path(__file__).resolve(), HERE / "observe_exec.py", HERE / "exec_transition.py", candidate]
    frozen = {str(f): pin(f) for f in files}
    for name, expected in PINS.items():
        assert frozen[str(ROOT / name)]["sha256"] == expected
    q = frozen[str(candidate)]
    assert q["bytes"] == 282324 and q["sha256"] == CANDIDATE and q["stat"][2] & 0o111
    protocol_path = HERE / "exec_transition.py"
    protocol_bytes = protocol_path.read_bytes()
    assert hashlib.sha256(protocol_bytes).hexdigest() == PROTOCOL_SHA256 == frozen[str(protocol_path)]["sha256"]
    protocol = types.ModuleType("exec_transition")
    exec(compile(protocol_bytes, str(protocol_path), "exec"), protocol.__dict__)
    kernel = protocol.running_kernel_identity()  # Exact proved GNU ID, before any inferior launch.
    out.mkdir(mode=0o700); stage = out / "candidate"; stage.mkdir(); (stage / "cwd").mkdir()
    config = dict(out=str(out), cpu=a.cpu, candidate_sha256=CANDIDATE,
                  candidate_stat=q["stat"], subject_environment=ENV,
                  protocol_path=str(protocol_path), protocol_sha256=PROTOCOL_SHA256,
                  kernel_identity=kernel)
    (out / "config.json").write_text(json.dumps(config, sort_keys=True) + "\n")
    argv = ["/usr/bin/prlimit", "--cpu=30", "--as=2147483648", "--fsize=1048576", "--core=0", "--",
            "/usr/libexec/gdb", "-q", "-nx", "-nh", "-batch",
            "-iex", "set auto-load off", "-iex", "set libthread-db-search-path /dev/null",
            "-iex", "set debuginfod enabled off",
            "-iex", "set index-cache enabled off", "-iex", "maint set worker-threads 1",
            "-iex", "python import sys; sys.dont_write_bytecode = True",
            "-ex", "python CONFIG = " + repr(str(out / "config.json")),
            "-x", str(HERE / "observe_exec.py"), "--args", "/usr/bin/python3.9", "-I", "-B",
            str(ROOT / "evaluation/offline-corpus/run_e9_help_parity.py"), "--exec-arm", "candidate",
            str(candidate), str(stage), str(a.cpu)]
    record = dict(status="DISPATCHED_UNRESOLVED", revision=a.revision, command=argv, environment=ENV,
                  inputs=frozen, cpu=a.cpu, load_before=os.getloadavg(), planned_candidate_attempts=1,
                  wall_seconds=10, debugger_log_cap=262144, trace_cap=262144,
                  subject_cpu_seconds=5, subject_as_bytes=1073741824, subject_file_bytes=65536,
                  qualification_complete=False, historical_help_failure_unchanged=True,
                  kernel_identity=kernel, protocol_sha256=PROTOCOL_SHA256)
    (out / "intent.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    owner_path = ROOT / "evaluation/admission/processes.py"
    spec = importlib.util.spec_from_file_location("diagnostic_owner", owner_path)
    owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
    result = owner.run_command(argv, ENV, out / "gdb.log", 10, 262144)
    record.update(owner=result, load_after=os.getloadavg())
    (out / "owner-closed.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    assert result["cleanup_complete"], "no output inspection before closed ownership"
    ready(); assert all(pin(Path(f)) == old for f, old in frozen.items())
    assert protocol.running_kernel_identity() == kernel
    logs = {str(f.relative_to(out)): pin(f) for f in [out / "gdb.log", out / "trace.jsonl", stage / "stdout", stage / "stderr"] if f.exists()}
    assert logs["gdb.log"]["sha256"] == result["private_log_sha256"]
    assert logs["gdb.log"]["bytes"] <= 262144 and all(v["bytes"] <= 262144 for v in logs.values())
    assert all(logs[name]["bytes"] <= 65536 for name in ("candidate/stdout", "candidate/stderr") if name in logs)
    record.update(status="CLOSED_DIAGNOSTIC_ONLY", source_unchanged=True, logs=logs,
                  cwd_entries=sorted(f.name for f in (stage / "cwd").iterdir()))
    (out / "closed.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return 0 if result["exit_code"] == 0 and result["termination"] is None and result["reaped_descendants"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
