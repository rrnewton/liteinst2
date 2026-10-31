#!/usr/bin/env python3
"""Once-only, pinned original/E9 candidate startup-and-help parity on Linux.

The caller owns one HARD CPU reservation and an outer bounded supervisor.
No backend generation, compilation, site-coverage or performance claim.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import time

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")

ROOT = Path.cwd().resolve()
SELF = Path(__file__).resolve()
OWNER = ROOT / "evaluation/admission/processes.py"
OWNER_SHA = "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f"
ELFS = {
    "original": (93520, "890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb"),
    "candidate": (282324, "eabf1d463a75d5644ec114bed7b66ace8c7a00f6a64892a4600e8a5661547afc"),
}
ENV = dict(PATH="/usr/bin:/bin", LANG="C", LC_ALL="C", TZ="UTC")
CPU_SECONDS, WALL_SECONDS, AS_BYTES, CAP = 5, 10, 1024**3, 65536


def stamp(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read_fd(fd, cap):
    before = os.fstat(fd)
    assert stat.S_ISREG(before.st_mode) and before.st_size <= cap
    with os.fdopen(os.dup(fd), "rb") as f:
        data = f.read(cap + 1)
    assert len(data) == before.st_size <= cap and stamp(before) == stamp(os.fstat(fd))
    return data, dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), stat=stamp(before))


def read(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        data, identity = read_fd(fd, cap)
        assert identity["stat"] == stamp(os.stat(path, follow_symlinks=False))
        return data, identity
    finally:
        os.close(fd)


def child(role, executable, stage, cpu):
    # One owned PID becomes the subject, with no shell or subprocess descendant.
    assert role in ELFS and os.execve in os.supports_fd
    assert os.sched_getaffinity(0) == {cpu}
    assert stage == stage.resolve(strict=True) and stage.parent.parent == ROOT / "target/evaluation"
    for which, limit in [(resource.RLIMIT_CPU, CPU_SECONDS), (resource.RLIMIT_AS, AS_BYTES),
                         (resource.RLIMIT_FSIZE, CAP), (resource.RLIMIT_CORE, 0)]:
        resource.setrlimit(which, (limit, limit))
    fd = os.open(executable, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    if fd < 3:
        held = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
        os.close(fd)
        fd = held
    data, identity = read_fd(fd, 1024**2)
    assert (len(data), identity["sha256"]) == ELFS[role]
    assert identity["stat"][2] & 0o111
    assert identity["stat"] == stamp(os.stat(executable, follow_symlinks=False))
    assert not list((stage / "cwd").iterdir())
    os.chdir(stage / "cwd")
    os.umask(0o077)
    opened = [os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)]
    for name in ("stdout", "stderr"):
        opened.append(os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                              os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))
    for target, source in enumerate(opened):
        if source == target:
            os.set_inheritable(source, True)
        else:
            os.dup2(source, target, inheritable=True)
            os.close(source)
    os.execve(fd, ["e9patch", "--help"], ENV)
    raise RuntimeError("execve returned")


def main():
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    p.add_argument("--revision", required=True)
    p.add_argument("--cpu", type=int, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--original", type=Path, required=True)
    p.add_argument("--candidate", type=Path, required=True)
    a = p.parse_args()
    assert len(a.revision) == 40 and all(c in "0123456789abcdef" for c in a.revision)
    out = a.out.absolute()
    assert out == out.resolve() and out.parent == ROOT / "target/evaluation" and not out.exists()
    out.mkdir(mode=0o700)
    record = dict(profile="pinned-e9-startup-help-parity-v1", revision=a.revision,
                  status="PREFLIGHT", arms={}, argv=["e9patch", "--help"], environment=ENV,
                  bounds=dict(cpu_seconds=CPU_SECONDS, wall_seconds=WALL_SECONDS,
                              address_space_bytes=AS_BYTES, regular_file_bytes=CAP,
                              owner_log_bytes=CAP, owner_cleanup_seconds=3),
                  qualification_complete=False, all_selected_sites_executed=False,
                  performance_qualified=False, reservation_evidence="external caller responsibility")

    def save():
        with (out / "receipt.tmp").open("w") as f:
            json.dump(record, f, indent=2, sort_keys=True)
            f.write("\n"); f.flush(); os.fsync(f.fileno())
        os.replace(out / "receipt.tmp", out / "receipt.json")

    def ready():
        assert os.sched_getaffinity(0) == {a.cpu}
        git = ["/usr/bin/git", "--no-optional-locks"]
        assert subprocess.check_output(git + ["rev-parse", "HEAD"], timeout=10).decode().strip() == a.revision
        assert not subprocess.check_output(git + ["status", "--porcelain", "--untracked-files=no"], timeout=10)
        return dict(cpu=a.cpu, affinity=sorted(os.sched_getaffinity(0)), load=list(os.getloadavg()),
                    cgroup=Path("/proc/self/cgroup").read_text(), kernel=os.uname().release,
                    architecture=os.uname().machine, monotonic=time.monotonic(),
                    utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    try:
        save()
        paths = {role: getattr(a, role).absolute() for role in ELFS}
        assert all(path == path.resolve(strict=True) for path in paths.values())
        python = Path(sys.executable).resolve(strict=True)
        frozen = {str(path): read(path, 64 * 1024**2)[1] for path in
                  [SELF, OWNER, python, Path("/usr/bin/git"), *paths.values()]}
        assert frozen[str(OWNER)]["sha256"] == OWNER_SHA
        for role, path in paths.items():
            q = frozen[str(path)]
            assert (q["bytes"], q["sha256"]) == ELFS[role] and q["stat"][2] & 0o111
        record.update(inputs=frozen, before=ready())
        spec = importlib.util.spec_from_file_location("help_owner", OWNER)
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        raw = {}
        for role, executable in paths.items():
            assert all(read(Path(name), 64 * 1024**2)[1] == q for name, q in frozen.items())
            stage = out / role
            stage.mkdir(mode=0o700); (stage / "cwd").mkdir(mode=0o700)
            argv = [str(python), "-I", "-B", str(SELF), "--exec-arm", role,
                    str(executable), str(stage), str(a.cpu)]
            arm = dict(status="DISPATCHED_UNRESOLVED", dispatch_attempts=1, argv=argv, before=ready())
            record["arms"][role] = arm
            save()
            arm["owner"] = owner.run_command(argv, ENV, stage / "owner.log", WALL_SECONDS, CAP)
            save()
            closed = arm["owner"]
            assert closed["cleanup_complete"], "unresolved ownership: no output read or next arm"
            log, log_pin = read(stage / "owner.log", CAP)
            assert log_pin["sha256"] == closed["private_log_sha256"]
            streams = {}
            for name in ("stdout", "stderr"):
                streams[name] = read(stage / name, CAP) if (stage / name).exists() else (None, None)
            arm.update(log=log_pin, streams={name: v[1] for name, v in streams.items()}, after=ready(),
                       cwd_entries=sorted(x.name for x in (stage / "cwd").iterdir()))
            assert all(read(Path(name), 64 * 1024**2)[1] == q for name, q in frozen.items())
            normal = (closed["exit_code"] == 0 and closed["termination"] is None and
                      closed["reaped_descendants"] == 0 and not log and not arm["cwd_entries"])
            stdout, stderr = streams["stdout"][0], streams["stderr"][0]
            valid = normal and stderr == b"" and stdout is not None and stdout.startswith(
                b"usage: e9patch [OPTIONS]\n\nOPTIONS:\n")
            arm["status"] = "HELP_EXIT_ZERO" if valid else "FAILED_OUTCOME_RETAINED"
            raw[role] = (stdout, stderr, closed["exit_code"])
            save()
        record["exact_stream_and_status_match"] = raw["original"] == raw["candidate"]
        passed = record["exact_stream_and_status_match"] and all(
            arm["status"] == "HELP_EXIT_ZERO" for arm in record["arms"].values())
        record.update(status="STARTUP_HELP_PARITY_PASS_ONLY" if passed else "FAILED_OUTCOME_RETAINED", after=ready())
        save()
        return 0 if passed else 1
    except BaseException as error:
        record.update(status="FAILED", error=dict(type=type(error).__name__, message=str(error)))
        save()
        raise


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "--exec-arm":
        child(sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4]), int(sys.argv[5]))
        raise SystemExit(125)
    raise SystemExit(main())
