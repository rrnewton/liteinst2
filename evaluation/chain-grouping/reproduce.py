#!/usr/bin/env python3
"""Run the unchanged required gates and collect the grouped-chain result."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def main():
    if sys.flags.optimize:
        raise SystemExit("Assertions must remain enabled")
    parser = argparse.ArgumentParser()
    for name in ("raw", "toolchain", "user-home", "cargo-home"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    raw = args.raw
    assert raw.is_absolute() and raw.parent.resolve() == raw.parent
    assert raw.is_relative_to(repo / "ignored") and not raw.exists()
    for p in (args.toolchain, args.user_home, args.cargo_home):
        assert p.is_absolute() and p.resolve() == p and p.is_dir()
    git = lambda *a: subprocess.check_output(["/usr/bin/git", "-C", str(repo), *a], timeout=15)
    revision = git("rev-parse", "HEAD").decode().strip()
    assert not git("diff", "HEAD", "--"), "clean tracked checkout required"
    names = git("ls-files", "-z").decode().split("\0")[:-1]
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    sources = {name: digest(repo / name) for name in names}
    assert str(Path(__file__).resolve().relative_to(repo)) in sources
    assert "evaluation/required-gates.py" in sources
    raw.mkdir()
    (raw / "captures").mkdir()
    def save(name, value):
        with (raw / name).open("x") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
    save("source.json", {"revision": revision, "files": sources})
    cpu = Path("/proc/cpuinfo").read_text()
    save("hardware.json", {
        "cpu_model": next(line.split(":", 1)[1].strip() for line in cpu.splitlines()
                          if line.startswith("model name")),
        "architecture": platform.machine(), "logical_cpus": os.cpu_count(),
        "kernel_release": platform.release(), "libc": platform.libc_ver(),
    })
    tool = args.toolchain / "bin"
    env = {
        "CARGO_BUILD_JOBS": "4", "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": str(repo / "target"),
        "CARGO_HOME": str(args.cargo_home), "HOME": str(args.user_home),
        "RUSTC": str(tool / "rustc"), "RUSTDOC": str(tool / "rustdoc"),
        "RUSTC_WORKSPACE_WRAPPER": "", "RUSTC_WRAPPER": "",
        "RUST_TEST_THREADS": "4", "LC_ALL": "C",
        "PATH": str(tool) + ":/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1",
        "LITEINST_CHAIN_MAIN_THREAD_CAPTURES": str(raw / "captures"),
    }
    save("tools.json", {name: subprocess.check_output(argv, env=env, text=True, timeout=15)
         for name, argv in (("rustc", [str(tool / "rustc"), "-vV"]),
                            ("cargo", [str(tool / "cargo"), "-V"]),
                            ("gcc", ["/usr/bin/gcc", "--version"]))})
    argv = [sys.executable, "-B", str(repo / "evaluation/required-gates.py"),
            "--repo", str(repo), "--output", str(raw / "gates")]
    save("command.json", {"revision": revision, "argv": argv, "cwd": str(repo),
         "env": env, "start_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
         "runner_sha256": digest(Path(__file__)),
         "required_runner_sha256": digest(repo / "evaluation/required-gates.py")})
    with (raw / "stdout.txt").open("xb") as out, (raw / "stderr.txt").open("xb") as err:
        # The unchanged dispatcher owns the 180/180/360/180-second command bounds.
        result = subprocess.run(argv, cwd=repo, env=env, stdout=out, stderr=err, check=False)
    save("result.json", {"exit": result.returncode, "stdout_sha256": digest(raw / "stdout.txt"),
         "stderr_sha256": digest(raw / "stderr.txt")})
    assert git("rev-parse", "HEAD").decode().strip() == revision
    assert not git("diff", "HEAD", "--")
    assert sources == {name: digest(repo / name) for name in names}
    save("source-after.json", {"revision": revision, "files": sources})
    if result.returncode:
        raise SystemExit(result.returncode)
    # Only the new cohort writes summary.json; old isolation captures are retained too.
    summaries = sorted((raw / "captures").glob("*/summary.json"))
    assert len(summaries) == 1, "required grouped cohort summary must exist exactly once"
    summary = json.loads(summaries[0].read_text())
    save("grouped-result.json", {"capture": str(summaries[0].relative_to(raw)),
         "sha256": digest(summaries[0]), "observed": summary})
    print("PASS required workspace gates and grouped chain cohort")


if __name__ == "__main__":
    main()
