#!/usr/bin/env python3
"""Fixed compiled-DSO reproduction under an external one-CPU lease.

The caller supplies pinned current source/runtime semantic premises. A compiler
result or JSON hash is provenance and never manufactures that authority.
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
from pathlib import Path
import stat
import shutil
import subprocess

ROOT = Path.cwd().resolve()
REVISION = "a306d916315a9bb9acc112fe306e1371d929ea1a"
BUILDER = "tools/unwind-oracle/indexed_dso/build_fixture.py"
OWNER = "evaluation/admission/processes.py"


def read_initial(path, expected):
    path = Path(path).resolve(strict=True)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_size <= 16 * 1024**2
        raw = stream.read(16 * 1024**2 + 1)
        stable = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_mtime_ns, s.st_ctime_ns)
        assert len(raw) == before.st_size and stable(os.fstat(stream.fileno())) == stable(before)
        assert stable(path.lstat()) == stable(before)
    assert hashlib.sha256(raw).hexdigest() == expected
    return raw


def unique(pairs):
    result = dict(pairs)
    assert len(result) == len(pairs), "duplicate JSON key"
    return result


def imported(name, path, digest):
    read_initial(path, digest)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("out", "toolchain", "profile", "recipe"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--profile-sha256", required=True)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    profile_path = args.profile.resolve(strict=True)
    profile = json.loads(read_initial(profile_path, args.profile_sha256), object_pairs_hook=unique)
    assert profile["schema"] == "indexed-dso-public-reproduction-profile-v1"
    assert profile["revision"] == REVISION and sys.version_info[:2] == (3, 9)
    git_pin = profile["tools"]["git"]
    read_initial(git_pin["path"], git_pin["sha256"])
    assert str(Path(shutil.which("git")).resolve()) == git_pin["path"]
    git = lambda *a: subprocess.check_output([git_pin["path"], *a], cwd=ROOT, timeout=10).decode().splitlines()
    assert git("rev-parse", "HEAD") == [REVISION]
    paths = set(git("ls-files", "--modified", "--others", "--exclude-standard"))
    paths.update(git("diff", "--cached", "--name-only"))
    assert not git("ls-files", "--", "BRIEF-li2core.md")
    assert not paths - {"BRIEF-li2core.md"}
    assert set(profile["modules"]) == {BUILDER, OWNER}
    recipe_path = args.recipe.resolve(strict=True)
    assert profile["recipe"]["path"] == str(recipe_path)
    recipe = imported("native_recipe", recipe_path, profile["recipe"]["sha256"])
    build = imported("fixture_builder", ROOT / BUILDER, profile["modules"][BUILDER])
    owner = imported("command_owner", ROOT / OWNER, profile["modules"][OWNER])
    # The pinned recipe independently rechecks the same duplicate-free profile.
    assert recipe.load(profile_path, args.profile_sha256) == profile
    pin = lambda path: recipe.capture(Path(path))[0]
    for key in ("recipe", "toolchain", "semantic_review", "native_review"):
        assert set(profile[key]) == {"path", "bytes", "sha256"}
    assert 1 <= len(profile["historical_reviews"]) <= 32
    assert all(set(p) == {"path", "bytes", "sha256"} for p in profile["historical_reviews"])
    tools = profile["tools"]
    assert set(tools) == {"cargo", "rustc", "rustdoc", "python", "timeout", "git"}
    assert str(Path(shutil.which("git")).resolve()) == tools["git"]["path"]
    assert tools["python"]["path"] == str(Path(sys.executable).resolve())
    rust = Path(tools["cargo"]["path"]).parent
    assert all(Path(tools[n]["path"]).parent == rust for n in ("rustc", "rustdoc"))
    toolchain = args.toolchain.resolve(strict=True)
    assert pin(toolchain) == profile["toolchain"]
    config = recipe.load(toolchain)
    assert len(profile["c_toolchain_files"]) == 79
    assert {p["path"] for p in profile["c_toolchain_files"]} == set(config["files"])
    assert config["tools"]["helper_python"] == tools["python"]["path"]
    assert config["tools"]["timeout"] == tools["timeout"]["path"]
    execution = recipe.all_pins(profile["execution_tools"])
    assert all(execution.get(p["path"]) == p for p in tools.values())
    frozen = recipe.all_pins(profile)
    frozen[str(profile_path)] = pin(profile_path)
    frozen[str(Path(__file__).resolve())] = pin(Path(__file__).resolve())
    for path, digest in profile["modules"].items():
        assert pin(ROOT / path)["sha256"] == digest
        frozen[str(ROOT / path)] = pin(ROOT / path)
    for value in frozen.values():
        recipe.check(value)
    revision = REVISION
    assert profile["revision"] == revision
    expected_source = dict(base=revision, working_source_sha256={})
    # source() permits only BRIEF-li2core.md after proving it is untracked.
    assert recipe.source() == expected_source
    lease = recipe.reservation(profile)
    hardware = recipe.hardware_metadata(profile["hardware"])
    out = args.out.absolute()
    assert out.resolve() == out and out.is_relative_to(ROOT / "ignored")
    logs = ROOT / "target/evaluation" / ("indexed-public-" + hashlib.sha256(str(out).encode()).hexdigest())
    env = dict(HOME=os.environ["HOME"], CARGO_HOME=profile["cargo_home"],
               PATH=str(rust) + ":/usr/bin:/bin", RUSTC=tools["rustc"]["path"], RUSTDOC=tools["rustdoc"]["path"],
               CARGO_TARGET_DIR=str(ROOT / "target"), CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="4",
               CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never", LANG="C.UTF-8", LC_ALL="C.UTF-8",
               PYTHONDONTWRITEBYTECODE="1", LITEINST_EVALUATION="1")
    for name in ("DEV", "TEST"):
        for key, value in (("DEBUG", "0"), ("OPT_LEVEL", "0"), ("DEBUG_ASSERTIONS", "true"), ("OVERFLOW_CHECKS", "true")):
            env["CARGO_PROFILE_" + name + "_" + key] = value
    env.update({k: str(out / "tmp") for k in ("TMPDIR", "TEMP", "TMP")})

    def unchanged():
        assert recipe.source() == expected_source and recipe.reservation(profile) == lease
        for value in frozen.values():
            recipe.check(value)

    summary_path = out / "summary.json"
    if not args.worker:
        out.mkdir(mode=0o700)
        (out / "tmp").mkdir()
        logs.mkdir(parents=True, exist_ok=False)
        recipe.save(out / "reservation.json", lease)
        initial = dict(schema="indexed-dso-public-reproduction-v1", status="PREPARING", revision=revision,
            profile_sha256=args.profile_sha256, recipe_sha256=profile["recipe"]["sha256"],
            native_qualification=False, **hardware,
            stage_status_scope="Owner command closure; complete success also requires subsequent product/inspection/native joins",
            cpu=lease["cores"][0], reservation_sha256=pin(out / "reservation.json")["sha256"],
            reservation_release="CALLER_CHECKS_AFTER_RETURN",
            stages=[dict(name=n, status="UNRUN", attempts=0) for n in ("c-build", "rust-build", "inspect", "native")],
            cells=[dict(mode=m, status="UNRUN", attempts=0) for m in recipe.MODES])
        recipe.save(summary_path, initial)
        command = [str(Path(sys.executable).resolve()), "-B", str(Path(__file__).resolve()),
                   "--out", str(out), "--toolchain", str(toolchain), "--profile", str(profile_path),
                   "--recipe", str(recipe_path),
                   "--profile-sha256", args.profile_sha256, "--worker"]
        closed = owner.run_command(command, env, logs / "aggregate.log", 1200, 8 * 1024**2)
        recipe.save(out / "outer.json", dict(command=command, closed=closed))
        assert closed["cleanup_complete"] is True and closed["reaped_descendants"] == 0
        raw = recipe.capture(logs / "aggregate.log", True, 8 * 1024**2)[1]
        assert hashlib.sha256(raw).hexdigest() == closed["private_log_sha256"]
        (out / "aggregate.log").write_bytes(raw)
        unchanged()
        actual = recipe.load(summary_path)
        actual["outer"] = {k: closed[k] for k in ("exit_code", "termination", "seconds", "private_log_sha256", "cleanup_complete", "reaped_descendants")}
        if not recipe.ordinary_closed(closed):
            actual["status"] = "FAILED_OR_INCOMPLETE"
        recipe.save(summary_path, actual)
        print(json.dumps(actual, sort_keys=True))
        return 0 if actual["status"] == "PASS_FINITE_CHECKS" else 1

    summary = recipe.load(summary_path)
    assert recipe.load(out / "reservation.json", summary["reservation_sha256"]) == lease
    frozen[str(out / "reservation.json")] = pin(out / "reservation.json")
    assert all(r["attempts"] == 0 for r in summary["stages"] + summary["cells"])
    def run(index, command, owner_path, allow_nonzero=False):
        unchanged()
        row = summary["stages"][index]
        if index == 3:
            summary["cells"] = [dict(mode=m, status="NATIVE_DISPATCHED_CELL_OUTCOME_UNKNOWN", attempts=None) for m in recipe.MODES]
        row.update(status="DISPATCHED_UNRESOLVED", attempts=1,
                   command_sha256=hashlib.sha256(json.dumps(command).encode()).hexdigest(),
                   load_before=Path("/proc/loadavg").read_text().split()[:3])
        recipe.save(summary_path, summary)
        closed = owner.run_command(command, env, logs / (row["name"] + ".log"), 1200, 8 * 1024**2)
        record = dict(**expected_source, command=command, closed=closed, source_unchanged=recipe.source() == expected_source)
        recipe.save(owner_path, record)
        row.update(status="CLOSED_UNCHECKED", seconds=closed["seconds"], exit=closed["exit_code"],
                   log_sha256=closed["private_log_sha256"], load_after=Path("/proc/loadavg").read_text().split()[:3])
        recipe.save(summary_path, summary)
        assert closed["cleanup_complete"] is True and closed["reaped_descendants"] == 0
        raw = recipe.capture(logs / (row["name"] + ".log"), True, 8 * 1024**2)[1]
        assert hashlib.sha256(raw).hexdigest() == closed["private_log_sha256"]
        (out / (row["name"] + ".log")).write_bytes(raw)
        unchanged()
        row["status"] = "PASS" if recipe.ordinary_closed(closed) else "FAILED"
        recipe.save(summary_path, summary)
        assert row["status"] == "PASS" or (allow_nonzero and closed["termination"] is None)
        frozen[str(owner_path)] = pin(owner_path)
        return raw, closed

    try:
        python = tools["python"]["path"]
        source_admission = out / "source-admission.json"
        recipe.save(source_admission, dict(schema="indexed-dso-build-source-v1", base_revision=revision,
            source_files={str(p.relative_to(ROOT)): pin(p)["sha256"] for p in build.SOURCES},
            review={k: profile["semantic_review"][k] for k in ("path", "sha256")}))
        frozen[str(source_admission)] = pin(source_admission)
        run(0, [python, "-B", str(ROOT / BUILDER), "--out", str(out / "build"),
            "--toolchain", str(toolchain), "--toolchain-sha256", profile["toolchain"]["sha256"],
            "--source-admission", str(source_admission), "--source-admission-sha256", pin(source_admission)["sha256"]], out / "closed.json")
        manifest = recipe.load(out / "build/manifest.json")
        assert manifest["status"] == "BUILD_ONLY_REVIEW_REQUIRED" and manifest["native_qualification"] is False
        assert [(r["name"], r["status"], r["attempts"]) for r in manifest["stages"]] == [(n, "PASS", 1) for n in recipe.STAGES]
        for path, value in recipe.all_pins(manifest).items():
            assert path not in frozen or frozen[path] == value
            frozen[path] = value
        frozen[str(out / "build/manifest.json")] = pin(out / "build/manifest.json")
        unchanged()
        run(1, [tools["timeout"]["path"], "--signal=TERM", "--kill-after=3s", "180s", tools["cargo"]["path"],
            "build", "--offline", "--locked", "-p", "liteinst-rewrite", "--example", "indexed_dso_native"], out / "native-build-owner.json")
        binary = pin(ROOT / "target/debug/examples/indexed_dso_native")
        frozen[binary["path"]] = binary
        subject, caller = [pin(out / "build" / ("libli2_uw_" + n + ".so")) for n in ("subject", "caller")]
        for name, value in (("subject", subject), ("caller", caller)):
            assert value == {k: manifest["links"][name]["elf"][k] for k in value}
        (out / "inspect").mkdir()
        common = [subject["path"], subject["sha256"], caller["path"], caller["sha256"],
                  str(out / "build/manifest.json"), pin(out / "build/manifest.json")["sha256"],
                  manifest["tools"]["libgcc"]["path"], str(out / "build/inputs" / recipe.CONSUMER_SHA)]
        data, _ = run(2, [binary["path"], "inspect", *common, str(out / "inspect")], out / "inspection-owner.json")
        assert data == b'{"kind":"inspection","caller_functions":2,"subject_functions":4,"native":false}\n'
        admission = dict(schema="indexed-dso-native-admission-v1", source=expected_source, hardware=profile["hardware"],
            c_build_owner=pin(out / "closed.json"), c_build_manifest=pin(out / "build/manifest.json"),
            subject_elf=subject, caller_elf=caller, native_binary=binary,
            native_build_owner=pin(out / "native-build-owner.json"), inspection_owner=pin(out / "inspection-owner.json"),
            inspection_out=str(out / "inspect"), semantic_review=profile["semantic_review"], native_review=profile["native_review"],
            historical_reviews=profile["historical_reviews"], execution_tools=profile["execution_tools"],
            reservation_ledger=profile["reservation_ledger"], reservation_tag=profile["reservation_tag"])
        recipe.save(out / "native-admission.json", admission)
        frozen[str(out / "native-admission.json")] = pin(out / "native-admission.json")
        _, native_closed = run(3, [python, "-B", str(recipe_path), "--admission", str(out / "native-admission.json"),
            "--admission-sha256", pin(out / "native-admission.json")["sha256"], "--build-root", str(out / "build"),
            "--out", str(out / "native")], out / "native-owner.json", allow_nonzero=True)
        child = recipe.load(out / "native/summary.json")
        assert child["native_qualification"] is False and [r["mode"] for r in child["cells"]] == list(recipe.MODES)
        assert child["status"] != "PASS_FINITE_CHECKS" or recipe.ordinary_closed(native_closed)
        summary.update(status=child["status"], cells=child["cells"], build_manifest_sha256=pin(out / "build/manifest.json")["sha256"],
                       subject_sha256=subject["sha256"], caller_sha256=caller["sha256"], native_binary_sha256=binary["sha256"])
    except BaseException as error:
        summary.update(status="FAILED_OR_INCOMPLETE", error_type=type(error).__name__)
        recipe.save(summary_path, summary)
        raise
    unchanged()
    recipe.save(summary_path, summary)
    return 0 if summary["status"] == "PASS_FINITE_CHECKS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
