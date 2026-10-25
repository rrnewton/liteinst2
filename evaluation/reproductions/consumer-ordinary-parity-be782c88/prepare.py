#!/usr/bin/env python3
"""Prepare bounded parity requests and bind files; never launch a process."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
OLD_LIB = "liteinst2_consumer_parity_base_v1"
EXPECTED_BUNDLE_SHA = None
EXPECTED_INPUTS_SHA = None
EXPECTED_INIT_RECEIPT_SHA = None
SUCCESS = b'{"exit": 0, "wall_timeout": false, "absence_proof": "ECHILD", "descendants": 0, "success": true}\n'


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(512 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def pairs(items):
    result = {}
    for k, v in items:
        assert k not in result
        result[k] = v
    return result


def read(path):
    p = Path(path)
    assert p.is_file() and not p.is_symlink() and p.stat().st_size <= 16 * 1024 * 1024
    return json.loads(p.read_text(), object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def write(path, value):
    with Path(path).open("x") as f:
        f.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def regular(path):
    p = Path(path)
    assert p.is_absolute() and p.resolve(strict=True) == p and p.is_file() and not p.is_symlink()
    return p


def bundle():
    assert re.fullmatch(r"[0-9a-f]{64}", EXPECTED_BUNDLE_SHA or "")
    assert sha(HERE / "files.json") == EXPECTED_BUNDLE_SHA
    files = read(HERE / "files.json")
    assert set(files) == {str(p.relative_to(HERE)) for p in HERE.rglob("*") if p.is_file()} - {"files.json"}
    for n, h in files.items():
        assert not Path(n).is_absolute() and ".." not in Path(n).parts
        assert sha(regular(HERE / n)) == h
    return read(HERE / "source-inputs.json")


def load_owner(repo, digest):
    name = "_consumer_parity_public_owner"
    assert name not in sys.modules
    p = regular(repo / "tools/unwind-oracle/adapter.py")
    raw = p.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    spec = importlib.util.spec_from_file_location(name, p)
    assert spec is not None and spec.origin == str(p)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(p), "exec", dont_inherit=True, optimize=0), vars(module))
    assert module.ROOT == repo and module.__file__ == str(p) and sha(p) == digest
    # Only its existing read/hash/depfile/copy helpers are called, never run_one/build.
    return module


def new_side(owner, raw, freeze_sha, build_sha, fixed):
    data = owner.verify(raw, freeze_sha)
    assert data["source_files"] == fixed["consumer_selected_files"]
    admission = data["source_admission"]
    assert admission["source_kind"] == "git_commit" and admission["clean_tracked"] is True
    assert admission["tested_revision"] == fixed["consumer_revision"]
    audit_path = raw / "build/build-audit.json"
    assert sha(audit_path) == build_sha
    audit = read(audit_path)
    assert audit["status"] == "BUILT_REVIEW_REQUIRED_NO_EXECUTION"
    actual = owner.files(raw / "build")
    assert actual == dict(audit["files"], **{"build-audit.json": build_sha})
    binding = owner.recheck_archives(raw / "build")
    assert binding["cargo_lock_sha256"] == data["source_files"]["Cargo.lock"]
    return data, binding


def receipt(raw, name, helper_sha, caps):
    qp, rp = raw / (name + ".request.json"), raw / (name + ".receipt.json")
    q, r = read(qp), read(rp)
    assert set(q) == {"argv", "cwd", "env", "cpu_seconds", "wall_seconds", "file_bytes", "stdout", "stderr"}
    assert q["stdout"] == str(raw / (name + ".stdout")) and q["stderr"] == str(raw / (name + ".stderr"))
    assert (q["cpu_seconds"], q["wall_seconds"], q["file_bytes"]) == caps
    assert set(r) == set("request_sha256 helper_sha256 exit wall_timeout aborted cleanup_error unexpected_descendants cleanup_events absence_proof inputs_unchanged elapsed_seconds stdout_sha256 stderr_sha256".split())
    assert r["request_sha256"] == sha(qp) and r["helper_sha256"] == helper_sha
    assert type(r["exit"]) is int and r["exit"] == 0 and r["wall_timeout"] is False
    assert r["unexpected_descendants"] == r["cleanup_events"] == []
    assert r["cleanup_error"] is None and r["aborted"] is None and r["inputs_unchanged"] is True
    assert r["absence_proof"] == "ECHILD"
    assert type(r["elapsed_seconds"]) in (float, int) and math.isfinite(r["elapsed_seconds"])
    assert 0 <= r["elapsed_seconds"] < q["wall_seconds"]
    for stream in ("stdout", "stderr"):
        assert r[stream + "_sha256"] == sha(q[stream])
    assert (raw / (name + ".helper.stdout")).read_bytes() == SUCCESS
    assert (raw / (name + ".helper.stderr")).read_bytes() == b""
    return q, r


def request_value(raw, name, argv, env, repo, caps):
    return dict(argv=argv, cwd=str(repo), env=env, cpu_seconds=caps[0], wall_seconds=caps[1],
                 file_bytes=caps[2], stdout=str(raw / (name + ".stdout")), stderr=str(raw / (name + ".stderr")))


def request(raw, name, argv, env, repo, caps):
    value = request_value(raw, name, argv, env, repo, caps)
    write(raw / (name + ".request.json"), value)
    return value


def phase_argv(phase, raw, data):
    argv = [data["tools"]["helper_python"]["path"], "-B", str(HERE / "prepare.py"), phase,
            "--raw", str(raw), "--bundle-sha256", EXPECTED_BUNDLE_SHA]
    if phase != "init":
        argv += ["--inputs-sha256", EXPECTED_INPUTS_SHA,
                 "--init-receipt-sha256", EXPECTED_INIT_RECEIPT_SHA]
    return argv


def old_cargo_argv(raw, data):
    return [data["tools"]["cargo"]["path"], "build", "--offline", "--locked", "--lib",
            "--manifest-path", str(raw / "old-crate/Cargo.toml"), "--message-format=json"]


def compile_argv(raw, saved, data, old, new):
    return [data["tools"]["rustc"]["path"], "--edition=2024", "--crate-name", "consumer_public_ordinary_parity_reproduction",
        "-Dwarnings", "-Ccodegen-units=1", "-Copt-level=0", "-Cdebuginfo=2", "-Cdebug-assertions=yes", "-Coverflow-checks=yes",
        "-Clinker=" + data["tools"]["gcc"]["path"], "-Clink-arg=-fuse-ld=bfd", str(HERE / "harness/main.rs"),
        "-L", "dependency=" + str(raw / "old-archives"), "-L", "dependency=" + str(Path(saved["consumer_raw"]) / "build/archives"),
        "--extern", "old_core=" + old["externs"][OLD_LIB], "--extern", "new_core=" + new["externs"]["liteinst2"],
        "--extern", "libc=" + old["externs"]["libc"], "--emit=link,dep-info=" + str(raw / "parity.d"), "-o", str(raw / "parity")]


def check_old(raw, owner):
    old = read(raw / "old-binding.json")
    assert owner.files(raw / "old-archives") == old["artifacts"]
    assert owner.files(raw / "old-dependency-sources") == old["dependency_copies"]
    assert sha(raw / "old-cargo-ancillary.json") == old["ancillary_sha256"]
    assert owner.files(raw / "cargo-build-scripts") == old["build_scripts"]
    assert owner.files(raw / "dependency-sources") == old["build_script_sources"]
    for dep in old["depfiles"].values():
        for name, digest in dep["sources"].items():
            assert sha(regular(name)) == sha(raw / "old-dependency-sources" / digest) == digest
    for row in read(raw / "old-cargo-ancillary.json")["records"]:
        owner.check_identity(row["archived"])
        for pair in row["sources"].values():
            owner.check_identity(pair["original"])
            owner.check_identity(pair["archived"])
    assert sha(raw / "old-cargo.receipt.json") == old["receipt_sha256"]
    assert sha(raw / "old-cargo.stdout") == old["stdout_sha256"]
    return old



def initial_result(inputs_digest, cargo_request_digest):
    return ("OLD_SOURCE_AND_CARGO_REQUEST_PREPARED_NO_EXECUTION inputs_sha256=" + inputs_digest
            + " old_cargo_request_sha256=" + cargo_request_digest + "\n")


def read_authority(raw, fixed):
    assert re.fullmatch(r"[0-9a-f]{64}", EXPECTED_INPUTS_SHA or "")
    assert re.fullmatch(r"[0-9a-f]{64}", EXPECTED_INIT_RECEIPT_SHA or "")
    path = raw / "inputs.json"
    assert sha(path) == EXPECTED_INPUTS_SHA
    saved = read(path)
    assert sha(path) == EXPECTED_INPUTS_SHA
    control = raw.with_name(raw.name + "-control")
    rp = control / "init.receipt.json"
    assert sha(rp) == EXPECTED_INIT_RECEIPT_SHA
    q, _ = receipt(control, "init", fixed["helper_sha256"], (20, 30, 16777216))
    cargo_digest = sha(raw / "old-cargo.request.json")
    assert Path(q["stdout"]).read_text() == initial_result(EXPECTED_INPUTS_SHA, cargo_digest)
    assert Path(q["stderr"]).read_bytes() == b""
    assert sha(path) == EXPECTED_INPUTS_SHA and sha(rp) == EXPECTED_INIT_RECEIPT_SHA
    return saved, dict(inputs_sha256=EXPECTED_INPUTS_SHA, init_receipt_sha256=EXPECTED_INIT_RECEIPT_SHA,
        init_request_sha256=sha(control / "init.request.json"), init_stdout_sha256=sha(q["stdout"]),
        old_cargo_request_sha256=cargo_digest)


def verify_elf_header(head):
    assert head[:7] == b"\x7fELF\x02\x01\x01" and head[18:20] == b"\x3e\x00" and head[16:18] in (b"\x02\x00", b"\x03\x00")


def state(raw):
    fixed = bundle()
    saved, authority = read_authority(raw, fixed)
    assert saved["bundle_sha256"] == sha(HERE / "files.json")
    repo = Path(saved["repository"])
    assert raw.is_relative_to(repo / "ignored") and raw.resolve(strict=True) == raw
    owner = load_owner(repo, fixed["public_adapter_sha256"])
    data, new = new_side(owner, Path(saved["consumer_raw"]), saved["consumer_freeze_sha256"], saved["consumer_build_sha256"], fixed)
    for name, digest in fixed["baseline_isolated_files"].items():
        assert sha(regular(raw / "old-crate" / name)) == digest
    assert data["environment"] == saved["consumer_environment"]
    assert saved["environment"] == dict(data["environment"], TMPDIR=str(raw / "tmp"))
    assert saved["old_source_revision"] == fixed["baseline_revision"] and saved["old_isolated_tested_revision"] is None
    assert saved["consumer_tested_revision"] == fixed["consumer_revision"] and saved["historical_result_credit"] is False
    for name, digest in fixed["baseline_original_files"].items():
        assert sha(regular(Path(saved["baseline"]) / name)) == digest
    init_argv = phase_argv("init", raw, data) + ["--repository", str(repo), "--baseline", saved["baseline"],
        "--consumer", saved["consumer_raw"], "--freeze-sha256", saved["consumer_freeze_sha256"],
        "--build-sha256", saved["consumer_build_sha256"]]
    control = raw.with_name(raw.name + "-control")
    assert read(control / "init.request.json") == request_value(control, "init", init_argv, saved["consumer_environment"], repo, (20, 30, 16777216))
    assert read_authority(raw, fixed) == (saved, authority)
    return fixed, saved, owner, data, new, authority


def initialize(args):
    fixed = bundle()
    repo, baseline, consumer, raw = (Path(getattr(args, n)).resolve() for n in ("repository", "baseline", "consumer", "raw"))
    assert repo.is_dir() and baseline.is_dir() and consumer.is_dir() and not raw.exists()
    assert raw.is_relative_to(repo / "ignored") and not raw.is_relative_to(consumer) and not consumer.is_relative_to(raw)
    assert not raw.is_relative_to(HERE) and not HERE.is_relative_to(raw)
    control = raw.with_name(raw.name + "-control")
    assert control.is_dir() and control.resolve(strict=True) == control
    owner = load_owner(repo, fixed["public_adapter_sha256"])
    data, _ = new_side(owner, consumer, args.freeze_sha256, args.build_sha256, fixed)
    for name, digest in fixed["baseline_original_files"].items():
        assert sha(regular(baseline / name)) == digest
    raw.mkdir()
    (raw / "tmp").mkdir()
    for name in fixed["baseline_isolated_files"]:
        source = HERE / "old-overlay" / name if name in ("Cargo.toml", "Cargo.lock") else baseline / name
        owner.copy_exact(source, raw / "old-crate" / name)
        assert sha(raw / "old-crate" / name) == fixed["baseline_isolated_files"][name]
    env = dict(data["environment"], TMPDIR=str(raw / "tmp"))
    assert env["CARGO_BUILD_JOBS"] == "4" and env["CARGO_INCREMENTAL"] == "0"
    assert "CARGO_ENCODED_RUSTFLAGS" not in env
    write(raw / "inputs.json", dict(bundle_sha256=sha(HERE / "files.json"), repository=str(repo), baseline=str(baseline),
        consumer_raw=str(consumer), consumer_freeze_sha256=args.freeze_sha256, consumer_build_sha256=args.build_sha256,
        consumer_environment=data["environment"], environment=env, old_source_revision=fixed["baseline_revision"],
        old_isolated_tested_revision=None, consumer_tested_revision=fixed["consumer_revision"], historical_result_credit=False))
    request(raw, "old-cargo", old_cargo_argv(raw, data), env, repo, (60, 90, 128 * 1024 * 1024))
    inputs_digest = sha(raw / "inputs.json")
    cargo_digest = sha(raw / "old-cargo.request.json")
    print(initial_result(inputs_digest, cargo_digest), end="")


def archive_old(args):
    raw = Path(args.raw).resolve()
    fixed, saved, owner, data, new, authority = state(raw)
    q, _ = receipt(raw, "old-cargo", fixed["helper_sha256"], (60, 90, 128 * 1024 * 1024))
    assert q == request_value(raw, "old-cargo", old_cargo_argv(raw, data), saved["environment"], Path(saved["repository"]), (60, 90, 128 * 1024 * 1024))
    rows = [json.loads(line, object_pairs_hook=pairs) for line in Path(q["stdout"]).read_text().splitlines()]
    assert rows[-1] == {"reason": "build-finished", "success": True}
    assert sum(r.get("reason") == "build-finished" for r in rows) == 1
    assert all(r.get("reason") in {"compiler-artifact", "compiler-message", "build-script-executed", "build-finished"} for r in rows)
    assert not any(r.get("reason") == "compiler-message" and r["message"]["level"] in {"error", "warning"} for r in rows)
    libs = [r for r in rows if r.get("reason") == "compiler-artifact" and r["target"]["kind"] == ["lib"]]
    newer = {r["target"]["name"]: r for r in new["records"]}
    assert len(libs) == 9 and {r["target"]["name"] for r in libs} == set(newer) - {"liteinst2"} | {OLD_LIB}
    packages = owner.locked_packages((raw / "old-crate/Cargo.lock").read_text())
    assert packages == new["locked_packages"]
    archive, sources = raw / "old-archives", raw / "old-dependency-sources"
    archive.mkdir(); sources.mkdir()
    artifacts, depfiles, records, externs = {}, {}, [], {}
    repo = Path(saved["repository"])
    for row in libs:
        target = row["target"]["name"]
        comparison = newer["liteinst2" if target == OLD_LIB else target]
        assert row["features"] == comparison["features"] and row["profile"] == comparison["profile"]
        assert row["target"]["kind"] == row["target"]["crate_types"] == ["lib"] and row["executable"] is None
        assert type(row["fresh"]) is bool
        manifest = regular(Path(row["manifest_path"]))
        crate = manifest.parent
        assert manifest.name == "Cargo.toml" and row["target"]["src_path"] == str(crate / "src/lib.rs")
        if target == OLD_LIB:
            assert crate == raw / "old-crate"
            assert row["package_id"] == "path+file://" + str(crate) + "#liteinst2@0.1.0"
            assert sha(manifest) == fixed["baseline_isolated_files"]["Cargo.toml"]
        else:
            assert row["package_id"] == comparison["package_id"] and row["target"] == comparison["target"]
            assert row["manifest_path"] == comparison["manifest_path"]
            assert sha(manifest) == new["package_owners"][target]["manifest"]["sha256"]
        rlibs = [regular(Path(x)) for x in row["filenames"] if x.endswith(".rlib")]
        rmetas = [regular(Path(x)) for x in row["filenames"] if x.endswith(".rmeta")]
        assert len(rlibs) == len(rmetas) == 1 and len(row["filenames"]) == 2
        rl, rm = rlibs[0], rmetas[0]
        assert rm.parent == repo / "target/debug/deps" and re.fullmatch("lib" + re.escape(target) + r"-[0-9a-f]{16}\.rmeta", rm.name)
        hashed = regular(rm.with_suffix(".rlib"))
        if target == OLD_LIB:
            assert rl == repo / "target/debug" / ("lib" + OLD_LIB + ".rlib") and sha(rl) == sha(hashed)
        else:
            assert rl == hashed
        dep = regular(rm.with_name(rm.name.removeprefix("lib").removesuffix(".rmeta") + ".d"))
        rules, environment = owner.dep_rules(dep)
        nonempty = {k: v for k, v in rules.items() if v}
        assert set(nonempty) == {str(dep), str(hashed), str(rm)}
        values = nonempty[str(dep)]
        assert values and all(v == values for v in nonempty.values())
        values = [str(regular(Path(v).resolve())) for v in values]
        assert len(values) == len(set(values)) and row["target"]["src_path"] in values
        assert {str(Path(k).resolve()) for k, v in rules.items() if not v} == set(values)
        if target == OLD_LIB:
            assert environment == []
        else:
            new_meta = next(Path(n) for n in comparison["filenames"] if n.endswith(".rmeta"))
            new_dep = new_meta.name.removeprefix("lib").removesuffix(".rmeta") + ".d"
            assert environment == new["depfiles"][new_dep]["environment"]
        source_hashes = {}
        for n in [str(manifest)] + values:
            p = regular(Path(n)); assert p.is_relative_to(crate)
            digest = sha(p)
            if target == OLD_LIB:
                assert digest == fixed["baseline_isolated_files"][str(p.relative_to(crate))]
            if not (sources / digest).exists(): owner.copy_exact(p, sources / digest)
            assert sha(sources / digest) == digest
            source_hashes[n] = digest
        for p in [rl, rm, dep]:
            assert p.name not in artifacts
            owner.copy_exact(p, archive / p.name)
            (archive / p.name).chmod(0o444)
            artifacts[p.name] = sha(archive / p.name)
        externs[target] = str(archive / rl.name)
        depfiles[target] = dict(path=str(archive / dep.name), sha256=sha(dep), rules=rules, environment=environment, sources=source_hashes)
        records.append(row)
    owner.archive_build_scripts(raw, data, "old-cargo")
    write(raw / "old-binding.json", dict(artifacts=artifacts, records=records, depfiles=depfiles, externs=externs,
        dependency_copies=owner.files(sources), ancillary_sha256=sha(raw / "old-cargo-ancillary.json"),
        build_scripts=owner.files(raw / "cargo-build-scripts"), build_script_sources=owner.files(raw / "dependency-sources"),
        receipt_sha256=sha(raw / "old-cargo.receipt.json"), stdout_sha256=sha(q["stdout"]), actual_reproduction=True,
        historical_result_credit=False, tested_revision=None, original_revision=fixed["baseline_revision"], input_authority=authority))
    assert read_authority(raw, fixed) == (saved, authority)
    print("OLD_ARCHIVES_BOUND_NO_HARNESS_EXECUTION")


def compile_request(args):
    raw = Path(args.raw).resolve(); fixed, saved, owner, data, new, authority = state(raw)
    old = check_old(raw, owner)
    assert old["input_authority"] == authority
    repo = Path(saved["repository"])
    argv = compile_argv(raw, saved, data, old, new)
    assert not (raw / "parity").exists() and not (raw / "parity.d").exists()
    request(raw, "compile", argv, saved["environment"], repo, (60, 90, 128 * 1024 * 1024))
    write(raw / "compile-inputs.json", dict(input_authority=authority, old_binding_sha256=sha(raw / "old-binding.json"),
        new_binding_sha256=sha(Path(saved["consumer_raw"]) / "build/cargo-binding.json"),
        source_bundle_sha256=sha(HERE / "files.json"), request_sha256=sha(raw / "compile.request.json"), old_archives=old["artifacts"],
        new_archives={n: row["copied"]["sha256"] for n, row in new["archives"].items()}))
    assert read_authority(raw, fixed) == (saved, authority)
    print("FRESH_HARNESS_COMPILE_REQUEST_PREPARED_NO_EXECUTION")


def bind(args):
    raw = Path(args.raw).resolve(); fixed, saved, owner, data, new, authority = state(raw)
    q, _ = receipt(raw, "compile", fixed["helper_sha256"], (60, 90, 128 * 1024 * 1024))
    old = check_old(raw, owner)
    assert old["input_authority"] == authority
    assert q == request_value(raw, "compile", compile_argv(raw, saved, data, old, new), saved["environment"], Path(saved["repository"]), (60, 90, 128 * 1024 * 1024))
    assert Path(q["stdout"]).read_bytes() == Path(q["stderr"]).read_bytes() == b""
    binary = regular(raw / "parity")
    assert binary.stat().st_nlink == 1 and binary.stat().st_mode & 0o111
    with binary.open("rb") as f: head = f.read(64)
    verify_elf_header(head)
    rules, env = owner.dep_rules(raw / "parity.d")
    dependencies = {str(HERE / "harness" / n) for n in ("main.rs", "capture.rs", "common.rs", "inventory.rs")}
    assert env == [] and set(rules) == dependencies | {str(binary), str(raw / "parity.d")}
    assert rules[str(binary)] == rules[str(raw / "parity.d")] and set(rules[str(binary)]) == dependencies
    assert all(not rules[n] for n in dependencies)
    inputs = read(raw / "compile-inputs.json")
    assert inputs["input_authority"] == authority
    assert inputs["old_binding_sha256"] == sha(raw / "old-binding.json") and inputs["source_bundle_sha256"] == sha(HERE / "files.json")
    assert inputs["request_sha256"] == sha(raw / "compile.request.json")
    assert inputs["new_binding_sha256"] == sha(Path(saved["consumer_raw"]) / "build/cargo-binding.json")
    for n, digest in inputs["old_archives"].items(): assert sha(raw / "old-archives" / n) == digest
    for n, digest in inputs["new_archives"].items(): assert sha(Path(saved["consumer_raw"]) / "build/archives" / n) == digest
    assert not (raw / "capture").exists() and not (raw / "run-once.receipt.json").exists()
    request(raw, "run-once", [str(binary), str(raw / "capture")], saved["environment"], Path(saved["repository"]), (20, 30, 16 * 1024 * 1024))
    write(raw / "binary-binding.json", dict(status="INDEPENDENT_ACTUAL_BINARY_REVIEW_REQUIRED", input_authority=authority, binary=str(binary),
        binary_sha256=sha(binary), depfile_sha256=sha(raw / "parity.d"), source_bundle_sha256=sha(HERE / "files.json"),
        compile_input_sha256=sha(raw / "compile-inputs.json"), compile_receipt_sha256=sha(raw / "compile.receipt.json"),
        run_request_sha256=sha(raw / "run-once.request.json"), required_inventory=fixed["required_inventory"], generated_execution=0))
    assert read_authority(raw, fixed) == (saved, authority)
    print("ACTUAL_BINARY_BOUND_REVIEW_REQUIRED_BEFORE_RUN")


def main():
    global EXPECTED_BUNDLE_SHA, EXPECTED_INPUTS_SHA, EXPECTED_INIT_RECEIPT_SHA
    p = argparse.ArgumentParser()
    p.add_argument("phase", choices=("init", "archive-old", "compile-request", "bind"))
    p.add_argument("--raw", required=True)
    p.add_argument("--bundle-sha256", required=True)
    p.add_argument("--inputs-sha256")
    p.add_argument("--init-receipt-sha256")
    p.add_argument("--repository")
    p.add_argument("--baseline")
    p.add_argument("--consumer")
    p.add_argument("--freeze-sha256")
    p.add_argument("--build-sha256")
    args = p.parse_args()
    EXPECTED_BUNDLE_SHA = args.bundle_sha256
    EXPECTED_INPUTS_SHA, EXPECTED_INIT_RECEIPT_SHA = args.inputs_sha256, args.init_receipt_sha256
    assert sys.pycache_prefix is None
    if args.phase == "init":
        assert args.inputs_sha256 is args.init_receipt_sha256 is None
        assert all(getattr(args, n) for n in ("repository", "baseline", "consumer", "freeze_sha256", "build_sha256"))
        initialize(args)
    else:
        assert args.inputs_sha256 is not None and args.init_receipt_sha256 is not None
        assert all(getattr(args, n) is None for n in ("repository", "baseline", "consumer", "freeze_sha256", "build_sha256"))
        {"archive-old": archive_old, "compile-request": compile_request, "bind": bind}[args.phase](args)


if __name__ == "__main__":
    main()
