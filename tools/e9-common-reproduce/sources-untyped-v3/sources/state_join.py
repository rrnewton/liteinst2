"""Explicit E9 body oracle join; no generated image or loader admission.

Only future actual six corrected outputs can generate fixture data. The copied
file mapper and native comparator are unchanged. All workloads remain separate
bounded-command requests with a review gate before compiling or executing.
"""
import json
from pathlib import Path
from bootstrap_validate import need, sha
from bounded_stage1 import capture, inventory, write_new
from guard import digest, read
from old_audit import validate_helper_receipt
from pipeline import admitted, bytes_at, emitted

STATE_STDOUT = b"actual E9 passthru file state oracle: 6 outputs, two distinct common biases each, 48 original/48 rewritten/48 restored-original, zero hook events; manual fixture load; artifact qualification incomplete\n"


def compiler_inputs(here):
    value = read(here / "state/compile-inputs.json")
    for name, checksum in value["historical_refs"].items():
        need(digest(name) == checksum, "historical compiler input provenance")
    owners = {Path(name).parent for name in value["dependency_files"]}
    need(len(owners) == 1, "one fixed dependency directory")
    actual_names = {str(path) for path in next(iter(owners)).iterdir()}
    need(actual_names == set(value["dependency_files"]), "no extra dependency archive candidates")
    for name, checksum in value["dependency_files"].items():
        need(not Path(name).is_symlink() and digest(name) == checksum, "exact archived dependency")
    for name, checksum in value["toolchain"]["files_sha256"].items():
        need(digest(name) == checksum, "exact resolved compiler/tool input")
    for row in value["artifacts"].values():
        need(digest(row["path"]) == row["sha256"], "same archived direct rlib")
    return value


def load_array(records):
    return "&[" + ",".join("FileLoad {" + ",".join(f"{key}:{value}" for key, value in row.items()) + "}" for row in records) + "]"


def request(here, inputs, argv, directory, name, bounds):
    return dict(argv=argv, cwd=str(here), env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
                "CARGO_INCREMENTAL": "0", "CARGO_MANIFEST_DIR": str(here.parents[2])},
                stdout=str(directory / (name + ".stdout")), stderr=str(directory / (name + ".stderr")), **bounds)


def bind_state(here, expected, args):
    inputs, _, _ = admitted(here, expected, args.prepared_sha256)
    cohort = emitted(here, inputs, expected, args.prepared_sha256, args.emitted_sha256)
    ci = compiler_inputs(here)
    target = here / "future-state-v1"
    target.mkdir()
    build = here / "state-build-v1"
    build.mkdir()
    records, rust = [], ["// Actual corrected E9 files; no image fabrication.\nconst FIXTURES: &[Fixture] = &[\n"]
    target_profile = (here / "state/target-profile.txt").read_text()
    page_count = 0
    for case_id, item in cohort.items():
        case, v = item["case"], item["verified"]
        original, rewritten = bytes_at(case["original"]), bytes_at(item["output"])
        geometry = v["geometry"]
        need(v["declared_hook_events"] == 0 and v["image_bytes"] == 10 and v["restored_boundary"] == v["image_pc"], "exact zero-hook passthru")
        need((geometry["original_file_pages"], geometry["rewritten_file_pages"]) == (5, 6), "separate E9 page geometry")
        page_count += 2 * 4 * (5 + 6 + 5)
        record = dict(name=case_id, original_path=case["original"]["path"], output_path=item["output"]["path"],
                      original_sha256=sha(original), output_sha256=sha(rewritten), target_profile=target_profile,
                      original_loads=geometry["original_loads"], output_loads=geometry["output_loads"],
                      body_ownership=geometry["body_ownership"],
                      min_vaddr=geometry["min_vaddr"], max_vaddr=geometry["max_vaddr"], source_page=v["ledger"]["source_page"],
                      **{key:v[key] for key in ("source_pc", "source_file_offset", "patched_source_file_offset", "image_pc", "image_file_offset", "image_bytes", "restored_boundary")})
        records.append(record)
        rust.append("Fixture {\n")
        rust.append(f"body_kind: {json.dumps(geometry['body_ownership']['kind'])},\n")
        for key in ("name", "original_path", "output_path", "original_sha256", "output_sha256", "target_profile"):
            rust.append(f"{key}: {json.dumps(record[key])},\n")
        for key in ("source_pc", "source_file_offset", "patched_source_file_offset", "source_page", "image_pc", "image_file_offset", "image_bytes", "restored_boundary", "min_vaddr", "max_vaddr"):
            rust.append(f"{key}: {record[key]},\n")
        rust.append(f"original: include_bytes!({json.dumps(record['original_path'])}),\nrewritten: include_bytes!({json.dumps(record['output_path'])}),\n")
        rust.append(f"original_loads: {load_array(record['original_loads'])},\noutput_loads: {load_array(record['output_loads'])},\n}},\n")
    need(len(records) == 6 and page_count == 768, "six actual files and complete distinct body-page inventory")
    rust.append("];\n")
    for name in ("main.rs", "quiescent_oracle.rs", "sparse_module.rs"):
        with (target / name).open("xb") as stream: stream.write((here / "state" / name).read_bytes())
    with (target / "fixtures.rs").open("x") as stream: stream.write("".join(rust))
    write_new(target / "input-inventory.json", dict(status="ACTUAL_E9_COMMON_INPUTS_STATE_PENDING", actual_emitted_files=6,
              fixtures=records, source_manifest_sha256=expected, emitted_sha256=args.emitted_sha256,
              required_traces=[48,48,48], required_points=360, expected_file_pages=768, required_hook_witnesses=0, retained_module_instances=12, reservation_roots=16, body_owned_bytes=425984, data_stack_owned_bytes=884736,
              manual_fixture_load=True, mapped_bootstrap=False, loader_admission=False, qualification_complete=False))
    arts = ci["artifacts"]
    dep_dirs = {str(Path(name).parent) for name in ci["dependency_files"]}
    need(len(dep_dirs) == 1, "one exact existing dependency archive")
    argv = [ci["toolchain"]["rustc"], "--edition=2024", "-Dwarnings", "-Ccodegen-units=1", str(target / "main.rs"),
            "-L", "dependency=" + next(iter(dep_dirs))]
    for name in ("libc", "liteinst2_artifact_draft", "sha2"):
        argv += ["--extern", name + "=" + arts[name]["path"]]
    argv += ["-o", str(build / "oracle")]
    commands = []
    for name, command, bounds in (
        ("compiler-version", [ci["toolchain"]["rustc"], "--version", "--verbose"], ci["limits"]["compiler_version"]),
        ("identity-calibrations", [inputs["python"]["path"], "-B", str(here / "entry.py"), "calibrate-state-identity", expected], ci["limits"]["identity_calibrations"]),
        ("compile", argv, ci["limits"]["compile"]),
    ):
        path = build / (name + ".request.json")
        write_new(path, request(here, inputs, command, build, name, bounds))
        commands.append(dict(id=name, request=str(path), request_sha256=digest(path), receipt=str(build / (name + ".receipt.json"))))
    need(compiler_inputs(here) == ci, "compiler inputs stable across binding")
    admitted(here, expected, args.prepared_sha256)
    write_new(target / "input-freeze.json", dict(status="ACTUAL_E9_STATE_DATA_REVIEW_REQUIRED_NO_COMPILE", source_manifest_sha256=expected,
              prepared_sha256=args.prepared_sha256, emitted_sha256=args.emitted_sha256, files=inventory(target),
              commands=commands, required_traces=[48,48,48], required_points=360, required_pages=768, required_hooks=0,
              actual_traces=0, manual_fixture_load=True, loader_admission=False, qualification_complete=False))
    print("ACTUAL_E9_STATE_DATA_REVIEW_REQUIRED_NO_COMPILE", digest(target / "input-freeze.json"), flush=True)


def frozen_state(here, expected, args):
    inputs, _, _ = admitted(here, expected, args.prepared_sha256)
    emitted(here, inputs, expected, args.prepared_sha256, args.emitted_sha256)
    target = here / "future-state-v1"
    need(digest(target / "input-freeze.json") == args.state_freeze_sha256, "actual independently reviewed state input freeze")
    freeze = read(target / "input-freeze.json")
    need(freeze["source_manifest_sha256"] == expected and freeze["prepared_sha256"] == args.prepared_sha256 and
         freeze["emitted_sha256"] == args.emitted_sha256 and freeze["actual_traces"] == 0, "same actual six artifact generation")
    need(inventory(target) == dict(freeze["files"], **{"input-freeze.json":dict(bytes=(target / "input-freeze.json").stat().st_size, sha256=args.state_freeze_sha256)}), "frozen state data tree exact")
    return inputs, freeze


def build_results(here, expected, args):
    inputs, freeze = frozen_state(here, expected, args)
    ci = compiler_inputs(here)
    receipts = {}
    need([row["id"] for row in freeze["commands"]] == ["compiler-version", "identity-calibrations", "compile"], "all fresh build commands")
    for row in freeze["commands"]:
        raw = Path(row["request"]).read_bytes()
        need(sha(raw) == row["request_sha256"], "unchanged compiler/calibration request")
        q = json.loads(raw)
        so, se = capture(Path(q["stdout"])), capture(Path(q["stderr"]))
        validate_helper_receipt(read(row["receipt"]), raw, inputs["helper"]["sha256"], so, se)
        if row["id"] == "compiler-version":
            need(sha(so) == ci["toolchain"]["prior_version_sha256"], "same exact compiler version")
        elif row["id"] == "identity-calibrations":
            need(so == (here / "expected/calibrate-state-identity.stdout").read_bytes(), "all unchanged two-positive seventeen-negative identity controls")
        else:
            need(so == b"", "compiler stdout empty")
        need(se == b"", "no compiler/calibration stderr")
        receipts[row["id"]] = dict(request_sha256=sha(raw), receipt_sha256=digest(row["receipt"]), stdout_sha256=sha(so), stderr_sha256=sha(se))
    return inputs, ci, receipts


def bind_state_run(here, expected, args):
    inputs, ci, receipts = build_results(here, expected, args)
    binary = here / "state-build-v1/oracle"
    need(binary.is_file() and not binary.is_symlink() and binary.stat().st_size > 0, "fresh compiled regular oracle")
    target = here / "state-run-v1"
    target.mkdir()
    raw = binary.read_bytes()
    need(raw[:5] == b"\x7fELF\x02", "actual ELF64 oracle")
    q = request(here, inputs, [str(binary), str(target / "captures")], target, "native", ci["limits"]["native"])
    write_new(target / "native.request.json", q)
    controls = request(here, inputs, [str(binary), "--ownership-controls"], target, "ownership-controls", dict(cpu_seconds=20, wall_seconds=30, file_bytes=1048576))
    write_new(target / "ownership-controls.request.json", controls)
    write_new(target / "binding.json", dict(status="FRESH_E9_STATE_BINARY_REVIEW_REQUIRED_NO_NATIVE", source_manifest_sha256=expected,
              state_freeze_sha256=args.state_freeze_sha256, build_receipts=receipts,
              binary=dict(path=str(binary), sha256=sha(raw), bytes=len(raw)),
              request_sha256=digest(target / "native.request.json"), ownership_controls_request_sha256=digest(target / "ownership-controls.request.json"), required_ownership_positives=2, required_ownership_negatives=18, required_traces=[48,48,48], required_points=360,
              required_pages=768, required_hooks=0, manual_fixture_load=True, loader_admission=False, qualification_complete=False))
    print("FRESH_E9_STATE_BINARY_REVIEW_REQUIRED_NO_NATIVE", digest(target / "binding.json"), flush=True)


def audit_state(here, expected, args):
    from state_audit import audit
    inputs, _, receipts = build_results(here, expected, args)
    target = here / "state-run-v1"
    need(digest(target / "binding.json") == args.binding_sha256, "reviewed fresh state binary/request")
    binding = read(target / "binding.json")
    need(binding["source_manifest_sha256"] == expected and binding["state_freeze_sha256"] == args.state_freeze_sha256 and
         binding["build_receipts"] == receipts, "same fresh build")
    need(digest(binding["binary"]["path"]) == binding["binary"]["sha256"] and
         Path(binding["binary"]["path"]).stat().st_size == binding["binary"]["bytes"], "actual fresh oracle unchanged")
    controls_raw = (target / "ownership-controls.request.json").read_bytes()
    need(sha(controls_raw) == binding["ownership_controls_request_sha256"], "same required ownership command")
    controls_q = json.loads(controls_raw)
    controls_out, controls_err = capture(Path(controls_q["stdout"])), capture(Path(controls_q["stderr"]))
    validate_helper_receipt(read(target / "ownership-controls.receipt.json"), controls_raw, inputs["helper"]["sha256"], controls_out, controls_err)
    need(controls_out == b"SPARSE_OWNERSHIP_CONTROLS_PASS positives=2 negatives=18\n" and controls_err == b"", "all native ownership positives and refusals")
    raw = (target / "native.request.json").read_bytes()
    need(sha(raw) == binding["request_sha256"], "same actual native command")
    q = json.loads(raw)
    so, se = capture(Path(q["stdout"])), capture(Path(q["stderr"]))
    validate_helper_receipt(read(target / "native.receipt.json"), raw, inputs["helper"]["sha256"], so, se)
    need(so == STATE_STDOUT and se == b"", "whole exact native completion output")
    need({path.name for path in target.iterdir()} == {"binding.json", "native.request.json", "native.stdout", "native.stderr", "native.receipt.json", "captures", "ownership-controls.request.json", "ownership-controls.receipt.json", "ownership-controls.stdout", "ownership-controls.stderr"}, "exact state-run tree before terminal audits")
    result = audit(target / "captures", here / "future-state-v1/input-inventory.json")
    admitted(here, expected, args.prepared_sha256)
    write_new(target / "capture-audit.json", result)
    write_new(target / "complete.json", dict(status="COMPLETE_SEPARATE_E9_BODY_STATE_ORACLE", source_manifest_sha256=expected,
              state_freeze_sha256=args.state_freeze_sha256, binding_sha256=args.binding_sha256,
              ownership_controls_receipt_sha256=digest(target / "ownership-controls.receipt.json"),
              native_receipt_sha256=digest(target / "native.receipt.json"), capture_audit_sha256=digest(target / "capture-audit.json"),
              totals=result["totals"], manual_fixture_load=True, loader_admission=False, qualification_complete=False))
    print("COMPLETE_SEPARATE_E9_BODY_STATE_ORACLE", digest(target / "complete.json"), flush=True)
