#!/usr/bin/env python3
"""Render private closed ELF-exec/parity records; never run a workload."""
import argparse
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import re
import stat
import sys

RECEIPT = {"request_sha256", "helper_sha256", "exit", "wall_timeout",
           "unexpected_descendants", "absence_proof", "stdout_sha256", "stderr_sha256",
           "elapsed_seconds", "cleanup_events", "cleanup_error", "aborted", "inputs_unchanged"}
NATIVE_COMPLETE = ("status\tpassed\noriginal_traces\t8\nrewritten_traces\t16\n"
    "full_state_comparisons\t72\nsubject_call_ret_witnesses\t24\n"
    "hook_call_return_witnesses\t8\nrecording_hook_rows\t4\n"
    "manual_load_mappings\t0\npost_seed_state_repairs\t0\n")
GATES = [("fmt", ["cargo", "fmt", "--check"], 180),
    ("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"], 180),
    ("test", ["cargo", "test", "--workspace"], 360),
    ("check", ["cargo", "check", "--workspace", "--all-features", "--all-targets"], 180)]

NATIVE_AUDIT_EXPECTED_SCRIPT_SHA256 = "7ad6e2e0f643eed7f4a743c1cf58673527bc7fb3725ccb3981152dfdcd1d11aa"
PARITY_RUNNER_SHA256 = "b4cd6602e2d72ceedcfaa24dfb2d6a8069d80e44c43cb003cfadf522a364bedb"
PARITY_MATERIALS_SHA256 = "eb60007d14812cca7d01d19cbc7c6b29702c7591f2347fb1ebbb33da9e780172"
DEPFILE_CONTROL_SOURCE_SHA256 = "fd5b1812162e3d9bf7341b7c4bf8995345850ce1e6ed64162b398186406876df"
DEPFILE_CONTROL_CASES = [('ACCEPT', 'relative_sources_and_parent_README'), ('ACCEPT', 'absolute_sources'), ('ACCEPT', 'escaped_space_and_backslash_owner'), ('REFUSE', 'wrong_depfile_target'), ('REFUSE', 'wrong_product_target'), ('REFUSE', 'package_escape'), ('REFUSE', 'package_leave_and_return'), ('REFUSE', 'missing_lib'), ('REFUSE', 'missing_capture_module'), ('REFUSE', 'missing_current_module'), ('REFUSE', 'unknown_source'), ('REFUSE', 'mutated_source_hash'), ('REFUSE', 'mismatched_product_dependencies'), ('REFUSE', 'missing_phony_owner'), ('REFUSE', 'duplicate_source_alias'), ('REFUSE', 'extra_product')]
ALIAS_CONTROL_SOURCE_SHA256 = "0c18802b5cceb2d3921bec1ee1bcec23f02a88583d21cbf0508f48cf39ca2295"
ALIAS_CONTROL_CASES = [('ACCEPT', 'reported_alias_exact_metadata_owner'), ('ACCEPT', 'reported_dependency_exact_metadata_owner'), ('ACCEPT', 'complete_alias_source_rule'), ('REFUSE', 'wrong_core_target'), ('REFUSE', 'foreign_metadata_directory'), ('REFUSE', 'malformed_metadata_hash'), ('REFUSE', 'duplicate_metadata'), ('REFUSE', 'missing_metadata'), ('REFUSE', 'mismatched_library_hash'), ('REFUSE', 'extra_reported_product'), ('REFUSE', 'wrong_alias_rule_target'), ('REFUSE', 'missing_alias_source'), ('REFUSE', 'extra_alias_source'), ('REFUSE', 'wrong_alias_source_owner')]
PARITY_BASE = "474094a7355c14c673f794cf34aa63d53566f030"
NATIVE_SOURCE_PINS = {'evaluation/elf-exec/reproduce.py': 'ab041ad6611d0c8000a77b70cdaaee4ef25433c94e5c9e4ff4d46b81a14b2c36', 'evaluation/elf-exec/render_selection.py': 'de1028fa9b590a6f1ba37627ac5ff78470c9f3b225eed794f7c32959c1a1c00c', 'evaluation/required-gates.py': '6d71d2a6518b8d93e136fb5fcb8170dded37e7bcfa0eae2c1fdefb1582a1fb8b', 'tools/unwind-oracle/bounded_command.py': 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44', 'tools/elf-rewrite/tests/compare_sites.py': '2ad3fcbe848154729556e3e650155c7c85390b379f0f3d4043c9ae4b380fc644', 'tests/support/elf_exec_driver.rs': 'eab2b3e0fdd0dc1c7520a2b04fa0430a93c3b1b03e62deb2266fc8b7f705b340', 'tests/support/elf_exec_oracle.rs': '22f06519dc3e6e54950c274fbbfcd1c6fb461c44732a4ead9271d6aeb045eb88', 'tests/support/quiescent_oracle.rs': 'e8c17e5daaf6e9720d6c515fd5e6f986307eca9c12ce115cdd51b465406dc756', 'tests/fixtures/elf-exec/subject.S': '6e13c95bd7cf00200b7d3d49f3fb3f4498fdd31df11084a53ccb199388577f81', 'tests/fixtures/elf-exec/subject.ld': 'c11637564a3f75ad67e66190149db2ee014e762621d7c3c834bf3eb75279ea52', 'tools/elf-rewrite/examples/verify_elf_exec.rs': 'af81840d319760a6d821f7e1d0476f559e2ee4208fa655dcd3fb46cd6ffc8eb4', 'tests/support/elf_exec_provider.rs': '9b5562034fc6bbdc32f889ab64df7f414e96ee5d9a99c06e39bf6728f128e730', 'tests/elf_exec_provider_contract.rs': '5c2dcebd4b2c845527718ddd640b757821f4a7c74c9ac56ee08666b0a38337fd'}
PARITY_MATERIAL_PINS = {'README.md': '1d28993655b662a1742c7079a25013f82181e14409202c026b8e7160002e7596', 'capture-28.rs': '1c0152b7ba94035fecd5741cab184bdcd46a3b7e78452558a3e87d2c0ea3c355', 'capture.rs': 'f8b882817789a23b1d7bf26f9c8d1bf989d3f5ddca22ed385ce1bcdb637a582b', 'chain_cases.rs': '0af5b568777cd34004eb4831678842e5bb5ec7da655380673cd8f67c12f2aae2', 'compare-28.py': 'd8206e117f08b2dd611addb0b1376c76682042035da63ac5f548c6219571afaa', 'compare-current.py': '5958310a37705f0d0e6faf2829556c2b0e461ec8c1b00d8d8cd1782e70e873e1', 'compare.py': 'b04e78cc044545c6e58d5e41b435f8376b4900de0a6f5cfb75596f429710419d', 'current_features.rs': 'fd331802e929350a8e630a7f913adf1c433dc4c98e9f10d05d6e374259ffc0e8', 'prepare.py': '3a741160be4573db5ad29f2cd5b1a3baab9ad44103d02c6473202ed79901b610'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def finite(value):
    assert type(value) in (int, float) and math.isfinite(value) and value >= 0
    return value


def main():
    assert not sys.flags.optimize, "assertions required"
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "native", "native-audit", "parity", "depfile-controls", "alias-controls", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--native-audit-sha256", required=True)
    parser.add_argument("--parents-closed-and-reaped", action="store_true", required=True,
                        help="Root confirms native, parity and both control parent sessions closed successfully and were reaped; no receipt is invented")
    args = parser.parse_args()
    repo, native, parity, controls, output = args.repo, args.native, args.parity, args.depfile_controls, args.output
    aliases = args.alias_controls
    raw_roots = (native, parity, controls, aliases)
    assert re.fullmatch("[0-9a-f]{64}", args.native_audit_sha256)
    for path in (repo, *raw_roots):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert len(set(raw_roots)) == 4 and all(p.is_relative_to(repo / "ignored") for p in raw_roots)
    assert all(not a.is_relative_to(b) for a in raw_roots for b in raw_roots if a != b)
    assert args.native_audit.is_relative_to(native)
    assert output.is_absolute() and output.parent.resolve(strict=True) == output.parent
    assert output.is_relative_to(repo / "ignored") and not output.exists() and not output.is_symlink()
    assert all(not output.is_relative_to(p) and not p.is_relative_to(output) for p in raw_roots)
    references = {}

    def read(path):
        assert any(path.is_relative_to(p) for p in raw_roots)
        assert path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode)
        data = path.read_bytes()
        digest = sha(data)
        assert references.get(str(path), digest) == digest, "saved input changed during collection"
        references[str(path)] = digest
        return data

    def js(path):
        return json.loads(read(path))

    def index(directory, expected):
        assert isinstance(expected, dict)
        for name, digest in expected.items():
            leaf = Path(name)
            assert not leaf.is_absolute() and ".." not in leaf.parts
            assert sha(read(directory / leaf)) == digest

    def receipt(directory, helper, suffix):
        request_bytes = read(directory / "request.json")
        request = json.loads(request_bytes)
        assert set(request) == {"argv", "cwd", "env", "stdout", "stderr", "cpu_seconds", "wall_seconds", "file_bytes"}
        assert request["cwd"] == str(repo)
        assert request["stdout"] == str(directory / ("stdout" + suffix))
        assert request["stderr"] == str(directory / ("stderr" + suffix))
        compiler = directory.name in ("native-compile", "codec-compile", "old-unit-compile", "new-unit-compile",
                                       "old-library", "new-library", "old-link-28", "new-link-28")
        assert (request["cpu_seconds"], request["wall_seconds"], request["file_bytes"]) == (
            60 if compiler else 20, 90 if compiler else 30, (128 if compiler else 16) * 1024 * 1024)
        assert all(type(request[k]) is int for k in ("cpu_seconds", "wall_seconds", "file_bytes"))
        value = js(directory / "receipt.json")
        assert set(value) == RECEIPT
        assert type(value["exit"]) is int and value["exit"] == 0
        assert value["wall_timeout"] is False and value["inputs_unchanged"] is True
        assert value["absence_proof"] == "ECHILD"
        assert value["unexpected_descendants"] == value["cleanup_events"] == []
        assert value["cleanup_error"] is None and value["aborted"] is None
        finite(value["elapsed_seconds"])
        assert value["request_sha256"] == sha(request_bytes) and value["helper_sha256"] == helper
        for stream in ("stdout", "stderr"):
            assert value[stream + "_sha256"] == sha(read(directory / (stream + suffix)))
        expected = dict(exit=0, wall_timeout=False, absence_proof="ECHILD", descendants=0, success=True)
        assert read(directory / "helper.stdout") == (json.dumps(expected) + "\n").encode()
        assert read(directory / "helper.stderr") == b""
        return request, value

    ns = js(native / "source.json")
    assert ns == js(native / "source-after.json")
    assert re.fullmatch("[0-9a-f]{40}", ns["revision"])
    assert all(ns["files"][name] == digest for name, digest in NATIVE_SOURCE_PINS.items())
    assert sha(read(args.native_audit)) == args.native_audit_sha256
    audit = js(args.native_audit)
    assert audit["status"] == "PASS_SAVED_RECORD_AND_INVENTORY_AUDIT"
    assert audit["source_revision"] == ns["revision"] and audit["source_files"] == len(ns["files"])
    assert audit["stages"] == 27 and audit["required_gates"] == 4 and audit["ordinary_processes"] == 6
    assert audit["capture_files"] == 1230 and audit["mapping_link_records"] == 48
    assert len(audit["provider_records"]) == 6 and len(audit["traces"]) == 24
    assert audit["recording_journal_rows"] == 4
    assert all(type(row["steps"]) is int and 0 < row["steps"] <= 20000 for row in audit["traces"])
    assert read(native / "captures/complete.tsv") == NATIVE_COMPLETE.encode()
    captures = js(native / "capture-files.json")
    assert len(captures) == 1230 and audit["captures_sha256"] == sha(read(native / "capture-files.json"))
    index(native / "captures", captures)
    nr = js(native / "results.json")
    assert len(nr) == 27 and [r["name"] for r in nr] == js(native / "stage-inventory.json")
    assert nr[0]["name"] == "required" and nr[20]["name"] == "native"
    commands = []
    for row in nr:
        name, directory = row["name"], native / row["name"]
        assert row == js(directory / "result.json")
        command = js(directory / "command.json")
        assert row == dict(command, exit=0, elapsed_seconds=row["elapsed_seconds"])
        finite(row["elapsed_seconds"])
        item = dict(scope="native", name=name, command=command, exit=0,
                    stdout_sha256=sha(read(directory / "stdout.txt")),
                    stderr_sha256=sha(read(directory / "stderr.txt")),
                    operational_parent_seconds=row["elapsed_seconds"], receipt=None)
        if name != "required":
            request, value = receipt(directory, ns["files"]["tools/unwind-oracle/bounded_command.py"], ".txt")
            assert request == row["request"]
            assert audit["helper_receipts"][name] == sha(read(directory / "receipt.json"))
            compiler = name in ("native-compile", "codec-compile")
            assert row["parent_timeout_seconds"] == (115 if compiler else 55)
            assert row["outer_argv"] == ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s",
                "100s" if compiler else "40s", "/usr/bin/python3.9", "-B", str(repo / "tools/unwind-oracle/bounded_command.py"),
                "--request", str(directory / "request.json"), "--receipt", str(directory / "receipt.json")]
            item.update(receipt=value, request=request, request_sha256=sha(read(directory / "request.json")))
        commands.append(item)
    assert len(audit["helper_receipts"]) == 26
    gates = js(native / "required/gates/commands.json")
    assert gates["head"] == ns["revision"] and gates["source_sha256"] == ns["files"]
    assert gates["tracked_diff_sha256"] == sha(b"") and len(gates["records"]) == 4
    for row, (name, argv, wall) in zip(gates["records"], GATES):
        assert (row["name"], row["argv"], row["timeout_seconds"], row["exit"]) == (name, argv, wall, 0)
        assert type(row["exit"]) is int
        assert row["sha256"] == sha(read(native / "required/gates" / (name + ".log")))
        finite(row["seconds"])
        gate_env = dict(nr[0]["env"], TMPDIR=str(native / "required/gates"))
        commands.append(dict(scope="native-required-nested", name=name, exit=0,
            command=dict(argv=argv, cwd=str(repo), env=gate_env, parent_timeout_seconds=wall),
            operational_parent_seconds=row["seconds"], receipt=None, merged_output_sha256=row["sha256"]))

    ps = js(parity / "source.json")
    final = js(parity / "complete.json")
    closure = js(parity / "final-closure.json")
    assert re.fullmatch("[0-9a-f]{40}", ps["revision"])
    assert not (parity / "failed-incomplete.json").exists() and not (parity / "failed-incomplete.json").is_symlink()
    assert ps["files"]["evaluation/emitter-parity-run.py"]["sha256"] == PARITY_RUNNER_SHA256
    assert ps["files"]["evaluation/emitter-parity/materials.json"]["sha256"] == PARITY_MATERIALS_SHA256
    assert all(ps["files"]["evaluation/emitter-parity/" + name]["sha256"] == digest
               for name, digest in PARITY_MATERIAL_PINS.items())
    assert final["old_revision"] == PARITY_BASE and final["materials_sha256"] == PARITY_MATERIALS_SHA256
    assert final["selected_tool_closure_only"] is True
    assert final["status"] == "EXACT_STATIC_PARITY" and final["candidate_revision"] == ps["revision"]
    assert final["generated_code_executed"] is False and final["native_qualification"] is False
    assert closure["revision"] == ps["revision"] and closure["source"] == ps["files"]
    assert closure["tools_and_configs"] == js(parity / "tools-and-configs.json")
    prepared = js(parity / "prepared/manifest.json")
    assert prepared["old"]["revision"] == PARITY_BASE and prepared["new"]["revision"] == ps["revision"]
    for side in ("old", "new"):
        assert prepared[side]["directory"] == str(parity / "prepared" / side)
        assert closure["prepared"][side] == prepared[side]["prepared_sha256"]
        index(parity / "prepared" / side, prepared[side]["prepared_sha256"])
    assert final["files_index_sha256"] == sha(read(parity / "files.json"))
    index(parity, js(parity / "files.json"))
    pr = final["commands"]
    stages = ["version-rustc", "version-cargo", "version-python", "version-helper-python", "prepare"]
    for side in ("old", "new"):
        stages += [side + "-" + suffix for suffix in ("unit-compile", "list", "capture-58", "capture-current", "library", "link-28", "capture-28")]
    stages += ["compare-28", "compare-58", "compare-current"]
    assert len(pr) == 22 and [r["name"] for r in pr] == js(parity / "stage-inventory.json") == stages
    for row in pr:
        name, directory = row["name"], parity / row["name"]
        assert row == js(directory / "result.json") and type(row["exit"]) is int and row["exit"] == 0
        assert row["parent_timeout"] is False
        finite(row["elapsed_seconds"])
        before = js(directory / "before.json")
        assert before == js(directory / "after.json") and before["source"] == ps["files"]
        assert before["revision"] == ps["revision"] and before["tools_and_configs"] == closure["tools_and_configs"]
        request, value = receipt(directory, ps["files"]["tools/unwind-oracle/bounded_command.py"]["sha256"], "")
        outer = js(directory / "outer.json")
        compiler = name.endswith(("unit-compile", "library", "link-28"))
        assert outer["cwd"] == str(repo) and outer["parent_timeout_seconds"] == (115 if compiler else 55)
        assert outer["env"] == dict(LC_ALL="C", PATH="/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
        assert outer["argv"] == ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s",
            "100s" if compiler else "40s", "/usr/bin/python3.9", "-B", str(repo / "tools/unwind-oracle/bounded_command.py"),
            "--request", str(directory / "request.json"), "--receipt", str(directory / "receipt.json")]
        assert row["request_sha256"] == sha(read(directory / "request.json"))
        assert row["outer_sha256"] == sha(read(directory / "outer.json"))
        commands.append(dict(scope="parity", name=name, command=dict(request=request, outer=outer),
            request=request, receipt=value, exit=0, request_sha256=row["request_sha256"],
            operational_parent_seconds=row["elapsed_seconds"]))
    scope = js(parity / "configuration-observation-scope.json")
    assert final["configuration_observation_scope_sha256"] == sha(read(parity / "configuration-observation-scope.json"))
    assert final["denied_configuration_paths"] == scope["denied_lookup_paths"]
    assert scope["denied_means_absent"] is scope["denied_contents_observed"] is False
    assert scope["denied_lookup_paths"] == sorted(path for path in scope["lookup_paths"]
        if closure["tools_and_configs"][path].get("observation") == "READ_DENIED")
    assert final["actual_cargo_config_consumption_attested"] is scope["actual_cargo_consumption_attested"] is False
    comparisons = final["comparisons"]
    for key in ("28", "58", "current"):
        assert comparisons[key] == js(parity / ("compare-" + key) / "stdout")
    a, b, c = (comparisons[key] for key in ("28", "58", "current"))
    assert a["old_head"] == final["old_revision"] and a["current_head"] == ps["revision"]
    assert len(a["fixtures"]) == 28 and a["callback_operands"] == 33 and a["all_non_callback_bytes_and_metadata_equal"] is True
    assert (b["status"], b["fixtures"], b["successes"], b["refusals"], len(b["images"]), b["authenticated_operands"]) == ("EXACT_STATIC_PARITY", 58, 48, 10, 56, 138)
    assert (c["status"], c["cases"], len(c["images"]), c["independent_refusals"], c["callback_operands"], c["dispatcher_operands"], c["control_operands"]) == ("EXACT_CURRENT_FEATURE_STATIC_PARITY", 21, 34, 2, 17, 3, 3)
    assert b["generated_code_executed"] is c["generated_code_executed"] is False
    assert c["preparation_sha256"] == sha(read(parity / "prepared/manifest.json"))
    for key, compared, count in (("58", b, 400), ("current", c, 219)):
        for side in ("old", "new"):
            outputs = compared[side + "_output_sha256"]
            assert len(outputs) == count
            assert outputs == js(parity / (side + "-capture-" + key) / "output-files.json")
            index(parity / (side + "-" + key), outputs)
    old28 = js(parity / "old-28-manifest.json")
    assert a["old_manifest_sha256"] == sha(read(parity / "old-28-manifest.json"))
    for outputs, side in ((old28["output_sha256"], "old"), (a["new_output_sha256"], "new")):
        expected = js(parity / (side + "-capture-28") / "output-files.json")
        assert len(expected) == len(outputs) == 114
        assert outputs == {str(parity / (side + "-28") / name): digest for name, digest in expected.items()}
        index(parity / (side + "-28"), expected)
    parity_rows = [dict(inventory="historical", fixtures=28, images=28, capture_files_per_side=114, callbacks=33, dispatchers=0, controls=0, authenticated_operands=33, planning_refusals=0, frame_metadata_successes=None, frame_metadata_refusals=None, independent_refusals=0),
        dict(inventory="extended", fixtures=58, images=56, capture_files_per_side=400, callbacks=30, dispatchers=54, controls=54, authenticated_operands=138, planning_refusals=10, frame_metadata_successes=None, frame_metadata_refusals=None, independent_refusals=0),
        dict(inventory="current", fixtures=21, images=34, capture_files_per_side=219, callbacks=17, dispatchers=3, controls=3, authenticated_operands=23, planning_refusals=0, frame_metadata_successes=12, frame_metadata_refusals=5, independent_refusals=2)]
    inventory_records = {"historical": a["fixtures"]}
    for key, expected in (("58", 58), ("current", 21)):
        data = read(parity / ("old-" + key) / "fixtures.tsv")
        assert data == read(parity / ("new-" + key) / "fixtures.tsv")
        rows = list(csv.DictReader(io.StringIO(data.decode()), delimiter="\t"))
        assert len(rows) == expected and len({r["fixture"] for r in rows}) == expected
        inventory_records["extended" if key == "58" else "current"] = rows

    cs = js(controls / "source.json")
    assert cs == js(controls / "source-after.json") and re.fullmatch("[0-9a-f]{40}", cs["revision"])
    assert cs["files"] == {"evaluation/emitter-parity-run.py": PARITY_RUNNER_SHA256,
        "evaluation/emitter-parity-depfile-controls.py": DEPFILE_CONTROL_SOURCE_SHA256,
        "tools/unwind-oracle/bounded_command.py": NATIVE_SOURCE_PINS["tools/unwind-oracle/bounded_command.py"]}
    control_request, control_receipt = receipt(controls, cs["files"]["tools/unwind-oracle/bounded_command.py"], "")
    assert control_request["argv"] == ["/usr/local/bin/python3", "-B", str(repo / "evaluation/emitter-parity-depfile-controls.py")]
    runtime_env = dict(LC_ALL="C", PATH="/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
    assert control_request["env"] == dict(runtime_env, TMPDIR=str(controls / "tmp"))
    control_outer = js(controls / "outer.json")
    assert control_outer == dict(argv=["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s", "40s",
        "/usr/bin/python3.9", "-B", str(repo / "tools/unwind-oracle/bounded_command.py"),
        "--request", str(controls / "request.json"), "--receipt", str(controls / "receipt.json")],
        cwd=str(repo), env=runtime_env, parent_timeout_seconds=55)
    parent = js(controls / "parent.json")
    assert set(parent) == {"exit", "parent_timeout", "seconds"}
    assert type(parent["exit"]) is int and parent["exit"] == 0 and parent["parent_timeout"] is False
    finite(parent["seconds"])
    expected = "".join(status + " " + name + "\n" for status, name in DEPFILE_CONTROL_CASES)
    expected += "PASS depfile owner controls: 3 accepted, 13 refused; no workload\n"
    assert read(controls / "stdout") == expected.encode() and read(controls / "stderr") == b""
    control_review = js(controls / "review-core-v1/binding.json")
    assert control_review["verdict"] == "CLOSED_PURE_CONTROLS_PASS_EXECUTION_RECORD_SCOPE"
    assert control_review["revision"] == cs["revision"]
    assert control_review["receipt_sha256"] == sha(read(controls / "receipt.json"))
    assert control_review["native_credit"] is control_review["static_parity_credit"] is False
    index(controls / "review-core-v1", control_review["files"])
    commands.append(dict(scope="depfile-controls", name="depfile-owner-controls", exit=0,
        command=dict(request=control_request, outer=control_outer), request=control_request,
        request_sha256=sha(read(controls / "request.json")), receipt=control_receipt,
        operational_parent_seconds=parent["seconds"]))
    als = js(aliases / "source.json")
    assert als == js(aliases / "source-after.json") and re.fullmatch("[0-9a-f]{40}", als["revision"])
    assert als["files"] == {"evaluation/emitter-parity-run.py": PARITY_RUNNER_SHA256,
        "evaluation/emitter-parity-library-controls.py": ALIAS_CONTROL_SOURCE_SHA256,
        "tools/unwind-oracle/bounded_command.py": NATIVE_SOURCE_PINS["tools/unwind-oracle/bounded_command.py"]}
    alias_request, alias_receipt = receipt(aliases, als["files"]["tools/unwind-oracle/bounded_command.py"], "")
    assert alias_request["argv"] == ["/usr/local/bin/python3", "-B", str(repo / "evaluation/emitter-parity-library-controls.py")]
    runtime_env = dict(LC_ALL="C", PATH="/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
    assert alias_request["env"] == dict(runtime_env, TMPDIR=str(aliases / "tmp"))
    alias_outer = js(aliases / "outer.json")
    assert alias_outer == dict(argv=["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s", "40s",
        "/usr/bin/python3.9", "-B", str(repo / "tools/unwind-oracle/bounded_command.py"),
        "--request", str(aliases / "request.json"), "--receipt", str(aliases / "receipt.json")],
        cwd=str(repo), env=runtime_env, parent_timeout_seconds=55)
    alias_parent = js(aliases / "parent.json")
    assert set(alias_parent) == {"exit", "parent_timeout", "seconds"}
    assert type(alias_parent["exit"]) is int and alias_parent["exit"] == 0 and alias_parent["parent_timeout"] is False
    finite(alias_parent["seconds"])
    alias_expected = "".join(status + " " + name + "\n" for status, name in ALIAS_CONTROL_CASES)
    alias_expected += "PASS library alias controls: 3 accepted, 11 refused; no workload\n"
    assert read(aliases / "stdout") == alias_expected.encode() and read(aliases / "stderr") == b""
    alias_review = js(aliases / "review-core-v1/binding.json")
    assert alias_review["verdict"] == "CLOSED_PURE_CONTROLS_PASS_EXECUTION_RECORD_SCOPE"
    assert alias_review["revision"] == als["revision"]
    assert alias_review["receipt_sha256"] == sha(read(aliases / "receipt.json"))
    assert alias_review["native_credit"] is alias_review["static_parity_credit"] is False
    index(aliases / "review-core-v1", alias_review["files"])
    commands.append(dict(scope="library-alias-controls", name="library-alias-owner-controls", exit=0,
        command=dict(request=alias_request, outer=alias_outer), request=alias_request,
        request_sha256=sha(read(aliases / "request.json")), receipt=alias_receipt,
        operational_parent_seconds=alias_parent["seconds"]))
    def control_tools(raw, request, outer):
        value = js(raw / "tools.json")
        assert value == js(raw / "tools-after.json")
        assert set(value) == {"python", "helper_python", "timeout"}
        expected_paths = {"python": request["argv"][0], "helper_python": outer["argv"][4],
                          "timeout": outer["argv"][0]}
        for name, row in value.items():
            assert set(row) == {"path", "resolved", "sha256"}
            assert row["path"] == expected_paths[name]
            assert isinstance(row["resolved"], str) and Path(row["resolved"]).is_absolute()
            assert re.fullmatch("[0-9a-f]{64}", row["sha256"])
        return value

    ctools = control_tools(controls, control_request, control_outer)
    atools = control_tools(aliases, alias_request, alias_outer)
    assert len(commands) == 55

    artifact_rows = []
    before = js(native / "candidate-files-before.json")
    assert before == js(native / "candidate-files-after.json")
    for strip_state in ("unstripped", "stripped"):
        original = read(native / "subjects" / ("original-" + strip_state))
        for hook in ("null", "journal"):
            name = strip_state + "-" + hook
            directory = native / (name + "-candidate")
            index(directory, before[name])
            candidate, image = read(directory / "candidate.elf"), read(directory / "image-0000.bin")
            assert len(candidate) > len(original)
            ledger = read(directory / "ledger.tsv").decode().splitlines()
            assert "qualification_complete\tfalse" in ledger and "execution_authority\tnone" in ledger
            changed, source_changed, source_spans, edits = set(), set(), 0, []
            for line in ledger:
                fields = line.split("\t")
                if fields[0] != "elf-change":
                    continue
                assert len(fields) == 5 and fields[1] in ("ProgramHeaderOffset", "ProgramHeaderCount", "DeclaredSource")
                offset, left, right = int(fields[2]), bytes.fromhex(fields[3]), bytes.fromhex(fields[4])
                assert left and len(left) == len(right)
                assert original[offset:offset + len(left)] == left and candidate[offset:offset + len(right)] == right
                actual = {offset + n for n, pair in enumerate(zip(left, right)) if pair[0] != pair[1]}
                assert not changed.intersection(actual)
                changed.update(actual)
                if fields[1] == "DeclaredSource":
                    source_spans += len(left)
                    source_changed.update(actual)
                edits.append(dict(kind=fields[1], file_offset=offset, original_hex=left.hex(), emitted_hex=right.hex()))
            assert changed == {n for n, pair in enumerate(zip(original, candidate)) if pair[0] != pair[1]}
            artifact_rows.append(dict(candidate=name, original_bytes=len(original), candidate_bytes=len(candidate),
                growth_bytes=len(candidate) - len(original), generated_image_bytes=len(image),
                source_edit_span_bytes=source_spans, changed_source_bytes=len(source_changed),
                original_sha256=sha(original), candidate_sha256=sha(candidate), image_sha256=sha(image),
                artifact_qualification_complete=False, edits=edits))

    roles = {"${NATIVE_RAW}": str(native), "${PARITY_RAW}": str(parity), "${CONTROLS_RAW}": str(controls), "${ALIAS_CONTROLS_RAW}": str(aliases), "${REPO}": str(repo)}
    for prefix, env in (("NATIVE", nr[0]["env"]), ("PARITY", js(parity / "old-unit-compile/request.json")["env"])):
        for role, value in (("TOOLCHAIN", str(Path(env["RUSTC"]).parent.parent)), ("USER_HOME", env["HOME"]), ("CARGO_HOME", env["CARGO_HOME"])):
            roles["${" + prefix + "_" + role + "}"] = value
    for number, path in enumerate(scope["lookup_paths"]):
        roles["${CONFIG_LOOKUP_" + str(number) + "}"] = path
    for prefix, values in (("DEPFILE_CONTROL", ctools), ("ALIAS_CONTROL", atools)):
        for name, row in values.items():
            for field in ("path", "resolved"):
                roles["${" + prefix + "_" + name.upper() + "_" + field.upper() + "}"] = row[field]
    # Longest owner first, one substitution pass. Equal owners share the first role.
    inverse = {}
    for role, value in roles.items():
        inverse.setdefault(value, role)
    pattern = re.compile("|".join(re.escape(s) for s in sorted(inverse, key=len, reverse=True)))
    tokens = re.compile("|".join(re.escape(s) for s in roles))

    def clean(value):
        if isinstance(value, str):
            assert not tokens.search(value), "literal role collision requires explicit review"
            result = pattern.sub(lambda match: inverse[match[0]], value)
            assert tokens.sub(lambda match: roles[match[0]], result) == value
            return result
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, dict):
            return {clean(k): clean(v) for k, v in value.items()}
        return value

    def hardware(raw):
        value = js(raw / "hardware.json")
        assert set(value) == {"cpu_model", "architecture", "logical_cpus", "kernel_release", "libc"}
        assert "AMD EPYC" in value["cpu_model"] and value["architecture"] == "x86_64"
        return dict(value, host_label="AMD EPYC Zen 5 dev host", observation_scope="Saved run observation; no continuous hardware attestation or benchmark")

    summary = dict(schema=1, collector_source_sha256=sha(Path(__file__).read_bytes()),
        authority="Closed saved-record audit plus original strict receipts; root separately confirmed successful parent termination/reaping",
        native_revision=ns["revision"], parity_revision=ps["revision"], same_revision=ns["revision"] == ps["revision"],
        native_source_sha256=sha(read(native / "source.json")), parity_source_sha256=sha(read(parity / "source.json")),
        native_audit_sha256=args.native_audit_sha256,
        native_audit_expected_script_sha256=NATIVE_AUDIT_EXPECTED_SCRIPT_SHA256,
        native_audit_producer_authority="Root separately pins the v5 script invocation; audit output alone does not identify its producer",
        parity_complete_sha256=sha(read(parity / "complete.json")),
        hardware=dict(native=hardware(native), parity=hardware(parity)),
        native=dict(recipe_stages=27, nested_required_gates=4, helper_receipts=26, original_traces=8, rewritten_traces=16,
                    full_state_comparisons=72, subject_call_ret=24, hook_call_ret=8, journal_rows=4, captures=1230,
                    ordinary_processes=6, manual_load_mappings=0, post_seed_state_repairs=0,
                    trace_step_limit=20000, trace_deadline_seconds=15,
                    state_authority=audit["architectural_state_authority"],
                    trace_records=[{k: row[k] for k in ("name", "files", "steps", "recording_rows", "mapping_link_rows")}
                                   for row in audit["traces"]]),
        parity=dict(stages=22, helper_receipts=22, baseline_revision=final["old_revision"], inventories=parity_rows,
                    exact_fixture_records=inventory_records,
                    generated_code_executed=False, configuration_observation_scope=scope),
        depfile_controls=dict(revision=cs["revision"], selected_source=cs["files"],
            source_sha256=sha(read(controls / "source.json")), accepted=3, refused=13,
            cases=[dict(name=name, expected=status, observed=status) for status, name in DEPFILE_CONTROL_CASES],
            review_binding_sha256=sha(read(controls / "review-core-v1/binding.json")),
            hardware_observation=hardware(controls), selected_tool_observations=ctools,
            tool_observation_scope="Saved before/after path, resolved owner and whole-byte hash; no version command inferred",
            native_credit=False, static_parity_credit=False),
        alias_controls=dict(revision=als["revision"], selected_source=als["files"],
            source_sha256=sha(read(aliases / "source.json")), accepted=3, refused=11,
            cases=[dict(name=name, expected=status, observed=status) for status, name in ALIAS_CONTROL_CASES],
            review_binding_sha256=sha(read(aliases / "review-core-v1/binding.json")),
            hardware_observation=hardware(aliases), selected_tool_observations=atools,
            tool_observation_scope="Saved before/after path, resolved owner and whole-byte hash; no version command inferred",
            native_credit=False, static_parity_credit=False),
        native_tool_version_observations=js(native / "tools.json"),
        timing_scope="Operational elapsed durations, not benchmark results; nested rows overlap parent durations",
        artifact_qualification_complete=False, full_A3_complete=False,
        prior_failures="Not relabelled by this success-only collector; publish prior stopped/failed attempts separately")
    public = {"summary.json": clean(summary), "commands.json": clean(commands), "native-artifacts.json": artifact_rows}
    public_text = {n: json.dumps(value, indent=2, sort_keys=True) + "\n" for n, value in public.items()}
    command_rows = []
    for row in commands:
        request = row.get("request")
        command_rows.append(dict(scope=row["scope"], name=row["name"], exit=row["exit"],
            operational_parent_seconds=row["operational_parent_seconds"],
            operational_child_seconds=None if row["receipt"] is None else row["receipt"]["elapsed_seconds"],
            cpu_seconds=None if request is None else request["cpu_seconds"],
            wall_seconds=None if request is None else request["wall_seconds"],
            file_bytes=None if request is None else request["file_bytes"],
            parent_timeout_seconds=(row["command"]["outer"]["parent_timeout_seconds"] if row["scope"] in ("parity", "depfile-controls", "library-alias-controls")
                                    else row["command"]["parent_timeout_seconds"]),
            receipt_present=row["receipt"] is not None))
    for name, rows in (("commands.csv", command_rows), ("parity.csv", parity_rows),
                       ("native-artifacts.csv", [{k: v for k, v in row.items() if k != "edits"} for row in artifact_rows])):
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        public_text[name] = stream.getvalue()
    public_text["README.md"] = ("# Closed ELF frontend observations\n\n"
        "The native and static-parity source revisions are recorded separately in summary.json. "
        "The fixed ET_EXEC native fixture has 8 original and 16 rewritten traces, 72 full-state driver assertions, "
        "24 subject CALL/RET witnesses, 8 hook CALL/RET witnesses and 4 exact journal rows; six ordinary executions are separate. "
        "The saved-record audit authenticates the 1,230-file inventory and ownership records; it is not a replacement state comparator.\n\n"
        "Parity retains three distinct inventories; required refusals and frame-metadata refusals remain distinct from accepted images. "
        "The separate depfile controls contain three accepted cases and thirteen required refusals; library-alias controls contain three accepted cases and eleven required refusals. Each has its own source revision, strict receipt and saved tool/hardware observations; neither adds parity or native credit. "
        "No generated image executes in parity. Configuration-denial observations do not establish absent files, content continuity or actual Cargo consumption.\n\n"
        "Commands and decoded environments use reversible directory roles: NATIVE_RAW, PARITY_RAW, CONTROLS_RAW and ALIAS_CONTROLS_RAW are the four separate saved-run roots; "
        "REPO is the tested checkout owner; each NATIVE/PARITY TOOLCHAIN, USER_HOME and CARGO_HOME names its corresponding recorded owner; "
        "CONFIG_LOOKUP_n denotes a complete historical configuration lookup path, including explicit denied observations. "
        "DEPFILE_CONTROL/ALIAS_CONTROL tool PATH and RESOLVED roles name each selected tool lookup and resolved owner. Equal owners share the first role. Exact raw request and stream hashes remain in the records; "
        "raw logs, captures, binaries and the coordinate inverse remain private. Five native tool-version observations have no invented helper receipt or elapsed time. "
        "Nested required-gate durations overlap their parent, and all durations are operational observations, not benchmarks.\n\n"
        "Artifact qualification remains false. This fixed native slice and static parity do not establish full A3, arbitrary-program, PIE/DSO, CET or unwind coverage. "
        "Earlier failures remain separate; neither a new publication revision nor a different run inherits these results.\n")
    for value in public_text.values():
        assert not re.search(r"/home/|/Users/|(?:facebook|fb|meta)\.com|\.internal\b", value)
    # Recheck every saved input without importing or running any producer.
    for name, expected in list(references.items()):
        assert sha(read(Path(name))) == expected
    # All validation precedes exclusive output creation. No input or active source is written.
    output.mkdir()
    (output / "public").mkdir()
    for name, value in public_text.items():
        with (output / "public" / name).open("x") as stream:
            stream.write(value)
    private = dict(coordinate_roles=roles, input_sha256=references,
                   parents_closed_and_reaped_confirmation=True, no_parent_receipt_invented=True)
    with (output / "private-binding.json").open("x") as stream:
        json.dump(private, stream, indent=2, sort_keys=True)
        stream.write("\n")
    with (output / "public/files.json").open("x") as stream:
        json.dump({name: sha(value.encode()) for name, value in public_text.items()}, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
