#!/usr/bin/env python3
"""Render separately closed B1 and four-tactic records; never execute a producer."""
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

READ_LIMIT = 128 * 1024 * 1024
# Frozen audit v4; its exclusive output coordinate intentionally remains v1.
AUDIT_SCRIPT_SHA256 = "15701346bc05e7e423b6df478ec16664367771b10f7d9a36e29708120c74c369"
AUDIT_SOURCE_PINS_SHA256 = "2c6d667264f9ae1822397e4ea85740989101f0f44424beba88c9858438f24cab"
AUDIT_FIXTURE_SHA256 = "622db2cca51521b2e088e0003a28c164175fd249e03c0f72d2b6f65bc2f84aec"
RECIPE_SHA256 = "c586e7df93f69031f947bbdadfa5df1de7c12b8fb1dfc13387f5f0f6bbf912ec"
B1_RECIPE_SHA256 = "ab041ad6611d0c8000a77b70cdaaee4ef25433c94e5c9e4ff4d46b81a14b2c36"
HELPER_SHA256 = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
RECEIPT = {"request_sha256", "helper_sha256", "exit", "wall_timeout",
           "unexpected_descendants", "absence_proof", "stdout_sha256", "stderr_sha256",
           "elapsed_seconds", "cleanup_events", "cleanup_error", "aborted", "inputs_unchanged"}
GATES = [("fmt", ["cargo", "fmt", "--check"], 180),
         ("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"], 180),
         ("test", ["cargo", "test", "--workspace"], 360),
         ("check", ["cargo", "check", "--workspace", "--all-features", "--all-targets"], 180)]
FAMILIES = {
    "B2": dict(heads=[0, 3, 8], original_traces=12, rewritten_traces=24, comparisons=120, images=1, refusal_cases=4),
    "T1": dict(heads=[0, 2, 7], original_traces=12, rewritten_traces=24, comparisons=120, images=1, refusal_cases=4),
    "T2": dict(heads=[0, 3, 11, 16, 64, 74], original_traces=24, rewritten_traces=48, comparisons=248, images=2, refusal_cases=5),
    "T3": dict(heads=[0, 2, 3, 64, 74], original_traces=20, rewritten_traces=40, comparisons=188, images=2, refusal_cases=5),
}
RUNTIME_ENV = dict(LC_ALL="C", PATH="/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def finite(value):
    assert type(value) in (int, float) and math.isfinite(value) and value >= 0
    return value


def inventory(tactics):
    if tactics:
        names = ["codec-compile"]
        for family in FAMILIES:
            names += [prefix + family for prefix in ("assemble-", "link-", "strip-")]
            for stripped in ("unstripped", "stripped"):
                for hook in ("null", "journal"):
                    names += [prefix + family + "-" + stripped + "-" + hook
                              for prefix in ("select-", "prepare-", "verify-")]
            names += ["controls-" + family, "native-" + family]
            names += ["ordinary-" + family + "-" + name for name in
                      ("original-unstripped", "original-stripped", "candidate-0", "candidate-1", "candidate-2", "candidate-3")]
        assert len(names) == 93
    else:
        names = ["required", "comparison", "native-compile", "codec-compile", "target", "assemble", "link", "strip"]
        for stripped in ("unstripped", "stripped"):
            for hook in ("null", "journal"):
                names += [prefix + stripped + "-" + hook for prefix in ("select-", "prepare-", "verify-")]
        names += ["native", "ordinary-original-unstripped", "ordinary-original-stripped"]
        names += ["ordinary-candidate-" + str(i) for i in range(4)]
        assert len(names) == 27
    assert len(set(names)) == len(names)
    return names


def main():
    assert not sys.flags.optimize, "assertions required"
    for pin in (AUDIT_SCRIPT_SHA256, AUDIT_SOURCE_PINS_SHA256, AUDIT_FIXTURE_SHA256):
        assert isinstance(pin, str) and re.fullmatch("[0-9a-f]{64}", pin)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "tactics", "b1", "audit", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--audit-sha256", required=True)
    parser.add_argument("--parents-closed-and-reaped", action="store_true", required=True,
                        help="Root separately observed successful B1, tactics and audit parent closure/reaping; no parent receipt is invented")
    args = parser.parse_args()
    repo, tactics, b1, output = args.repo, args.tactics, args.b1, args.output
    assert re.fullmatch("[0-9a-f]{64}", args.audit_sha256)
    for path in (repo, tactics, b1):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    roots = (tactics, b1)
    assert tactics != b1 and all(p.is_relative_to(repo / "ignored") for p in roots)
    assert all(not a.is_relative_to(b) for a in roots for b in roots if a != b)
    assert args.audit == tactics / "runtime-audit-tactics-v1/audit.json"
    assert output.is_absolute() and output.parent.resolve(strict=True) == output.parent
    assert output.is_relative_to(repo / "ignored") and not output.exists() and not output.is_symlink()
    assert all(not output.is_relative_to(p) and not p.is_relative_to(output) for p in roots)
    references = {}

    def read(path):
        assert any(path.is_relative_to(p) for p in roots)
        assert path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode)
        assert path.stat().st_size <= READ_LIMIT
        with path.open("rb") as stream:
            data = stream.read(READ_LIMIT + 1)
        assert len(data) <= READ_LIMIT
        digest = sha(data)
        assert references.get(str(path), digest) == digest, "saved input changed during collection"
        references[str(path)] = digest
        return data

    def js(path):
        return json.loads(read(path))

    def index(directory, values):
        assert isinstance(values, dict)
        for name, digest in values.items():
            relative = Path(name)
            assert not relative.is_absolute() and ".." not in relative.parts
            assert re.fullmatch("[0-9a-f]{64}", digest)
            assert sha(read(directory / relative)) == digest

    source = js(tactics / "source.json")
    assert source == js(tactics / "source-after.json") == js(b1 / "source.json") == js(b1 / "source-after.json")
    assert set(source) == {"revision", "files"} and re.fullmatch("[0-9a-f]{40}", source["revision"])
    assert source["files"]["evaluation/elf-exec/reproduce_tactics.py"] == RECIPE_SHA256
    assert source["files"]["evaluation/elf-exec/reproduce.py"] == B1_RECIPE_SHA256
    assert source["files"]["tools/unwind-oracle/bounded_command.py"] == HELPER_SHA256
    for name, digest in source["files"].items():
        assert not Path(name).is_absolute() and ".." not in Path(name).parts
        assert re.fullmatch("[0-9a-f]{64}", digest)
    assert sha(read(args.audit)) == args.audit_sha256
    audit = js(args.audit)
    assert audit["schema"] == 1 and audit["status"] == "PASS_SAVED_CAPTURE_COMPARISON"
    assert audit["source_revision"] == source["revision"] and audit["source_files"] == source["files"]
    assert audit["source_sha256"] == sha(read(tactics / "source.json"))
    assert audit["audit_source_sha256"] == AUDIT_SCRIPT_SHA256
    assert audit["source_pins_sha256"] == AUDIT_SOURCE_PINS_SHA256
    assert audit["fixture_contract_sha256"] == AUDIT_FIXTURE_SHA256
    assert audit["qualification_complete"] is False
    assert audit["limits"] == dict(whole_child_steps=20000, whole_child_seconds=15)
    assert audit["stages"] == 93
    prerequisite = js(tactics / "b1-prerequisite-inputs.json")
    assert prerequisite == js(tactics / "b1-prerequisite-inputs-after.json")
    assert audit["b1_prerequisite_inputs_sha256"] == sha(read(tactics / "b1-prerequisite-inputs.json"))
    for name, digest in prerequisite.items():
        assert Path(name).is_relative_to(b1) and sha(read(Path(name))) == digest

    commands, receipt_hashes, request_documents = [], {}, []
    results_by_scope = {}
    for scope, root, is_tactics in (("b1-prerequisite", b1, False), ("tactics", tactics, True)):
        results = js(root / "results.json")
        assert [r["name"] for r in results] == js(root / "stage-inventory.json") == inventory(is_tactics)
        results_by_scope[scope] = results
        for row in results:
            name, directory = row["name"], root / row["name"]
            command = js(directory / "command.json")
            assert row == js(directory / "result.json") == dict(command, exit=0, elapsed_seconds=row["elapsed_seconds"])
            assert command["cwd"] == str(repo)
            assert type(row["exit"]) is int and row["exit"] == 0
            finite(row["elapsed_seconds"])
            item = dict(scope=scope, name=name, command=command, result=row, receipt=None,
                        command_sha256=sha(read(directory / "command.json")), result_sha256=sha(read(directory / "result.json")),
                        stdout_sha256=sha(read(directory / "stdout.txt")), stderr_sha256=sha(read(directory / "stderr.txt")),
                        operational_parent_seconds=row["elapsed_seconds"])
            if name == "required":
                assert scope == "b1-prerequisite" and command["parent_timeout_seconds"] == 1000
                assert command["argv"] == ["/usr/bin/python3.9", "-B", str(repo / "evaluation/required-gates.py"),
                                           "--repo", str(repo), "--output", str(b1 / "required/gates")]
                assert command["outer_argv"] == command["argv"] and command["outer_env"] == command["env"]
            else:
                request_bytes = read(directory / "request.json")
                request, receipt = json.loads(request_bytes), js(directory / "receipt.json")
                assert set(request) == {"argv", "cwd", "env", "stdout", "stderr", "cpu_seconds", "wall_seconds", "file_bytes"}
                assert request == row["request"]
                assert (request["argv"], request["cwd"], request["env"]) == (command["argv"], str(repo), command["env"])
                assert request["stdout"] == str(directory / "stdout.txt") and request["stderr"] == str(directory / "stderr.txt")
                compiler = name in ("codec-compile", "native-compile")
                assert all(type(request[k]) is int for k in ("cpu_seconds", "wall_seconds", "file_bytes"))
                assert (request["cpu_seconds"], request["wall_seconds"], request["file_bytes"]) == (
                    60 if compiler else 20, 90 if compiler else 30, (128 if compiler else 16) * 1024 * 1024)
                assert command["parent_timeout_seconds"] == (115 if compiler else 55)
                assert command["outer_argv"] == ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s",
                    "100s" if compiler else "40s", "/usr/bin/python3.9", "-B", str(repo / "tools/unwind-oracle/bounded_command.py"),
                    "--request", str(directory / "request.json"), "--receipt", str(directory / "receipt.json")]
                assert command["outer_env"] == RUNTIME_ENV
                assert set(receipt) == RECEIPT and type(receipt["exit"]) is int and receipt["exit"] == 0
                assert receipt["wall_timeout"] is False and receipt["inputs_unchanged"] is True
                assert receipt["absence_proof"] == "ECHILD" and receipt["unexpected_descendants"] == receipt["cleanup_events"] == []
                assert receipt["cleanup_error"] is None and receipt["aborted"] is None
                finite(receipt["elapsed_seconds"])
                assert receipt["request_sha256"] == sha(request_bytes) and receipt["helper_sha256"] == HELPER_SHA256
                assert all(receipt[s + "_sha256"] == item[s + "_sha256"] for s in ("stdout", "stderr"))
                expected = dict(exit=0, wall_timeout=False, absence_proof="ECHILD", descendants=0, success=True)
                assert read(directory / "helper.stdout") == (json.dumps(expected) + "\n").encode()
                assert read(directory / "helper.stderr") == b""
                receipt_digest = sha(read(directory / "receipt.json"))
                if is_tactics:
                    receipt_hashes[name] = receipt_digest
                item.update(request=request, request_sha256=sha(request_bytes), receipt=receipt, receipt_sha256=receipt_digest)
                request_documents.append(dict(scope=scope, name=name, path=str(directory / "request.json"), sha256=sha(request_bytes)))
            commands.append(item)
    assert receipt_hashes == audit["helper_receipts"] and len(receipt_hashes) == 93
    gates = js(b1 / "required/gates/commands.json")
    assert gates["head"] == source["revision"] and gates["source_sha256"] == source["files"]
    assert gates["tracked_diff_sha256"] == sha(b"") and len(gates["records"]) == 4
    for row, (name, argv, wall) in zip(gates["records"], GATES):
        assert (row["name"], row["argv"], row["timeout_seconds"], row["exit"]) == (name, argv, wall, 0)
        assert type(row["exit"]) is int and row["sha256"] == sha(read(b1 / "required/gates" / (name + ".log")))
        finite(row["seconds"])
        gate_env = dict(results_by_scope["b1-prerequisite"][0]["env"], TMPDIR=str(b1 / "required/gates"))
        commands.append(dict(scope="b1-required-nested", name=name, receipt=None, result=row,
            command=dict(argv=argv, cwd=str(repo), env=gate_env, parent_timeout_seconds=wall),
            operational_parent_seconds=row["seconds"], merged_output_sha256=row["sha256"]))
    assert len(commands) == 124

    b1_captures = js(b1 / "capture-files.json")
    assert len(b1_captures) == 1230
    index(b1 / "captures", b1_captures)
    b1_complete = ("status\tpassed\noriginal_traces\t8\nrewritten_traces\t16\nfull_state_comparisons\t72\n"
        "subject_call_ret_witnesses\t24\nhook_call_return_witnesses\t8\nrecording_hook_rows\t4\n"
        "manual_load_mappings\t0\npost_seed_state_repairs\t0\n")
    assert read(b1 / "captures/complete.tsv") == b1_complete.encode()
    assert js(b1 / "candidate-files-before.json") == js(b1 / "candidate-files-after.json")
    for root in roots:
        for name, value in js(root / "artifacts.json").items():
            assert sha(read(root / "artifacts" / name)) == value["sha256"]

    artifact_rows, family_rows, refusal_rows = [], [], []
    summaries = js(tactics / "summary.json")
    assert set(summaries) == set(FAMILIES) == set(audit["families"])
    for family, fixed in FAMILIES.items():
        observed, checked = summaries[family], audit["families"][family]
        captures = js(tactics / ("capture-files-" + family + ".json"))
        index(tactics / ("captures-" + family), captures)
        assert checked["captures_sha256"] == sha(read(tactics / ("capture-files-" + family + ".json")))
        assert checked["captures_count"] == observed["capture_files"] == len(captures)
        assert checked["capture_inventory_sha256"] == sha(read(tactics / ("expected-captures-" + family + ".tsv")))
        assert read(tactics / ("expected-captures-" + family + ".tsv")) == read(tactics / ("captures-" + family) / "capture-inventory.tsv")
        expected = dict(original_traces=fixed["original_traces"], rewritten_traces=fixed["rewritten_traces"],
                        comparisons=fixed["comparisons"], capture_files=len(captures), ordinary_processes=6, qualification_complete=False)
        assert observed == expected
        assert checked["original_traces"] == fixed["original_traces"] and checked["rewritten_traces"] == fixed["rewritten_traces"]
        assert checked["full_state_comparisons"] == fixed["comparisons"]
        assert checked["subject_call_ret_witnesses"] == fixed["original_traces"] + fixed["rewritten_traces"]
        assert checked["hook_call_return_witnesses"] == 8 and checked["recording_hook_rows"] == 4
        assert checked["ordinary_processes"] == 6
        steps = checked["trace_steps"]
        assert len(steps) == checked["traces"] == fixed["original_traces"] + fixed["rewritten_traces"]
        assert all(type(value) is int and 0 < value <= 20000 for value in steps.values())
        refusal_lines = [family + " unknown-entries Refused(7) no-artifact",
            family + " source-byte-tamper original-identity",
            family + " hook-byte-tamper-rebound-original hook-identity",
            family + " selected-placement-unavailable Refused(11) no-artifact"]
        if family in ("T2", "T3"):
            refusal_lines.append(family + " one-image-budget Refused(11) no-artifact")
        assert len(refusal_lines) == fixed["refusal_cases"]
        for line in refusal_lines:
            _, name, reason = line.split(" ", 2)
            refusal_rows.append(dict(family=family, name=name, expected=reason, observed=reason,
                                     outcome="required-refusal", positive_native_credit=False))
        refusal_lines.append(f"PASS adjacent tactic refusals: tactic={family} cases={fixed['refusal_cases']} qualification_complete=false")
        assert read(tactics / ("controls-" + family) / "stdout.txt") == ("\n".join(refusal_lines) + "\n").encode()
        assert read(tactics / ("controls-" + family) / "stderr.txt") == b""
        family_rows.append(dict(family=family, declared_heads=len(fixed["heads"]), seeds=2, strip_variants=2, hook_variants=2,
            original_traces=fixed["original_traces"], rewritten_traces=fixed["rewritten_traces"],
            full_state_comparisons=fixed["comparisons"], subject_call_ret_witnesses=checked["subject_call_ret_witnesses"],
            hook_call_return_witnesses=8, recording_journal_rows=4, refusal_cases=fixed["refusal_cases"],
            ordinary_processes=6, capture_files=len(captures), minimum_trace_steps=min(steps.values()),
            maximum_trace_steps=max(steps.values()), artifact_qualification_complete=False))
        before = js(tactics / ("candidate-files-before-" + family + ".json"))
        assert before == js(tactics / ("candidate-files-after-" + family + ".json"))
        assert checked["candidate_files_before_sha256"] == sha(read(tactics / ("candidate-files-before-" + family + ".json")))
        assert checked["candidate_files_after_sha256"] == sha(read(tactics / ("candidate-files-after-" + family + ".json")))
        originals = js(tactics / ("originals-" + family + ".json"))
        assert set(originals) == {"unstripped", "stripped"}
        assert set(before) == {family + "-" + s + "-" + h for s in originals for h in ("null", "journal")}
        for stripped in ("unstripped", "stripped"):
            original = read(tactics / "subjects" / family / ("original-" + stripped))
            assert sha(original) == originals[stripped]
            for hook in ("null", "journal"):
                name = family + "-" + stripped + "-" + hook
                directory = tactics / (name + "-candidate")
                index(directory, before[name])
                candidate = read(directory / "candidate.elf")
                assert len(candidate) > len(original)
                images = [read(directory / ("image-%04d.bin" % i)) for i in range(fixed["images"])]
                ledger = read(directory / "ledger.tsv").decode().splitlines()
                assert "qualification_complete\tfalse" in ledger and "execution_authority\tnone" in ledger
                changed, source_changed, spans, edits = set(), set(), 0, []
                for line in ledger:
                    fields = line.split("\t")
                    if fields[0] != "elf-change":
                        continue
                    assert len(fields) == 5 and fields[1] in ("ProgramHeaderOffset", "ProgramHeaderCount", "DeclaredSource")
                    offset, left, right = int(fields[2]), bytes.fromhex(fields[3]), bytes.fromhex(fields[4])
                    assert offset >= 0 and left and len(left) == len(right)
                    assert original[offset:offset + len(left)] == left and candidate[offset:offset + len(right)] == right
                    actual = {offset + n for n, pair in enumerate(zip(left, right)) if pair[0] != pair[1]}
                    assert not changed.intersection(actual)
                    changed.update(actual)
                    if fields[1] == "DeclaredSource":
                        spans += len(left)
                        source_changed.update(actual)
                    edits.append(dict(kind=fields[1], file_offset=offset, original_hex=left.hex(), emitted_hex=right.hex()))
                assert changed == {n for n, pair in enumerate(zip(original, candidate)) if pair[0] != pair[1]}
                artifact_rows.append(dict(family=family, candidate=name, original_bytes=len(original), candidate_bytes=len(candidate),
                    growth_bytes=len(candidate) - len(original), generated_image_count=len(images), generated_image_bytes=sum(map(len, images)),
                    source_edit_span_bytes=spans, changed_source_bytes=len(source_changed), original_sha256=sha(original),
                    candidate_sha256=sha(candidate), images=[dict(index=i, bytes=len(v), sha256=sha(v)) for i, v in enumerate(images)],
                    artifact_qualification_complete=False, edits=edits))
    assert len(artifact_rows) == 16
    assert len(refusal_rows) == 18
    for key, expected in dict(original_traces=68, rewritten_traces=136, traces=204,
                             full_state_comparisons=676, subject_call_ret_witnesses=204,
                             hook_call_return_witnesses=32, recording_hook_rows=16, ordinary_processes=24).items():
        assert audit["totals"][key] == expected
    assert audit["totals"]["captures_count"] == sum(row["capture_files"] for row in family_rows)
    assert audit["hardware_sha256"] == sha(read(tactics / "hardware.json"))
    assert audit["hardware"] == js(tactics / "hardware.json")

    roles = {"${TACTICS_RAW}": str(tactics), "${B1_RAW}": str(b1), "${REPO}": str(repo)}
    for prefix, scope in (("TACTICS", "tactics"), ("B1", "b1-prerequisite")):
        env = results_by_scope[scope][0]["env"]
        for role, value in (("TOOLCHAIN", str(Path(env["RUSTC"]).parent.parent)), ("USER_HOME", env["HOME"]), ("CARGO_HOME", env["CARGO_HOME"])):
            assert isinstance(value, str) and Path(value).is_absolute() and "\0" not in value
            roles["${" + prefix + "_" + role + "}"] = value
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

    def hardware(root):
        value = js(root / "hardware.json")
        assert set(value) == {"cpu_model", "architecture", "logical_cpus", "kernel_release", "libc"}
        assert "AMD EPYC" in value["cpu_model"] and value["architecture"] == "x86_64"
        assert type(value["logical_cpus"]) is int and value["logical_cpus"] > 0
        return dict(value, host_label="AMD EPYC Zen 5 dev host", observation_scope="Saved run observation, not continuous attestation or a benchmark")

    summary = dict(schema=1, authority="Successful separately pinned saved-record/state audit and strict stage receipts; explicit root parent-closure authority",
        tested_revision=source["revision"], source_files=len(source["files"]), source_record_sha256=sha(read(tactics / "source.json")),
        collector=dict(source_sha256=sha(Path(__file__).read_bytes()), tested_revision=None,
                       revision_scope="Collector source publication is separate from the tested campaign checkout"),
        audit=dict(sha256=args.audit_sha256, expected_producer_source_sha256=AUDIT_SCRIPT_SHA256,
                   expected_source_pins_sha256=AUDIT_SOURCE_PINS_SHA256, expected_fixture_sha256=AUDIT_FIXTURE_SHA256,
                   state_scope="The independent audit corroborates the same 676 serialized full-state comparisons; it adds no traces or comparisons to that denominator",
                   producer_authority="Root separately pins the actual audit invocation; its output alone does not identify its producer"),
        hardware=dict(tactics=hardware(tactics), b1_prerequisite=hardware(b1)),
        tool_version_observations=dict(tactics=js(tactics / "tools.json"), b1_prerequisite=js(b1 / "tools.json")),
        tool_observation_scope="Five saved version queries per recipe; no helper receipt, duration or full configuration closure is invented",
        tactics=dict(stages=93, strict_helper_receipts=93, heads=17, original_traces=68, rewritten_traces=136,
                     full_state_comparisons=676, subject_call_ret_witnesses=204, hook_call_return_witnesses=32,
                     recording_journal_rows=16, refusal_cases=18, ordinary_processes=24, families=family_rows,
                     declared_head_offsets={name: fixed["heads"] for name, fixed in FAMILIES.items()},
                     refusal_inventory=refusal_rows,
                     trace_step_limit=20000, trace_deadline_seconds=15, manual_load_mappings=0, post_seed_state_repairs=0),
        b1_prerequisite=dict(revision=source["revision"], stages=27, strict_helper_receipts=26, nested_required_gates=4,
                             original_traces=8, rewritten_traces=16, full_state_comparisons=72, subject_call_ret_witnesses=24,
                             hook_call_return_witnesses=8, recording_journal_rows=4, captures=1230, ordinary_processes=6,
                             scope="Separate same-revision prerequisite; never added to the four-tactic denominator",
                             required_gate_cleanup_scope="Original required runner limits; no strict helper/ECHILD attestation for the nested workspace gates"),
        command_rows=dict(tactics=93, b1_prerequisite=27, b1_required_nested=4, total=124),
        timing_scope="Operational diagnostic durations only, not benchmarks; nested rows overlap their parent; no durations are summed",
        artifact_qualification_complete=False, full_A3_complete=False,
        limits="Fixed ET_EXEC authored fixtures only; no PIE/DSO, arbitrary program, unwind/early-loader, E9, cross-vendor or new static-parity result",
        prior_failures="Remain distinct historical failures; incomplete attempts cannot satisfy this success-only collector")
    public = {"summary.json": clean(summary), "commands.json": clean(commands), "artifacts.json": artifact_rows}
    texts = {name: json.dumps(value, indent=2, sort_keys=True) + "\n" for name, value in public.items()}
    command_rows = []
    for row in commands:
        request = row.get("request")
        command_rows.append(dict(scope=row["scope"], name=row["name"], exit=0,
            operational_parent_seconds=row["operational_parent_seconds"],
            operational_child_seconds=None if row["receipt"] is None else row["receipt"]["elapsed_seconds"],
            cpu_seconds=None if request is None else request["cpu_seconds"], wall_seconds=None if request is None else request["wall_seconds"],
            file_bytes=None if request is None else request["file_bytes"], parent_timeout_seconds=row["command"]["parent_timeout_seconds"],
            strict_receipt_present=row["receipt"] is not None))
    for name, rows in (("commands.csv", command_rows), ("families.csv", family_rows),
                       ("artifacts.csv", [{k: v for k, v in row.items() if k not in ("images", "edits")} for row in artifact_rows])):
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        texts[name] = stream.getvalue()
    for value in texts.values():
        assert not re.search(r"/home/|/Users/|(?:facebook|fb|meta)\.com|\.internal\b|\bdev(?:big|vm|box|gpu)[A-Za-z0-9_.-]+", value)
    for name, expected in list(references.items()):
        assert sha(read(Path(name))) == expected
    # All validation completes before the first output write. Inputs stay private.
    output.mkdir()
    (output / "public").mkdir()
    for name, value in texts.items():
        with (output / "public" / name).open("x") as stream:
            stream.write(value)
    with (output / "public/files.json").open("x") as stream:
        json.dump({name: sha(value.encode()) for name, value in texts.items()}, stream, indent=2, sort_keys=True)
        stream.write("\n")
    with (output / "private-binding.json").open("x") as stream:
        json.dump(dict(coordinate_roles=roles, input_sha256=references, request_documents=request_documents,
                       parents_closed_and_reaped_confirmation=True, parent_authority="Explicit root observation, not an invented receipt",
                       source_revision=source["revision"], audit_sha256=args.audit_sha256), stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
