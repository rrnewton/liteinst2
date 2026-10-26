#!/usr/bin/env python3
"""Stage authenticated A3 materials and requests; never launch a workload."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent
HELPER_SHA = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
MAX_JSON = 16 * 1024 * 1024
MAX_INPUT = 256 * 1024 * 1024
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
PHASES = ("prepare", "calibrations", "emit", "bind-native", "native", "audit-native",
          "bind-state", "state-build", "bind-state-run", "ownership-controls", "state-native",
          "receipt-controls", "audit-state")


def require(value, message):
    if not value:
        raise AssertionError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checksum(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "SHA256 syntax")
    return value


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read(path):
    path = Path(path)
    require(path.is_file() and path.stat().st_size <= MAX_JSON, "bounded JSON file")
    return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def identity(path):
    path = Path(path)
    require(path.is_absolute(), "explicit absolute local input")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= MAX_INPUT,
                "bounded regular prerequisite")
        h = hashlib.sha256()
        for block in iter(lambda: stream.read(512 * 1024), b""):
            h.update(block)
        after = os.fstat(stream.fileno())
    current = path.stat()
    fields = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
    require(fields(before) == fields(after) == fields(current), "input changed during read")
    return dict(path=str(path), resolved=str(path.resolve(strict=True)), sha256=h.hexdigest(),
                bytes=before.st_size, device=before.st_dev, inode=before.st_ino,
                mtime_ns=before.st_mtime_ns)


def relative(value):
    require(type(value) is str, "relative path string")
    p = Path(value)
    require(not p.is_absolute() and ".." not in p.parts and str(p) == value, "owned relative path")
    return p


def tree_files(directory, maximum):
    pending, names, visited = [directory], set(), 0
    while pending:
        parent = pending.pop()
        with os.scandir(parent) as entries:
            for entry in entries:
                visited += 1
                require(visited <= maximum and not entry.is_symlink(), "bounded owned source tree")
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                else:
                    require(entry.is_file(follow_symlinks=False), "regular source file")
                    names.add(str(path.relative_to(directory)))
    return names


def material(expected, variant="sparse-v4"):
    require(sha((HERE / "materials.json").read_bytes()) == checksum(expected), "reviewed materials")
    value = read(HERE / "materials.json")
    require(value["schema"] == 1, "material schema")
    require(tree_files(HERE, 1024) == set(value["files"]) | {"materials.json"}, "exact material inventory")
    for name, digest in value["files"].items():
        p = HERE / relative(name)
        require(not p.is_symlink() and p.resolve().is_relative_to(HERE), "owned material")
        require(identity(p)["sha256"] == checksum(digest), "material bytes")
    require("prepare.py" in value["files"] and "contract.json" in value["files"], "complete preparer owner")
    require(variant in value["contracts"], "explicit fixed historical variant")
    contract_name = value["contracts"][variant]
    require(contract_name in value["files"], "contract material owner")
    contract = read(HERE / relative(contract_name))
    require(contract["variant"] == variant, "contract variant identity")
    return value, contract


def exact_inputs(contract, bindings):
    require(type(bindings) is dict and set(bindings) == {"schema", "resources", "directories"}, "binding schema")
    require(type(bindings["schema"]) is int and bindings["schema"] == 1, "binding version")
    require(set(bindings["resources"]) == set(contract["resources"]), "every fixed prerequisite")
    require(len(set(bindings["resources"].values())) == len(bindings["resources"]), "distinct path owners")
    result = {}
    for role, expected in contract["resources"].items():
        require(type(bindings["resources"][role]) is str and
                re.fullmatch(r"/[A-Za-z0-9_./:+@-]+", bindings["resources"][role]),
                "unambiguous ASCII path for exact frontend JSON")
        row = identity(bindings["resources"][role])
        require(row["sha256"] == expected["sha256"] and row["bytes"] == expected["bytes"], "prerequisite bytes")
        result[role] = row
    directories = {row["id"]: row["entries"] for row in contract["runtime_directories"]}
    require(set(bindings["directories"]) == set(directories), "all loader configuration directories")
    for role, expected in directories.items():
        path = Path(bindings["directories"][role])
        require(path.is_absolute() and path.is_dir() and path.resolve() == path, "configuration directory owner")
        require(sorted(x.name for x in path.iterdir()) == expected, "exact loader configuration inventory")
    for name in contract["required_absent"]:
        require(not Path(name).exists() and not Path(name).is_symlink(), "required absent preload")
    interpreter = result[contract["interpreter_resource"]]
    require(interpreter["path"] == contract["interpreter_spelling"], "original ELF interpreter contract")
    return result


def operational_inputs(contract, bindings, inputs):
    """Keep selected operational lookup owners distinct from movable evidence."""
    runtime = contract["runtime_roles"]
    owners = contract["operational_owners"]
    evidence = contract["runtime_evidence_roles"]
    require(len(runtime) == len(set(runtime)) and set(runtime) <= set(inputs),
            "complete distinct runtime role inventory")
    require(not set(owners) & set(evidence) and set(owners) | set(evidence) == set(runtime),
            "every runtime role has exactly one explicit ownership class")
    for role, expected in owners.items():
        require(set(expected) == {"path", "resolved"}, "exact operational owner fields")
        require(inputs[role]["path"] == expected["path"], "actual operational lookup spelling")
        require(inputs[role]["resolved"] == expected["resolved"], "actual operational resolved owner")
    for role, expected in evidence.items():
        require(expected == {"consumed_by_this_pipeline": False,
                             "purpose": "retained-extra-runtime-evidence"},
                "extra evidence does not assert a consumed operational owner")
    for row in contract["runtime_directories"]:
        require(set(row) == {"id", "entries", "path", "resolved"}, "exact operational directory fields")
        path = Path(bindings["directories"][row["id"]])
        require(str(path) == row["path"] and str(path.resolve(strict=True)) == row["resolved"],
                "actual loader configuration directory owner")


def render(value, package, inputs, contract):
    if isinstance(value, list):
        return [render(x, package, inputs, contract) for x in value]
    if isinstance(value, dict):
        if set(value) == {"$resource"}:
            return inputs[value["$resource"]]["path"]
        if set(value) == {"$package"}:
            name = value["$package"]
            return str(package if name == "" else package / relative(name))
        if set(value) == {"$metadata"}:
            row = contract["metadata_tokens"][value["$metadata"]]
            require(row["runtime_input"] is False, "historical text is not executable input")
            return "historical-path-sha256:" + row["historical_text_sha256"]
        if set(value) == {"$pairs"}:
            rows = [(render(k, package, inputs, contract), render(v, package, inputs, contract))
                    for k, v in value["$pairs"]]
            require(len({k for k, _ in rows}) == len(rows), "no owner-key collapse")
            return dict(rows)
        require(not any(k.startswith("$") for k in value), "unknown template marker")
        return {k: render(v, package, inputs, contract) for k, v in value.items()}
    return value


def new_file(path, raw):
    require(len(raw) <= MAX_JSON, "stage output retains 16 MiB cap")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def request(argv, cwd, output, name, bounds):
    require(len(bounds) == 3 and all(type(x) is int and x > 0 for x in bounds), "literal finite command limits")
    return dict(argv=argv, cwd=str(cwd), env=dict(ENV), stdout=str(output / (name + ".stdout")),
                stderr=str(output / (name + ".stderr")), cpu_seconds=bounds[0],
                wall_seconds=bounds[1], file_bytes=bounds[2])



def control_request(argv, cwd, output, name, bounds, inputs):
    """Add scratch placement only to the two auxiliary control requests."""
    require(name in ("preparation-controls", "operational-controls"), "fixed auxiliary control name")
    helper_layout(inputs, output)
    root = Path(inputs["helper"]["path"]).resolve(strict=True).parents[2]
    output = Path(output)
    require(output.is_dir() and output.is_absolute() and output.resolve(strict=True) == output
            and output != root / "ignored" and output.is_relative_to(root / "ignored"),
            "existing canonical control parent strictly inside ignored")
    require(not output.is_relative_to(HERE), "control scratch is outside immutable materials")
    result = request(argv, cwd, output, name, bounds)
    result["env"]["TMPDIR"] = str(output)
    return result


def control_scratch_parent():
    """Use the admitted exact control TMPDIR with no tempfile fallback."""
    value = os.environ.get("TMPDIR")
    require(type(value) is str and value, "explicit control scratch parent")
    parent = Path(value)
    require(parent.is_absolute() and parent.is_dir() and parent.resolve(strict=True) == parent,
            "canonical existing control scratch parent")
    require(not parent.is_relative_to(HERE), "no scratch inside immutable materials")
    return parent


def helper_layout(inputs, *outputs):
    helper = Path(inputs["helper"]["path"]).resolve(strict=True)
    require(inputs["helper"]["sha256"] == HELPER_SHA, "unchanged helper implementation")
    root = helper.parents[2]
    require(HERE.is_relative_to(root), "public source under the helper's repository owner")
    for output in outputs:
        require(Path(output).is_absolute() and Path(output).is_relative_to(root / "ignored"),
                "unchanged helper's private output boundary")


def receipt(path, request_path):
    qraw = Path(request_path).read_bytes()
    q = read(request_path)
    r = read(path)
    require(set(r) == set("request_sha256 helper_sha256 exit wall_timeout unexpected_descendants absence_proof stdout_sha256 stderr_sha256 elapsed_seconds cleanup_events cleanup_error aborted inputs_unchanged".split()), "exact helper receipt fields")
    require(r["request_sha256"] == sha(qraw) and r["helper_sha256"] == HELPER_SHA, "request/helper identity")
    require(type(r["exit"]) is int and r["exit"] == 0, "required command success")
    require(r["wall_timeout"] is False and r["unexpected_descendants"] == [] and r["absence_proof"] == "ECHILD", "clean helper ownership")
    require(r["cleanup_events"] == [] and r["cleanup_error"] is None and r["aborted"] is None and r["inputs_unchanged"] is True, "complete helper cleanup")
    require(type(r["elapsed_seconds"]) in (int, float) and math.isfinite(r["elapsed_seconds"]) and r["elapsed_seconds"] >= 0, "finite elapsed time")
    for name in ("stdout", "stderr"):
        require(identity(q[name])["sha256"] == r[name + "_sha256"], "whole command output")
    return q, r


def stage(args):
    materials, contract = material(args.materials_sha256, args.variant)
    control_q, _ = receipt(args.controls_receipt, args.controls_request)
    require(control_q["argv"][1:] == ["-B", str(HERE / "calibrate_prepare.py"), args.materials_sha256], "exact additive preparation controls")
    require([control_q[k] for k in ("cpu_seconds", "wall_seconds", "file_bytes")] == [20, 30, 16777216], "preparation-control bounds")
    require(Path(control_q["stdout"]).read_bytes() == (HERE / "prepare-controls.expected.stdout").read_bytes()
            and Path(control_q["stderr"]).read_bytes() == b"", "complete 4/16 preparation controls")
    owner_q, _ = receipt(args.owner_controls_receipt, args.owner_controls_request)
    require(owner_q["argv"][1:] == ["-B", str(HERE / "calibrate_operational.py"), args.materials_sha256],
            "exact separate operational-owner controls")
    require([owner_q[k] for k in ("cpu_seconds", "wall_seconds", "file_bytes")] == [20, 30, 16777216],
            "unchanged separate owner-control bounds")
    require(Path(owner_q["stdout"]).read_bytes() == (HERE / "operational-controls.expected.stdout").read_bytes()
            and Path(owner_q["stderr"]).read_bytes() == b"", "complete separate 3/10 owner controls")
    require(identity(args.bindings)["sha256"] == checksum(args.bindings_sha256), "reviewed local binding bytes")
    bindings = read(args.bindings)
    inputs = exact_inputs(contract, bindings)
    operational_inputs(contract, bindings, inputs)
    output = Path(args.output)
    require(output.is_absolute() and output.parent.resolve() == output.parent and not output.exists() and not output.is_symlink(), "fresh owned stage")
    package = output / "package"
    files = {name: (HERE / relative(contract["source_directory"]) / name).read_bytes()
             for name in contract["immutable_sources"]}
    require(all(sha(files[n]) == h for n, h in contract["immutable_sources"].items()), "unchanged executable source bodies")
    data = {name: render(value, package, inputs, contract) for name, value in contract["templates"].items()}
    inp = data["inputs.json"]
    helper_layout(inp, output, args.controls_request, args.controls_receipt)
    helper_layout(inp, args.owner_controls_request, args.owner_controls_receipt)
    require(control_q["argv"][0] == inp["python"]["path"], "preparation-control Python owner")
    control_root = Path(args.controls_request).parent
    require(Path(args.controls_request) == control_root / "preparation-controls.request.json"
            and Path(args.controls_receipt) == control_root / "preparation-controls.receipt.json", "control request/receipt owners")
    require(control_q == control_request([inp["python"]["path"], "-B", str(HERE / "calibrate_prepare.py"), args.materials_sha256],
                                         HERE, control_root, "preparation-controls", [20, 30, 16777216], inp),
            "whole control request including fixed environment")
    require(Path(args.owner_controls_request) == control_root / "operational-controls.request.json"
            and Path(args.owner_controls_receipt) == control_root / "operational-controls.receipt.json",
            "separate owner-control request/receipt owners")
    require(owner_q == control_request([inp["python"]["path"], "-B", str(HERE / "calibrate_operational.py"), args.materials_sha256],
                                       HERE, control_root, "operational-controls", [20, 30, 16777216], inp),
            "whole owner-control request including fixed environment")
    inp["directory_names"] = {bindings["directories"][row["id"]]: row["entries"] for row in contract["runtime_directories"]}
    require(len(inp["runtime_hashes"]) == 156, "complete inherited runtime file set")
    require(inp["absent"] == contract["required_absent"], "unchanged preload requirement")
    require(Path(inp["python"]["path"]).resolve() == Path(inp["python"]["path"]), "canonical Python owner")
    require(inp["helper"]["sha256"] == HELPER_SHA, "unchanged public helper")
    cases = data["cases.json"]["cases"]
    require([x["id"] for x in cases] == contract["case_order"], "exact six inputs")
    for case, item in zip(cases, contract["rpc_templates"]):
        require(case["id"] == item["case"] and case["input"] == inputs[item["input_resource"]]["path"], "one RPC/input owner")
        raw = (HERE / item["template"]).read_bytes()
        require(sha(raw) == item["template_sha256"] and raw.count(b'"@@INPUT_FILENAME_JSON@@"') == 1, "one exact RPC path relocation")
        rpc = raw.replace(b'"@@INPUT_FILENAME_JSON@@"', json.dumps(case["input"], ensure_ascii=True).encode())
        name = "rpc/" + case["id"] + ".jsonl"
        files[name] = rpc
        case["frozen_rpc"] = dict(path=str(package / name), sha256=sha(rpc), bytes=len(rpc))
        case["future_corrected_output"] = str(package / "future-emission" / case["id"] / "a.out")
        case["future_output_sha256"] = None
    plan = data["emission-plan.json"]
    require(len(plan["commands"]) == 12, "twelve tool calls")
    for index, row in enumerate(plan["commands"]):
        case = cases[index // 2]
        phase = ("frontend", "backend")[index % 2]
        require(row["case"] == case["id"] and row["phase"] == phase, "exact serial tool order")
        name = row["request"]
        q = data[name]
        require([q[k] for k in ("cpu_seconds", "wall_seconds", "file_bytes")] == [20, 45, 16777216], "unchanged tool bounds")
        row["request_sha256"] = sha(encoded(q))
    require(data["native-inventory.json"]["runs"] == contract["native_rows"] and len(contract["native_rows"]) == 40, "literal loader denominator")
    require(data["state-inventory.json"]["rows"] == contract["state_rows"] and len(contract["state_rows"]) == 144, "literal state denominator")
    ci = data["state/compile-inputs.json"]
    owners = {Path(n).parent for n in ci["dependency_files"]}
    require(len(owners) == 1, "single exact dependency archive")
    require({str(p) for p in next(iter(owners)).iterdir()} == set(ci["dependency_files"]), "no unbound dependency candidates")
    require(len(ci["dependency_files"]) == 34 and len(ci["toolchain"]["files_sha256"]) == 81, "unchanged compiler closure inventory")
    for name, value in data.items():
        files[name] = encoded(value)
    refs = {inputs[k]["path"]: inputs[k]["sha256"] for k in contract["historical_reference_roles"]}
    require(len(refs) == contract["historical_reference_count"], "all historical authorities retained")
    manifest = dict(schema=1, files={n: sha(b) for n, b in sorted(files.items())}, references=refs,
                    historical_source_manifest_sha256=contract["source_manifest_sha256"],
                    typed_none_manifest_sha256=contract["typed_none_manifest_sha256"],
                    tested_revision=None, qualification_complete=False)
    manifest_raw = encoded(manifest)
    source_hash = sha(manifest_raw)
    files["manifest.json"] = manifest_raw
    # Preconditions above finish before any output is created. No oversized
    # archive is copied through this 16 MiB staging phase.
    output.mkdir()
    for name, raw in files.items():
        new_file(package / relative(name), raw)
    controls = output / "receipt-controls"
    for name in ("audit_state.py", "calibrate_receipts.py", "manifest.json"):
        new_file(controls / name, (HERE / "receipt-controls" / name).read_bytes())
    new_file(output / "bindings.json", encoded(bindings))
    new_file(output / "input-identities.json", encoded(inputs))
    require(exact_inputs(contract, bindings) == inputs, "prerequisites unchanged after staging")
    operational_inputs(contract, bindings, inputs)
    material(args.materials_sha256, args.variant)
    record = dict(schema=1, status="STAGED_REVIEW_REQUIRED_NO_WORKLOAD", materials_sha256=args.materials_sha256,
                  bindings_sha256=sha(encoded(bindings)), input_identities_sha256=sha(encoded(inputs)),
                  source_manifest_sha256=source_hash, files={n: sha(b) for n, b in files.items()},
                  receipt_controls_manifest_sha256=contract["receipt_controls_manifest_sha256"],
                  tested_revision=None, actual_tool_calls=0, actual_native_calls=0, actual_state_traces=0,
                  variant=args.variant, expected_failure=contract["expected_failure"],
                  controls_request_sha256=identity(args.controls_request)["sha256"],
                  controls_receipt_sha256=identity(args.controls_receipt)["sha256"],
                  owner_controls_request_sha256=identity(args.owner_controls_request)["sha256"],
                  owner_controls_receipt_sha256=identity(args.owner_controls_receipt)["sha256"],
                  contract_sha256=materials["files"][materials["contracts"][args.variant]])
    new_file(output / "stage.json", encoded(record))
    print("STAGED_REVIEW_REQUIRED_NO_WORKLOAD", sha(encoded(record)))


def frozen_stage(args):
    base = Path(args.stage)
    require(base.is_absolute() and base.resolve() == base, "stage owner")
    require(identity(base / "stage.json")["sha256"] == checksum(args.stage_sha256), "reviewed stage")
    s = read(base / "stage.json")
    materials, contract = material(args.materials_sha256, s["variant"])
    require(s["materials_sha256"] == args.materials_sha256 and s["status"] == "STAGED_REVIEW_REQUIRED_NO_WORKLOAD", "stage/source join")
    require(s["contract_sha256"] == materials["files"][materials["contracts"][s["variant"]]]
            and s["files"]["manifest.json"] == s["source_manifest_sha256"], "contract/manifest identity join")
    bindings = read(base / "bindings.json")
    require(identity(base / "bindings.json")["sha256"] == s["bindings_sha256"], "binding bytes")
    identities = read(base / "input-identities.json")
    require(identity(base / "input-identities.json")["sha256"] == s["input_identities_sha256"], "identity record bytes")
    require(exact_inputs(contract, bindings) == identities, "no silent prerequisite or runtime epoch refresh")
    operational_inputs(contract, bindings, identities)
    for name, digest in s["files"].items():
        path = base / "package" / relative(name)
        require(not path.is_symlink() and path.resolve().is_relative_to(base / "package"), "owned staged source")
        require(identity(path)["sha256"] == digest, "staged source unchanged")
    for directory in ("sources", "legacy", "state", "support", "expected", "requests", "rpc"):
        prefix = directory + "/"
        wanted = {n[len(prefix):] for n in s["files"] if n.startswith(prefix)}
        require(tree_files(base / "package" / directory, 512) == wanted, "exact staged source-directory inventory")
    require(tree_files(base / "receipt-controls", 16) == {"audit_state.py", "calibrate_receipts.py", "manifest.json"}, "exact receipt-control source inventory")
    for name, digest in read(base / "receipt-controls/manifest.json")["files"].items():
        require(identity(base / "receipt-controls" / relative(name))["sha256"] == digest, "receipt controls unchanged")
    require(identity(base / "receipt-controls/manifest.json")["sha256"] == s["receipt_controls_manifest_sha256"], "controls manifest")
    return base, s, contract


def bootstrap(args):
    _, contract = material(args.materials_sha256, args.variant)
    require(identity(args.bindings)["sha256"] == checksum(args.bindings_sha256), "explicit binding hash")
    bindings = read(args.bindings)
    inputs = exact_inputs(contract, bindings)
    operational_inputs(contract, bindings, inputs)
    out, stage_out = Path(args.output), Path(args.stage_output)
    for target in (out, stage_out):
        require(target.is_absolute() and target.parent.resolve() == target.parent
                and not target.exists() and not target.is_symlink(), "fresh bootstrap/stage owner")
    require(out != stage_out and not out.is_relative_to(stage_out) and not stage_out.is_relative_to(out), "distinct bootstrap and stage roots")
    inp = render(contract["templates"]["inputs.json"], stage_out / "package", inputs, contract)
    helper_layout(inp, out, stage_out)
    python, helper = inp["python"]["path"], inp["helper"]["path"]
    timeout = inputs[contract["timeout_resource"]]["path"]
    commands = [
        ("preparation-controls", [python, "-B", str(HERE / "calibrate_prepare.py"), args.materials_sha256]),
        ("operational-controls", [python, "-B", str(HERE / "calibrate_operational.py"), args.materials_sha256]),
        ("stage", [python, "-B", str(HERE / "prepare.py"), "stage",
                   "--materials-sha256", args.materials_sha256, "--variant", args.variant,
                   "--bindings", str(Path(args.bindings)), "--bindings-sha256", args.bindings_sha256,
                   "--output", str(stage_out), "--controls-request", str(out / "preparation-controls.request.json"),
                   "--controls-receipt", str(out / "preparation-controls.receipt.json"),
                   "--owner-controls-request", str(out / "operational-controls.request.json"),
                   "--owner-controls-receipt", str(out / "operational-controls.receipt.json")]),
    ]
    out.mkdir()
    rows = []
    for name, argv in commands:
        q = (control_request(argv, HERE, out, name, [20, 30, 16777216], inp)
             if name in ("preparation-controls", "operational-controls")
             else request(argv, HERE, out, name, [20, 30, 16777216]))
        qp, rp = out / (name + ".request.json"), out / (name + ".receipt.json")
        new_file(qp, encoded(q))
        rows.append(dict(id=name, request_path=str(qp), request_sha256=sha(encoded(q)), receipt=str(rp),
                         helper_argv=[timeout, "--signal=TERM", "--kill-after=10s", "40s", python, "-B", helper,
                                      "--request", str(qp), "--receipt", str(rp)], parent_timeout_seconds=55))
    require(exact_inputs(contract, bindings) == inputs, "unchanged bootstrap inputs")
    operational_inputs(contract, bindings, inputs)
    material(args.materials_sha256, args.variant)
    new_file(out / "requests.json", encoded(dict(status="REQUESTS_ONLY_NO_WORKLOAD", variant=args.variant,
             materials_sha256=args.materials_sha256, binding_sha256=args.bindings_sha256, rows=rows)))
    print("BOOTSTRAP_REQUESTS_ONLY_NO_WORKLOAD", len(rows))


def requests(args):
    base, s, contract = frozen_stage(args)
    require(args.phase in PHASES and args.phase in contract["allowed_phases"], "fixed phase; failed variants cannot advance")
    require(identity(args.review)["sha256"] == checksum(args.review_sha256), "explicit review bytes")
    review = read(args.review)
    require(set(review) == {"stage_sha256", "source_manifest_sha256", "phase", "decision", "files"}, "review contract")
    require(review["stage_sha256"] == args.stage_sha256 and review["source_manifest_sha256"] == s["source_manifest_sha256"] and review["phase"] == args.phase and review["decision"] == "approve", "explicit same-phase admission")
    package = base / "package"
    for name, digest in review["files"].items():
        require(identity(base / relative(name))["sha256"] == checksum(digest), "reviewed actual prerequisite")
    output = Path(args.output)
    require(output.is_absolute() and output.parent.resolve() == output.parent and not output.exists() and not output.is_symlink(), "fresh request directory")
    inp = read(package / "inputs.json")
    helper_layout(inp, base, output)
    def require_reviewed(name):
        require(name in review["files"], "missing actual review input: " + name)
        return review["files"][name]
    def checked_terminal(name):
        require_reviewed("package/" + name)
        return identity(package / name)["sha256"]
    extras = []
    if args.phase not in ("prepare", "receipt-controls"):
        extras += ["--prepared-sha256", checked_terminal("prepared-v1/complete.json")]
    if args.phase in ("bind-native", "native", "audit-native", "bind-state", "state-build", "bind-state-run", "ownership-controls", "state-native", "audit-state"):
        extras += ["--emitted-sha256", checked_terminal("future-emission/complete.json")]
    if args.phase in ("bind-state-run", "ownership-controls", "state-native", "audit-state"):
        extras += ["--state-freeze-sha256", checked_terminal("future-state-v1/input-freeze.json")]
    rows = []
    def existing(name, qpath, receipt_path, expected_hash, bounds):
        relative_q = str(qpath.relative_to(base))
        require_reviewed(relative_q)
        q = read(qpath)
        require(identity(qpath)["sha256"] == checksum(expected_hash), "generated request binding")
        require([q[k] for k in ("cpu_seconds", "wall_seconds", "file_bytes")] == bounds,
                "original per-command limits")
        rows.append(dict(id=name, request=q, original_request_sha256=identity(qpath)["sha256"],
                         receipt=str(receipt_path)))
    if args.phase == "calibrations":
        t = read(package / "prepared-v1/complete.json")
        require(set(t["calibration_requests"]) == set(contract["calibration_order"]), "all fixed variant calibrations")
        for name in contract["calibration_order"]:
            row = t["calibration_requests"][name]
            existing(name, Path(row["path"]), Path(row["receipt"]), row["sha256"], [20, 30, 16777216])
    elif args.phase == "native":
        checked_terminal("native-v1/plan.json")
        plan = read(package / "native-v1/plan.json")
        require([r["id"] for r in plan["rows"]] == [r["id"] for r in contract["native_rows"]], "all forty native requests")
        for row in plan["rows"]:
            existing(row["id"], Path(row["request"]), Path(row["receipt"]), row["request_sha256"], [10, 30, 16777216])
    elif args.phase == "state-build":
        checked_terminal("future-state-v1/input-freeze.json")
        plan = read(package / "future-state-v1/input-freeze.json")
        require([r["id"] for r in plan["commands"]] == ["compiler-version", "identity-calibrations", "compile"], "all state build prerequisites")
        for row in plan["commands"]:
            bounds = [60, 90, 134217728] if row["id"] == "compile" else [20, 30, 1048576]
            existing(row["id"], Path(row["request"]), Path(row["receipt"]), row["request_sha256"], bounds)
    elif args.phase in ("ownership-controls", "state-native"):
        checked_terminal("state-run-v1/binding.json")
        binding = read(package / "state-run-v1/binding.json")
        binary = binding["binary"]
        require_reviewed(str(Path(binary["path"]).relative_to(base)))
        require(identity(binary["path"])["sha256"] == binary["sha256"], "reviewed fresh oracle")
        name = "native" if args.phase == "state-native" else "ownership-controls"
        key = "request_sha256" if name == "native" else "ownership_controls_request_sha256"
        bounds = [60, 90, 16777216] if name == "native" else [20, 30, 1048576]
        existing(name, package / "state-run-v1" / (name + ".request.json"), package / "state-run-v1" / (name + ".receipt.json"), binding[key], bounds)
    else:
        phase = args.phase
        bounds = [20, 30, 16777216]
        if phase == "emit":
            bounds = [120, 180, 16777216]
        if phase == "audit-native":
            extras += ["--plan-sha256", checked_terminal("native-v1/plan.json")]
        if phase == "audit-state":
            extras += ["--binding-sha256", checked_terminal("state-run-v1/binding.json")]
            for name in ("ownership-controls", "native"):
                q = package / "state-run-v1" / (name + ".request.json")
                r = package / "state-run-v1" / (name + ".receipt.json")
                require_reviewed(str(q.relative_to(base)))
                require_reviewed(str(r.relative_to(base)))
                receipt(r, q)
            require_reviewed("receipt-controls-result/receipt.json")
            require_reviewed("receipt-controls-result/request.json")
            control_q, _ = receipt(base / "receipt-controls-result/receipt.json", base / "receipt-controls-result/request.json")
            require(control_q["argv"] == [inp["python"]["path"], "-B", str(base / "receipt-controls/calibrate_receipts.py"), s["receipt_controls_manifest_sha256"]], "exact unchanged receipt calibrator")
            require(Path(control_q["stdout"]).read_bytes() == b"STATE_AUDIT_RECEIPT_CONTROLS_PASS positives=1 negatives=23\n" and Path(control_q["stderr"]).read_bytes() == b"", "all receipt controls")
        if phase == "receipt-controls":
            output = base / "receipt-controls-result"
            require(str(Path(args.output)) == str(output) and not output.exists(), "fixed receipt-control owner")
            argv = [inp["python"]["path"], "-B", str(base / "receipt-controls/calibrate_receipts.py"), s["receipt_controls_manifest_sha256"]]
        else:
            argv = [inp["python"]["path"], "-B", str(package / "entry.py"), phase, s["source_manifest_sha256"], *extras]
        q = request(argv, package, output, "command", bounds)
        rows.append(dict(id=phase, request=q, receipt=str(output / "receipt.json")))
    # Existing requests are copied without changing executable arguments,
    # outputs, environment or caps. Their original receipt destinations remain.
    output.mkdir()
    for index, row in enumerate(rows):
        name = "request.json" if len(rows) == 1 else f"{index:02d}-{row['id']}.request.json"
        new_file(output / name, encoded(row["request"]))
        row["request_path"] = str(output / name)
        wall = row["request"]["wall_seconds"]
        row["helper_argv"] = [read(base / "bindings.json")["resources"][contract["timeout_resource"]],
                              "--signal=TERM", "--kill-after=10s", str(wall + 10) + "s",
                              inp["python"]["path"], "-B", inp["helper"]["path"],
                              "--request", row["request_path"], "--receipt", row["receipt"]]
        row["parent_timeout_seconds"] = wall + 25
        row["request_sha256"] = sha(encoded(row.pop("request")))
        row["identity_checks"] = []
        for when in ("before", "after"):
            check_name = f"{index:02d}-{row['id']}-{when}"
            check_argv = [inp["python"]["path"], "-B", str(HERE / "prepare.py"), "verify",
                          "--materials-sha256", args.materials_sha256, "--stage", str(base),
                          "--stage-sha256", args.stage_sha256]
            check_q = request(check_argv, package, output, check_name, [20, 30, 16777216])
            check_path = output / (check_name + ".request.json")
            new_file(check_path, encoded(check_q))
            check_receipt = output / (check_name + ".receipt.json")
            row["identity_checks"].append(dict(when=when, request_path=str(check_path),
                request_sha256=sha(encoded(check_q)), receipt=str(check_receipt),
                helper_argv=[read(base / "bindings.json")["resources"][contract["timeout_resource"]],
                    "--signal=TERM", "--kill-after=10s", "40s", inp["python"]["path"], "-B",
                    inp["helper"]["path"], "--request", str(check_path), "--receipt", str(check_receipt)],
                parent_timeout_seconds=55))
    frozen_stage(args)
    require(identity(args.review)["sha256"] == args.review_sha256, "review unchanged")
    new_file(output / "requests.json", encoded(dict(status="REQUESTS_ONLY_NO_WORKLOAD", phase=args.phase,
             stage_sha256=args.stage_sha256, review_sha256=args.review_sha256,
             variant=s["variant"], expected_failure=contract["expected_failure"], rows=rows)))
    print("REQUESTS_ONLY_NO_WORKLOAD", args.phase, len(rows))


def main():
    require(sys.pycache_prefix is None and sys.dont_write_bytecode, "no authored bytecode cache")
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="mode", required=True)
    a = sub.add_parser("stage")
    a.add_argument("--materials-sha256", required=True)
    a.add_argument("--bindings", required=True)
    a.add_argument("--bindings-sha256", required=True)
    a.add_argument("--output", required=True)
    a.add_argument("--variant", required=True, choices=("sparse-v4", "untyped-v3", "legacy-v1"))
    a.add_argument("--controls-request", required=True)
    a.add_argument("--controls-receipt", required=True)
    a.add_argument("--owner-controls-request", required=True)
    a.add_argument("--owner-controls-receipt", required=True)
    a = sub.add_parser("bootstrap")
    for name in ("materials-sha256", "bindings", "bindings-sha256", "output", "stage-output", "variant"):
        a.add_argument("--" + name, required=True)
    a = sub.add_parser("requests")
    for name in ("materials-sha256", "stage", "stage-sha256", "phase", "review", "review-sha256", "output"):
        a.add_argument("--" + name, required=True)
    a = sub.add_parser("verify")
    for name in ("materials-sha256", "stage", "stage-sha256"):
        a.add_argument("--" + name, required=True)
    args = p.parse_args()
    if args.mode == "verify":
        frozen_stage(args)
        print("STAGE_INPUTS_UNCHANGED", args.stage_sha256)
    else:
        {"bootstrap": bootstrap, "stage": stage, "requests": requests}[args.mode](args)


if __name__ == "__main__":
    main()
