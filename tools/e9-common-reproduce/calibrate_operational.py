#!/usr/bin/env python3
"""Separate pure operational-owner controls; no loader or workload execution."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python is forbidden")
sys.dont_write_bytecode = True
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import types


def main():
    assert len(sys.argv) == 2 and sys.pycache_prefix is None
    here = Path(__file__).resolve().parent
    raw = (here / "materials.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == sys.argv[1]
    manifest = json.loads(raw)
    for name in ("prepare.py", "calibrate_operational.py"):
        assert hashlib.sha256((here / name).read_bytes()).hexdigest() == manifest["files"][name]
    source = (here / "prepare.py").read_bytes()
    module = types.ModuleType("e9_common_operational_controls")
    module.__file__ = str(here / "prepare.py")
    exec(compile(source, module.__file__, "exec", dont_inherit=True, optimize=0), module.__dict__)
    accepted, refused = [], []

    def no(name, call):
        try:
            call()
        except (AssertionError, ValueError, TypeError, KeyError):
            refused.append(name)
        else:
            raise AssertionError("required refusal accepted: " + name)

    def check(contract, bindings):
        inputs = module.exact_inputs(contract, bindings)
        module.operational_inputs(contract, bindings, inputs)

    with tempfile.TemporaryDirectory(prefix="e9-operational-controls-",
                                     dir=module.control_scratch_parent()) as temporary:
        root = Path(temporary)
        paths = {name: root / name for name in ("config", "python", "evidence", "interpreter")}
        for path in paths.values():
            path.write_bytes(b"same")
        directory = root / "config-directory"
        directory.mkdir()
        (directory / "entry.conf").write_bytes(b"configuration")
        contract = dict(
            resources={name: dict(sha256=hashlib.sha256(b"same").hexdigest(), bytes=4) for name in paths},
            runtime_roles=["config", "python", "evidence"],
            operational_owners={name: dict(path=str(paths[name]), resolved=str(paths[name]))
                                for name in ("config", "python")},
            runtime_evidence_roles={"evidence": dict(consumed_by_this_pipeline=False,
                                                       purpose="retained-extra-runtime-evidence")},
            runtime_directories=[dict(id="directory", entries=["entry.conf"],
                                      path=str(directory), resolved=str(directory))],
            required_absent=[], interpreter_resource="interpreter",
            interpreter_spelling=str(paths["interpreter"]))
        bindings = dict(schema=1, resources={name: str(path) for name, path in paths.items()},
                        directories={"directory": str(directory)})
        check(contract, bindings)
        accepted.append("exact-operational-owners")

        copied_evidence = root / "evidence-copy"
        copied_evidence.write_bytes(b"same")
        moved = copy.deepcopy(bindings)
        moved["resources"]["evidence"] = str(copied_evidence)
        check(contract, moved)
        accepted.append("movable-mandatory-nonconsumed-evidence")

        resolved_config = root / "config-real"
        paths["config"].rename(resolved_config)
        paths["config"].symlink_to(resolved_config)
        symlink_contract = copy.deepcopy(contract)
        symlink_contract["operational_owners"]["config"]["resolved"] = str(resolved_config)
        check(symlink_contract, bindings)
        accepted.append("fixed-lookup-and-symlink-target")

        for label, role in (("same-bytes-wrong-config-owner", "config"),
                            ("same-bytes-wrong-python-owner", "python")):
            wrong = root / (role + "-copy")
            wrong.write_bytes(b"same")
            changed = copy.deepcopy(bindings)
            changed["resources"][role] = str(wrong)
            no(label, lambda: check(symlink_contract, changed))

        other_directory = root / "directory-copy"
        other_directory.mkdir()
        (other_directory / "entry.conf").write_bytes(b"configuration")
        changed = copy.deepcopy(bindings)
        changed["directories"]["directory"] = str(other_directory)
        no("same-members-wrong-config-directory", lambda: check(symlink_contract, changed))

        other_config = root / "config-other-real"
        other_config.write_bytes(b"same")
        paths["config"].unlink()
        paths["config"].symlink_to(other_config)
        no("same-bytes-retargeted-config-symlink", lambda: check(symlink_contract, bindings))
        paths["config"].unlink()
        paths["config"].symlink_to(resolved_config)

        changed_contract = copy.deepcopy(symlink_contract)
        del changed_contract["operational_owners"]["python"]
        no("missing-operational-owner", lambda: check(changed_contract, bindings))
        changed_contract = copy.deepcopy(symlink_contract)
        changed_contract["operational_owners"]["interpreter"] = dict(
            path=str(paths["interpreter"]), resolved=str(paths["interpreter"]))
        no("extra-operational-owner", lambda: check(changed_contract, bindings))
        changed_contract = copy.deepcopy(symlink_contract)
        del changed_contract["runtime_evidence_roles"]["evidence"]
        no("missing-runtime-classification", lambda: check(changed_contract, bindings))
        changed_contract = copy.deepcopy(symlink_contract)
        changed_contract["operational_owners"]["evidence"] = dict(
            path=str(paths["evidence"]), resolved=str(paths["evidence"]))
        no("overlapping-runtime-classification", lambda: check(changed_contract, bindings))
        changed_contract = copy.deepcopy(symlink_contract)
        changed_contract["operational_owners"]["python"]["resolved"] = str(other_config)
        no("unproven-resolved-owner", lambda: check(changed_contract, bindings))
        changed_contract = copy.deepcopy(symlink_contract)
        changed_contract["runtime_evidence_roles"]["evidence"]["consumed_by_this_pipeline"] = True
        no("evidence-classification-claims-consumption", lambda: check(changed_contract, bindings))

    assert accepted == ["exact-operational-owners", "movable-mandatory-nonconsumed-evidence",
                        "fixed-lookup-and-symlink-target"]
    assert refused == ["same-bytes-wrong-config-owner", "same-bytes-wrong-python-owner",
                       "same-members-wrong-config-directory", "same-bytes-retargeted-config-symlink",
                       "missing-operational-owner", "extra-operational-owner",
                       "missing-runtime-classification", "overlapping-runtime-classification",
                       "unproven-resolved-owner", "evidence-classification-claims-consumption"]
    assert len(accepted) == 3 and len(refused) == 10
    assert hashlib.sha256((here / "prepare.py").read_bytes()).hexdigest() == manifest["files"]["prepare.py"]
    print(json.dumps(dict(accepted=accepted, refused=refused, acceptances=3, refusals=10,
                         process_launches=0, native_executions=0, signal_deliveries=0), indent=2))


if __name__ == "__main__":
    main()
