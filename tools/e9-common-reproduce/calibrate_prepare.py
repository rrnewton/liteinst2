#!/usr/bin/env python3
"""Pure preparation controls: no process, signal, compiler or ELF execution."""
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
    for name in ("prepare.py", "calibrate_prepare.py"):
        assert hashlib.sha256((here / name).read_bytes()).hexdigest() == manifest["files"][name]
    source = (here / "prepare.py").read_bytes()
    module = types.ModuleType("e9_common_prepare_controls")
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
    with tempfile.TemporaryDirectory(prefix="e9-preparation-controls-",
                                     dir=module.control_scratch_parent()) as temporary:
        root = Path(temporary)
        item = root / "input"
        item.write_bytes(b"same")
        role = "rfixture"
        contract = dict(resources={role: dict(sha256=hashlib.sha256(b"same").hexdigest(), bytes=4)},
                        runtime_directories=[], required_absent=[], interpreter_resource=role,
                        interpreter_spelling=str(item), metadata_tokens={})
        bindings = dict(schema=1, resources={role: str(item)}, directories={})
        got = module.exact_inputs(contract, bindings)
        assert got[role]["sha256"] == contract["resources"][role]["sha256"]
        accepted.append("exact-local-prerequisite")
        assert module.render({"$package": "a/b"}, root, got, contract) == str(root / "a/b")
        accepted.append("owned-package-path")
        q = module.request(["/synthetic/command"], root, root, "command", [20, 30, 16777216])
        assert (q["cpu_seconds"], q["wall_seconds"], q["file_bytes"]) == (20, 30, 16777216)
        accepted.append("fixed-request-geometry")
        Path(q["stdout"]).write_bytes(b"ok\n")
        Path(q["stderr"]).write_bytes(b"")
        qp = root / "request.json"
        qp.write_bytes(module.encoded(q))
        good = dict(request_sha256=module.sha(qp.read_bytes()), helper_sha256=module.HELPER_SHA,
                    exit=0, wall_timeout=False, unexpected_descendants=[], absence_proof="ECHILD",
                    stdout_sha256=module.sha(b"ok\n"), stderr_sha256=module.sha(b""),
                    elapsed_seconds=0.01, cleanup_events=[], cleanup_error=None, aborted=None,
                    inputs_unchanged=True)
        rp = root / "receipt.json"
        rp.write_bytes(module.encoded(good))
        module.receipt(rp, qp)
        accepted.append("exact-success-receipt")
        no("boolean-limit", lambda: module.request([], root, root, "bad", [True, 30, 16777216]))
        no("negative-limit", lambda: module.request([], root, root, "bad", [20, -1, 16777216]))
        no("unknown-template-marker", lambda: module.render({"$unknown": "x"}, root, got, contract))
        no("package-path-escape", lambda: module.render({"$package": "../escape"}, root, got, contract))
        changed = copy.deepcopy(bindings); del changed["resources"][role]
        no("missing-resource", lambda: module.exact_inputs(contract, changed))
        changed = copy.deepcopy(bindings); changed["resources"]["extra"] = str(item)
        no("extra-resource", lambda: module.exact_inputs(contract, changed))
        changed = copy.deepcopy(contract); changed["resources"][role]["sha256"] = "0" * 64
        no("wrong-resource-hash", lambda: module.exact_inputs(changed, bindings))
        changed = copy.deepcopy(contract); changed["resources"][role]["bytes"] = 3
        no("wrong-resource-size", lambda: module.exact_inputs(changed, bindings))
        changed = copy.deepcopy(contract); changed["resources"]["duplicate"] = changed["resources"][role]
        duplicate = copy.deepcopy(bindings); duplicate["resources"]["duplicate"] = str(item)
        no("collapsed-resource-owners", lambda: module.exact_inputs(changed, duplicate))
        changed = copy.deepcopy(contract); changed["runtime_directories"] = [dict(id="config", entries=[])]
        other = copy.deepcopy(bindings); other["directories"]["config"] = str(root)
        no("configuration-member-drift", lambda: module.exact_inputs(changed, other))
        changed = copy.deepcopy(contract); changed["required_absent"] = [str(item)]
        no("present-preload", lambda: module.exact_inputs(changed, bindings))
        changed = copy.deepcopy(contract); changed["interpreter_spelling"] = str(root / "other")
        no("wrong-interpreter-path", lambda: module.exact_inputs(changed, bindings))
        for name, key, value in (("boolean-exit", "exit", False), ("boolean-elapsed", "elapsed_seconds", True),
                                 ("failed-command", "exit", 1)):
            changed = copy.deepcopy(good); changed[key] = value; rp.write_bytes(module.encoded(changed))
            no(name, lambda: module.receipt(rp, qp))
        bad_json = root / "duplicate.json"; bad_json.write_bytes(b'{"a":1,"a":2}\n')
        no("duplicate-json-key", lambda: module.read(bad_json))
    expected = ["boolean-limit", "negative-limit", "unknown-template-marker", "package-path-escape",
                "missing-resource", "extra-resource", "wrong-resource-hash", "wrong-resource-size",
                "collapsed-resource-owners", "configuration-member-drift", "present-preload",
                "wrong-interpreter-path", "boolean-exit", "boolean-elapsed", "failed-command", "duplicate-json-key"]
    assert len(accepted) == 4 and refused == expected and len(refused) == 16
    assert hashlib.sha256((here / "prepare.py").read_bytes()).hexdigest() == manifest["files"]["prepare.py"]
    print(json.dumps(dict(accepted=accepted, refused=refused, acceptances=4, refusals=16,
                         process_launches=0, native_executions=0, signal_deliveries=0), indent=2))


if __name__ == "__main__":
    main()
