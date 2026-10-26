#!/usr/local/bin/python3
"""Finite pure Cargo alias-owner controls; separate from the 16 depfile controls."""
import hashlib
import sys
from pathlib import Path

RUNNER_SHA256 = "b4cd6602e2d72ceedcfaa24dfb2d6a8069d80e44c43cb003cfadf522a364bedb"


def main():
    if sys.flags.optimize:
        raise SystemExit("Assertions required")
    path = Path(__file__).resolve().with_name("emitter-parity-run.py")
    source = path.read_bytes()
    assert hashlib.sha256(source).hexdigest() == RUNNER_SHA256
    namespace = {"__name__": "authenticated_parity_source", "__file__": str(path)}
    exec(compile(source, str(path), "exec"), namespace)
    layout = namespace["ordinary_library_layout"]
    alias_check = namespace["bind_library_alias_depfile"]
    target = Path("/fixture/target")
    package = Path("/fixture/prepared/old")
    name = "liteinst2_parity_old_474094a7355c"
    stem = name + "-c555d5a77ff8a976"
    reported = str(target / "debug" / ("lib" + name + ".rlib"))
    derived = str(target / "debug/deps" / ("lib" + stem + ".rlib"))
    metadata = str(target / "debug/deps" / ("lib" + stem + ".rmeta"))
    members = ["README.md", "src/lib.rs", "src/patcher/synchronized.rs", "src/patcher.rs"]
    core = {"package_owner": str(package), "sources": {name: {} for name in members}}
    alias_text = reported + ": " + " ".join(str(package / name) for name in members) + "\n"
    calls = []

    def accept(label, operation):
        operation()
        calls.append((label, "ACCEPT"))

    def refuse(label, operation):
        try:
            operation()
        except AssertionError:
            calls.append((label, "REFUSE"))
        else:
            raise AssertionError(label)

    def alias_layout():
        value = layout([reported, metadata], name, target)
        assert value == {"reported_library": reported, "reported_metadata": metadata,
                         "derived_library": derived,
                         "dependency_depfile": str(target / "debug/deps" / (stem + ".d")),
                         "reported_alias_depfile": str(Path(reported).with_suffix(".d"))}

    def dependency_layout():
        value = layout([derived, metadata], name, target)
        assert value["reported_library"] == value["derived_library"] == derived
        assert value["reported_alias_depfile"] is None

    def full_alias_sources():
        value = alias_check(alias_text, reported, package, core)
        assert value == {"target": reported, "sources": [str(package / name) for name in members]}

    accept("reported_alias_exact_metadata_owner", alias_layout)
    accept("reported_dependency_exact_metadata_owner", dependency_layout)
    accept("complete_alias_source_rule", full_alias_sources)
    refuse("wrong_core_target", lambda: layout([reported, metadata], name.replace("474094a7355c", "000000000000"), target))
    refuse("foreign_metadata_directory", lambda: layout([reported, metadata.replace("/debug/deps/", "/foreign/")], name, target))
    refuse("malformed_metadata_hash", lambda: layout([reported, metadata.replace("c555d5a77ff8a976", "bad")], name, target))
    refuse("duplicate_metadata", lambda: layout([metadata, metadata], name, target))
    refuse("missing_metadata", lambda: layout([reported], name, target))
    refuse("mismatched_library_hash", lambda: layout([derived.replace("c555d5a77ff8a976", "0000000000000000"), metadata], name, target))
    refuse("extra_reported_product", lambda: layout([reported, metadata, derived], name, target))
    refuse("wrong_alias_rule_target", lambda: alias_check(alias_text.replace(reported + ":", derived + ":"), reported, package, core))
    refuse("missing_alias_source", lambda: alias_check(reported + ": " + str(package / "src/lib.rs") + "\n", reported, package, core))
    refuse("extra_alias_source", lambda: alias_check(alias_text.rstrip() + " " + str(package / "src/foreign.rs") + "\n", reported, package, core))
    refuse("wrong_alias_source_owner", lambda: alias_check(alias_text.replace(str(package) + "/src/lib.rs", "/foreign/src/lib.rs"), reported, package, core))
    assert len(calls) == 14 and sum(status == "ACCEPT" for _, status in calls) == 3
    for label, status in calls:
        print(status + " " + label)
    print("PASS library alias controls: 3 accepted, 11 refused; no workload")


if __name__ == "__main__":
    main()
