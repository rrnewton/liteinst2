#!/usr/local/bin/python3
"""Pure finite depfile owner controls; no filesystem fixtures or workloads."""
import hashlib
import sys
from pathlib import Path

RUNNER_SHA256 = "716dc4aff8ff87c36d6e7b1f617d6de540e40188fd7eb4cf070d3a87a8edf25f"


def main():
    if sys.flags.optimize:
        raise SystemExit("Assertions required")
    path = Path(__file__).resolve().with_name("emitter-parity-run.py")
    source = path.read_bytes()
    assert hashlib.sha256(source).hexdigest() == RUNNER_SHA256
    namespace = {"__name__": "authenticated_parity_source", "__file__": str(path)}
    exec(compile(source, str(path), "exec"), namespace)
    check = namespace["bind_core_depfile"]
    package = "/fixture/prepared/old"
    depfile = "/fixture/target/core.d"
    products = ["/fixture/target/core"]
    members = ["src/lib.rs", "src/emitter_parity.rs", "src/parity/current_features.rs", "README.md"]
    expected = {name: hashlib.sha256(name.encode()).hexdigest() for name in members}

    def quote(word):
        return word.replace("\\", "\\\\").replace("$", "$$").replace(" ", "\\ ").replace("\t", "\\\t").replace(":", "\\:").replace("#", "\\#")

    def render(deps, targets=None):
        targets = targets if targets is not None else [depfile, *products]
        body = " ".join(quote(x) for x in deps)
        return "".join(quote(x) + ": " + body + "\n" for x in targets) + "\n" + "".join(quote(x) + ":\n" for x in deps)

    relative = [*members[:-1], "src/../README.md"]
    calls = []
    def accepted(name, text, owner=package, pins=expected):
        result = check(text, depfile, products, owner, pins, dict(pins), True)
        assert set(result["sources"]) == set(pins)
        calls.append((name, "ACCEPT"))
    def refused(name, text, owner=package, pins=expected, current=None):
        try:
            check(text, depfile, products, owner, pins, dict(pins) if current is None else current, True)
        except AssertionError:
            calls.append((name, "REFUSE"))
        else:
            raise AssertionError(name)

    accepted("relative_sources_and_parent_README", render(relative))
    accepted("absolute_sources", render([package + "/" + n for n in members]))
    special = "/fixture/a space\\backslash/prepared/old"
    accepted("escaped_space_and_backslash_owner", render([special + "/" + n for n in members]), special)
    refused("wrong_depfile_target", render(relative, ["/wrong/core.d", *products]))
    refused("wrong_product_target", render(relative, [depfile, "/wrong/core"]))
    refused("package_escape", render([*relative[:-1], "../../README.md"]))
    refused("package_leave_and_return", render(["../../foreign/../prepared/old/src/lib.rs", *relative[1:]]))
    refused("missing_lib", render(relative[1:]))
    refused("missing_capture_module", render([relative[0], *relative[2:]]))
    refused("missing_current_module", render([*relative[:2], relative[3]]))
    refused("unknown_source", render([*relative, "src/unknown.rs"]))
    changed = dict(expected, **{"src/lib.rs": "0" * 64})
    refused("mutated_source_hash", render(relative), current=changed)
    refused("mismatched_product_dependencies", render(relative).replace(products[0] + ": " + " ".join(relative), products[0] + ": src/lib.rs"))
    refused("missing_phony_owner", render(relative).replace("src/lib.rs:\n", ""))
    refused("duplicate_source_alias", render([*relative, "README.md"]))
    refused("extra_product", render(relative, [depfile, *products, "/fixture/target/foreign"]))
    assert len(calls) == 16 and sum(status == "ACCEPT" for _, status in calls) == 3
    for name, status in calls:
        print(status + " " + name)
    print("PASS depfile owner controls: 3 accepted, 13 refused; no workload")


if __name__ == "__main__":
    main()
