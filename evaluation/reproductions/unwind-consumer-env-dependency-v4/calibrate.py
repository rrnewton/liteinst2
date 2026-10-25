#!/usr/bin/env python3
"""Run only two authenticated pure functions; root owns this bounded invocation."""
import argparse
import ast
import hashlib
import json
import sys
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Depfile:
    def __init__(self, text):
        self.text = text

    def read_text(self):
        return self.text


def main():
    assert __debug__ and sys.flags.optimize == 0 and sys.dont_write_bytecode
    parser = argparse.ArgumentParser()
    for name in ("adapter", "cases", "expected"):
        parser.add_argument("--" + name, type=Path, required=True)
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--self-sha256", required=True)
    args = parser.parse_args()
    pins = {Path(__file__).resolve(): args.self_sha256,
            args.adapter: args.adapter_sha256, args.cases: args.cases_sha256,
            args.expected: args.expected_sha256}
    assert all(path.is_absolute() and not path.is_symlink() and sha(path) == digest
               for path, digest in pins.items())
    source = args.adapter.read_bytes()
    tree = ast.parse(source, filename=str(args.adapter))
    names = ("dep_rules", "fixture_environment")
    functions = [node for node in tree.body
                 if isinstance(node, ast.FunctionDef) and node.name in names]
    assert [node.name for node in functions] == list(names)
    assert all(not node.decorator_list for node in functions)
    pure = {}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(args.adapter),
                 "exec", dont_inherit=True, optimize=0), pure)
    inventory = json.loads(args.cases.read_text())
    expected = json.loads(args.expected.read_text())
    rows = inventory["cases"]
    assert len(rows) == 36 and len({row["name"] for row in rows}) == 36
    assert expected["accepted"] == [row["name"] for row in rows if row["expected"] == "accept"]
    assert expected["refused"] == [row["name"] for row in rows if row["expected"] == "refuse"]
    assert len(expected["accepted"]) == 4 and len(expected["refused"]) == 32
    result = dict(accepted=[], refused=[], status="PURE_ENV_DEPENDENCY_CONTROLS_PASS")
    for row in rows:
        assert set(row) == {"name", "fixture", "depfile", "compile_environment", "expected"}
        assert row["expected"] in {"accept", "refuse"}
        assert type(row["depfile"]) is str and 0 < len(row["depfile"]) < 4096
        try:
            rules, environment = pure["dep_rules"](Depfile(row["depfile"]))
            assert rules == {"fixture": ["source.rs"], "fixture.d": ["source.rs"], "source.rs": []}
            pure["fixture_environment"](row["fixture"], environment, row["compile_environment"])
        except AssertionError:
            assert row["expected"] == "refuse", row["name"]
            result["refused"].append(row["name"])
        else:
            assert row["expected"] == "accept", row["name"]
            result["accepted"].append(row["name"])
    assert result == expected
    assert all(sha(path) == digest for path, digest in pins.items())
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
