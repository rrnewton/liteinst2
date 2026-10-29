"""Reproduce strict decoding and a separately labelled, unqualified diagnostic.

Run from this file's tracked evaluation directory layout. Arguments are the
same as decode_perf.py; supply independently retained data/command hashes.
This reads an existing capture. It never starts perf or a workload.
"""
import sys
if sys.flags.optimize:
    raise SystemExit("assertions required")
sys.dont_write_bytecode = True

import collections
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools/rapid-profiler/tree-work"


def sibling(name):
    spec = importlib.util.spec_from_file_location("_report_" + name, TOOLS / (name + ".py"))
    if spec is None or spec.loader is None:
        raise RuntimeError("missing decoder source")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def describe(words):
    cli = sibling("decode_perf")
    args = cli.arguments(words)
    if "--command-json" not in args:
        raise cli.InputRefusal("external_command_required_for_strict_comparison")
    data = cli.read_bound(args["--data"], cli.MAX_BYTES, args["--sha256"], "data")
    command = cli.command_words(cli.read_bound(args["--command-json"], cli.MAX_COMMAND_BYTES,
                                               args["--command-sha256"], "command"))
    parser = sibling("perf_data")
    strict = parser.decode(data, command)
    # Deliberately separate diagnosis never replaces the strict result.
    diagnostic = parser.decode(data)
    recorded = next((f["argv"] for f in diagnostic["features"] if f.get("encoding") == "cmdline"), None)
    sample_misc = collections.Counter(r["misc"] for r in diagnostic["inventory"] if r["type"] == 9)
    reads = collections.Counter((r["read"]["value"], r["read"]["enabled"], r["read"]["running"], r["read"].get("lost"))
                                for r in diagnostic["records"] if r["type"] == 8)
    return {
        "authority": "diagnostic only; no capture, attribution, terminal accounting or accuracy qualification",
        "strict": strict["summary"],
        "diagnostic_without_command_authority": diagnostic["summary"],
        "command_comparison": {"expected_words": len(command),
                               "decoded_words": None if recorded is None else len(recorded),
                               "equal": None if recorded is None else recorded == command},
        "framed_sample_misc_counts": [{"misc": misc, "count": n} for misc, n in sorted(sample_misc.items())],
        "decoded_prefix_read_value_counts": [
            {"value": key[0], "enabled": key[1], "running": key[2], "lost": key[3], "count": n}
            for key, n in sorted(reads.items(), key=lambda item: tuple(-1 if v is None else v for v in item[0]))],
        "read_group_scope": "all READs in diagnostic decoded prefix; grouped without task/event identity; not a sum or final total",
    }


def main():
    try:
        result = describe(sys.argv[1:])
        wire = json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        if len(wire) + 1 > 4 * 1024 * 1024:
            raise RuntimeError("report output cap")
    except Exception:
        print('{"status":"REPORT_REFUSED","authority":"no qualification"}')
        return 2
    print(wire)
    # Exit 0 means this report was emitted, never that either decode passed.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
