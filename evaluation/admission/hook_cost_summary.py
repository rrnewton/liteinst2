"""Descriptive finite-process summaries; no performance pass criterion."""

import csv
import io
import json
import math
import random
import statistics

from hook_cost_proof import require, sha
from hook_cost_schema import IDENTITY, TIMES

BOOTSTRAP_SAMPLES = 10000
BOOTSTRAP_SEED = 20261026


def summarize(evidence):
    if evidence["status"] != "complete" or not all(r["qualified"] for r in evidence["completions"]):
        return []
    measured = [r for r in evidence["completions"] if r["phase"] == "measured"]
    groups = {}
    for row in measured:
        key = (row["fixture"], row["ordinal"], row["class"], row["site_offset"], row["encoding_hex"], row["script_id"])
        groups.setdefault(key, {}).setdefault(row["pair_index"], {})[row["lane"]] = row
    summaries = []
    for key, pairs in sorted(groups.items()):
        require(len(pairs) == 10 and all(set(p) == {"static_trap", "dynamic_page"} for p in pairs.values()),
                "summary_pair_inventory")
        ordered = [pairs[n] for n in sorted(pairs)]
        # One resampled index selects both lanes in one independent process pair.
        # Keep the same paired draws for every timing component in this group.
        rng = random.Random(BOOTSTRAP_SEED)
        draws = [[rng.randrange(10) for _ in range(10)] for _ in range(BOOTSTRAP_SAMPLES)]
        for component in sorted(TIMES):
            a = [p["static_trap"][component] for p in ordered]
            b = [p["dynamic_page"][component] for p in ordered]
            delta = [right - left for left, right in zip(a, b)]
            estimate = sorted(statistics.median([delta[i] for i in sample]) for sample in draws)
            def spread(values):
                return {"samples": len(values), "minimum_ns": min(values), "median_ns": statistics.median(values),
                        "maximum_ns": max(values)}
            summaries.append(dict(zip(("fixture", "ordinal", "class", "site_offset", "encoding_hex", "script_id"), key)) | {
                "component": component, "static_trap": spread(a), "dynamic_page": spread(b),
                "paired_dynamic_minus_static": spread(delta) | {
                    "bootstrap_95_percentile_low_ns": estimate[math.ceil(0.025 * BOOTSTRAP_SAMPLES) - 1],
                    "bootstrap_95_percentile_high_ns": estimate[math.ceil(0.975 * BOOTSTRAP_SAMPLES) - 1],
                    "resamples": BOOTSTRAP_SAMPLES, "seed": BOOTSTRAP_SEED,
                    "unit": "independent_process_pair", "statistic": "median_of_paired_differences",
                    "percentile_rule": "nearest_rank"}})
    return summaries


def csv_bytes(rows, fields):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        encoded = {}
        for key in fields:
            value = row.get(key)
            encoded[key] = json.dumps(value, sort_keys=True, separators=(",", ":")) if isinstance(value, (dict, list)) else value
        writer.writerow(encoded)
    return output.getvalue().encode()


def artifacts(evidence):
    identity = ["fixture", "phase", "pair_index", "round", "order_index", "lane"]
    session_fields = identity + ["status", "qualified", "covered", "raw_reference_completed", "callbacks",
        "collateral_completions", "launch_total_ns", "validation_ns", "cleanup_ns", "completed", "cleanup"]
    completion_fields = identity + ["ordinal", "class", "site_offset", "encoding_hex", "script_id", "status", "qualified",
        "completion_ns", "before_provider_ns", "checked_provider_ns", "after_provider_ns", "validation_ns",
        "metrics_before", "metrics_after", "completed", "cleanup"]
    summary = summarize(evidence)
    return {"sessions": csv_bytes(evidence["sessions"], session_fields),
            "completions": csv_bytes(evidence["completions"], completion_fields),
            "summary": csv_bytes(summary, ["fixture", "ordinal", "class", "site_offset", "encoding_hex",
                "script_id", "component", "static_trap", "dynamic_page", "paired_dynamic_minus_static"])}


def publish_csv(directory, run_id, evidence):
    result = {}
    for kind, data in artifacts(evidence).items():
        name = run_id + "-" + kind + ".csv"
        path = directory / name
        temporary = path.with_suffix(".pending")
        temporary.write_bytes(data)
        temporary.replace(path)
        result[kind] = {"file": name, "sha256": sha(data), "bytes": len(data)}
    return result


def partial_csv(directory, run_id):
    """Describe surviving files after a publication error; none can qualify."""
    result = {}
    for kind in ("sessions", "completions", "summary"):
        name = run_id + "-" + kind + ".csv"
        path = directory / name
        try:
            if not path.exists():
                continue
            require(not path.is_symlink(), "partial_csv_symlink")
            with path.open("rb") as stream:
                data = stream.read(8 * 1024 * 1024 + 1)
            require(len(data) <= 8 * 1024 * 1024, "partial_csv_limit")
            result[kind] = {"file": name, "sha256": sha(data), "bytes": len(data),
                            "qualified": False, "publication_complete": False}
        except Exception:
            result[kind] = {"file": name, "status": "unreadable_partial_artifact",
                            "qualified": False, "publication_complete": False}
    return result
