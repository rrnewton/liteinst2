#!/usr/bin/env python3
"""Static inventory/proof checks, optionally followed by complete result audit.

This program never executes native code. Missing results remain incomplete.
"""
import sys
if sys.flags.optimize:
    raise SystemExit("proof/generation scripts require assertions; optimized Python is refused")

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
args = argparse.ArgumentParser()
args.add_argument("--results", type=Path, help="parent of 0000..0543 result directories")
options = args.parse_args()
manifest = json.loads((ROOT / "generated.json").read_text())
samples = json.loads((ROOT / "samples.json").read_text())["selected"]
sample_runtime = json.loads((ROOT / "sample-runtime.json").read_text())
cases = manifest["cases"]
assert [case["id"] for case in cases] == list(range(512))
assert len(samples) == 32
assert [sample["id"] for sample in sample_runtime] == list(range(512,544))
assert manifest["generator_sha256"] == hashlib.sha256((ROOT / "generate.py").read_bytes()).hexdigest()


def window(case, code, prefixes=None):
    prefixes = case["prefixes"] if prefixes is None else prefixes
    free = case["selected_len"] - prefixes - 1
    start = case["selected"]
    word = bytes(free) + code[start + case["selected_len"]:start + 5 + prefixes]
    assert len(word) == 4
    low = start + 5 + prefixes + int.from_bytes(word, "little", signed=True)
    return low, low + (1 << (8 * free))


def intersects(a, b):
    return a[0] < b[1] and b[0] < a[1]


for case in cases:
    # Existing xstate seeding uses checked debug additions, not modulo-u64.
    # All fixed seeds are proved safe for the helper's full 64-KiB buffer;
    # no seed is changed, retried, filtered, or replaced by this assertion.
    assert all(seed + 65536*29 + 7 < (1 << 64) for seed in case["state_seeds"])
    original = dict(case)
    actual_hash = original.pop("input_sha256")
    assert hashlib.sha256(json.dumps(original, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == actual_hash
    data = bytes.fromhex(case["code"])
    assert case["alignment"] + len(data) < 2048
    assert len(case["heads"]) == len(case["native_paths"]) == len(case["instructions"])
    cursor = 0
    for instruction, head in zip(case["instructions"], case["heads"]):
        assert cursor == instruction["pc"] == head
        cursor += instruction["length"]
        assert cursor <= len(data)
        if instruction["jump"] is not None:
            assert instruction["jump"] in case["heads"]
            if instruction["mnemonic"] != "call":
                assert instruction["jump"] > head
                assert data[head] == 0xEB
                assert head + 2 + int.from_bytes(data[head+1:head+2], "little", signed=True) == instruction["jump"]
    assert cursor == len(data)
    assert max(map(len, case["native_paths"])) == case["max_native_steps"]
    assert case["max_native_steps"] <= len(case["heads"]) + 1
    assert {path[0] for path in case["native_paths"]} == set(case["heads"])
    assert all(path[-1] in case["heads"] and data[path[-1]] == 0xC3 for path in case["native_paths"])
    if case["target_kind"] in ("pun", "successor"):
        if case["target_kind"] == "successor":
            victim = case["victim"]
            overlay = bytearray(data)
            overlay[victim:victim+5] = bytes([0xE9]) + case["victim_delta"].to_bytes(4, "little", signed=True)
        else:
            overlay = data
        low, high = window(case, overlay)
        target = low + (high-low)//2
        # Coordinates are relative to the aligned oracle page, independently
        # including each original alignment and selected instruction offset.
        mapped = ((target+case["alignment"]) & ~4095,
                  ((target+case["alignment"]) & ~4095)+8192)
        if case["target_kind"] == "successor":
            old = window(case, data)
            assert not intersects(mapped, (old[0]+case["alignment"],old[1]+case["alignment"]))
        if case["prefixes"]:
            for other in range(case["selected_len"]):
                if other != case["prefixes"]:
                    old = window(case, overlay, other)
                    assert not intersects(mapped, (old[0]+case["alignment"],old[1]+case["alignment"]))
        if case["expected"] == "allocation_refusal":
            policy = (case["selected_delta"] & ~4095, (case["selected_delta"] & ~4095)+4096)
            assert not intersects(policy, (low+case["alignment"],high+case["alignment"]))
    if case["target_kind"] == "neighbor":
        selected = case["alignment"] + case["selected"]
        victim = case["alignment"] + case["victim"]
        assert selected//64 == (selected+1)//64
        assert victim//64 == (victim+9)//64
        assert -128 <= victim+5-(selected+2) <= 127
        body = data[case["victim"]:case["victim"]+case["victim_len"]]
        assert body[:case["victim_len"]-10] == bytes([0x2E])*(case["victim_len"]-10)
        assert body[case["victim_len"]-10:case["victim_len"]-8] == bytes([0x48,0xB8])
    if case["family"] == "ownership":
        word = bytes([128]) + data[2:5]
        target = case["alignment"] + 5 + int.from_bytes(word,"little",signed=True)
        owner_pages = (target & ~4095,(target & ~4095)+8192)
        main_pages = (case["selected_delta"] & ~4095,(case["selected_delta"] & ~4095)+8192)
        assert not intersects(owner_pages,main_pages)

summary = dict(
    generated=512, samples=32,
    original_entries=sum(len(case["heads"]) for case in cases)+sum(len(sample["heads"]) for sample in samples),
    original_traces=2*(sum(len(case["heads"]) for case in cases)+sum(len(sample["heads"]) for sample in samples)),
    primary_installed=manifest["primary_installed"]+128,
    primary_retired=manifest["primary_retired"]+128,
    auxiliary_installed=manifest["auxiliary_installed"],
    auxiliary_retired=manifest["auxiliary_retired"],
    primary_events=manifest["primary_events"]+64,
    auxiliary_events=manifest["auxiliary_events"],
    refusal_preservation_traces=sum(2*len(case["heads"]) for case in cases if case["expected"] in
                                  ("allocation_refusal","call_refusal","cet_refusal")),
    max_original_visits=max(case["max_native_steps"] for case in cases),
    outcomes=manifest["expected_outcomes"], native_execution="NOT_EXECUTED_BY_THIS_AUDIT")

if options.results:
    missing = []
    counts = Counter()
    for case_id in range(544):
        path = options.results / f"{case_id:04d}" / "events.txt"
        if not path.is_file():
            missing.append(case_id)
            continue
        lines = path.read_text().splitlines()
        starts = [line for line in lines if line.startswith("started ")]
        complete = [line for line in lines if line.startswith("complete ")]
        if len(starts) != 1 or len(complete) != 1:
            missing.append(case_id)
            continue
        assert f"id={case_id} " in starts[0]
        frozen_input = cases[case_id] if case_id < 512 else sample_runtime[case_id-512]
        assert f'input_sha256={frozen_input["input_sha256"]} ' in starts[0]
        record = dict(re.findall(r"(\w+)=([^ ]+)", complete[0]))
        case = cases[case_id] if case_id < 512 else None
        expected_installed = case["expected_primary_installed"] if case else 4
        expected_retired = case["expected_primary_retired"] if case else 4
        expected_events = case["expected_primary_events"] if case else 2
        assert int(record["primary_installed"]) == expected_installed
        assert int(record["primary_retired"]) == expected_retired
        if expected_installed:
            assert int(record["verified_primary_events"]) == expected_events
            assert record["outcome"] == (case["expected"] if case else "positive")
        else:
            assert record["outcome"] == "expected_refusal"
        expected_auxiliary = 2*len(case["heads"]) if case and case["family"] == "ownership" else 0
        assert int(record.get("auxiliary_installed",0)) == expected_auxiliary
        assert int(record.get("auxiliary_retired",0)) == expected_auxiliary
        expected_auxiliary_events = 2 if expected_auxiliary else 0
        assert int(record.get("verified_auxiliary_events",0)) == expected_auxiliary_events
        observations = [line for line in lines if line.startswith("memory_observation ")]
        phases = {re.search(r"phase=([^ ]+)", line).group(1) for line in observations}
        expected_phases = {"primary-installed","primary-retired"} if expected_installed else set()
        if expected_auxiliary:
            expected_phases |= {"owner-installed","owner-retired"}
        assert phases == expected_phases and len(observations) == len(expected_phases)
        for phase in expected_phases:
            for suffix in ("maps.txt","trampoline-smaps.txt"):
                capture = path.parent / f"{phase}-{suffix}"
                assert capture.is_file() and capture.stat().st_size > 0
        for key in ("primary_installed","primary_retired","auxiliary_installed","auxiliary_retired"):
            counts[key] += int(record.get(key,0))
        counts["primary_events"] += int(record.get("verified_primary_events",0))
        counts["auxiliary_events"] += int(record.get("verified_auxiliary_events",0))
        if case and case["family"] in ("collision","ownership"):
            assert sum(line.startswith("required_negative=") for line in lines) == 1
        counts["inputs_completed"] += 1
    summary["results"] = dict(counts)
    summary["missing_or_incomplete_ids"] = missing
    print(json.dumps(summary, indent=2))
    assert not missing, "fixed 544-input campaign incomplete; no skipped input is success"
    for key in ("primary_installed","primary_retired","auxiliary_installed","auxiliary_retired", "primary_events", "auxiliary_events"):
        assert counts[key] == summary[key]
else:
    print(json.dumps(summary, indent=2))
