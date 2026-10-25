#!/usr/bin/env python3
"""Convert the coordinator's pinned sample manifest to private Rust literals.

This preserves all 32 selections; it does not filter, execute, or decode them.
"""
import sys
if sys.flags.optimize:
    raise SystemExit("proof/generation scripts require assertions; optimized Python is refused")

import hashlib
import json
from pathlib import Path
import generate as generator

root = Path(__file__).resolve().parent
manifest = json.loads((root / "samples.json").read_text())
assert len(manifest["selected"]) == 32
rows = []
runtime_rows = []
for index, sample in enumerate(manifest["selected"]):
    data = bytes.fromhex(sample["bytes"])
    assert len(sample["heads"]) == 2 and sample["heads"][0] == 0
    first_len = sample["heads"][1]
    assert first_len >= 5 and len(data) == first_len + 1 and data[-1] == 0xC3
    assert sample["virtual_address"] % 64 <= 59
    case = generator.make(512 + index, "b1", 0)
    case.update(family="sample_b1", input_sha256=hashlib.sha256(data).hexdigest(),
                code=sample["bytes"], heads=sample["heads"],
                native_paths=[sample["heads"], sample["heads"][1:]],
                state_seeds=[0x1234567887654320, 0xFEDCBA9801234567],
                alignment=sample["virtual_address"] % 64, selected=0, physical=0,
                selected_len=first_len, block_start=0, block_end=first_len,
                expected_primary_installed=4, expected_primary_retired=4,
                expected_primary_events=2)
    runtime = dict(id=512+index, binary_sha256=manifest["binary_sha256"],
                   source_virtual_address=sample["virtual_address"],
                   source_file_offset=sample["file_offset"], segment=sample["segment"],
                   bytes=sample["bytes"], heads=sample["heads"],
                   state_seeds=case["state_seeds"], memory_seed=case["memory_seed"],
                   source_alignment=case["alignment"], forced="B1",
                   expected="positive", expected_installed=4, expected_retired=4,
                   expected_events=2)
    runtime["input_sha256"] = hashlib.sha256(json.dumps(runtime, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    case["input_sha256"] = runtime["input_sha256"]
    runtime_rows.append(runtime)
    rows.append(generator.rust_case(case))
(root / "sample-cases.rs").write_text(
    "// Private adapter of root-owned pinned sample manifest. No native execution.\n"
    "const SAMPLES: &[Case] = &[\n" + "\n".join(rows) + "\n];\n")
(root / "sample-runtime.json").write_text(json.dumps(runtime_rows, indent=2)+"\n")
print("32 unchanged pinned samples adapted; 128 installed + 128 retired required")
