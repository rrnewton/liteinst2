# Accuracy attachment: focused controls

The build check, 35 Rust accuracy tests, three raw-wire tests and final strict Clippy passed. Python reader/truth/compatibility/legacy controls passed. The two earlier Clippy failures and new-driver fixture error remain in [receipt.json](receipt.json); the repaired driver then passed all 21 controls. Repeated and inherited tests are not counted as unique coverage.

Execution used `dd75e61346a04a5a5423007801407ae0bcebc97d` plus each captured overlay. The receipt joins those bytes to commits through `0ac5765ee6b3df5ba74c84b06737959dafa29ade`; these were not execution revisions. The 35 Rust tests preceded the unnecessary-unit and boxed-acquisition repairs. Final wire tests and Clippy used committed Rust bytes. All 52 final-overlay files match the final Git blobs; later STATE documentation was outside these runs.

All eight owners closed with source unchanged and no rescued descendants, including failed commands. Reserved CPUs, load, wall time, limits and raw owner/log hashes are recorded. These unoptimized control durations are not application performance. Exact compiler version/tool binaries were not pinned by these owners.

To reproduce corrected controls, check out the final source, set the receipt environment (`ROOT`, `TOOLCHAIN`, `USER_HOME`, `CARGO_HOME`, and fresh writable `TMP` are local substitutions), reserve four disjoint CPUs using cpuset-alloc, apply that affinity, and run the literal command arrays from `ROOT`. `${PYTHON_BATCH}` is this equivalent wrapper; the receipt retains the original wrapper hash:

```python
import json, subprocess, sys
from pathlib import Path
suites = json.loads(Path("evaluation/ordinary-accuracy-results/focused-v1/receipt.json").read_text())["python_batch"]["suites"]
failed = []
for path in suites:
    print("COMMAND", path, flush=True)
    rc = subprocess.run([sys.executable, "-B", path], timeout=120).returncode
    if rc:
        failed.append((path, rc))
print("FAILED", failed, flush=True)
raise SystemExit(bool(failed))
```

Use `/usr/bin/timeout 180 /usr/bin/python3.9 -B` for the wrapper, then the separate final driver command. The suite-list lookup differs from the original literal list. Earlier failures require their recorded older source variants. See [BUILD](../../ordinary-selected-session/BUILD.md) and [STATE](../../ordinary-selected-session/STATE.md) for the separate campaign.

Native accuracy remains **UNRUN: 192 pairs / 27,560 prospective state comparisons**. These controls do not qualify PMU metrics, cadence, the strict 2 ms gate, performance, full SDK state or executable-code reclamation. Earlier strict 2 ms failures stand. No assertion, population, deadline, comparator or failure status was relaxed.
