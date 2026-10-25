# Historical A5 reporting controls

[The result](results/generation-reporting-tools-20261025.json) records two successful reporting commands and four expected refusals. These commands ran from private script snapshots, so `tested_revision` is null. `source_repository_revision` identifies the public generation source used for reconstruction. It does not claim that these reporting scripts executed from that commit. The seven historical compiler/model/doc results exported by the reporting command are not new executions.

The commands below reproduce the controls with the same script bytes and request limits. They use the existing bounded helper; there is no new supervisor. They do not execute the formatter request produced by reconstruction, any compiler, or model/native tests. The templates and instructions are a new, unexecuted reproduction proposal; the JSON result describes the retained original captures.

Provide absolute local paths in `REPO`, `EVALUATION`, `RAW`, `TOOLCHAIN`, `MSRV_TOOLCHAIN`, `CARGO_HOME`, `USER_HOME`, `PYTHON`, `TIMEOUT`, `WRONG_TOOL`, and `EXPORT_INPUTS`. `EVALUATION` contains the published `prepare-generation.py`, `export-generation.py`, their reproduction material, and these reporting templates. `RAW` must be a fresh directory below `REPO/ignored` whose parent exists. `PYTHON` and `TIMEOUT` are the admitted interpreter and timeout tool; the original wrong-tool control used `/usr/bin/true`. Do not assign a different meaning to the shell's `HOME` variable.

Export requires the retained historical raw receipts and an independently reviewed local input JSON joining them. Raw host paths stay private. On another host, explicitly rebase only those raw paths/path substitutions, review the complete source/receipt/metadata join, and set `EXPORT_INPUTS_SHA256` to that reviewed file's SHA-256. Rebinding a local path does not create a new historical result or tool identity. The historical input digest is preserved in the result JSON. Without those raw captures, reconstruction and its negative controls remain reproducible, but an exact historical export cannot be fabricated from the summary alone.

The result pins exact script/tool bytes. Tool banners were not collected by these reporting controls. A different executable requires a new reviewed admission and result, not editing the recorded hashes. Hardware is an inherited same-host observation with no established phase relative to these six controls; elapsed times are operational diagnostics only.

Materialize the six requests and the exact wrong-source fixture without running them:

```sh
export REPO EVALUATION RAW TOOLCHAIN MSRV_TOOLCHAIN CARGO_HOME USER_HOME
export PYTHON TIMEOUT WRONG_TOOL EXPORT_INPUTS EXPORT_INPUTS_SHA256
"$PYTHON" -B - <<'PY'
from pathlib import Path
import hashlib, json, os, re, shutil, sys
if sys.flags.optimize:
    raise SystemExit("optimized preparation is forbidden")
def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(524288), b""):
            h.update(block)
    return h.hexdigest()
roles = {key: os.environ[key] for key in (
    "REPO", "EVALUATION", "RAW", "TOOLCHAIN", "MSRV_TOOLCHAIN", "CARGO_HOME",
    "USER_HOME", "PYTHON", "TIMEOUT", "WRONG_TOOL", "EXPORT_INPUTS", "EXPORT_INPUTS_SHA256")}
repo = Path(roles["REPO"]).resolve(strict=True)
raw = Path(roles["RAW"])
assert raw.is_absolute() and not raw.is_symlink()
raw = raw.resolve()
assert raw.is_relative_to(repo / "ignored") and raw != repo / "ignored"
assert raw.parent.is_dir() and not raw.exists()
roles["REPO"], roles["RAW"] = str(repo), str(raw)
evaluation = Path(roles["EVALUATION"]).resolve(strict=True)
roles["EVALUATION"] = str(evaluation)
templates_path = evaluation / "generation-reporting-requests.json"
assert sha(templates_path) == "d9a6fe9f44c0f7f256830f9c2c968af0cd769e12ffe81eb804bf2eed62e9e75b"
templates = json.loads(templates_path.read_text())
for name, expected in templates["scripts_sha256"].items():
    assert sha(evaluation / name) == expected
assert sha(repo / "tools/word-sync-oracle/bounded_command.py") == templates["helper_sha256"]
assert sha(roles["PYTHON"]) == "9cfdf1a01d07dadb394dd2dc9fd8316254c36764076d23dc2c895c8401735576"
assert sha(roles["TIMEOUT"]) == "8eb5abb15bad3a1d608c68272412f0d55c9100c64078ae083b4f8b0e746d781c"
assert sha(roles["WRONG_TOOL"]) != sha(roles["TIMEOUT"])
assert sha(roles["EXPORT_INPUTS"]) == roles["EXPORT_INPUTS_SHA256"]
source = {
    "tools/rapid-profiler/src/generation.rs": "b5ce2255f4aa27354a13d6a1ba27c131ca89a7a5d6a67df67af939e8d6486ebb",
    "tools/rapid-profiler/src/generation/tests.rs": "73199ffb0034e5d8658397aa77c547c899f8c9fcb23247d962a62649833e5a9f",
    "tools/word-sync-oracle/bounded_command.py": templates["helper_sha256"],
}
for name, expected in source.items():
    assert sha(repo / name) == expected
raw.mkdir()
wrong = raw / "wrong-source-repo"
for name, expected in source.items():
    dest = wrong / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("xb") as f:
        f.write((repo / name).read_bytes())
    assert sha(dest) == expected
with (wrong / "tools/rapid-profiler/src/generation.rs").open("ab") as f:
    f.write(b"\n// deliberate source identity mismatch control\n")
(wrong / "ignored").mkdir()
def expand(value):
    if isinstance(value, str):
        return re.sub(r"\$\{([A-Z0-9_]+)\}", lambda m: roles[m.group(1)], value)
    if isinstance(value, list):
        return [expand(v) for v in value]
    if isinstance(value, dict):
        return {k: expand(v) for k, v in value.items()}
    return value
for row in templates["requests"]:
    directory = raw / row["id"]
    directory.mkdir()
    request = expand(row["request"])
    assert (request["cpu_seconds"], request["wall_seconds"], request["file_bytes"]) == (20, 30, 16777216)
    with (directory / "request.json").open("x") as f:
        json.dump(request, f, indent=2, sort_keys=True)
        f.write("\n")
print("SIX_REQUESTS_PREPARED_NO_WORKLOAD_EXECUTED")
PY
```

Review the generated source/tool/input identities and all six requests before execution. Then run each request once through the unchanged helper. Each expected refusal must retain exit 1, its raw stderr, and an absent output directory; do not turn a nonzero exit into a successful command row.

The loop also retains the original root-operated outer timeout: TERM at 40 seconds, then KILL after a further 10 seconds. The request itself remains CPU 20 seconds / wall 30 seconds / file 16 MiB. The original outer JSON records retain exit/stream hashes rather than argv; the exact wrapper spelling is the root operator's stated command, not a reconstructed raw argv capture. A timeout exit cannot satisfy an expected command exit of 0 or 1.

```sh
set -eu
for CASE in export reconstruct wrong-source wrong-tool optimized-generator optimized-export; do
  EXPECTED=1
  case "$CASE" in export|reconstruct) EXPECTED=0;; esac
  set +e
  "$TIMEOUT" --signal=TERM --kill-after=10s 40s \
    "$PYTHON" -B "$REPO/tools/word-sync-oracle/bounded_command.py" \
    --request "$RAW/$CASE/request.json" --receipt "$RAW/$CASE/receipt.json" \
    >"$RAW/$CASE/helper.stdout" 2>"$RAW/$CASE/helper.stderr"
  OBSERVED=$?
  set -e
  test "$OBSERVED" -eq "$EXPECTED"
done
```

Independently audit the receipt request/helper hashes, all raw stdout/stderr, exit types and values, finite elapsed time, no timeout/abort/cleanup error, empty cleanup/descendant lists, `inputs_unchanged=true`, and `absence_proof=ECHILD`. Check the exporter produces exactly the five reviewed historical files, reconstruction exactly the four original source files, and all four negative output paths are absent. The wrong-source and wrong-tool tracebacks must identify their specific identity checks; optimized runs must print exactly `optimized Python is forbidden`. The original helper receipts and independent audit, including their metadata limitations, remain the result's evidence boundary. This procedure does not itself certify an arbitrary metadata description or a complete runtime dependency closure.
