# Strict step attribution

One attempt on AMD EPYC Zen 5 dev host failed at the unchanged 20,000-step guard: 1 FAILED row, 31 UNOBSERVED, zero pairs. The diagnostic ELF recorded 17,810 steps after step 2,190: 15,833 in 52 main-ELF function ranges and 1,977 unclassified. Counts and plan are literal copies.

Counts exclude callees; inlined work belongs to its enclosing symbol. This prefix establishes no timing, speedup, whole-program cost, qualification or landing readiness. The 54.3868-second rebuild duration is operational. Prior results remain in [current-ret](../current-ret/receipt.json).

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.

`reproduce.py` is byte-identical to the executed private script; its public path is new. The commands and outer wrapper below are reproduction syntax, not the exact executed private wrapper. Run the entire sequence on one externally reserved CPU. Use `ROOT` for a clean checkout and `PUB` for a separate retained checkout/copy containing this publication, so it remains available across the source switch. Set absolute machine-local paths for the variables below; all output directories must be fresh.

First generate the four fixtures and CLOSED failed request with [state.py](../state.py) at the prior production revision:

```sh
FIXTURE_REV=3581ddb9309e98d1030d040d7a22586ae6c91df9
REV=8d65de7fc0c72ea1542ba46ecc37693ad398df8b
git -C "$ROOT" switch --detach "$FIXTURE_REV"
/usr/bin/python3.9 -I -B "$ROOT/evaluation/early-entry-module/state.py" --root "$ROOT" --revision "$FIXTURE_REV" --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" --output "$FIXTURES"
```

The strict recipe is expected to exit nonzero. Before continuing, authenticate its CLOSED result, cleanup and first `native-order01-k10-enabled` owner/request; an earlier preparation failure is not a usable fixture. Keep all outputs. Set `FIXTURE_REQUEST` to `FIXTURES/native-order01-k10-enabled/request.json`.

Then switch the same checkout to the diagnostic revision and build using [build.py](../ret-inline/build.py). Do not clean, retry, or run `state.py` at the diagnostic revision before this build: that would prebuild the same ELF and can violate the builder's required `fresh=false` Cargo product.

```sh
git -C "$ROOT" switch --detach "$REV"
/usr/bin/python3.9 -I -B "$PUB/evaluation/early-entry-module/ret-inline/build.py" --root "$ROOT" --revision "$REV" --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" --output "$BUILD" --logs "$BUILD_LOGS"
```

Create and review `input-pins.json` (`INPUT_PINS`) with four exact absolute path keys: `BUILD/closed.json`, `BUILD/artifact.json`, `FIXTURE_REQUEST`, and its sibling `closed.json`. Values are `{"bytes": N, "sha256": "..."}` from the exact file bytes.

`FIXTURES`, `BUILD`, `OUTPUT`, and `OWNER_OUTPUT` belong under `ROOT/ignored`; `BUILD_LOGS` belongs under `ROOT/target/evaluation`. Choose distinct fresh directory basenames for `OUTPUT`, `OWNER_OUTPUT`, and the build logs. Do not precreate `OUTPUT` or its `native-output` child. This wrapper uses the existing process owner for the whole driver at 240 seconds/1 MiB, writes its owner record durably before reading the log, and retains failures:

```sh
/usr/bin/python3.9 -I -B - "$ROOT" "$PUB" "$REV" "$BUILD" "$FIXTURE_REQUEST" "$OUTPUT" "$INPUT_PINS" "$OWNER_OUTPUT" <<'PY'
import hashlib, importlib.util, json, os, sys
from pathlib import Path
root, pub = (Path(s).resolve(strict=True) for s in sys.argv[1:3])
rev, build, fixture, output, inputs, owner_output = sys.argv[3:]
assert len(os.sched_getaffinity(0)) == 1
destination = Path(owner_output).absolute()
assert destination.resolve() == destination and not destination.exists()
destination.relative_to(root / 'ignored')
logs = root / 'target/evaluation' / destination.name
assert not logs.exists()
destination.mkdir(parents=True)
logs.mkdir(parents=True)
helper = root / 'evaluation/admission/processes.py'
assert hashlib.sha256(helper.read_bytes()).hexdigest() == '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
source = pub / 'evaluation/early-entry-module/step-attribution/reproduce.py'
assert hashlib.sha256(source.read_bytes()).hexdigest() == '0c67883d287f19e5cd83e0d319caa2c58ed683b495dbd7ea197bc7397d7dcd07'
spec = importlib.util.spec_from_file_location('owner', helper)
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
argv = ['/usr/bin/python3.9', '-I', '-B', str(source), '--root', str(root),
        '--revision', rev, '--build', build, '--fixture-request', fixture,
        '--output', output, '--input-pins', inputs]
env = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
record = owner.run_command(argv, env, logs / 'driver.log', 240, 1 << 20)
with (destination / 'owner.json').open('x') as f:
    json.dump(record, f, indent=2)
    f.write('\n'); f.flush(); os.fsync(f.fileno())
assert record['cleanup_complete'] and record['reaped_descendants'] == 0
data = (logs / 'driver.log').read_bytes()
assert len(data) <= 1 << 20
assert hashlib.sha256(data).hexdigest() == record['private_log_sha256']
with (destination / 'driver.log').open('xb') as f:
    f.write(data); f.flush(); os.fsync(f.fileno())
assert record['termination'] is None and record['exit_code'] == 0
PY
```

Raw logs stay ignored. The receipt binds the recorded bounds and custody; neither these reproduction instructions nor a completed diagnostic grants strict qualification credit.
