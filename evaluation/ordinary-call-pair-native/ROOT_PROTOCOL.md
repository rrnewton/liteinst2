# Public root protocol for original-address CallPair native qualification

This is the public composition of the existing native recipe and its unchanged
root owner. `launch.py` has SHA256
`5665c1dd0b98ff0884fd3132ed807b33e814463d226158f532ea4605ea90b7e5`.
It retains 37 stages, one 192-pair cohort, three hard-reserved CPUs, the middle
CPU for native parent/tracees, 15-second/20,000-step pair limits, and the existing
480-CPU-second/510-wall-second native owner. Its outer limit is 1,200 seconds
with an 8 MiB log. No retry, fallback or partial-population acceptance is added.

The owner records invocation and closure. Its exit-zero status still says
`CLOSED_EXIT_0_RECIPE_AUDIT_REQUIRED`. A source freeze, local numeric transcript,
root-manifest JSON or successful wrapper exit alone is not native acceptance.
No Schedule, K-exhaustion, FunctionClosed, bank-reuse, whole-worker, performance
or full-A5 claim follows from this native profile.

## Freeze from public sources

Integrate these three files and commit them before use. When this prerequisite
will feed CallPair session qualification, commit the native, receipt-helper and
intended session sources before choosing that one shared revision; adding those
sources after freezing would break the exact-revision join. Start from an exact,
clean tracked revision, with its offline dependencies and release toolchain
available. Choose canonical absolute paths for the repository, toolchain,
Cargo home, user home, Python executable and allocator repository. The allocator
must be at `d0c2867be75b495eb64239e664c6306af9747783`; all 31 Python sources are
checked against the embedded map whose canonical SHA256 is
`5f47ef0ee344f8e28bdb200e2ae21bab2c4a276d2746d73c204410a2a798d212`.

The shell variables below are named inputs supplied by the operator; no user,
host, UID, bus address or allocator ledger location is guessed. `XDG_DIR` and
`BUS_ADDRESS` are optional explicit existing-session inputs: omit both option
lines when unused. Supported bus addresses have one `unix:path=` filesystem
socket, optionally followed by a lowercase 32-hex `guid`. The freezer checks
that supplied paths are canonical and that the bus path is a socket; it does
not connect to the bus or certify its service.

```sh
"$PYTHON" -I -B "$REPOSITORY/evaluation/ordinary-call-pair-native/freeze.py" \
  --revision "$REVISION" --toolchain "$TOOLCHAIN" \
  --cargo-home "$CARGO_HOME_DIR" --user-home "$USER_HOME_DIR" \
  --allocator-root "$ALLOCATOR_ROOT" \
  --xdg-runtime-dir "$XDG_DIR" --dbus-session-bus-address "$BUS_ADDRESS"
```

`freeze.py` requires assertions and isolated Python. It authenticates its own
source, this document, the exact launcher and the bounded process owner against
clean Git before compiling the held launcher bytes. It does not import a
protocol template or execute a recipe, allocator, compiler or qualification.
It pins all 13 actual executable tools, checks `systemd-run`, `true` and `cc`
resolution under the exact launch PATH, and creates the owner's complete source
inventory with its unchanged COMMON/EXTRA selectors, including `crates`, `.cargo`
and Cargo manifests. The public freezer/document are independently pinned in
the final marker because the unchanged owner selector does not include them.
The recipe retains its own compiler-subtool discovery and pins.

The fixed per-revision directory is
`ignored/a5/call-pair-public-<REVISION>/`. It contains `protocol.json`, an initial
immutable `freeze-attempt.json`, and, only after final source/tool/allocator
rechecks, `source-frozen.json` with status `SOURCE_FROZEN_UNRUN`. Any exception
retains the attempt and, once the guarded publication section starts, a
`freeze-failure.json`; a failure is never repaired by deleting or overwriting
these files. The fixed raw/capture/outer-log/inner-log destinations must all be
fresh. A failed attempt is not permission to change the revision label, create
a retry suffix or start another qualification.

For unchanged receipt controls, freezing also materializes the authenticated
tracked `launch.py` bytes at
`ignored/a5/normal-call-pair-launch-source-v1/launch.py`. An existing identical
copy is accepted; a symlink or different file is refused and never overwritten.
The actual protocol deliberately names the tracked launcher. The receipt
helper authenticates that caller-supplied absolute path and the same fixed SHA.

The protocol records prospective allowances of 2 GiB retained evidence,
1 GiB build space and 24 MiB wrapper evidence, within a strict 20,000,000,000-byte
slot projection. The unchanged owner measures slot size and applies that test
before launching. These allowances are not a quota or a promise of free space
or elapsed fit. Source freezing happens before the owner starts; it does not
renew or reset any qualification deadline.

## One owner invocation

Root must review the exact source-frozen marker, absence of a freeze failure,
protocol hash, source/tool/allocator pins and prospective space plan, and retain
exclusive custody of these sources and destinations. Supply the exact
`protocol.path` and `protocol.sha256` from the marker, without recomputing a new
expected hash after mutation:

```sh
"$PYTHON" -B "$REPOSITORY/evaluation/ordinary-call-pair-native/launch.py" \
  --protocol "$PROTOCOL" --sha256 "$PROTOCOL_SHA256"
```

This executes the single hard-reservation command encoded by the unchanged
owner. The owner captures load before/after, selected cores, command/environment,
normal closure and immutable joins. It reads the allocator log only after the
bounded owner reports complete cleanup, then joins the log hash and exact
allocator return. This is the pinned allocator context-manager return, not a
new independent ledger readback. Preserve failures, signals, unexpected
children, missing output, partial numeric prefixes and all remaining UNRUN
slots. Neither freezer nor owner repairs, retries or promotes them.

## Root manifest after a successful closed prerequisite

Root must first audit actual, normally closed zero-exit ownership and all
37 stages, complete 192-pair/12-coverage-row output, retained first pins,
source/tool/compiler-subtool/artifact identity, original-address caller and E8
geometry, distinct candidate/trusted inodes, all comparisons, and normal reaps.
Do not inspect child logs before their exact closure and hash join. Source and
artifact expectations for the later session must come from independently
authenticated inputs and retained geometry, not from a result's claim of
acceptance. Keep the closed evidence under exclusive no-writer custody.

The root prerequisite manifest has exactly seven fields:

```json
{
  "schema": "call-pair-native-prerequisite-v1",
  "version": 1,
  "revision": "<EXACT_REVISION>",
  "profile": "normal-call-pair-original-rust-v1",
  "protocol": {"path": "<PROTOCOL>", "bytes": 0, "sha256": "<PIN>"},
  "launcher_result": {"path": "<CAPTURE_RESULT>", "bytes": 0, "sha256": "<PIN>"},
  "recipe_result": {"path": "<RAW_RESULT>", "bytes": 0, "sha256": "<PIN>"}
}
```

Zeros and angle-bracket names above are schema placeholders, never a receipt.
After the audit, this serialization-only command derives the three pins from
held actual files, preserves their first bytes and creates a fresh manifest.
It performs no qualification and cannot supply the audit's external custody.
`PROTOCOL_SHA256` is the already retained source-freeze hash; `MANIFEST` is a
fresh canonical path inside the per-revision directory. Root retains the
printed manifest pin before any later session attempt.

```sh
"$PYTHON" -I -B - "$REVISION" "$PROTOCOL" "$PROTOCOL_SHA256" "$CAPTURE_RESULT" "$RAW_RESULT" "$MANIFEST" <<'PY'
import hashlib, json, os, stat, sys
from pathlib import Path
assert not sys.flags.optimize
revision, protocol, expected, outer, recipe, destination = sys.argv[1:]
def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')
def held(name, cap):
    p = Path(name); assert p.is_absolute() and p.resolve(strict=True) == p
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        before = os.fstat(f.fileno()); assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap
        data = f.read(cap+1)
        assert len(data) == before.st_size and identity(before) == identity(os.fstat(f.fileno())) == identity(p.lstat())
    return data
def pin(name, data):
    return dict(path=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
pb = held(protocol, 2*1048576); assert pin(protocol, pb)['sha256'] == expected
p = json.loads(pb); assert pb == canonical(p) and p['revision'] == revision
assert p['profile'] == 'call-pair-original-native'
assert outer == str(Path(p['paths']['capture'])/'result.json')
assert recipe == str(Path(p['paths']['raw'])/'result.json')
ob = held(outer, 262144); o = json.loads(ob)
assert o['status'] == 'CLOSED_EXIT_0_RECIPE_AUDIT_REQUIRED'
assert o['attempts'] == 1 and o['source_verified_after'] is True
c = o['closed']; assert c['cleanup_complete'] is True and c['termination'] is None
assert type(c['exit_code']) is int and c['exit_code'] == 0
assert type(c['reaped_descendants']) is int and c['reaped_descendants'] == 0
rb = held(recipe, 16*1048576); r = json.loads(rb)
assert r['status'] == 'CALL_PAIR_ORIGINAL_NATIVE_LOCAL_COMPLETE'
assert r['custody_closed'] is True and r['retention_verified'] is True
manifest = dict(schema='call-pair-native-prerequisite-v1', version=1, revision=revision,
    profile='normal-call-pair-original-rust-v1', protocol=pin(protocol,pb),
    launcher_result=pin(outer,ob), recipe_result=pin(recipe,rb))
for name, data in ((protocol,pb),(outer,ob),(recipe,rb)):
    assert held(name,len(data)) == data
out = Path(destination); assert out.is_absolute() and out.parent.resolve(strict=True) == out.parent
assert out.parent == Path(protocol).parent and not os.path.lexists(out)
data = canonical(manifest); assert len(data) <= 16384
with out.open('xb') as f: f.write(data)
assert held(str(out),16384) == data
print(json.dumps(pin(str(out),data),sort_keys=True))
PY
```

The authenticated `native_receipt.accept_native` helper still performs the full
source-bound audit. Its `expected` dictionary must contain exactly `revision`,
`protocol_pin`, `source_pins`, `tool_pins`, `module_pin`, `application_pin` and
`geometry`, frozen by root before the session. Source/tool maps are joined to
the existing Run; geometry contains independent parent/child/caller descriptors.
Only the helper's completed audit may yield `CALL_PAIR_NATIVE_PREREQUISITE_ACCEPTED`.
Manifest serialization itself emits no accepted status. If any audit fails,
retain the failure and leave the session prerequisites unqualified. This
procedure does not fabricate a native success or grant permission to rerun it.
