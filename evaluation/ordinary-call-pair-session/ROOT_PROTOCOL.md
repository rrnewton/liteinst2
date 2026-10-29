# Public root protocol for CallPair input sessions

This separate owner freezes and invokes one fixed CallPair input-session campaign. The native owner stays byte-identical at SHA256 `5665c1dd0b98ff0884fd3132ed807b33e814463d226158f532ea4605ea90b7e5`; neither that owner nor the native receipt helper is replaced. Source freezing, wrapper closure, native acceptance and session acceptance are distinct checks.

Commit the native public sources, session components, corrected campaign and these three public files together before choosing the exact revision. A native prerequisite from a different revision cannot be reused. The source freezer requires a clean tracked tree and joins every selected file to that exact Git revision. Failed attempts and their files must remain; the deterministic destinations cannot be reset or overwritten for a favorable retry.

## Explicit source and prerequisite inputs

Provide canonical absolute paths in `REPOSITORY`, `PYTHON`, `TOOLCHAIN`, `CARGO_HOME`, `USER_HOME` and `ALLOCATOR_ROOT`; `REVISION` is the full 40-hex commit. Use the same Python executable, toolchain and homes as the native prerequisite. `HARDWARE_LABEL` is an operator-supplied printable label, not a hardware observation or performance assertion.

The allocator source repository is <https://github.com/rrnewton/agent-utils>, pinned to commit `d0c2867be75b495eb64239e664c6306af9747783`. The immutable native freezer supplies the exact map of all31 `py/dagrun/*.py` sources, whose canonical JSON SHA256 is `5f47ef0ee344f8e28bdb200e2ae21bab2c4a276d2746d73c204410a2a798d212`. The freezer checks the allocator revision, clean tracked source, exact Python file set and Git bytes; it does not connect to a ledger or reserve CPUs.

First follow `evaluation/ordinary-call-pair-native/ROOT_PROTOCOL.md` at the same committed revision. That process creates its own source-frozen protocol and performs the separate fixed192-pair native attempt. It also materializes the unchanged launcher bytes at `ignored/a5/normal-call-pair-launch-source-v1/launch.py`, as required by existing receipt controls. This session freezer requires that identical compatibility source; it does not modify it.

Only after independently auditing a successful, fully closed native prerequisite may root create the canonical seven-field manifest described in the native document. The manifest fields are exactly `schema`, `version`, `revision`, `profile`, `protocol`, `launcher_result`, and `recipe_result`. It contains no acceptance flag. Root must bind the native protocol's independently retained path/size/hash and the actual unchanged root and recipe results, after closure and their complete source, artifact, native-state, retention and census checks. A hash-consistent JSON file by itself is not a successful prerequisite.

Set `NATIVE_PROTOCOL` and `NATIVE_PROTOCOL_SHA256` to that independently retained protocol pin, and `NATIVE_RECEIPT` and `NATIVE_RECEIPT_SHA256` to the independently audited manifest pin. Both must be canonical regular files under this repository's `ignored/`, outside the new session destinations. Do not use this freezer to discover or certify a favorable native result.

## Freeze source without executing the campaign

From the canonical repository root:

```sh
"$PYTHON" -I -B "$REPOSITORY/evaluation/ordinary-call-pair-session/freeze.py" \
  --revision "$REVISION" --toolchain "$TOOLCHAIN" \
  --cargo-home "$CARGO_HOME" --user-home "$USER_HOME" \
  --allocator-root "$ALLOCATOR_ROOT" --hardware-label "$HARDWARE_LABEL" \
  --native-protocol "$NATIVE_PROTOCOL" --native-protocol-sha256 "$NATIVE_PROTOCOL_SHA256" \
  --native-receipt "$NATIVE_RECEIPT" --native-receipt-sha256 "$NATIVE_RECEIPT_SHA256"
```

If the hard allocator requires an explicit session bus, append `--xdg-runtime-dir "$XDG_DIRECTORY"` and `--dbus-session-bus-address "$BUS_ADDRESS"`. The supported bus form is one canonical existing filesystem Unix socket, `unix:path=...` with an optional lowercase32-hex `guid`; abstract, alternate and inherited addresses are not accepted. No bus connection occurs in freezing.

The freezer authenticates bootstrap bytes against clean Git and fixed helper hashes before compiling held shared source. It pins thirteen actual executables: Python, Git, du, systemd-run, true, Cargo, rustc, rustdoc, gcc, readelf, objdump, bash and rg. The actual launch PATH must resolve `systemd-run`, `true`, and Rust's default `cc` to their pinned tools (`cc` to gcc), including after the invocation. Compiler subtool checks remain the campaign's unchanged bounded stages.

The source inventory is the exact campaign selector union, plus the native owner's exact selector union and both public owner/freezer/document sets. It includes `src`, `crates`, `tests/support`, `tools/rapid-profiler`, `.cargo`, Cargo manifests and the explicit helper/corpus/control sources. No evaluation result tree is selected. Every source and tool retains its first pin; final verification cannot refresh a changed value.

Fresh paths are deterministic:

| Purpose | Repository-relative path |
| --- | --- |
| Source freeze directory | `ignored/a5/call-pair-session-public-<REVISION>/` |
| Protocol | `<freeze directory>/protocol.json` |
| Source marker | `<freeze directory>/source-frozen.json` |
| Campaign raw evidence | `<freeze directory>/call-pair-session-<REVISION>/` |
| Outer owner evidence | `<freeze directory>/owner/` |
| Outer owner log directory | `target/evaluation/call-pair-session-owner-<REVISION>/` |
| Campaign inner log directory | `target/evaluation/call-pair-session-<REVISION>/` |

The exclusive initial `freeze-attempt.json` remains failed unless a final `SOURCE_FROZEN_UNRUN` marker is created. All native metadata, source, tool, allocator, compatibility source and path checks repeat before that marker. Freezing performs no allocator, compiler, test, campaign or native execution, and reads neither native result file named by the manifest. The marker is source authority only; its `qualification_attempts` remains zero.

## One invocation and its authority

Root must review the source marker, full command, explicit environment, independently supplied hardware label and unchanged prerequisite pins. Take `PROTOCOL` and `PROTOCOL_SHA256` from the marker's `protocol` entry, retaining that original pin. Invoke once:

```sh
"$PYTHON" -I -B "$REPOSITORY/evaluation/ordinary-call-pair-session/launch.py" \
  --protocol "$PROTOCOL" --sha256 "$PROTOCOL_SHA256"
```

There is one allocator invocation with `run --cores 3 --sample-s 1`; the whole recipe tree is hard-pinned by the unchanged allocator. The retained reservation record must list three distinct CPUs. Their sorted order defines controller, worker and producer. Record the operator's hardware label, actual reserved roles, exact revision/command/environment and the owner's load-before/load-after values. The joined ordinary allocator return is not an independent ledger readback.

The deadline is7200 seconds from initial launcher start, never reset. Its bounded owner receives only the remaining time, with the unchanged three-second cleanup bound and8MiB outer log limit. Final wrapper success also requires the original deadline. The prospective space check adds2GiB retained evidence,1GiB build allowance and24MiB wrapper allowance to current slot size and requires the sum below20,000,000,000 bytes. These are planning allowances, not a filesystem quota or free-space guarantee.

The owner reads the combined log only after complete owned closure and a hash join. Unknown cleanup causes failure without reading that log or campaign artifacts. It requires the exact reservation line and one campaign JSON line containing only `profile`, `status`, `summary_sha256`, and `outcomes_sha256`. There is no campaign `custody_closed` stdout field. Extra diagnostics, duplicate keys, wrong profile, missing hashes or abnormal allocator return fail the join. A safely closed recipe exit1 remains failed; even a preceding PASS summary cannot override that exit (the campaign's final deadline check follows its print).

The wrapper records closure and retained source/prerequisite pins. `CLOSED_EXIT_0_RECIPE_AUDIT_REQUIRED` is not campaign acceptance. Root must still inspect the authoritative actual invocation exit and closure before inspecting hash-joined recipe files, and verify custody, retention, native acceptance, all395 stages, eight malformed references,32 accepted references,320 installed children and all five complete qualification outcomes. The fixed K10/K1000 ordering,32 cases,520 epochs, E3 banks and2ms/10ms/2s schedule gates remain the recipe's unchanged checks. Failure, missing outcomes and UNRUN suffixes remain visible; no retry, subset or replacement population is permitted.

Only after that audit may root publish the compact numeric outcome projection and exact receipt pins. Keep raw logs/artifacts private under ignored evidence paths, and omit absolute paths, account names and private host identifiers from public reports. This route grants no performance, full-worker architectural-state, new native or broader A5 claim.
