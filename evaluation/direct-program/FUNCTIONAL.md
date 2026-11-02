# Direct GNU cat experiment — source only, UNRUN

The selected source consists of `reproduce.py`, `direct_support.py`, `direct_data.py`, and `native_exec.py`. Their intended tracked directory is `evaluation/direct-program/`. They add no decoder, CFG builder, placement search or process supervisor. `evaluation/admission/processes.py` is the pinned existing owner. The complete source revision must be clean and all four files tracked before either phase can run. Root alone dispatches after source review and the current Rust campaign closes.

The separately built GNU coreutils 9.5 cat must have a CLOSED `READY_BUILT_UNEXECUTED` receipt, the exact `cd328ede…` source archive, unchanged artifact bytes, and ET_EXEC header. The currently installed ET_DYN `/usr/bin/cat` is not a substitute. A future artifact/source identity is not filled in here.

From the repository root, with one externally reserved CPU, the build-phase command is:

```sh
/usr/bin/python3.9 -I -B evaluation/direct-program/reproduce.py build \
  --revision "$REV" --work "$BUILD_WORK" --toolchain "$TOOLCHAIN" \
  --cargo-home "$CARGO_HOME" --user-home "$USER_HOME"
```

`BUILD_WORK` is fresh under `ignored/`. This performs one metadata invocation and one combined release Cargo invocation selecting only the two rewrite examples and `elf-exec-oracle`. It records all three actual Cargo product profiles/fresh flags and hashes. It does not run any product. The build has a separately admitted 128 MiB incremental storage reserve, outside the functional 1 GiB physical-memory scope; source/configuration observations do not claim a complete sysroot or absence of inaccessible Cargo configuration.

Once both cat and Rust build receipts have closed and their durable owners have been reviewed, run one functional attempt in the existing externally owned systemd scope pattern:

```sh
/usr/bin/systemd-run --user --scope --collect --quiet --unit="$UNIT" \
  -p "AllowedCPUs=$CPU" -p CPUQuota=100% -p MemoryMax=1073741824 \
  -p MemorySwapMax=0 -p TasksMax=64 -- \
  /usr/bin/python3.9 -I -B evaluation/direct-program/reproduce.py functional \
  --revision "$REV" --work "$FUNCTIONAL_WORK" --unit "$UNIT" \
  --cat-receipt "$CAT_CLOSED" --cat-receipt-sha256 "$CAT_CLOSED_SHA" \
  --build-receipt "$BUILD_CLOSED" --build-receipt-sha256 "$BUILD_CLOSED_SHA" \
  --trusted-complete-code
```

`UNIT` starts with `li2core-direct-cat-`; work/log namespaces must be fresh. Root wraps each top-level command with the existing owner, retains its durable owner before captures, and declares its whole-driver wall bound before dispatch. The child script checks the actual scope properties on every dispatch, not merely this command spelling. The original host CPU reservation is root-owned; no independent scheduler-quiescence claim follows.

The input premise is explicit: complete code and nonoverlapping original instruction heads supplied by the caller, no code-as-data or unreported entries into displaced bytes, and a private image. The provider CSV is independently decoded by the existing bridge but is not proof of whole-binary CFG completeness or page-exemption authority. Modern provider and PLDI2020 backend identities are fixed separately. A current `elf-exec-oracle target` observation supplies the actual saved-state layout. No historical target descriptor substitutes for it.

Every imported site receives exactly one fixed search row and selected/victim permit rows, in original order, without preferences. Domain 7, arena `[0x01000000,0x20000000)`, existing numerical limits, carrier-after-LOADs and lowest C3 candidate are predeclared. The existing binder and later ownership checks can refuse. The actual planner is `--whole-program-packed-entry-veneer-mixed-neighbors-4096`; there is no fallback mode. LI2's no-effect null hook and E9's passthrough trampoline are distinct mechanisms, recorded as such.

The three stdin cases are empty, all 256 bytes repeated 256 times, and `alpha\n\nbeta\nomega` with `-n`. Expected output for the last is exactly `     1\talpha\n     2\t\n     3\tbeta\n     4\tomega`, with no final LF. Every arm uses regular-file stdin, piped stdout, argv[0] `cat`, a fresh working directory, identical locale, and an empty-stderr requirement. All nine rows exist before input authentication. The native helper only authenticates/open FDs, redirects and calls `execve`; it neither supervises nor invokes a shell. `ENOEXEC` is retained explicitly.

All stage bounds are in `direct-stages-proposal.md` and the exact source. The new generation file cap is 64 MiB, not the old 512 MiB profile. Cat executions retain 2 GiB AS /20 CPU /30 wall seconds; only backend generation uses 36 GiB virtual AS within the 1 GiB physical scope. The functional reserve is 160 MiB, separately admitted after the cat/build footprints are measured. Owned full-slot scans check original ceilings and incremental/namespace usage; no deletion, capacity increase or retry is automatic. Incomplete cleanup forbids payload reads and follow-up processes.

Complete inventories, source files, requests, outcomes, refusal reports, stdout/stderr, owners and exact artifacts remain in the private namespace. Clean rewrite refusal leaves the dependent arm's three cases UNOBSERVED; independent original/E9 work can proceed if global guards pass. An E9 output with misses can pass exact functional comparisons but cannot pass full N/N coverage. Historical 1,035 misses/action pairs, prior strict failures and all earlier execution profiles remain unchanged. This finite experiment grants neither universal CFG completeness nor page exemption.
