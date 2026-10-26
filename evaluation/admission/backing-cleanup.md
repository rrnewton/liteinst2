# Exec backing cleanup helper evidence

This is an implementation and validation recipe, not a completed experiment.
Qualification requires a new successful receipt at the exact combined Rust and
recorder source. The earlier admitted-exec receipt does not qualify these
additional local resource-cleanup controls.

The existing six-command protocol naturally executes the ordinary-main Cargo
target `exec_backing_cleanup` in workspace and serial launch tests. Cargo must
announce the exact source `tests/exec_backing_cleanup.rs` and a binary named
`target/debug/deps/exec_backing_cleanup-<16 lowercase hex digits>`. An alternate
source, binary, directory or malformed header does not supply helper evidence.
The non-default development feature and self dev dependency select the reviewed
fixed-control library bridge. No required-feature skip, filter, additional
command, changed timeout or synthetic libtest summary is introduced.

The parent emits a bounded closed JSON protocol under
`LITEINST_BACKING_CLEANUP_V1 `: one begin record, four ordered trajectory records,
then one complete record. Each trajectory is emitted only after the parent
authenticates the child's private fixed receipt, terminal status, original
pidfd and authoritative physical reap. These rows are observations from that
reviewed program, not authentication against hostile code printing matching
JSON. Private maps, addresses, file descriptors, process identities, paths and
failure messages remain outside the public protocol.

| Trajectory | Control | Probes | Exact result |
| --- | --- | ---: | --- |
| `complete` | `admitted_exec_native_backing_probes_close_exact_owned_resources` | 6 | Connected assertions and owner cleanup; exit 0 |
| `read_error` | `admitted_exec_native_backing_read_and_unwind_preserve_cleanup` | 1 | Actual read EFAULT (14), owner cleanup; exit 0 |
| `unwind` | Same error/unwind control | 1 | Explicit injected unwind, owner cleanup; exit 0 |
| `invalid_unmap` | `exec_backing_native_invalid_unmap_aborts_isolated_owner` | 1 | Actual EINVAL (22), then SIGABRT in the same failed-release branch |

Every row requires exact index, identity, control, outcome, probe count, errno
and terminal enum, plus `physical_cleanup=true` and
`receipt_authenticated=true`. `owner_cleanup` is true only for the three
connected trajectories; it is false for the abort leaf. The leaf has no
application tracees. Parent-authenticated process teardown is not relabelled
as a successful unmap or successful application execution. The error/unwind
control needs both of its distinct child trajectories.

The parser accepts exactly those field sets and types. Booleans cannot replace
integers. Duplicate JSON keys, unknown fields/identities, reordered or duplicate
records, changed counts, alternate errno/status values, oversize records,
protocol outside the helper's Cargo block and forged libtest summaries all
invalidate the evidence. The first failure freezes the validated prefix; later
records cannot repair it. Invalid payload strings never enter public partial
observations or error codes. Missing observations remain explicitly unknown.

`backing_cleanup_harnesses` is a separate required corpus inventory for both
workspace and serial commands. The real runner validates that inventory before
executing any command. The recorder separates only the exact authenticated
helper block before calling the unchanged aggregate libtest parser. All other
output lines remain byte-identical, and the native fixture/CPU parsers still
receive the original capture. A helper failure and an old libtest failure are
independently retained; neither can conceal or qualify the other. Raw captures
remain saved in full with their hashes under the existing output limit.

The original 89 workspace and 27 serial libtest inventories remain exact:
1,731 workspace cases including four unchanged ignores, and 647 serial cases.
The 56 named native libtest fixtures, 50 static cases, 15 dynamic fixtures and
388 matrix rows remain unchanged. The new target contributes three separate
typed control outcomes and four trajectories, not three or four added libtest
methods. Fourteen additive Python calibrations change the recorder inventory
from 240 to 254 methods. Existing parser controls and the six argv/deadline
specifications remain required. The separate default unit/fork repetition
recipes continue selecting their original targets and do not execute this
helper.

Completed observations remain unqualified until the entire original protocol
passes with unchanged source/configuration and its existing command cleanup
gates. A complete helper transcript inside a failed command is retained but
cannot qualify. The receipt's explicit `backing_cleanup_required` gate checks
both exact complete helper observations again at whole-run qualification.

Run the original source-pinned protocol from the clean combined revision:

```sh
python3 evaluation/admission/run.py --expect-revision "$(/usr/bin/git rev-parse HEAD)"
```

These finite controls address local executable-backing resource custody and
fail-stop behavior. They do not add ordinary-application, full B3/B4,
preemption-clock or performance claims.
