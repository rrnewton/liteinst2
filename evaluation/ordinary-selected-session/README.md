`ordinary-interval normal-selected-session` accepts caller-selected scalar functions in one independently trusted final DSO. It uses the existing leaf-set loader, preparation, publication, actual CALL/RET worker, controller, journal, history and retirement paths. The selected functions need not implement one of the four built-in application operations. The old `normal-leaf-set-session` command and its output checks are unchanged.

The trusted-input CLI is:

```
ordinary-interval normal-selected-session CANDIDATE TRUSTED_FINAL TABLE K EPOCHS N \
  (ID LABEL ELF_VA EXTENT POLICY){N}
```

Both ELF paths identify the exact final bytes, including any stripping transformation. Selections are in increasing, disjoint ELF-VA order, have unique function IDs and unique labels, and describe complete functions. Labels are 1–24 ASCII identifier bytes beginning with a letter; they are metadata, never symbol lookup keys. Policy remains `certified` (extent 1–256) or `whole` (5–80). N remains 1–4; K is 10 or 1000; epochs are 1–520. The existing 64-byte printable CSV input grammar, min(2048,4096/N) records, 4096 calls, one/two complete source pages, three banks, 10 ms cadence, strict 2 ms arm bound and 2 s retirement bound remain in force.

A result table grants no permission to execute code. Before invoking this trusted-input tool, the caller must independently establish the unsafe contract of `LoadedNormalLeafSet::load_selected`: trusted complete final-ELF functions with SysV `(*const u8,usize)->u64` ABI, sole external entries and no saved interior resumes, readable immutable input bounds, terminating matching ordinary returns, one controlled caller at depth one, and quiescence during publication. Inter-function CALLs, recursion, tail entries, signals, unwind/nonlocal exit, cancellation, fork, active CET, writers, unload, code-as-data and later mapping/protection changes remain excluded. The complete DSO and process-lived code/control owners stay immutable except for the qualified publication. Decoding, labels, expected results or a Boolean contract cannot establish these premises.

The table is a bounded regular-file snapshot (at most 1 MiB), parsed completely before loading the DSO. It has exact single-space/LF framing, canonical unsigned decimal integers and lowercase hex payloads (`-` means empty):

```
LI2SELECTED 1 2 2
functions 101 202
record 1 413d62 1 1
record 2 - 0 0
END
```

The header gives N and M; every consecutive record ID 1..M has exact input bytes and exactly N u64 results in selection order. M is 1..min(2048,4096/N). Inputs retain the old CSV grammar; a table cannot enable binary input or a new ABI. The controller validates the entire frozen row before dispatch. The worker independently obtains its retained row before the first call; every returned call checks its own row/column/dimension and existing input/output guards. The controller separately joins every result to the original accepted input owner. Wrong bytes, missing/extra records, missing values and early EOF refuse; success requires every row exactly once. Once captured, the immutable table snapshot is authoritative for this invocation; later edits to its file cannot change expected results. The caller must freeze its independent oracle before execution.

Successful output uses `READY,selected-session-v1,...`; `LEAF` carries the supplied label. Existing CALL/RESULT/SAMPLE/HISTORY/COVERAGE/IO/DONE layouts and line/transcript caps remain. Selected RESULT values may be any u64. The old command still rejects values above 65 through its unchanged operation-specific assertion. `DONE` alone never establishes exit status or timely closure: the final output deadline is checked afterward.

The small fixture contains two ordinary compiled byte scans absent from Csv/Length/Digits/Spaces: `first_equal` returns the first raw `=` byte's index or the encoded input length; `uppercase_count` counts raw ASCII uppercase bytes. Neither body asks for patchable NOPs or explicit alignment. `oracle.py` uses independent Python `bytes.find` and byte counts, freezes every input/result, and compares every scalar output including unsampled calls. It never launches a candidate. `reference.c` calls the actual unmodified DSO in a separate process through ordinary C CALLs and retains its loader owner to exit. This reference and the Python scalar comparison do not qualify the installed Rust caller's architectural state or validate its complete wire history.

After source review, a bounded execution owner can use these fixed build commands, recording the actual tool paths/hashes, source revision, complete commands and final file digests. All outputs belong in its private directory. The fixture source is `evaluation/ordinary-selected-session/leaves.c`:

```
gcc -O2 -std=c11 -Wall -Wextra -Werror -fPIC -shared -nostdlib \
  -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables \
  -fno-tree-vectorize -fno-tree-slp-vectorize -fno-builtin -fno-ipa-icf \
  -fno-toplevel-reorder -fno-jump-tables -fcf-protection=none \
  -Wl,--build-id=none,-z,now,-z,noexecstack \
  evaluation/ordinary-selected-session/leaves.c -o leaves.so
strip --strip-all -o leaves-stripped.so leaves.so
gcc -O2 -std=c11 -Wall -Wextra -Werror -fno-stack-protector \
  -fno-optimize-sibling-calls -fcf-protection=none \
  evaluation/ordinary-selected-session/reference.c -ldl -o reference
cargo build --release -p rapid-profiler --bin ordinary-interval
python3 -B evaluation/ordinary-selected-session/oracle.py prepare inputs-k10 --k 10
python3 -B evaluation/ordinary-selected-session/oracle.py prepare inputs-k1000 --k 1000
```

Before dispatch, independently freeze complete FUNC extents, decoded CFG/RET sets, exact final-file/source-page geometry and both callers' CALL/RET/continuation shapes. Prove selected bytes and geometry survived stripping; section metadata is still required. The fixture exports protected symbols for the original C reference; the installed command still selects by explicit ELF VA/extent with no symbol fallback. The compiler emits the sizes: do not guess them, truncate a function, modify flags after an observed refusal, select a favorable subset, or change the grammar to fit a result.

The prospective fixed population is the two final DSO variants × K10/K1000, one attempt per cell, both functions in every cell. Use all 12 literal records for K10 and 1001 records for K1000; both exceed K and include empty/64-byte/quoted/boundary cases. IDs/labels are `(101,first_equal)` and `(202,uppercase_count)` in that ELF order; an unexpected order is a fixed-fixture refusal. Both use `certified` and 520 epochs. Obtain the uninstrumented scalar reference in a separate bounded process for each cell, passing the absolute DSO and record count to `reference`. Freeze an independent trusted copy of each final DSO before the installed invocation. Reserve separate producer/controller/worker CPUs and record that reservation and load. Use the existing bounded owner with unchanged 20 CPU-second/30 wall-second child caps; the session's internal timing limits remain strict. This document is not permission to run without that owner or to retry a failed cell.

Run each installed command with the exact frozen ELF VA/extents, table, K and all input records. The external owner must require exit 0, empty stderr, complete cleanup and exact source/artifact identity, then use `oracle.py compare STDOUT --k K` (add `--original` for reference output). Scalar comparison reports only `SCALAR_ROWS_MATCH`; separate full history/native-state gates remain required for a qualification claim. Failure of compiler shape, preparation, timing, output or custody remains a failure; all later unrun cells remain UNRUN. Preserve earlier failed reference, 510 s cohort, strict 2 ms and offline-rewrite histories. No performance result is proposed here.

Additive pure controls are `cargo test -p rapid-profiler --bin ordinary-interval normal::selected_session_controls::` (24 cases) and `python3 -B evaluation/ordinary-selected-session/controls.py` (4 cases). The former live outside the frozen old LeafSet test-name prefix; its 16-control inventory and all prior assertions remain unchanged. Execution results belong in a separate revision-pinned receipt; these commands and fixtures alone do not establish native or architectural-state qualification.
