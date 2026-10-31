# Experimental CALL components

This runner builds and runs both complete component recipes: the sealed decoder/emitter byte model and the planner/compact reconstruction model. The directory and stack-window values are supplied test authority. Neither component executes generated code or a guest. This does not reproduce the separate native136 observation or qualify an actual runtime owner, the original 392/522 cohorts, or performance.

Use Linux x86-64, Python 3.11 or newer, GCC, GNU binutils and glibc's dynamic loader. Invoke from a clean checkout at the expected full revision, with assertions enabled. Reserve one CPU through the host's normal reservation mechanism and inherit exactly that one-CPU affinity; `--cpu` must match it. The runner does not allocate a CPU itself.

The archive is an explicit, externally prepared prerequisite. The existing decoder recipe is `tools/page-entry/selected/build.sh` with `LI2_DECODER_FEATURES=linked-epoch,mov-guard`. Its decoder step uses:

```sh
export CARGO_TARGET_DIR="$PWD/target"
export CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1
unset CARGO_ENCODED_RUSTFLAGS
export RUSTFLAGS='-C relocation-model=pic -C panic=abort -C force-unwind-tables=no'
cargo rustc --manifest-path tools/page-entry/selected/decoder/Cargo.toml \
  --release --locked --offline -j 1 --features linked-epoch,mov-guard \
  -- -C metadata=li2_page_entry_selected_product_generic_tf_v1
```

`linked-epoch` includes `scalar-span`, which includes `scalar-region`; the complete feature set is scalar-region, scalar-span, linked-epoch and mov-guard. The existing recipe copies `target/release/libli2_page_selected_decoder.a` to `target/page-entry/selected/decoder.a` and retains compiler versions and dep-info. Prepare or reuse that artifact under the normal build owner, then supply its independently authenticated SHA-256. This runner checks the exact archive bytes and required providers. It does not build the archive or prove its source/build provenance from its hash. The caller must retain that prerequisite evidence separately.

After reserving a CPU, run:

```sh
python3 -B evaluation/inprocess/call_dispatch_component/run.py \
  --expect-revision FULL_COMMIT_SHA \
  --archive PATH_TO_AUTHENTICATED_DECODER_ARCHIVE \
  --archive-sha256 FULL_ARCHIVE_SHA256 \
  --cpu RESERVED_CPU \
  --output target/evaluation/inprocess/call-components-attempt-1
```

The output directory must be new. There is no case selector, retry or receipt-reuse path. The two unchanged recipes are `tools/page-entry/selected/tests/call_dispatch/build.sh` and `tools/page-entry/selected/tests/call_dispatch_plan/build.sh`. Their compiler argv is expanded literally; the only additions are `-save-temps=obj` and `-Wl,--trace`, retaining actual objects and linker inputs. All recipe flags, assertions and populations remain intact. Full compiler-M rules, compiler/subtool identities, prebound linker inputs, the actual ELF interpreter and every dynamic dependency are checked before component execution. Unknown link or loader forms refuse the run.

The existing `page_selected_process.invoke` owns every child and descendant cleanup. Build/metadata commands retain 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB output limits. Each component retains 5 CPU seconds, 15 wall seconds and the same memory/output limits. Failure stops the sequence and retains partial artifacts. Source, input bytes/modes, aliases, loader configuration and CPU affinity are checked through closure.

Successful stdout must be exactly:

```text
call-dispatch descriptors=16 decoded=736 models=4111 forms=512 arguments=8 bindings=12 corruptions=16 interiors=466 geometry=4 recovery_controls=8
call-dispatch-plan plans=51 models=1105 refusals=6 geometry=12 capacities=2 corruptions=17 interiors=466 compact_recoveries=164070
```

`receipt.json`, command captures, compiler intermediates and executables remain private in the attempt directory. `summary.json` is the compact shareable projection: actual revision, hardware, bounds, tool/archive identities, both complete results, command outcomes and capture hashes, inventory counts/digests, and the exact private receipt hash. It omits host paths and raw logs. A successful result is `components_passed`; all native, owner, whole-profile and performance credit remains false. Earlier failed observations are separate evidence and are never reclassified by this runner.
