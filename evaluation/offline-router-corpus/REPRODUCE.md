Run the committed scripts from the exact checkout being measured. These reproduce commands and checked input construction; they do not promise a historical cache race, identical host metadata, native success or performance. The supported native profile remains the fixed AMD EPYC Zen 5 development-host profile, both complete programs,187 original heads/42 selected sites,U2/L1/J2, two observer controls and twenty pairs/forty N01 invocations.

Use canonical absolute paths for `ROOT`, `PYTHON`, `TOOLCHAIN`, `CARGO_HOME_DIR`, `USER_HOME_DIR`, `TEMP_DIR` and new private output parents. `PYTHON` must be the canonical interpreter used to invoke the driver and, for a probe, the one captured in original facts. Keep the existing single `ROOT/target`. No private home path is compiled into these scripts.

A command plan is an externally hashed JSON file:

```json
{"schema":"LI2-PREPARATION-COMMAND-1","stage":"controls","arguments":[],"history":[]}
```

```sh
PYTHON -B evaluation/offline-router-corpus/reproduce_preparation.py run   --root ROOT --revision REV --python PYTHON --toolchain TOOLCHAIN   --cargo-home CARGO_HOME_DIR --user-home USER_HOME_DIR --temporary TEMP_DIR   --plan PLAN --plan-sha256 PLAN_SHA --output NEW_OWNER_DIRECTORY
```

The driver requires a clean exact committed revision and authenticates the existing command owner. Each invocation owns one selected stage with the unchanged1200-second/8-MiB outer bounds and records actual argv, environment, source, affinity/load, raw log, errors and cleanup. Setup can refuse before dispatch; a dispatched command's failure remains failure. The exact child result is retained as `command_closed`. Any unsuccessful owner completion writes `closed: null`, including a later load/source/log-copy error after a successful child, so existing probe readers cannot consume it as success. Errors and actual child outcomes remain visible. Inspect outputs only after confirmed cleanup. Every owner directory and stage output must be new. There is no automatic continuation or retry.

`controls` runs both existing discovery suites once even if the first fails. `profiler-controls` runs all ten preserved controls against the actual tracked profiler. `reproducer-controls` runs all fourteen preparation controls, including successful and failed owner receipts through the existing probe reader. These stages accept no filtering arguments. For direct public reproduction, run `PYTHON -B evaluation/offline-router-corpus/profile_preflight_controls.py` and `PYTHON -B evaluation/offline-router-corpus/reproduce_preparation_controls.py`; the bounded stage forms additionally retain owner receipts.

For other stages, `arguments` is the ordinary flag/value array for the existing command below, with exact canonical flag spellings. All required flags must appear once. `FLAGS` in the driver is the finite roster; unknown flags, abbreviations, duplicate overrides and equals-form options refuse before dispatch. Each stage's own checker and limits remain active.

| Stage | Existing command / role |
| --- | --- |
| source-freeze | artifact-verifier/freeze_startup_sources.py; `--output` new profile file |
| platform | offline-router-corpus/platform_inputs.py; `--output` new passive inventory |
| producer | artifact-verifier/startup_produce.py; full existing CLI, readonly-headerpad original profile |
| producer-absolute | same producer with the additional exact `--startup-profile elf-disassembly-null-jumps-static-exec-router-absolute-prerequisites-v1` pair |
| verifier-build | artifact-verifier/startup_verifier_build.py; existing CLI |
| saved | artifact-verifier/verify_saved.py; complete current capture/producer/build/startup references |
| bootstrap | artifact-verifier/startup_bootstrap.py; same references plus current main joins |
| observer-plan | offline-router-native/prepare_profile.py observer-plan; complete current source/capture references |
| observer-build | offline-router-native/native_launch.py build-observer; current plan/hash |
| final-profile | offline-router-native/prepare_profile.py final-profile; prospective inputs/hash |
| final-profile-absolute-prerequisites | offline-router-native/prepare_profile.py final-profile-absolute-prerequisites; explicit new main/policy/contract class, same prospective inputs/hash |
| probe | offline-router-native/probe_xstate.py; exact `--raw-output` new file |
| observe / n01 | offline-router-native/native_launch.py selected population; explicitly separate invocation |

Paths in the table are relative to `evaluation/adjacent-b2/` for artifact-verifier and `evaluation/` otherwise. Stop preparation on a failed stage. Derive each downstream SHA from the actual complete file after its owner closes. Never reuse a prior argv, receipt template, source profile or failed output directory.

For producer, provide all eleven required flag/value pairs, including the exact `--original-profile startup-original-facts-readonly-headerpad-v1`. The explicit `history` array retains the producer's existing bound of zero through 64 distinct external `{path,sha256}` references. Every supplied reference is authenticated and appended as `--failure-history` in the supplied order. An explicit `history: []` starts a fresh prospective campaign; it is not a replay of historical evidence. Fresh outputs and digests require their own checks and qualification. Stages other than the two producer stages require `history: []`.

`producer-absolute` requires those same eleven pairs plus the exact startup-profile pair above, and accepts the same explicit history population. Run its two additional wrapper controls with `PYTHON -B evaluation/offline-router-corpus/reproduce_absolute_controls.py`. The ordinary `producer` stage retains its original flags and default class.

Strict replay of the recorded six-history campaign requires all six actual historical closure references, in their original order. Those private inputs are not distributed by this repository. If any is unavailable, strict historical replay is unavailable: do not manufacture placeholders, clone receipts, or describe a fresh empty-history campaign as that replay. All earlier receipts and failures remain unchanged.

The actual frozen platform contract and SHA are explicit external inputs. `platform_inputs.py` captures complete passive file facts, three readelf results, ldconfig output and stable alias/search snapshots, but never writes a contract or acceptance. External review must supply the contract's actual pinned facts and unsafe rationale. A changed inode does not permit automatic cache refresh/rebinding. Preserve old contracts and failures. The recorded historical contract-authoring decision is not manufactured by a reproducer.

To build final-profile inputs without a prior private template, create this explicit reference plan; producer/verifier/joins/bootstrap and observer-build are actual current output directories, while observer-plan is the actual plan file:

```json
{"schema":"LI2-PREPARATION-REFERENCES-1","producer":"PRODUCER_DIR","verifier":"VERIFIER_DIR","joins":"JOINS_DIR","bootstrap":"BOOTSTRAP_DIR","observer_plan":"PLAN_FILE","observer_build":"OBSERVER_BUILD_DIR","contract":{"path":"CONTRACT_FILE","sha256":"CONTRACT_SHA"},"xstate":{"owner_source":{"path":"REVIEWED_OWNER_SOURCE","sha256":"OWNER_SOURCE_SHA"},"owner_receipt":{"path":"PROBE_OWNER_JSON","sha256":"PROBE_OWNER_SHA"},"log":{"path":"PROBE_OWNER_LOG","sha256":"LOG_SHA"},"raw":{"path":"PROBE_RAW","sha256":"RAW_SHA"}}}
```

```sh
PYTHON -B evaluation/offline-router-corpus/reproduce_preparation.py final-inputs   --root ROOT --revision REV --plan REFERENCES --plan-sha256 REFERENCES_SHA   --output NEW_INPUTS_FILE
```

This only serializes current whole-file references. It is not artifact acceptance. Run the `final-profile` stage afterward; the existing reader independently reconstructs complete W01/package/dependency/observer/probe evidence. A fresh `probe` stage can create the four explicit measurement references using this tracked driver as the separately reviewed owner source. Its receipt contains the actual probe argv, not a wrapper argv. Preserve all raw bytes and exact cleanup evidence.

The old `final-profile` stage remains profile2-only. The separately selected `final-profile-absolute-prerequisites` stage requires the checked new producer/policy class and exact externally supplied contract2; it returns only a profile3 draft after both complete dependency graphs pass. It never derives acceptance or changes the fixed populations.

The absolute class emits three ordered main dependencies: canonical libgcc, canonical libc, then the program's bootstrap. Its exact nine-row dynamic table is 144 bytes; the old seven-row table remains 112 bytes. All three terminated names share the existing 4096-byte allowance, and the complete metadata retains the 16384-byte cap. The catalog and independent verifier check the selected class explicitly.

Contract2's cache omission relies on the pinned GNU loader opening all three absolute names before traversing their child dependencies, whose SONAMEs then match already loaded objects. A failed absolute open is fatal. The actual five-object graph, symbol populations, versions, constructors, preload state and retained file identities must still pass. The pinned loader is from glibc 2.34-285.el9; its digest and reviewed source basis are in `final_platform.py`. This is an explicit vendor implementation premise, not a source-to-binary derivation proof or a claim about later application loading. Contract1 continues to require its cache identity, and earlier cache refusals remain failures.

Preparation ends at a draft profile. Whole-fact review and unsafe caller acceptance remain separate. `observe` and `n01` require a separate command plan with exactly `--root`, `--final-profile`, `--final-profile-sha256`, `--accept-contract-sha256` and `--output`. The accepted digest must be explicitly supplied and match the exact supplied profile's contract. The existing launcher still performs final admission; the driver grants no authority. No preparation stage automatically dispatches either population, and no program/dataset subset flag exists.

The read-only `profile_preflight.py` remains a separate diagnostic entry point documented in its header. Its instrumented output is not a runtime improvement or performance measurement. Post-refusal passive captures cannot establish who changed a global file. Raw histories remain immutable regardless of subsequent results.


For the separately reviewed kernel-config-off profile, run the named
`kernel-basis` stage with exactly `--root`, `--release`, `--headers`, and `--output`.
Its committed `offline-router-native/kernel_basis.py capture` entrypoint captures
the live compressed config plus three matching kernel headers into four bounded
files and a draft basis record. Review that exact record and its explicit unsafe
kernel premise; no capture or digest grants acceptance.

Use reference schema `LI2-PREPARATION-REFERENCES-2`, preserving every existing
reference and adding `"kernel_basis":{"path":"BASIS_FILE","sha256":"BASIS_SHA"}`.
Invoke the assembler's `final-inputs-kernel-config-off` mode with the same exact
root/revision/plan/hash/output flags, then the `final-profile-kernel-config-off`
stage. The resulting profile4 draft retains both complete absolute-prerequisite
namespace proofs and requires its own whole-fact review.

The separate `observe-kernel-config-off` and `n01-kernel-config-off` stages use the
original population flags plus exactly `--accept-kernel-basis-sha256 BASIS_SHA`.
Both the platform-contract and kernel-basis acceptances must match their exact
profile references. The original stage names and profiles do not accept this
extension. Preparation still performs no native dispatch; neither stage offers a
subset, retry or changed deadline. Prior failed attempts remain failed.
