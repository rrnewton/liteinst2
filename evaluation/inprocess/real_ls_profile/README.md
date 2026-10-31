# Reproduce a bounded real-LS profile

This is an input-binding successor to the observed fixed-input profiler, not the script identity of that observation. It accepts an explicit whole failed-program receipt and its source revision, rechecks the original typed cases, build/archive/ELF/source/counter/namespace closure, and reuses the existing native41 public/private/CSV validator without rerunning its controls. The capture owner and fresh-chain driver are byte-identical to the reviewed versions. Every observation remains unqualified; a killed target remains a failed prefix.

Run from a clean checkout. `AGENT_UTILS_ROOT` identifies the external agent-utils checkout whose relative source hashes and executable facts are in `exact_cpu/SOURCE.json`. Use Python matching those exact executable facts, and keep the parent affinity broad enough for the allocator's real escape probe. Never wrap the allocator in `taskset`.

## Fresh inputs

Choose an explicit clean revision and a nonexistent private output path. The unchanged driver runs cold9, native41, then the real `/usr/bin/ls -d .` and `/usr/bin/true` probe on one reserved CPU. It retains every original source/CPU/hardware/archive join, finite control population, bound and failure label. It stops if a prerequisite fails.

```sh
export PYTHONDONTWRITEBYTECODE=1
export AGENT_UTILS_ROOT=/path/to/agent-utils
REVISION=$(git rev-parse HEAD)
AGENT_UTILS_ENGINE=python "$AGENT_UTILS_ROOT/bin/cpuset-alloc" run --cores 1 --   python3 -B evaluation/inprocess/real_ls_profile/fresh_chain/run.py   --expect-revision "$REVISION"   --output target/evaluation/inprocess/FRESH-CHAIN
```

A chain exit of 1 is still a failure. It supplies a diagnostic origin only if both preceding stages passed and the final program stage actually ran, closed its source/process custody, and failed solely because both counted programs hit the original CPU bound. An earlier prerequisite failure is not an eligible origin. Read the exact `program` stage's `public_receipt` from this chain's `receipt.json`; its stem identifies `target/evaluation/inprocess/<stem>/receipt.json`. Do not use a latest-file glob. Take the CPU and source revision from that exact private program receipt and calculate its complete SHA-256. The profiler independently requires all four exact native/generated outcomes and the whole native41 prerequisite.

## Retained-input observation

Fresh preparation is optional when that exact eligible origin is already retained. The following command performs only the bounded observation and metadata/file joins; it does not rebuild or rerun the cohorts. Supply explicit values obtained from the chosen whole origin, not the sample placeholders below.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B   evaluation/inprocess/real_ls_profile/exact_cpu/run_exact_cpu.py   --tool-root "$AGENT_UTILS_ROOT" --cpu CPU_FROM_ORIGIN   --expect-revision CURRENT_FULL_REVISION   --expect-origin-revision ORIGIN_FULL_REVISION   --origin-receipt target/evaluation/inprocess/EXACT-PROGRAM-STEM/receipt.json   --expect-origin-sha256 WHOLE_RECEIPT_SHA256   --output target/evaluation/inprocess/FRESH-PROFILE
```

The current and origin commit IDs may differ only insofar as every original source input still matches both complete Git versions. The public native41 JSON/CSV pair is explicitly bounded and joined to the whole original producer, never treated as a broad untracked-source exemption. New PID, timestamps, nonce and count values are observations, not hardcoded acceptance values.

Target limits remain 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB file/capture size. The unchanged observer uses 99 Hz user-DWARF sampling with a 16 MiB per-thread ring, 4 KiB saved stack, 30 CPU seconds / 80 wall seconds / 1 GiB address space / 128 MiB file limit. Zero loss, whole exec-to-exit envelope, READY/reap, held descriptor custody, exact source/ELF joins, and original counter split-update parsing remain mandatory. Counter cells never become a completed transaction count. The wrapper uses the actual shared ledger and hard-scope escape probe with no fallback or retry.

The full private receipt and raw captures remain under the chosen output. Only its compact summary is suitable for publication after independent review; it includes unknown sample attribution and preserves target failure. No throughput, speedup or whole-profile qualification follows. Original392/522 qualification and the ten-run same-host native/DynamoRIO comparison remain required and unmet.

## Historical provenance

The published 226 observation used fixed profiler SOURCE `33872022293d805d792cb14c784408f67ba44d2bb2275231323d30a5ff32b1ed`, exact-CPU SOURCE `7226b90e14f82b0637d8c137edfcfc3b6a24572d0bb285ee498e896f016fdfbd`, and private profile receipt `35ac01edad2518111df53ea4c4bab40347fda2ef0174f9da9ea3dcbdb49f7587`. Those packets remain unchanged. This successor's own SOURCE facts distinguish it from those executed bytes; publishing source does not grant execution credit.
