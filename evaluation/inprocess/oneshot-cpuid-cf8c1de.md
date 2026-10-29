CPUID interception through NX faults now composes with temporary publication of real syscall and RDTSC instructions in the initial main image and interpreter, including windows crossing a page boundary. This finite capability passed at revision `cf8c1de3e55ca2e4aa491d3d1b05bd6dfc659853`.

The [closed native receipt](results/20261028T224854.702565Z-page-selected-oneshot-cpuid-cf8c1de3e55c.json) records 813 commands, 2,139 captures and all 15 added subjects accepted. Twelve added operations exited successfully; three required refusal operations exited 125 and remain labelled failed operations. The original 385 provider cases, 51 callback cases, 57 CPUID-NX cases, registered pair and three ordinary interpreter lanes also passed their unchanged checks. Fresh same-revision prerequisites retained the six-owner positive cohort, all 49 negative cases and all 17 inactive-rseq cases.

The added evidence covers these concrete paths:

- Dynamic `/bin/true`, with glibc rseq disabled for ordinary publication, completed in production and observed lanes with 38 CPUID samples, two RDTSC publications and six syscall publications. All eight publication owners completed and restored their source pages; no owner remained active. These are eight publication executions, not eight distinct source addresses.
- Two finite layouts exercise nine selected windows. Each observed and control-denied lane completes the first eight owners, four RDTSC and four syscall, then uses the existing capacity fallback for the ninth. The second layout's first two owners span two pages. Each lane records 11 raw CPUID commits, including first interpreter/main entry and eight continuations at restored PC+2, with 22 complete before/after CPUID frames.
- The combined registered-rseq pair completes with one CPUID sample and zero publication owners. Actual three-byte mmap/rseq setup instructions and four complete setup frames precede the existing registered fallback checks; registration does not enable temporary publication.

The readers retain full architectural comparisons, actual incoming CPUID inputs, complete saved signal-frame/FP state and exact source restoration. Native and gated clock values remain separate observations. Bootstrap-disabled and application CPUID-control refusals remain mandatory; previous failed build and exploratory attempts receive no qualification credit.

This is partial B2 evidence for the explicitly enabled composition. Ordinary publication still requires rseq to be disabled, has eight non-recycled owners, and is restricted to the qualified initial images and instruction windows. It establishes neither general B2/B3 completion nor a performance or low-overhead claim.

The run used one reserved CPU on x86-64 AMD EPYC 9D85 hardware (family 26, model 17, stepping 0, microcode `0xb101066`), Linux `7.1.3`, without effective capabilities. The receipt retains the exact kernel-release hash, tool identities, source and capture digests. Added subjects and their build profile retain 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB per file; earlier cohorts keep their original limits.

All [six required checks](results/20261028T230022.837900Z-checks-cf8c1de3e55c.json) passed at the same source revision: formatting, strict Clippy, all-feature checking, 350 recorder tests, 3,056 workspace tests (36 ignored) and 1,039 serial launch tests. Workspace, recorder and serial runs took 341.9, 167.0 and 128.1 seconds. Main `abab69594a19140fe5e6f78492da883803dfbe4c`, including the requested `7ab79270`, is an ancestor of this tested revision.

To reproduce, use the exact revision above with a clean tracked tree and one reserved CPU. Run the positive prerequisite first:

```sh
REVISION=cf8c1de3e55ca2e4aa491d3d1b05bd6dfc659853
python3 evaluation/inprocess/page_selected_oneshot.py --expect-revision "$REVISION"
```

Set `POSITIVE_RECEIPT` to its fresh full private `target/evaluation/inprocess/<stem>/receipt.json`, then run:

```sh
python3 evaluation/inprocess/page_selected_oneshot_failure.py --expect-revision "$REVISION" --positive-receipt "$POSITIVE_RECEIPT"
python3 evaluation/inprocess/page_selected_rseq_application.py --expect-revision "$REVISION" --fast-memset
```

Set `NEGATIVE_RECEIPT` and `RSEQ_RECEIPT` to those fresh full private receipts. Each public `evaluation/inprocess/results/<stem>.json` identifies the matching stem; the compact public projections are not substitutes for these inputs. Then run:

```sh
python3 evaluation/inprocess/page_selected_cpuid_nx_run.py \
  --expect-revision "$REVISION" --oneshot-interpreter \
  --positive-receipt "$POSITIVE_RECEIPT" \
  --negative-receipt "$NEGATIVE_RECEIPT" \
  --rseq-receipt "$RSEQ_RECEIPT"
```
