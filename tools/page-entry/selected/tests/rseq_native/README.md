# Registered rseq during unchanged-page execution

This opt-in native-page profile permits rseq publication while application code executes at its original PCs. The kernel owns critical-section interruption and abort. Before entering the existing instruction or syscall owners, the runtime requires a pinned zero publication word, complete verified closure of every admitted page, a fresh matching data-page identity, and actual FS/GS base observations. It never repairs the application word or interprets an exit zero as proof that no publication occurred.

The profile retains the existing whole-page and halo scanner, source/backing/alias checks, singleton and reserved-signal restrictions, syscall gateway and all inactive instruction/write-footprint guards. Registered native exits require the current kernel RIP, si_addr and CR2 to agree; registered straddler retries are refused. Equality can describe a genuine coincident-address abort and does not prove an earlier instruction completed. An untrusted pin or nonzero word at the first handler check takes a direct nonreturning exit without claiming verified closure. Arbitrary corruption of private runtime state or kernel-directed entry into private code is outside the cooperative application contract.

`build-rseq-native.sh` adds `LI2_RSEQ_NATIVE=1` to the CPUID-NX native-page profile. Existing recipes omit it. From the repository root:

```sh
sh tools/page-entry/selected/build-rseq-native.sh
python3 evaluation/inprocess/native_pages.py --expect-revision <full-commit-sha> --output evaluation/inprocess/results/native-pages-rseq-native.json --cpuid-nx --rseq-native
```

The matrix command requires one externally reserved CPU. Its five original cases, native output comparisons, 30 CPU-second and 60 wall-second limits remain unchanged. The bridge is written to `target/page-entry/rseq-native/bridge-rseq-native.so`.

The unchanged `LI2_RSEQ` row describes the inactive instruction/syscall component. `LI2_RSEQ_NATIVE` separately records native epochs, fresh TLS transitions and failed prefixes; `reports.py` retains every original report and completion check. Disabled-rseq subjects have zero new epochs. Registration alone is not evidence of native execution. Public summaries contain numeric counts, not addresses.

The sixteen-case native/controlled cohort passed at `d0d14067c441`, including actual scheduling and NX aborts, coincident addresses, straddler refusals, TLS changes and failed operations. The original prerequisite and regression suites also passed. The release matrix still fails both default-rseq applications at the registered native entry guard; it establishes no default-application completion or speedup. See the [results and reproduction commands](../../../../../evaluation/inprocess/rseq-native-d0d1406.md). This profile does not complete B2 or B3 and does not provide general thread, signal or arbitrary-kernel support.
