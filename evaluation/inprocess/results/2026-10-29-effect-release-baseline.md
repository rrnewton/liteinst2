ADDS a five-pair release baseline for real dynamically linked `/bin/ls -d .` under the in-process page gate (claims 1, 2 for CPUID/SYSCALL/RDTSC, and 4).

Revision: `5238024d0dfbae964d6dd6e3fe3f8c63cbac7e6c`. AMD EPYC 9D85 158-Core Processor, one reserved CPU, x86-64 family 26/model 17/stepping 0, microcode `0xb101066`, kernel 7.1.3. Tool/input/build hashes are bound by the compact prerequisite and performance receipts. Release bridge: `-O2`; decoder: Cargo release. Default inactive application rseq remains enabled.

| Fresh-process interval | Native | Page gate |
| --- | ---: | ---: |
| Median | 3.421884 ms | 13.643163010 s |
| Minimum | 3.150076 ms | 13.071072190 s |
| Maximum | 3.479490 ms | 13.850919000 s |

All ten processes passed, with alternating pair order, no discarded sample and no warmup exclusion. Timing starts immediately before Popen and ends at leader reap, including launch, gated namespace preparation, execution and terminal reports. Parent FD/provenance queries are outside this interval. This is a high-overhead baseline, not a speedup result.

Each gated process published/restored 148 temporary patches: 38 CPUID, 100 SYSCALL and 10 RDTSC. There were 147 returning completions/retirements and one explicitly nonreturning final exit. All 5,721 native page admissions closed. First successful admission-work intervals were 82,724–87,912 ns; the 80 same-page admission-work revisits were 81,162–108,483 ns. Those intervals exclude fault entry, final publication hooks, execution and close. They establish neither complete first-touch latency nor steady-state instruction throughput. The existing 9,216-operation stress failure remains failed.

Raw compact measurements: [CSV](20261029T124009-effect-release-five-pair-5238024d0dfb.csv), [JSON](20261029T124009-effect-release-five-pair-5238024d0dfb.json). Fresh prerequisite: [JSON](20261029T124009.707345Z-page-selected-effect-ls-5238024d0dfb.json). Private captures are represented only by content hashes and byte counts.

Reproduce on the exact revision using one CPU affinity throughout: run `python3 -B evaluation/inprocess/page_selected_effect_ls.py --expect-revision 5238024d0dfbae964d6dd6e3fe3f8c63cbac7e6c`, then run `python3 -B evaluation/inprocess/page_default_ls_release_performance.py --expect-revision 5238024d0dfbae964d6dd6e3fe3f8c63cbac7e6c --qualification-receipt "$RECEIPT" --qualification-sha256 "$SHA256" --output "$NEW_OUTPUT" --library-root /usr/lib64 --effect-provider`. Set RECEIPT to the first script's retained private receipt, SHA256 to its actual hash, and NEW_OUTPUT to a fresh output directory. The recorded prerequisite hash was `4e3bd38db37ecd7288710672b9bd6b2161bdc7b3d74d273c4ab04a66d3c3cef0`; new runs produce new receipts. Both scripts enforce exact revision, source/tool custody, cleanup and original resource limits. The performance path requires all ten samples; failed samples remain failures.
