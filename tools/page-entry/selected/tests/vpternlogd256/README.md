# VPTERNLOGD256 qualification

From the source revision being qualified:

```
python3 evaluation/inprocess/page_selected_vpternlogd256.py --expect-revision <full-current-commit>
```

Reserve one CPU using the existing validation owner. The evaluator builds one current decoder archive and 141 group executables from the exact five-TU recipe, then requires all 147 processes. Per-process limits remain 5 CPU seconds, 15 wall seconds, 512 MiB address space and 16 MiB file size. The stdout/stderr capture limit is 65,536 bytes; each complete native record must remain below 16 MiB. All 147 processes are mandatory; a stopped or failed process leaves the cohort incomplete. See the tracked evaluation receipt for observed results and their exact revision.

The product admits only canonical unmasked/unbroadcast EVEX.256.W0 Code 3848: original register/m256 source, original address, full 32-byte read, all immediate values. The old destination is input A, source 1 B, source 2 C. Each output bit is `imm8[(A<<2)|(B<<1)|C]`; upper 256 destination bits clear. Other state remains unchanged. No masks, broadcast, alternate width/W/map/prefix, store authority or native-page/provider exemption is added.

The deterministic generator emits the five frozen catalogue/protocol files into the private build output. All five complete byte extents and SHA-256 values are mandatory before catalogue reading or C compilation and remain in final source/artifact closure. The original XOR256 source tables are separately pinned; no decoder or subject runs during generation. The C and independent Python models are unchanged.

The fixed source catalogue has 2,250 IDs (sample IDs 20000–22249):

- IDs 0–2047 are all 256 immediates × all eight input triples. Every one of the 256 bit positions observes each triple for every immediate, using distinct physical register roles rotated across all 32 registers.
- IDs 2048–2240 retain all 193 XOR256 register/address/fetch geometries as ternary analogues. Adding the immediate also increments the fetch tail, preserving each original nextPC and RIP-relative operand. Input aliases name the same physical bytes; the original XOR cases remain a separate required regression.
- IDs 2241–2245 complete the first-byte fetch tail for lengths 7/8/9/11/12 (all 47 length/tail combinations). IDs 2246/2247 are exact retained-libc memory DE/register FE literals. This is source consistency, not a claim of captured ASLR/mapping authority.
- IDs 2248/2249 are memory operands with constant 00/FF truth tables.

Six additional processes require real failed reads at the original instruction: full/cross ordinary and indexed DE forms, plus both constant 00/FF memory forms. They use real PROT_NONE pages; no EA substitution occurs after the actual pre-state is captured. Every fault must preserve full native/TF state, original PC, trap/error/CR2, source/stack/data and actual revoke/release prefix. Failed reads never earn completed-instruction credit.

The C oracle computes each bit from captured old destination/B/C with a truth-table lookup. The independent Python catalogue uses a sum of Boolean minterms and authenticates every literal and role/address geometry. The existing complete native/TF kernel and live XSAVE, all ZMM/K/GPR/flags/selectors/FS/GS, and all source/stack/data checks remain. The Python record reader authenticates complete framing/CPUID/actual-before queries and failure prefixes; it does not claim a second full architectural replay.

All original supplied query loops remain: generic 47, old 73, old 37 and old 35 rows, including their mandatory Code 2785/2791/2460 promotions. The new 42 unsafe neighbors are extra supplied queries, not executed operations. A complete new cohort requires 2,391 completed pairs (2,250 new +141 startup), six verified failed reads with their six startup pairs, 4,512 actual-before NONE queries and 32,634 supplied refusals. Public JSON keeps all 147 numeric process rows and full-record collection digests under 16 KiB; full records remain private. The evaluator archives accepted records losslessly after full reader acceptance. Every later record fact verifies the archive and the complete decompressed bytes. Journal descriptors close before the next fixed-descriptor native launch. Failed or partial storage prevents successful finalization.

Qualification also requires existing XOR256 (193+4), the existing XOR128/BZHI/BMI1/VPMINUB/KORTESTQ cohorts, original 6/49/17, full native-pair 22 plus old 16+4, unchanged real late-DSO and all six merged checks. Historical failures remain failed. Full B3/application/performance completion is outside this finite family.
