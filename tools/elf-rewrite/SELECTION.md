# Strict selection version one

UTF-8, whitespace-separated fields; no comments or unknown records. The first
line is exactly `LI2TOOL 1`. Numbers are decimal or have an explicit `0x` prefix.
A digest is 64 hexadecimal characters. All five global records are required
once. Site IDs are unique and sorted for serialization. Limits are prospective;
exceeding a hard implementation ceiling refuses instead of clamping the bound.

```
original FULL_ORIGINAL_SHA256
target fxsave64
# Alternatively: target xsave64 MASK FEATURE_BIT:OFFSET:SIZE ...
domain COMMON_BIAS_NAMESPACE
carrier ALIGNED_MODULE_VADDR
limits INPUT_BYTES SITES IMAGES IMAGE_BYTES NEW_LOAD_PAGES OUTPUT_BYTES ADDED_FILE_BYTES PROGRAM_HEADERS VIRTUAL_SPAN
hook ID ORIGINAL_VADDR LENGTH EXACT_HOOK_BYTES_SHA256
site ID PC INSTRUCTION_LENGTH FILE_OFFSET SNAPSHOT_PC SNAPSHOT_LEN FUNCTION_PC FUNCTION_LEN BLOCK_PC BLOCK_LEN HOOK_ID observe|replace original-decode
entries SITE_ID complete|unknown PROVENANCE_SHA256 HEAD:ENDBR_FLAG ...
resumes SITE_ID none|unknown|enumerated [SAVED_PC ...]
search SITE_ID preferred|B1|B2|T1|T2|T3 UPSTREAM_BYTES DISPLACED_BYTES SITE_BOUND FORCED_VICTIM_PC|none VICTIM_BOUND PAIR_BOUND
allocation SITE_ID selected PREFERRED_PC|none CANDIDATES MAPPED_BYTES PERMIT_START:PERMIT_LEN ...
allocation SITE_ID victim PREFERRED_PC|none CANDIDATES MAPPED_BYTES PERMIT_START:PERMIT_LEN ...
```

The `# Alternatively` explanatory line above is not valid input. A valid manifest
uses exactly one target record. Each site requires one entries, resumes, search
and both allocation records. Every hook must be used and every site must resolve
a hook ID. Every allocation requests one mapping and every outer leaf permits
at most two source steps; aggregate frontend/carrier limits remain independent.
T2's internal pun order is PreferGeneralizedPun in this schema. T1 prefix counts
can be constrained with exact page permits; no extra opcode fallback is enabled.

`complete` is a caller's authenticated declaration about original entries, not
a CFG proof created by this parser. Its provenance digest and exact selection
bytes are persisted. `unknown` stays unresolved and must refuse. No active saved
context is fabricated by `resumes none`; the artifact is an original
image and its runtime loader contract remains unqualified. ENDBR flags are 0 or
1; active CET support is not inferred from 0.

The target state description is required, not detected on the build host.
FXSAVE64 has a precise limited state requirement; the presence of an AVX-capable
execution machine cannot be inferred to satisfy it. The saved-state mask and
components must be qualified at entry before the candidate can be admitted.

Output file names and record tags are described in [README.md](README.md#output-records). All variable
producer roles/diagnostics in TSV records are hexadecimal UTF-8. Sidecar hashes
are integrity checks and no file is a live publication or admission receipt.
