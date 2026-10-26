The failed 7e464a42 unit stored its unchanged 13,712-byte ELF fixture at an address misaligned for the configured parser. The corrected 74aaf19a unit gives the parser a named, eight-byte-aligned static owner. Archived executable bytes establish both placements; the saved corrected unit run passes all fourteen original parser cases and the added alignment/whole-byte regression.

| Attempt / embedding | ELF-relative address | Modulo 8 |
| --- | ---: | ---: |
| Failed unit: sole complete fixture | 293553 | 1 |
| Corrected unit: ALIGNED_SUBJECT | 280368 | 0 |
| Corrected unit: additional identical bytes | 294081 | 1 |

The corrected executable still contains an unaligned byte copy. The decoded ALIGNED_SUBJECT object symbol identifies the owner used by SUBJECT; the additional occurrence is not labelled a parser owner. Both attempts contain the exact same fixture hash. Addresses in this table are ELF-relative, not observed process addresses.

The fourteen original test bodies, helper bodies and production parser remain unchanged. The new regression checks the named owner's alignment and full fixture bytes. The earlier fourteen failures remain failures: thirteen stopped before constructing their mutants, so they provide no negative-refusal credit.

[JSON evidence](results/frontend-native-alignment-20261025/summary.json) and [embedding rows](results/frontend-native-alignment-20261025/embeddings.csv) record exact revisions, hashes and scope. The [failed required-run report](frontend-native-required-7e464a42-failure.md) preserves the original failed outcome and unrun suffix. Raw executables and logs remain private. This appendix adds no execution, benchmark, native qualification or complete target-closure claim.
