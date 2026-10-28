# One-acquisition RX alias memo

The runtime reuses only a successful alias predicate for the exact query,
object identity, and active complete maps acquisition. It does not cache source,
owner, permission, descriptor, or rseq authority. Every write query, failure,
inactive/poisoned phase, transaction, and key mismatch uses the exact old body.
The original overflow check runs before lookup. Direct seal/stat observations,
all public layouts, and all existing callers remain unchanged.

The default-ls diagnostic confirmed frequent plain TRACE handoffs with two fresh
maps acquisitions and six reused maps queries. It did not measure map row count
or stage cost: 802 was live owned pages, not VMAs. For the conditional same-page
handoff, this memo reduces eight full-row alias scans to two. Their work is 8R
versus 2R for the unknown actual row count R; there is no measured speedup claim.
The retained-record scan exists only for writes, which always bypass this memo.
Backing reuse was not chosen: it would alter the meaning/layout of direct
F_GET_SEALS/fstat receipts, and its ten-syscall opportunity is not a time share.

The oracle includes the whole real lifecycle translation unit. Dead-section GC
drops unrelated loader functions. It compares the actual wrapper to the exact
old body and literal expected errors, and checks complete rows, records, object
facts, lifecycle counters/transaction and maps observations for mutation.
Supplied tables cover zero and maximum row counts, all query arguments and
object identity components, phase/receipt guards, coalesced exclusions, offsets,
overflow/first-error order, high integer addresses, and writes across all 8192
retained slots. These supplied acquisitions are explicitly modeled inputs.
A separate real sealed-memfd sequence performs actual maps acquisitions,
writable-alias creation/removal, protection changes, benign queries, unknown
raw calls, EBADF and event-boundary invalidation. No program instruction is
executed from those mappings. Test-only branch counters are absent in production.

Root supervises this existing three-argument recipe, with source/header/tool,
ELF/capture identities and the original 5 CPU-second / 15 wall-second / 512 MiB /
16 MiB bounds. It is C-only and needs no decoder archive or Cargo. For a private
source candidate, the first argument selects its lifecycle_loader.c; the second
selects the unchanged tracked headers/includes:

```
sh tools/page-entry/selected/tests/maps_query_reuse/build.sh OWNER_CONTEXT tools/page-entry/selected UNIQUE_OUTPUT
UNIQUE_OUTPUT/maps-query-reuse
```

`check.check(stdout)` requires the entire exact integer result in EXPECTED.json.
No build or native result exists at source freeze. Existing fetch/maps-phase,
generic/chain/full-state and rseq suites remain mandatory and unchanged before
application qualification. The actual default-rseq ls command must retain its
30 CPU-second / 60 wall-second limits and strict terminal comparator. Diagnostic
clock/write effects remain part of its observed cost; a faster failed prefix
does not become an application pass.
