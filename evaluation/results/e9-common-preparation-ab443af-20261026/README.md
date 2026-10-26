# Original heap-sort preparation

The recorded source revision is `ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05`. This preparation built and stripped one dynamically loaded ET_EXEC fixture, then checked all eight complete dataset outputs and full zero journals for each original. All 30 bounded stages completed as specified: 24 returned zero, and six required refusals returned their exact 64/65/67 statuses. Refusals are labelled separately. There were zero rewrites.

`commands.json` retains every stage request, outer command, result and strict receipt, plus the enclosing recipe invocation. `commands.csv` presents the 30 ordered stage rows; `cases.csv` separates 16 original-output checks and six required refusals. Times are operational diagnostics, not benchmarks. `$REPO`, `$RAW` and `$LAUNCH` are injective path symbols with a private inverse.

`artifacts.json` reports binary, metadata and original ELF slice hashes without publishing binaries, logs or journals. `source-files.json` binds the saved before/after map to every Git blob at the tested revision. This does not establish instruction/dataflow completeness, rewritten execution, hook equivalence, architectural state or full A3 qualification. The collector source revision is recorded separately and its running bytes must equal the tracked Git blob before and after collection.
