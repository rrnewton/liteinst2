# TLS historical request-directory coordinates

The private v1 and v2 result summaries use `${FIRST_REQUESTS}` and `${REMAINING_REQUESTS}` as **whole directory coordinates**, not prefixes, workspace paths, or fragments to append to `${RAW}`. The suffix `/library.json`, `/compile.json` or a later phase filename is appended exactly once. These roles supplement the other coordinates already defined in [the reproduction instructions](frontend-tls-private/README.md).

| Attempt | Complete coordinate | Historical owner directory, identified by its package-relative label | Owned requests |
| --- | --- | --- | --- |
| Private v1 | `${FIRST_REQUESTS}` | `frontend-tls-qualification-plan-v1/requests` | `library.json`, `compile.json` |
| Private v1 | `${REMAINING_REQUESTS}` | `frontend-tls-remaining-requests-v1/requests` | `list.json`, `models.json`, `clippy.json`, `docs.json`, `msrv.json` |
| Private v2 | `${FIRST_REQUESTS}` | `frontend-tls-qualification-plan-v2/requests` | `library.json`, `compile.json` |
| Private v2 | `${REMAINING_REQUESTS}` | `frontend-tls-remaining-requests-v2/requests` | `list.json`, `models.json`, `clippy.json`, `docs.json`, `msrv.json` |

These labels identify the original immutable request-owner directories; they are not paths required to exist in a public checkout. Historical absolute owner coordinates remain in the private receipts and are not published. Substitute each role with that attempt's whole original directory when inspecting its historical raw invocation. The two owners were separately frozen and need not be children of `${RAW}`. V1 docs/MSRV requests were planned but unexecuted; naming their owners does not create execution credit.

A **new reproduction** uses the request-only preparer described in the linked instructions. It places both compiler requests and, only after actual artifact admission, the five remaining requests in the single `${RAW}/requests` directory. Thus both historical directory roles can be represented by `${RAW}/requests` for that new reproduction, but the old command rows and their request hashes remain historical. New coordinates, source observations, receipts and outcomes must be captured anew. The historical separate-owner scheme is not retroactively rewritten.

This clarification changes no source, material inventory, template, control, resource cap, comparator, result row or revision label. Both private tested revisions remain null; the public required-gate record remains bound to its exact tested revision.
