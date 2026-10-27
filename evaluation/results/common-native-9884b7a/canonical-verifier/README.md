# Canonical verifier production at 9884b7a

The second direct-rustc attempt compiled and archived the verifier and its depfile. A separately recorded root byte check verified both copies and their dependency/source owners. The first attempt remains failed: its compiler exited successfully, but the producer rejected changed private-input directory timestamps before admitting any archive. Neither attempt executed the verifier or an application.

| Attempt | Compiler exit / seconds | Producer exit / seconds | Result |
| --- | ---: | ---: | --- |
| V1 | 0 / 2.273004 | 1 / 5.335136 | Private-input owner equality failed; no archive admission |
| V2 | 0 / 2.431145 | 0 / 6.416439 | Two archived products; separate root byte check passed |

Both compilers and producers have strict `ECHILD` receipts and recorded direct-parent waits. V1 changed only the root directory's mtime/ctime in its opened and pathname views; leaves, membership and other directories matched. The actor is unproven. V2 adds only `--out-dir <raw/output>` to compiler argv; all 67 assertions, directory/leaf checks and output-membership requirements remain. V2 success does not explain V1's timestamps or promise that the failure will recur.

The [four earlier archive failures](../originals-and-archive-failures/README.md) remain failed and are retained literally in [summary.json](summary.json). Their compilers exited 0 and archive recipes exited 1. The first lacks an after-map; only attempts 2–4 establish the reported alias-parent timestamp differences.

The tested revision is `9884b7a259b4e0ea80d2cca6d726abab4594807a`. Hardware is the saved build context, **AMD EPYC Zen 5 dev host**, with affinity `[0,1,2,3]`; no separate per-attempt hardware capture was made. Durations are operational wall times, not benchmarks. Compiler limits were 60 CPU seconds, 90 wall seconds and 128 MiB per file; its outer timeout was 100 seconds and direct-parent backstop 115 seconds. Producer limits were 120 CPU seconds, 180 wall seconds and 128 MiB per file, with outer 190 seconds and parent 205 seconds. Both outer timeout commands retained a 10-second kill-after. File limits are not aggregate disk quotas.

## Reproduction

The three [recipe sources](recipe-sources.json) are exact historical bytes: V1/V2 producers and their shared compiler entry. The materializer only copies verified sources into four absent ignored destinations. It launches nothing and has not been executed for this packet. In a fresh checkout, save this packet before returning to the tested revision:

```sh
cp -a evaluation/results/common-native-9884b7a/canonical-verifier ignored/reproduce-canonical-verifier
git switch --detach 9884b7a259b4e0ea80d2cca6d726abab4594807a
/usr/bin/python3.9 -B ignored/reproduce-canonical-verifier/materialize.py --repo "$PWD"
```

First produce and independently review a fresh prerequisite build at `ignored/a3/common-native-epoch-v1/build-v1`, following the committed [build recipe](../../../e9-common-app/BUILD.md) with `--allocation-profile original-derived-v1`. The producer requires all 1,839 source files and their original owners to match that build, unchanged tools/configuration, and the complete common-sites archive: 43 records, including 38 library copies. A checkout or owner change requires a new reviewed epoch; old owner tuples cannot be recreated or refreshed into historical authority.

Create a fresh `references.json` beside each restored producer. [references-contract.json](references-contract.json) publishes the complete 35 historical member names and byte identities, with the required owner-row schema. It withholds private old owners. Fresh build/review/caller metadata must be complete, separately reviewed and pinned as a new envelope; the historical whole-envelope hash is not a current admission.

A caller has exactly `schema`, `authority`, `revision`, `raw`, `producer_sha256`, `entry_sha256`, `references_sha256`, `linker` and `capacity_record`. Use schema 1, authority `ROOT_AUTHORIZED_DIRECT_RUSTC_VERIFIER_PRODUCTION`, the tested revision, an absent raw directory below the epoch directory, and the selected exact script hashes. Linker and capacity descriptors each require `path`, `sha256`, `bytes` and six-stat `stat`. Capacity, tools and runtime must be freshly admitted; the historical namespace keeper has closed. Reproducing that environment requires a separately reviewed replacement keeper/caller, not reuse of its old identity.

[commands.json](commands.json) retains 16 exact normalized compiler, entry, producer, namespace, root-parent and byte-check contexts. Substitute the declared roles and fresh caller/output hashes, then use the committed `tools/unwind-oracle/bounded_command.py` with the recorded requests, timeouts, affinity and direct-parent closure. Preserve failures and every postcheck. The source packet deliberately supplies no automatic admission or new runner. The receipt's `inputs_unchanged` covers request/helper bytes; separate source/private-tree checks establish their own scope.

[files.json](files.json) binds the source and saved metadata used here; private inverse and owner maps remain outside publication. Product-byte authority comes from the recorded root check, joined by the independent actual review; this report projection did not read compiled products. The direct-rustc archive is not compatible with the existing Cargo consumer admission. Consumer integration, verifier execution, native equivalence and complete A3 qualification remain unclaimed.
