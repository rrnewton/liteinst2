# Explicit profile admission controls

Tested revision: `59c026e4da35b25dae2e270a5a63aa1b9e8cd41b`, hardware **AMD EPYC Zen 5 dev host**. The production suite passed all 10 methods and the ordinary-consumer suite passed all 11, with no failures or skips. These finite synthetic saved-record checks support claim 4. They do not execute a compiler, ELF producer, application or native candidate.

The exact tests are `evaluation/e9-common-app/test_production_profile.py` and `test_candidate_profile.py` at that revision. They call the actual profile and whole-bundle admission helpers. Complete and withheld outcomes remain distinct; invalid markers, profile joins, commands, histories and owners must refuse. All 74 production stages and 192 ordinary case obligations remain in the recipes. A synthetic fixture is not evidence that those actual campaigns have run.

Save this exported `validate.py` outside the checkout before selecting the tested revision; the reproduction files were published later. Use a clean checkout and fresh absolute ignored output paths:

```sh
python3.9 -B /absolute/saved/validate.py --repo "$REPO" --output "$REPO/ignored/profile-production" --phase production
python3.9 -B /absolute/saved/validate.py --repo "$REPO" --output "$REPO/ignored/profile-ordinary" --phase ordinary
```

Each invocation records exact source/tool observations, hardware, full commands and direct parent/helper closure. The strict helper has 10 CPU seconds, 15 wall seconds and a 1 MiB per-file cap, enclosed by a 25-second timeout with 10-second kill grace and a 40-second parent wait. It uses CPUs 0-3, keeps temporary fixtures inside the new output directory, and preserves all assertion checks. The recorded outer caller also has a 70-second parent wait. The exact validation source SHA-256 is `e347afd9326c1d6e232ce4ce72b3abd2217b6a3bba8d19046192189b496bae3d`. Durations are operational diagnostics, not performance results.

The seven [CSV/JSON data files](../../data/owned-neighbor-profiles-59c026e/summary.json) retain complete method names, command contexts, source pins, hardware and record digests. Only paths are replaced with the injective `${REPO}` role; raw logs, complete source owner snapshots and inverse maps remain ignored. The saved command contexts preserve the historical private script coordinates; the public script is a byte-identical export.

The exact saved-record projector is `collect.py`, SHA-256 `b00190a9e877625ad97f57b682bc93d389ec27fefb55b44921b0406606b5dbeb`. With both phase directories and their closed outer launch records in a common raw directory, run the saved collector against the exact source checkout:

```sh
python3.9 -B /absolute/saved/collect.py --repo "$REPO" --raw "$REPO/ignored/closed-profile-controls" --new-output "$REPO/ignored/profile-report"
```

It joins every successful method to the source AST and the complete unittest log, verifies closures and source/tool equality, and writes public data plus private command inverses. Exact historical collection also needs its private closed records; those are not published. This evidence establishes neither fresh preparation/build/production/runtime admission nor ordinary/native equivalence or full A3 completion.
