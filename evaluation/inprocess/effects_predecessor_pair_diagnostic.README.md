# Predecessor-pair two-subject diagnostic

The recorded run failed in both maintained and differential case6/placement3.
Both children exited125 with empty stdout; the full reader rejected each with
`typed complete paired prefix`. Both runtime terminals reported3309/detail88 at
`pda_complete`'s `pda_receipt(c)` check, before the focal application prefix.
The recorded durations are failed-run observations, not performance results.

`effects_predecessor_pair_diagnostic.py` is byte-identical to the actually
executed private `diagnostic.py`:21,802 bytes,
SHA256`871c0d33368b9a75078ef93bec8191c97e2d75e5bea456613a014d037cfb0190`.
Only its publication path changes. The private launcher is not published; its
whole receipt and script identity are referenced in the result. The recipe
below describes the published path and was not separately executed.

This is a replay-dependent diagnostic. It requires the original closed native
receipt and all inputs/artifacts that it names, at their original paths in the
same checkout. The receipt SHA is
`63ffcec24921e93d9ef9682e04feb411a1684f21c1ed93939701a5a0e4f4fbf1`, from clean
`1b2028e795bac3b308114d73681311b67cf2da1a`, CPU192. A newly generated native
receipt has different identities and cannot substitute for this input.

Run from the repository root with Python3.12 and a disjoint, hard-pinned
singleton reservation for CPU192. The historical hardware, tools,13 Rust
decoder inputs, fixture inputs, seed and reference captures must still match.
The script refuses another CPU or changed historical inputs. Reservation and
release belong to the coordinator; the recorded launcher used the existing
agent-utils allocator with an additional allowed parent CPU for its pin probe.
Do not interpret an ordinary affinity setting as a disjoint reservation.

For the exact observed source, use clean
`e5d3635eeec0fc06aaf65c751dd0902247ada542`. Copy the published script unchanged
to an external file before switching to this revision, because that historical
revision predates the script's publication. Preserve the original historical
inputs; choose a fresh, absent direct child under `target/evaluation/inprocess`.
Under the CPU192 reservation, invoke:

```sh
python3.12 -B /absolute/path/to/effects_predecessor_pair_diagnostic.py \
  --expect-revision e5d3635eeec0fc06aaf65c751dd0902247ada542 \
  --native-receipt /absolute/path/to/checkout/target/evaluation/inprocess/tunables-effects-full19-r2-loop-native/receipt.json \
  --native-receipt-sha256 63ffcec24921e93d9ef9682e04feb411a1684f21c1ed93939701a5a0e4f4fbf1 \
  --output /absolute/path/to/checkout/target/evaluation/inprocess/effects-predecessor-pair-reproduction-1
```

The50 setup commands retain both actual current capture builds and their
ELF/DWARF/byte-oracle checks. The two subjects retain the original
30CPU-second/60wall-second/512MiB-address-space/16MiB-file and capture bounds,
actual FD3 preparation, native pair, owner and terminal checks. There is no
additional outer limit. Mutation controls are not run. Neither this diagnostic
nor its failed receipt grants current native, owner56, qualification or
performance credit. Use `reproduce_effects_tunables.py` for a fresh complete
pipeline with all original prerequisites, populations and controls.

The compact JSON preserves the failed inner and outer outcomes, source,
hardware, actual normalized private-driver argv and whole receipt identities.
Its `whole_rows_sha256` hashes the complete recorded52-row command list using
`json.dumps(rows,sort_keys=True,separators=(',',':')).encode()` without a
newline. CSV contains the two actual subject outcomes. The historical failure
is never rewritten by a later reproduction.
