# E9 witness byte controls

These 93 finite controls exercise the complete pinned
[`e9-null-witness.py`](../../tools/elf-rewrite/e9-null-witness.py) module with
synthetic byte ownership and independent expected results. They retain all
24 categories of the original control plan, including categories that require
actual produced images and remain unrun by this harness. A pure control pass
does not supply structural-image, loader, architectural-state or native credit.

From the repository root, use a new output directory beneath `ignored/`:

```sh
python3 -B evaluation/e9-witness-controls/controls.py \
  --reader "$REPO/tools/elf-rewrite/e9-null-witness.py" \
  --new-output "$REPO/ignored/e9-witness-controls-result"
```

`REPO` is the absolute canonical checkout path. The output parent must already
exist. The harness requires assertions, authenticates its reader and every
fixture, retains all failures, and checks input ownership and bytes at closure.
It starts no subprocess. For the recorded bounded recipe, use
[`bounded_command.py`](../../tools/unwind-oracle/bounded_command.py) with
10 CPU seconds, 15 wall seconds and a 2 MiB per-file limit; the enclosing
timeout is 25 seconds plus a five-second kill grace and a 40-second parent
backstop. Keep raw results private and publish sanitized CSV/JSON with the exact
source revision, command and hardware observation.

`vectors.json` contains the expected values used at runtime.
`build_vectors.py` records their authoring arithmetic and is not invoked by the
test command. The fixture and category files describe prospective scope;
actual outcomes belong in the separately generated result files.
