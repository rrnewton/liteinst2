# Pinned E9Patch upstream self-rewrite corpus

All **10 cases passed**: five instrumentation actions on each of `e9tool` and `e9patch`. The unmodified upstream test rewrites both tools, uses those rewritten tools to rewrite the originals again, and compares the two generations byte for byte. This validates the pinned E9Patch baseline; it is separate from the LiteInst multi-program comparison.

`cases.csv` gives the complete fixed denominator. `receipt.json` records exact source/tool hashes, revision, hardware, command, limits and strict process closure. Raw logs stay ignored. The 119.56-second duration is operational validation time, not a performance result.

Reproduction requires the stock PLDI2020 source at `ignored/a3/upstream/e9patch-pldi2020`: E9Patch revision `0d5d36e4c4edcac37ca2499694d64302a391136f`, Capstone revision `e3f106739a6ae78d47772dff31062d644ea21078`, built with `make -j4 tool release`. The [existing reproduction guide](../e9-common-reproduction.md) explains fixed local prerequisite-artifact staging. The runner authenticates the five exact input hashes in the receipt, including both built tools, and refuses different products. This historical reproduction does not silently accept a new toolchain build.

```sh
mkdir -p ignored/a3/e9-upstream-corpus-source-v1
cp evaluation/e9-upstream-corpus-c66ea06/run.py ignored/a3/e9-upstream-corpus-source-v1/run.py
python3.9 -B ignored/a3/e9-upstream-corpus-source-v1/run.py
```

The output directory must be fresh. The runner copies the five inputs before executing the original script. A failed printed comparison remains FAILED even when the shell exits zero; missing terminals remain UNOBSERVED and do not imply that the rewrite never started. Selected file hashes are recorded, without claiming complete compiler-chain or runtime-owner admission. There is no performance or full LiteInst qualification claim.
