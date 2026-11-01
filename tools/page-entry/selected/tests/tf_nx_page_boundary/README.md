# NX page-boundary policy oracle

The 57-case oracle calls the same descriptive predicate used by the ordinary
TRACE and genuine span-resume tails. It checks one/two opened pages, half-open
endpoints, a borrowed-but-unopened second page, both eligible continuation
reasons, every preserved declined reason, and malformed requests. It grants no
source, permission, runtime-owner, equivalence or performance credit.

From a clean checkout with an externally reserved CPU and the complete process
tree pinned to it, set `LI2_CPU` to that CPU number and run:

```sh
python3 -B evaluation/inprocess/tf_nx_page_boundary.py \
  --cpu "$LI2_CPU" --expect-revision "$(git rev-parse HEAD)" \
  --output target/evaluation/inprocess/tf-nx-page-boundary-oracle-attempt-1
```

The runner uses the installed header, oracle and `build.sh` recipe directly.
It checks the exact clean revision and CPU, records their complete identities,
observes the actual compiler-M header closure, and retains all command outputs
and the static freestanding executable. There are seven fixed commands: four
compiler-tool observations, headers, build, and the oracle. The first six have
30 CPU-second / 60 wall-second bounds; the oracle has 5 CPU seconds / 15 wall
seconds. All retain 512 MiB memory and 16 MiB output bounds. Failure is retained;
there is no retry or substitute result.

Success requires the exact output:

```text
LI2_TF_NX_PAGE_BOUNDARY cases=57 geometry=32 declined=15 malformed=10
```

The receipt status is `policy_observed`. The separate unchanged five-stage
`evaluation/inprocess/reproduce_resident_three.py` cohort must still establish
the actual close/release/NX behavior and complete native/owner/pair state. In
particular it compares the kernel-provided CR2 literally; this pure policy
oracle cannot satisfy that runtime gate.
