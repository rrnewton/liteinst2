"""Additive fixed pure ownership-geometry controls; old 17/19 unchanged."""
from bootstrap_validate import Invalid
from sparse_geometry import describe, actual_roots


def calibrate():
    accepted, refused = [], []
    compact = ("compact", 0, 0x6000, 0x1000, 0x5000, 0x5000)
    sparse = ("sparse-exec", 0x400000, 0x405000, 0x401000, 0x10000, 0x5000)
    def yes(name, call):
        call()
        accepted.append(name)
    def no(name, call):
        try:
            call()
        except (Invalid, AssertionError):
            refused.append(name)
        else:
            raise AssertionError("required sparse refusal accepted: " + name)
    yes("exact-compact", lambda: describe(*compact))
    yes("exact-sparse-exec", lambda: describe(*sparse))
    yes("sparse-exact-40KiB-budget", lambda: describe(*sparse, max_bytes=40960))
    yes("exact-common-bias-two-roots", lambda: actual_roots(0x70000000, describe(*sparse)["roots"]))
    for name, index, value in (
        ("unknown-kind", 0, "packed"),
        ("wrong-compact-base", 1, 0x1000),
        ("wrong-compact-end", 2, 0x7000),
        ("wrong-source-page", 3, 0x2000),
        ("wrong-generated-PC", 4, 0x6000),
        ("wrong-backing-offset", 5, 0x6000),
        ("unaligned-source", 3, 0x1001),
    ):
        values = list(compact); values[index] = value
        no(name, lambda values=values: describe(*values))
    no("zero-root-budget", lambda: describe(*sparse, max_roots=0))
    no("one-root-budget-for-EXEC", lambda: describe(*sparse, max_roots=1))
    no("root-budget-above-contract", lambda: describe(*sparse, max_roots=3))
    no("zero-byte-budget", lambda: describe(*sparse, max_bytes=0))
    no("one-byte-below-required-storage", lambda: describe(*sparse, max_bytes=40959))
    no("byte-budget-above-contract", lambda: describe(*sparse, max_bytes=1048577))
    no("actual-address-underflow", lambda: actual_roots(0, describe(*compact)["roots"]))
    no("actual-address-overflow", lambda: actual_roots((1 << 64) - 4096, describe(*sparse)["roots"]))
    no("noncanonical-actual-address", lambda: actual_roots(1 << 47, describe(*sparse)["roots"]))
    no("overlapping-acquisition-roots", lambda: actual_roots(0x70000000, [[0, 0x3000], [0x2000, 0x4000]]))
    no("actual-aggregate-budget", lambda: actual_roots(0x70000000, [[0, 0x100000], [0x200000, 0x201000]]))
    assert len(accepted) == len(set(accepted)) == 4
    assert len(refused) == len(set(refused)) == 18
    return dict(accepted=accepted, refused=refused, acceptances=4, refusals=18, mappings=0, application_executions=0)
