"""Explicit body-view ownership for the fixed compact and sparse EXEC cohort."""
from bootstrap_validate import PAGE, LOADER, need

MAX_BODY_BYTES = 1024 * 1024
MAX_ROOTS = 2
USER_END = 1 << 47


def describe(kind, minimum, maximum, source, image, image_offset,
             max_roots=MAX_ROOTS, max_bytes=MAX_BODY_BYTES):
    need(type(max_roots) is int and 0 < max_roots <= MAX_ROOTS, "bounded root count")
    need(type(max_bytes) is int and 0 < max_bytes <= MAX_BODY_BYTES, "bounded owned bytes")
    need(all(type(v) is int for v in (minimum, maximum, source, image, image_offset)), "integer geometry")
    need(all(v % PAGE == 0 for v in (minimum, maximum, source, image, image_offset)), "page geometry")
    if kind == "compact":
        need((minimum, maximum, source, image, image_offset) == (0, 0x6000, 0x1000, 0x5000, 0x5000), "exact compact cohort")
        roots = [[-PAGE, 0x7000]]
    else:
        need(kind == "sparse-exec", "explicit geometry variant")
        need((minimum, maximum, source, image, image_offset) == (0x400000, 0x405000, 0x401000, 0x10000, 0x5000), "exact sparse EXEC cohort")
        roots = [[0x3ff000, 0x406000], [0xf000, 0x12000]]
    need(0 < maximum - minimum <= MAX_BODY_BYTES, "unchanged compact mapper span")
    need(len(roots) <= max_roots, "root budget exhausted")
    lengths = [end - start for start, end in roots]
    need(all(0 < length <= MAX_BODY_BYTES for length in lengths) and sum(lengths) <= max_bytes, "aggregate owned-body budget")
    need(all(not (start <= LOADER < end) for start, end in roots), "bootstrap excluded")
    return dict(kind=kind, roots=roots, root_count=len(roots), owned_bytes=sum(lengths))


def actual_roots(bias, roots):
    need(type(bias) is int and 0 <= bias < (1 << 64) and bias % PAGE == 0, "checked bias")
    need(0 < len(roots) <= MAX_ROOTS, "actual root count")
    result = []
    total = 0
    for start, end in roots:
        need(type(start) is type(end) is int and start % PAGE == end % PAGE == 0, "root integer alignment")
        need(0 < end - start <= MAX_BODY_BYTES, "root byte bound")
        low, high = bias + start, bias + end
        need(0 < low < high <= USER_END and high < (1 << 64), "nonwrapping canonical user root")
        need(all(high <= old_low or old_high <= low for old_low, old_high in result), "disjoint acquired roots")
        total += end - start
        need(total <= MAX_BODY_BYTES, "aggregate root byte bound")
        result.append([low, high])
    return result
