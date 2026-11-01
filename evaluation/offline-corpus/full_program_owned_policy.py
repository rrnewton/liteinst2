#!/usr/bin/env python3
"""Explicit owned-placement 2GiB hints for the complete pinned e9patch input.

This separate input policy does not change the original generator or any core
search/acceptance rule. Address arithmetic is not instruction qualification.
"""
import argparse
from bisect import bisect_left, bisect_right
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

if not __debug__:
    raise SystemExit("assertions required")

PINS = dict(original="890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb",
    ledger="727d43acbbb31ac419ba2a87f75433a495c2b838fa9d6d08a138d16c6e52e60d",
    inventory="7d3e1d485fad55ed75139a40fc456374f9fcdbda101096a5d137d1df758b4f5f",
    target="6ac466f4721cc43cbecd450cd3f37cb75cfc8d372e22f1295ae6d2ba2182788c")
PAGE, LANE, LOW, SPAN = 4096, 65536, 262144, 2147483648
U64 = (1 << 64) - 1
LIMITS = "1048576 4096 2896 11862016 2936 12120064 12026544 2910 2147483648"
SEARCH = "preferred 64 256 64 none 256 4096"
PROFILE = "full-e9patch-owned-placement-2g-v1"


class Refusal(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def projection(physical, mask, hint):
    """The existing candidate_target ordinal ZERO, including eager default overflow."""
    require(type(physical) is int and 0 <= physical <= U64, "physical u64")
    require(type(hint) is int and 0 <= hint <= U64, "hint u64")
    require(len(mask) == 4 and all(type(x) is bool for x in mask), "four mask bits")
    if physical > U64 - 5 - LANE:
        return None
    displacement = hint - (physical + 5)
    if not -(1 << 31) <= displacement < (1 << 31):
        return None
    encoded = bytearray(struct.pack("<i", displacement))
    for index, constrained in enumerate(mask):
        if constrained:
            encoded[index] = 0x06
    result = physical + 5 + int.from_bytes(encoded, "little", signed=True)
    return result if 0 <= result <= U64 else None


def pun_window(pc, following, prefixes=0):
    """Only the pinned two-byte originals: B2, or the one T1 prefix."""
    require(prefixes in (0, 1) and len(following) == 3 + prefixes, "pun suffix")
    free = 1 - prefixes
    low = pc + 5 + prefixes + int.from_bytes(bytes(free) + following, "little", signed=True)
    size = 1 << (8 * free)
    return (low, low + size) if 0 <= low <= U64 - size else None


def first_pun(window, hint, ranges):
    """Existing pun_candidates at max_candidates=1; preferred precedes permits."""
    if window is None:
        return None
    low, end = window
    if hint is not None and low <= hint < end:
        return hint
    for start, length in ranges:
        if start > U64 - (PAGE - 1):
            continue
        address = max(low, (start + PAGE - 1) & -PAGE)
        if address < min(end, start + length):
            return address
    return None


def fits_page(address, size):
    # Used only by controls with an independently specified image length.
    return (type(size) is int and 0 < size <= PAGE and 0 <= address <= U64 - size
            and address // PAGE == (address + size - 1) // PAGE)


def window_pages(window):
    if window is None:
        return []
    low, end = window
    require(0 <= low < end <= U64 and end - low <= 256, "finite pun window")
    return [p for p in range(low & -PAGE, ((end - 1) & -PAGE) + PAGE, PAGE)
            if LOW <= p and p + PAGE <= SPAN]


def permits(pages):
    """Deduplicate in priority order; merge only forward-adjacent owned pages."""
    result = []
    for page in dict.fromkeys(pages):
        require(page % PAGE == 0 and LOW <= page and page + PAGE <= SPAN, "permit hull")
        if result and result[-1][0] + result[-1][1] == page:
            result[-1] = (result[-1][0], result[-1][1] + PAGE)
        else:
            result.append((page, PAGE))
    require(1 <= len(result) <= 16, "complete assignment exceeds existing 16-permit bound")
    return result


def source(inputs):
    require(set(inputs) == set(PINS), "four pinned inputs")
    for name, raw in inputs.items():
        require(len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == PINS[name], name + " pin")
    original = inputs["original"]
    heads, sizes, regions = [], {}, {}
    for row in inputs["ledger"].decode("ascii").splitlines()[3:]:
        fields = row.split()
        if fields[0] == "region":
            pc, offset, length = map(int, fields[1:])
            regions[pc] = (offset, length)
        else:
            require(fields[0] == "head" and len(fields) == 3, "ledger row")
            address, data = int(fields[1]), bytes.fromhex(fields[2])
            require(0 <= address - pc <= length - len(data), "head region")
            require(original[offset + address - pc:offset + address - pc + len(data)] == data, "head bytes")
            require(address not in sizes and 1 <= len(data) <= 15, "head identity")
            heads.append(address)
            sizes[address] = len(data)
    sites = [tuple(map(int, row.split("\t")))
             for row in inputs["inventory"].decode("ascii").splitlines()[7:]]
    require(len(heads) == 13143 and heads == sorted(heads), "complete heads")
    require(len(sites) == 2053 and [s[0] for s in sites] == list(range(1, 2054)), "complete sites")
    require(Counter(s[2] for s in sites) == {2: 843, 5: 420, 6: 790}, "site lengths")
    for sid, pc, size, offset, region, length, block, block_length in sites:
        require(sizes.get(pc) == size and regions[region] == (offset - pc + region, length), "site source")
        require(region <= block <= pc < block + block_length <= region + length, "block bounds")
    require(all(a[1] + a[2] <= b[1] for a, b in zip(sites, sites[1:])), "site overlap")
    h = struct.unpack_from("<16sHHIQQQIHHHHHH", original)
    ph = [struct.unpack_from("<IIQQQQQQ", original, h[5] + i * h[9]) for i in range(h[10])]
    require(len(original) == 93520 and len(ph) == 13 and sum(p[0] == 6 for p in ph) == 1, "original ELF")
    require(min(p[3] & -PAGE for p in ph if p[0] == 1) == 0, "LOAD start")
    require(max((p[3] + p[6] + PAGE - 1) & -PAGE for p in ph if p[0] == 1) == 98304, "LOAD end")
    require(98304 + ((2910 * 56 + 128 + PAGE - 1) & -PAGE) == LOW, "carrier reservation")
    require(sizes.get(8218) == 1 and original[8218:8219] == b"\xc3", "null hook")
    return original, heads, sites


def physicals(site, heads):
    _, pc, _, _, _, _, block, block_length = site
    candidates = heads[bisect_left(heads, max(block, pc - 64)):bisect_right(heads, pc)]
    candidates = [p for p in candidates if p < block + block_length]
    candidates.sort(key=lambda p: (p != pc, p % 64 > 56, pc - p))
    result = []
    for physical in candidates[:64]:
        interior = set(heads[bisect_right(heads, physical):bisect_left(heads, physical + 5)])
        result.append((physical, tuple(physical + i in interior for i in range(1, 5))))
    return result


def construct(original, heads, sites):
    owners, windows, pages, intended = {}, {}, {}, {}
    counts = Counter()
    # Protect every mathematical original B2/T1 page before independent hints.
    blocked = set()
    for sid, pc, size, offset, region, length, *_ in sites:
        windows[sid] = []
        pages[sid], intended[sid] = [], []
        if size == 2 and pc // 64 == (pc + 1) // 64:
            for prefix in (0, 1):
                if pc + 5 + prefix <= region + length:
                    window = pun_window(pc, original[offset + 2:offset + 5 + prefix], prefix)
                    windows[sid].append(window)
                    blocked.update(window_pages(window))
    # Highest PC is planned first by the unchanged whole frontend.
    for sid, *_ in reversed(sites):
        for window in windows[sid]:
            choices = sorted(window_pages(window), key=lambda p: (max(window[0], p) - p, p))
            selected = next((p for p in choices if owners.get(p, (sid, "selected")) == (sid, "selected")), None)
            if selected is None:
                counts["original_pun_windows_without_owned_page"] += 1
                continue
            owners[selected] = (sid, "selected")
            pages[sid].append(selected)
            intended[sid].append((window, first_pun(window, None, permits(pages[sid]))))

    victim, lane = {}, LOW
    # A single monotone lane cursor bounds ALL victim-lane probes by 32764.
    for site in reversed(sites):
        sid, pc, size, *_ = site
        if size != 2:
            continue
        pair = None
        for delta in range(256):
            window = (pc + 5 + 0xe900 + delta * LANE, pc + 5 + 0xe900 + delta * LANE + 256)
            for page in sorted(window_pages(window), key=lambda p: (max(window[0], p) - p, p)):
                if page in blocked and owners.get(page) != (sid, "selected"):
                    continue
                if page in owners and owners[page] != (sid, "selected"):
                    continue
                selected = max(window[0], page)
                ordered = permits(pages[sid] + [page])
                if first_pun(window, None, ordered) != selected:
                    continue
                while lane + LANE <= SPAN:
                    target = lane + ((pc + 7 + delta) % LANE)
                    lane += LANE
                    counts["victim_lane_probes"] += 1
                    vp = target & -PAGE
                    if vp == page or vp in owners or vp in blocked:
                        continue
                    redirect = b"\xe9" + struct.pack("<i", target - (pc + 7))
                    require(pun_window(pc, redirect[:3]) == window, "T2 overlay arithmetic")
                    pair = (page, selected, target, window)
                    break
                if pair:
                    break
            if pair:
                break
        require(pair is not None, "bounded complete T2/independent-victim assignment exhausted")
        page, selected, target, window = pair
        owners[page], owners[target & -PAGE] = (sid, "selected"), (sid, "victim")
        pages[sid].append(page)
        intended[sid].append((window, selected))
        victim[sid] = target

    hints, cursor = {}, LOW
    for sid, *_ in reversed(sites):
        while cursor + PAGE <= SPAN:
            hint, cursor = cursor, cursor + PAGE
            counts["selected_page_probes"] += 1
            if hint in owners or hint in blocked:
                continue
            if any(w[0] <= hint < w[1] for w, _ in intended[sid]):
                continue
            hints[sid] = hint
            owners[hint] = (sid, "selected")
            pages[sid].append(hint)
            break
        require(sid in hints, "complete aligned selected assignment exhausted")

    # Enumerate the actual finite physical/mask domain, not selected-PC alone.
    # Every admitted projection gets a whole exclusive page. An unavailable
    # case stays outside this role's permits and is counted, never a skipped site.
    for site in reversed(sites):
        sid = site[0]
        for physical, mask in physicals(site, heads):
            counts["b1_physical_candidates"] += 1
            target = projection(physical, mask, hints[sid])
            if target is None or not LOW <= target < SPAN:
                counts["b1_unavailable_arithmetic_or_hull"] += 1
                continue
            page = target & -PAGE
            if ((page in owners and owners[page] != (sid, "selected"))
                    or (page in blocked and owners.get(page) != (sid, "selected"))):
                counts["b1_unavailable_owned_or_reserved"] += 1
                continue
            owners[page] = (sid, "selected")
            pages[sid].append(page)
            counts["b1_permitted_projections"] += 1
    allocations = {}
    for sid, _, size, *_ in sites:
        ranges = permits(pages[sid])
        for window, expected in intended[sid]:
            require(first_pun(window, hints[sid], ranges) == expected, "ordered pun target changed")
        allocations[sid] = (hints[sid], ranges, victim.get(sid, hints[sid]))
        require(size == 2 or sid not in victim, "long-site unused victim role")
    require(counts["b1_physical_candidates"] == counts["b1_permitted_projections"]
            + counts["b1_unavailable_arithmetic_or_hull"] + counts["b1_unavailable_owned_or_reserved"],
            "complete B1 address census")
    validate(sites, allocations)
    return allocations, dict(sorted(counts.items()))


def validate(sites, allocations):
    require(len(sites) == 2053 and [s[0] for s in sites] == list(range(1, 2054)), "full allocation roster")
    require(set(allocations) == {s[0] for s in sites}, "no missing or extra site")
    held = {}
    for sid, _, size, *_ in sites:
        hint, ranges, victim = allocations[sid]
        require(hint % PAGE == 0 and 1 <= len(ranges) <= 16, "aligned hint/range count")
        require(any(start <= hint < start + length for start, length in ranges), "preferred ownership")
        for start, length in ranges + ([(victim & -PAGE, PAGE)] if size == 2 else []):
            require(start % PAGE == length % PAGE == 0 and length > 0
                    and LOW <= start < start + length <= SPAN, "owned range")
            for page in range(start, start + length, PAGE):
                require(page not in held, "overlapping selected/victim/site permits")
                held[page] = sid
        require(LOW <= victim < SPAN, "victim hull")


def policy(inputs):
    original, heads, sites = source(inputs)
    allocations, counts = construct(original, heads, sites)
    rows = ["LI2DISASM-WHOLE-POLICY 1", "original " + PINS["original"], "ledger " + PINS["ledger"],
            inputs["target"].decode("ascii").strip(), "domain 1", "carrier 98304",
            "limits " + LIMITS, "null-hook 8218"]
    for sid, *_ in sites:
        hint, ranges, victim = allocations[sid]
        permit_text = " ".join(f"{start}:{length}" for start, length in ranges)
        rows.extend((f"search {sid} {SEARCH}", f"allocation {sid} selected {hint} 1 4096 {permit_text}",
                     f"allocation {sid} victim {victim} 1 4096 {victim & -PAGE}:{PAGE}"))
    raw = ("\n".join(rows) + "\n").encode("ascii")
    require(len(raw) <= 1048576, "unchanged policy file ceiling")
    return raw, dict(profile=PROFILE, heads=len(heads), sites=len(sites), counters=counts,
                    qualification_complete=False, limits=LIMITS, search=SEARCH,
                    bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in PINS:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    # Freeze a fresh output directory before work; retain any generation refusal.
    args.out.mkdir(mode=0o700)
    try:
        inputs = {}
        for name in PINS:
            with getattr(args, name).open("rb") as stream:
                inputs[name] = stream.read(1048577)
        raw, summary = policy(inputs)
        with (args.out / "policy-owned-2g-v1.txt").open("xb") as stream:
            stream.write(raw)
        summary["status"] = "GENERATED_UNQUALIFIED"
    except Exception as error:
        summary = dict(profile=PROFILE, status="REFUSED", qualification_complete=False,
                       error=type(error).__name__ + ": " + str(error))
        with (args.out / "summary.json").open("x") as stream:
            json.dump(summary, stream, sort_keys=True, indent=2)
            stream.write("\n")
        raise
    with (args.out / "summary.json").open("x") as stream:
        json.dump(summary, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
