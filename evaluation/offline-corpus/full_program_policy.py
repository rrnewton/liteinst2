#!/usr/bin/env python3
"""Fixed source-derived placement hints for the pinned complete e9patch ledger.

This reads bytes and the already imported complete site roster. It is not an
instruction decoder or planner; every generated policy still passes the Rust
importer and all existing tactic, emission, ownership and composition checks.
"""
import argparse
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
PAGE, LANE, LOW, HULL = 4096, 65536, 262144, 16777216
LIMITS = "1048576 4096 2896 11862016 2936 12120064 12026544 2910"

def preferred(low):
    boundary = (low + PAGE - 1) & -PAGE
    return boundary if boundary < low + 256 else low

def policies(inputs):
    assert set(inputs) == set(PINS)
    for name, raw in inputs.items():
        assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == PINS[name]
    original = inputs["original"]
    heads = []
    for row in inputs["ledger"].decode("ascii").splitlines():
        f = row.split()
        if f[0] == "region":
            pc, offset, length = map(int, f[1:])
        elif f[0] == "head":
            address, data = int(f[1]), bytes.fromhex(f[2])
            assert original[offset + address - pc:offset + address - pc + len(data)] == data
            heads.append((address, len(data)))
    sites = [tuple(map(int, row.split("\t")))
             for row in inputs["inventory"].decode("ascii").splitlines()[7:]]
    assert len(heads) == 13143 and len(sites) == 2053
    assert [s[0] for s in sites] == list(range(1, 2054))
    assert all(a[1] + a[2] <= b[1] for a, b in zip(sites, sites[1:]))
    assert sum(s[2] == 2 for s in sites) == 843
    assert sum(s[2] == 5 for s in sites) == 420 and sum(s[2] == 6 for s in sites) == 790
    assert (8218, 1) in heads and original[8218:8219] == b"\xc3"
    h = struct.unpack_from("<16sHHIQQQIHHHHHH", original)
    ph = [struct.unpack_from("<IIQQQQQQ", original, h[5] + i * h[9]) for i in range(h[10])]
    assert len(original) == 93520 and len(ph) == 13 and sum(p[0] == 6 for p in ph) == 1
    assert min(p[3] & -PAGE for p in ph if p[0] == 1) == 0
    assert max((p[3] + p[6] + PAGE - 1) & -PAGE for p in ph if p[0] == 1) == 98304
    # Reserve direct B2 pages once; fixed-byte arithmetic mirrors the public
    # window formula, not instruction classification. Collisions stay refusals.
    used, direct = set(), {}
    for sid, pc, size, offset, *_ in sites:
        if size != 2 or pc // 64 != (pc + size - 1) // 64:
            continue
        low = pc + 5 + int.from_bytes(b"\0" + original[offset + 2:offset + 5], "little", signed=True)
        if low < 0:
            continue
        target = preferred(low); page = target & -PAGE
        if LOW <= page and page + PAGE <= 2147483648 and page not in used:
            direct[sid] = page; used.add(page)
    targets = {}
    for sid, pc, size, offset, *_ in sites:
        if size != 2:
            continue
        pair = None
        for delta in range(256):
            low = pc + 5 + 0xe900 + delta * LANE
            selected = preferred(low); page = selected & -PAGE
            if page < LOW or page + PAGE > HULL or page in used:
                continue
            residue = (pc + 7 + delta) % LANE
            for base in range(LOW, HULL, LANE):
                victim = base + residue; victim_page = victim & -PAGE
                if victim_page == page or victim_page in used or victim_page + PAGE > HULL:
                    continue
                displacement = victim - (pc + 7)
                redirect = b"\xe9" + struct.pack("<i", displacement)
                actual = pc + 5 + int.from_bytes(b"\0" + redirect[:3], "little", signed=True)
                assert actual == low and low <= selected < low + 256
                pair = (selected, victim)
                break
            if pair:
                break
        assert pair is not None, "fixed source-derived paired hint placement exhausted"
        targets[sid] = pair
        used.update(target & -PAGE for target in pair)
    for sid, pc, size, *_ in sites:
        if size == 2:
            continue
        page = next(p for p in range(LOW, HULL, PAGE) if p not in used)
        used.add(page); targets[sid] = (page, page)  # long sites never use T2/T3.
    result = {}
    for label, span in (("16m", HULL), ("2g", 2147483648)):
        rows = ["LI2DISASM-WHOLE-POLICY 1", "original " + PINS["original"], "ledger " + PINS["ledger"],
            inputs["target"].decode("ascii").strip(), "domain 1", "carrier 98304",
            "limits " + LIMITS + " " + str(span), "null-hook 8218"]
        for sid, pc, size, *_ in sites:
            selected, victim = targets[sid]
            # The same preferences serve both profiles. Only the hull clips
            # permissions; an out-of-hull B2 page is never admitted to 16 MiB.
            preferred_ranges = [direct[sid]] if sid in direct and direct[sid] + PAGE <= span else []
            preferred_ranges.append(selected & -PAGE)
            permits = " ".join(f"{p}:{PAGE}" for p in dict.fromkeys(preferred_ranges))
            permits += f" {LOW}:{span - LOW}"
            rows += [f"search {sid} preferred 64 256 64 none 256 4096",
                f"allocation {sid} selected {selected} 1 4096 {permits}",
                f"allocation {sid} victim {victim} 1 4096 {LOW}:{span - LOW}"]
        raw = ("\n".join(rows) + "\n").encode("ascii")
        assert len(raw) <= 1048576
        result["policy-" + label + ".txt"] = raw
    return result

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in PINS:
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    result = policies({name: getattr(a, name).read_bytes() for name in PINS})
    a.out.mkdir(mode=0o700)
    pins = {}
    for name, raw in result.items():
        with (a.out / name).open("xb") as f:
            f.write(raw)
        pins[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    print(json.dumps(pins, sort_keys=True))
