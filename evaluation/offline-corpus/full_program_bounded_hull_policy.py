#!/usr/bin/env python3
"""Clip the exact legacy complete policy to one explicit 512 MiB hull.

This adapter changes permissions, not hints, tactics or acceptance rules. Use
the existing packed entry-veneer frontend; no planner or native run is started.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

if not __debug__:
    raise SystemExit("assertions required")

PINS = dict(original="890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb",
    ledger="727d43acbbb31ac419ba2a87f75433a495c2b838fa9d6d08a138d16c6e52e60d",
    inventory="7d3e1d485fad55ed75139a40fc456374f9fcdbda101096a5d137d1df758b4f5f",
    target="6ac466f4721cc43cbecd450cd3f37cb75cfc8d372e22f1295ae6d2ba2182788c")
POLICY_PIN = (359381, "ef09bcd4c78949ff4b93a928c59e04b545081f9e56c2056f2cfcdfe068604cce")
PAGE, LOW, HIGH, U64 = 4096, 262144, 536870912, (1 << 64) - 1
LIMITS = "1048576 4096 2896 11862016 2936 12120064 12026544 2910"
PROFILE = "full-e9patch-packed-hull512m-v1"
FILENAME = "policy-packed-hull512m-v1.txt"


class Refusal(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def clip_permits(ranges):
    """Intersect in caller order, keeping duplicate/overlapping survivors."""
    require(1 <= len(ranges) <= 16, "existing 1..16 permit bound")
    result = []
    for start, length in ranges:
        require(type(start) is int and type(length) is int
                and 0 <= start <= U64 and 0 < length <= U64 - start, "permit u64 extent")
        require(start % PAGE == 0 and length % PAGE == 0, "page-aligned permit")
        low, end = max(start, LOW), min(start + length, HIGH)
        if low < end:
            result.append((low, end - low))
    return result


def allocation(line, sid, role):
    fields = line.split()
    require(line == " ".join(fields) and 7 <= len(fields) <= 22, "canonical allocation row")
    require(fields[:3] == ["allocation", str(sid), role] and role in ("selected", "victim"), "allocation identity")
    require(fields[3].isascii() and fields[3].isdecimal() and 0 <= int(fields[3]) <= U64, "preferred address")
    require(fields[4:6] == ["1", "4096"], "unchanged candidate/image caps")
    ranges = []
    for token in fields[6:]:
        pair = token.split(":")
        require(len(pair) == 2 and all(x.isascii() and x.isdecimal() for x in pair), "permit syntax")
        ranges.append(tuple(map(int, pair)))
    clipped = clip_permits(ranges)
    require(clipped, f"no in-arena {role} permit for site {sid}; complete policy refused")
    # A numerical preference never grants permission. Keep it even if a future
    # policy's hint lies outside the arena; core placement must certify it.
    return " ".join(fields[:6] + [f"{start}:{length}" for start, length in clipped])


def bounded_policy(raw, inputs):
    require(set(inputs) == set(PINS), "four pinned inputs")
    for name, value in inputs.items():
        require(type(value) is bytes and len(value) <= 1048576
                and hashlib.sha256(value).hexdigest() == PINS[name], name + " pin")
    require(type(raw) is bytes and len(raw) == POLICY_PIN[0]
            and hashlib.sha256(raw).hexdigest() == POLICY_PIN[1], "legacy 2GiB policy pin")
    heads = []
    for line in inputs["ledger"].decode("ascii").splitlines():
        fields = line.split()
        if fields[0] == "head":
            require(len(fields) == 3, "head row")
            data = bytes.fromhex(fields[2])
            require(1 <= len(data) <= 15, "head length")
            heads.append((int(fields[1]), len(data)))
    require(len(heads) == 13143 and [h[0] for h in heads] == sorted({h[0] for h in heads}), "complete heads")
    sizes = dict(heads)
    sites = [tuple(map(int, line.split("\t")))
             for line in inputs["inventory"].decode("ascii").splitlines()[7:]]
    require(len(sites) == 2053 and all(len(s) == 8 for s in sites)
            and [s[0] for s in sites] == list(range(1, 2054)), "complete ordered sites")
    require(all(sizes.get(s[1]) == s[2] for s in sites), "site/head identity")
    require(all(a[1] + a[2] <= b[1] for a, b in zip(sites, sites[1:])), "site overlap")
    rows = raw.decode("ascii").splitlines()
    prefix = ["LI2DISASM-WHOLE-POLICY 1", "original " + PINS["original"], "ledger " + PINS["ledger"],
        inputs["target"].decode("ascii").strip(), "domain 1", "carrier 98304",
        "limits " + LIMITS + " 2147483648", "null-hook 8218"]
    require(rows[:8] == prefix and len(rows) == 8 + 3 * len(sites)
            and raw == ("\n".join(rows) + "\n").encode("ascii"), "complete canonical legacy policy")
    result = rows[:8]
    result[6] = "limits " + LIMITS + " " + str(HIGH)
    for index, site in enumerate(sites):
        sid = site[0]
        search, selected, victim = rows[8 + 3 * index:11 + 3 * index]
        require(search == f"search {sid} preferred 64 256 64 none 256 4096", "unchanged search row")
        result.extend((search, allocation(selected, sid, "selected"), allocation(victim, sid, "victim")))
    output = ("\n".join(result) + "\n").encode("ascii")
    require(len(output) <= 1048576 and len(result) == len(rows), "unchanged file/complete population bounds")
    return output, dict(profile=PROFILE, status="GENERATED_UNQUALIFIED", qualification_complete=False,
        selected_sites=len(sites), heads=len(heads), arena=dict(start=LOW, end_exclusive=HIGH),
        virtual_span=HIGH, limits=LIMITS + " " + str(HIGH), hints_unchanged=True,
        search_rows_unchanged=True, surviving_permit_order_unchanged=True,
        legacy_policy=dict(bytes=len(raw), sha256=POLICY_PIN[1]), inputs=PINS,
        bytes=len(output), sha256=hashlib.sha256(output).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in PINS:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--policy-2g", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(mode=0o700, exist_ok=False)
    try:
        inputs = {}
        for name in PINS:
            with getattr(args, name).open("rb") as stream:
                inputs[name] = stream.read(1048577)
        with args.policy_2g.open("rb") as stream:
            raw = stream.read(1048577)
        output, summary = bounded_policy(raw, inputs)
        with (args.out / FILENAME).open("xb") as stream:
            stream.write(output); stream.flush(); os.fsync(stream.fileno())
    except Exception as error:
        summary = dict(profile=PROFILE, status="REFUSED", qualification_complete=False,
                       error=type(error).__name__ + ": " + str(error))
        with (args.out / "summary.json").open("x") as stream:
            json.dump(summary, stream, indent=2, sort_keys=True); stream.write("\n")
        raise
    with (args.out / "summary.json").open("x") as stream:
        json.dump(summary, stream, indent=2, sort_keys=True); stream.write("\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
