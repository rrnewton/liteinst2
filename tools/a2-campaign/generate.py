#!/usr/bin/env python3
"""Pure literal generator; never maps, executes, disassembles, or invokes Cargo.

The 512-case denominator and strata below are prospective. Generation is not a
native campaign result. No output can silently drop a case or change its outcome.
"""
import sys
if sys.flags.optimize:
    raise SystemExit("proof/generation scripts require assertions; optimized Python is refused")

import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MASK = (1 << 64) - 1
MASTER = 0xA2CA_2026_1025_0512
STRATA = [
    ("unbiased_b1", 256),
    ("b2", 32), ("b1", 24), ("t1", 36), ("t2", 32),
    ("t3", 36), ("coalesced", 16), ("grouped", 8),
    ("window_refusal", 16), ("collision", 16),
    ("ownership", 24), ("unsupported_call", 8), ("cet", 8),
]
assert sum(n for _, n in STRATA) == 512


class Rng:
    def __init__(self, seed):
        self.state = seed

    def word(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
        return (z ^ (z >> 31)) & MASK

    def bits(self, n):
        return self.word() & ((1 << n) - 1)


class Code:
    def __init__(self):
        self.data = bytearray()
        self.instructions = []

    def add(self, data, mnemonic, operands="", jump=None):
        pc = len(self.data)
        data = bytes(data)
        self.data.extend(data)
        self.instructions.append(dict(pc=pc, length=len(data), mnemonic=mnemonic,
                                      operands=operands, jump=jump))
        return pc

    def ret(self):
        return self.add([0xC3], "ret")


def imm32(value):
    return struct.pack("<I", value & 0xFFFFFFFF)


def selected(code, length, rng):
    if length == 1:
        code.add([0x90], "nop")
    elif length == 2:
        code.add([0x89, 0xC0], "mov", "eax,eax")
    elif length == 3:
        code.add([0x48, 0x8D, 0x07], "lea", "rax,[rdi]")
    else:
        displacement = 8 * rng.bits(3)
        code.add([0x48, 0x8D, 0x4F, displacement], "lea", f"rcx,[rdi+{displacement}]")


def mov32(code, rng, register=0):
    immediate = rng.bits(32)
    return code.add(bytes([0xB8 + register]) + imm32(immediate), "mov",
                    f"{['eax', 'ecx', 'edx'][register]},0x{immediate:08x}")


def body_op(code, rng):
    # Eight equally likely forms. Each operand choice uses power-of-two draws.
    # All memory accesses use unchanged oracle RDI and offsets 0..56, width 8.
    choice = rng.bits(3)
    displacement = 8 * rng.bits(3)
    immediate = rng.bits(8)
    if choice == 0:
        code.add([0x48, 0x8D, 0x47, displacement], "lea", f"rax,[rdi+{displacement}]")
    elif choice == 1:
        mov32(code, rng, 1)
    elif choice in (2, 3):
        code.add([0x48, 0x83, 0xC0 if choice == 2 else 0xE8, immediate],
                 "add" if choice == 2 else "sub", f"rax,signext(0x{immediate:02x})")
    elif choice == 4:
        code.add([0x48, 0x89, 0x47, displacement], "mov", f"[rdi+{displacement}],rax")
    elif choice == 5:
        code.add([0x48, 0x8B, 0x57, displacement], "mov", f"rdx,[rdi+{displacement}]")
    elif choice == 6:
        code.add([0x48, 0x39, 0xC8], "cmp", "rax,rcx")
    else:
        forms = [b"\x90", b"\x66\x90", b"\x0f\x1f\x00", b"\x0f\x1f\x40\x00"]
        width = rng.bits(2)
        code.add(forms[width], "nop", f"width={width+1}")


def visits(instructions, entry):
    by_pc = {insn["pc"]: insn for insn in instructions}
    result = []
    pc = entry
    while True:
        assert len(result) <= len(instructions) + 2
        result.append(pc)
        insn = by_pc[pc]
        if insn["mnemonic"] == "ret":
            return result
        # CALL is a declared planner negative. Its native itinerary is specified
        # separately below; it is never treated as an ordinary fallthrough.
        assert insn["mnemonic"] != "call"
        nxt = insn["jump"] if insn["jump"] is not None else pc + insn["length"]
        assert nxt > pc, "normal grammar must strictly advance or return"
        pc = nxt


def make(case_id, family, index):
    seed = (MASTER + case_id * 0x9E3779B97F4A7C15) & MASK
    rng = Rng(seed)
    state_seeds = [rng.word(), rng.word()]
    assert all(state_seeds) and state_seeds[0] != state_seeds[1]
    code = Code()
    # Eight equiprobable aligned starts keep the declared B1 E9 inside its
    # cache line. This is a placement grammar, not an execution-time filter.
    alignment = 8 * rng.bits(3)
    c = dict(id=case_id, cohort="unbiased" if case_id < 256 else "biased",
             family=family, family_index=index, generator_seed=seed,
             memory_seed=Rng(seed ^ 0x4D454D4F52593031).word(),
             state_seeds=state_seeds, alignment=alignment, selected=0, physical=0,
             selected_len=5, prefixes=0, victim=None, victim_len=0,
             block_start=0, block_end=5, functions=[], actions=[],
             target_kind="ordinary", selected_delta=0, victim_delta=0,
             expected="positive", forced="Relocation", controls=0,
             holes=[-4096, 4096], search_classification="unknown")
    if family == "unbiased_b1":
        # Explicit fixed-width relocation prologue; randomness is in operands,
        # body forms, body count, branch presence/skip width, and initial states.
        mov32(code, rng, rng.bits(1))
        for _ in range(1 + rng.bits(2)):
            body_op(code, rng)
        if rng.bits(1):
            skip = Code()
            body_op(skip, rng)
            branch = code.add([0xEB, len(skip.data)], "jmp", f"forward +{len(skip.data)}",
                              len(code.data) + 2 + len(skip.data))
            assert branch + 2 + len(skip.data) == code.instructions[-1]["jump"]
            for instruction in skip.instructions:
                code.add(skip.data, instruction["mnemonic"], instruction["operands"])
        code.ret()
    elif family in ("b1", "collision", "cet"):
        mov32(code, rng)
        if family == "b1" and index % 2:
            c.update(selected=5, selected_len=2, block_end=8)
            selected(code, 2, rng)
        else:
            body_op(code, rng)
        code.ret()
        if family == "collision":
            c["expected"] = "publication_collision_then_same_plan_positive"
        if family == "cet":
            c["expected"] = "cet_refusal"
    elif family in ("b2", "t1", "window_refusal"):
        pairs = [(2, 1), (3, 1), (3, 2), (4, 1), (4, 2), (4, 3)]
        prefix_family = family == "t1" or (family == "window_refusal" and index >= 8)
        length, prefixes = pairs[index % 6] if prefix_family else (1 + index % 4, 0)
        selected(code, length, rng)
        # High immediate byte varies; the consumed opcode + low 3 bytes remain
        # independently controllable and separate every prefix window.
        immediate = (rng.bits(8) << 24) | 0x375A82
        code.add(bytes([0xB9]) + imm32(immediate), "mov", f"ecx,0x{immediate:08x}")
        code.ret()
        c.update(selected_len=length, prefixes=prefixes, block_end=length,
                 target_kind="pun", forced="PrefixedPun" if prefixes else "GeneralizedPun",
                 holes=[])
        if family == "window_refusal":
            c["expected"] = "allocation_refusal"
    elif family == "t2":
        prefixes, length = (0, 3) if index % 2 == 0 else (1, 2)
        selected(code, length, rng)
        victim = len(code.data)
        if index % 4 < 2:
            mov32(code, rng)
            victim_len = 5
        else:
            victim_len = 10 + (index // 4) % 6
            immediate = rng.word()
            code.add(bytes([0x2E] * (victim_len-10) + [0x48, 0xB8]) +
                     struct.pack("<Q", immediate), "mov", f"rax,0x{immediate:016x}")
        code.add([0x48, 0x89, 0x07], "mov", "[rdi],rax")
        code.ret()
        c.update(selected_len=length, prefixes=prefixes, victim=victim,
                 victim_len=victim_len, block_end=length, target_kind="successor",
                 victim_delta=0x00123456 + ((index // 2) << 16),
                 forced="SuccessorEviction", holes=[])
    elif family == "t3":
        length = 2 + index // 12
        victim_len = 10 + (index // 2) % 6
        backward = index % 2 == 1
        c["alignment"] = 8 * rng.bits(2)
        selected_pc, victim_pc = (16, 0) if backward else (0, 16)
        # NOP1 fills every gap, and every filler head is retained in the cohort.
        for pc, role in sorted([(selected_pc, "selected"), (victim_pc, "victim")]):
            while len(code.data) < pc:
                code.add([0x90], "nop")
            if role == "selected":
                selected(code, length, rng)
            else:
                immediate = rng.word()
                code.add(bytes([0x2E] * (victim_len-10) + [0x48, 0xB8]) +
                         struct.pack("<Q", immediate), "mov", f"rax,0x{immediate:016x}")
            code.ret()
        c.update(selected=selected_pc, physical=selected_pc, selected_len=length,
                 victim=victim_pc, victim_len=victim_len, block_start=selected_pc,
                 block_end=selected_pc+length, target_kind="neighbor",
                 forced="NeighborEviction", holes=[])
    elif family in ("coalesced", "grouped"):
        groups = 2 if family == "grouped" else 1
        controls_per_group = 2 if groups == 2 else 3
        for _ in range(groups):
            start = len(code.data)
            for register in range(controls_per_group):
                c["actions"].append(len(code.data))
                mov32(code, rng, register)
            end = len(code.data)
            code.ret()
            c["functions"].append([start, len(code.data), end])
        c.update(controls=groups*controls_per_group, block_end=c["functions"][0][2],
                 target_kind="controlled", holes=[])
    elif family == "ownership":
        selected(code, 2, rng)
        mov32(code, rng)
        code.ret()
        c.update(selected=2, physical=2, selected_len=5, block_start=2, block_end=7,
                 expected="ownership_refusal_then_replan_positive", holes=[])
    elif family == "unsupported_call":
        code.add([0xE8, 1, 0, 0, 0], "call", "target=6", 6)
        code.add([0x90], "nop")
        code.ret()
        c["expected"] = "call_refusal"
    else:
        raise AssertionError(family)
    heads = [instruction["pc"] for instruction in code.instructions]
    assert sorted(set(heads)) == heads
    if family == "unsupported_call":
        paths = [[0, 6, 5, 6], [5, 6], [6]]
    else:
        paths = [visits(code.instructions, entry) for entry in heads]
    c.update(code=code.data.hex(), instructions=code.instructions, heads=heads,
             native_paths=paths, max_native_steps=max(map(len, paths)),
             permitted_entry_count=len(heads), masks=(1 << c["controls"]) if c["controls"] else 1)
    # The B1 ordinary preferred target and occupied neighboring holes vary by
    # whole pages but keep the required image's page free. No adaptive search.
    c["selected_delta"] = 0x10000100 + 4096 * rng.bits(5)
    if c["target_kind"] == "neighbor":
        c["victim_delta"] = 0x18000200 + 4096 * rng.bits(5)
    per_phase = len(heads) * 2
    c["expected_primary_installed"] = 0 if c["expected"] in (
        "allocation_refusal", "call_refusal", "cet_refusal") else per_phase * c["masks"]
    c["expected_primary_retired"] = 0 if c["expected_primary_installed"] == 0 else per_phase
    visits_with_hooks = sum(sum(pc in (c["actions"] or [c["selected"]]) for pc in path) for path in paths)
    c["expected_primary_events"] = 0 if c["expected_primary_installed"] == 0 else (
        2 * visits_with_hooks * (c["masks"] // 2 if c["controls"] else 1))
    c["expected_auxiliary_installed"] = per_phase if family == "ownership" else 0
    c["expected_auxiliary_retired"] = c["expected_auxiliary_installed"]
    c["expected_auxiliary_events"] = 2 if family == "ownership" else 0
    c["input_sha256"] = hashlib.sha256(json.dumps(c, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return c


def rust_string(value):
    return json.dumps(value)


def rust_case(c):
    paths = ",".join("&[" + ",".join(map(str, path)) + "]" for path in c["native_paths"])
    functions = ",".join(f"({a},{b},{d})" for a,b,d in c["functions"])
    fields = dict(id=str(c["id"]), family=rust_string(c["family"]),
                  input_sha256=rust_string(c["input_sha256"]),
                  code="&["+",".join(f"0x{b:02x}" for b in bytes.fromhex(c["code"]))+"]",
                  heads="&["+",".join(map(str,c["heads"]))+"]", paths=f"&[{paths}]",
                  states=f'[{c["state_seeds"][0]}u64,{c["state_seeds"][1]}u64]',
                  memory_seed=f'{c["memory_seed"]}u64',
                  alignment=str(c["alignment"]), selected=str(c["selected"]),
                  physical=str(c["physical"]), length=str(c["selected_len"]),
                  prefixes=str(c["prefixes"]), victim="None" if c["victim"] is None else f'Some({c["victim"]})',
                  victim_len=str(c["victim_len"]), block=f'({c["block_start"]},{c["block_end"]})',
                  functions=f"&[{functions}]", actions="&["+",".join(map(str,c["actions"]))+"]",
                  target_kind=rust_string(c["target_kind"]), selected_delta=str(c["selected_delta"]),
                  victim_delta=str(c["victim_delta"]), expected=rust_string(c["expected"]),
                  forced="Tactic::"+c["forced"], masks=str(c["masks"]),
                  expected_installed=str(c["expected_primary_installed"]),
                  expected_retired=str(c["expected_primary_retired"]),
                  expected_events=str(c["expected_primary_events"]))
    return "Case { " + ", ".join(f"{k}: {v}" for k,v in fields.items()) + " },"


def main():
    cases = []
    for family, count in STRATA:
        first_id = len(cases)
        cases.extend(make(first_id+i, family, i) for i in range(count))
    assert [c["id"] for c in cases] == list(range(512))
    manifest = dict(schema=1, phase="DRAFT_NOT_EXECUTED", master_seed=MASTER,
                    generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    strata=STRATA, generated_denominator=512, samples_denominator=32,
                    expected_outcomes=dict(Counter(c["expected"] for c in cases)),
                    original_heads=sum(len(c["heads"]) for c in cases),
                    primary_installed=sum(c["expected_primary_installed"] for c in cases),
                    primary_retired=sum(c["expected_primary_retired"] for c in cases),
                    auxiliary_installed=sum(c["expected_auxiliary_installed"] for c in cases),
                    auxiliary_retired=sum(c["expected_auxiliary_retired"] for c in cases),
                    primary_events=sum(c["expected_primary_events"] for c in cases),
                    auxiliary_events=sum(c["expected_auxiliary_events"] for c in cases),
                    cases=cases)
    (ROOT / "generated.json").write_text(json.dumps(manifest, indent=2)+"\n")
    (ROOT / "cases.rs").write_text("// Generated literally; review/freeze before native execution.\n"+
        "const CASES: &[Case] = &[\n" + "\n".join(rust_case(c) for c in cases)+"\n];\n")
    print(json.dumps({k:v for k,v in manifest.items() if k != "cases"}, indent=2))


if __name__ == "__main__":
    main()
