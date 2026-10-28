#!/usr/bin/env python3
"""Literal within-process cache and clock-bracket streams; no compiler codegen."""
import json
from pathlib import Path
import struct
import sys
from page_selected_generic_images import Program, PAGE, MAIN, DATA, old, tail
from page_selected_embedded_images import emit_stream

LITERAL = 0x13579bdf2468ace0
SENTINELS = (0x1122334455667788, 0x8877665544332211)
ITERATIONS = (1, 10, 100)  # Steady hits AFTER the separately retained first miss.
NAMES = [f'{mode}_{n}' for n in ITERATIONS for mode in ('cache', 'bracket')]
RECORD_BYTES, TRAILER = 40, 4064


def indirect_store(p, name, reg, offset, wide=False):
    # Canonical MOV [r9+disp8], register. Timestamp components are exact u32.
    assert reg in (0, 1, 2, 11, 12) and 0 <= offset < 128
    rex = 0x41 | (8 if wide else 0) | (4 if reg >= 8 else 0)
    p.add(name, bytes((rex, 0x89, 0x41 | ((reg & 7) << 3), offset)), 'generic')


def rip_store(p, name, reg, address):
    assert reg in (8, 9, 11, 12)
    p.add(name, bytes((0x4c, 0x89, 0x05 | ((reg & 7) << 3))) +
          struct.pack('<i', address-(p.pc+7)), 'generic')


def streams():
    result = []
    for n in ITERATIONS:
        for cache in (True, False):
            mode, k = ('cache' if cache else 'bracket'), n+1
            p = Program()
            # Ten-byte immediates prevent incidental setup publication. The
            # six-byte count followed by a ten-byte pointer also cannot run.
            for name, reg, value in (('literal', 10, LITERAL),
                                     ('sentinel_r11', 11, SENTINELS[0]),
                                     ('sentinel_r12', 12, SENTINELS[1])):
                p.add(name, old.mov64(reg, value), 'old')
            p.add('iterations', old.mov32(8, k), 'old')
            p.add('output_pointer', old.mov64(9, DATA), 'old')
            setup_names = [r['name'] for r in p.rows]
            p.label('loop')
            p.add('start_clock', bytes.fromhex('0f01f9'), 'builtin')
            for name, reg, off in (('start_lo', 0, 0), ('start_hi', 2, 4), ('start_aux', 1, 8)):
                indirect_store(p, name, reg, off)
            p.add('serialize_leaf0', bytes.fromhex('31c0'), 'generic')
            p.add('serialize_after_start', bytes.fromhex('0fa2'), 'builtin')
            # Both CPUIDs use leaf0 (subleaf is ignored), with the latter the
            # real unexecuted guard reached by generated JMP -> original NX.
            p.add('guard_leaf0', bytes.fromhex('31c0'), 'generic')
            run_pc = p.pc
            if cache:
                p.add('copy_r10_r11', bytes.fromhex('4d89d3'), 'old')
                p.add('copy_r11_r12', bytes.fromhex('4d89dc'), 'old')
            guard_pc = p.pc
            p.add('cpuid_guard', bytes.fromhex('0fa2'), 'builtin')
            p.add('end_clock', bytes.fromhex('0f01f9'), 'builtin')
            for name, reg, off in (('end_lo', 0, 12), ('end_hi', 2, 16), ('end_aux', 1, 20)):
                indirect_store(p, name, reg, off)
            indirect_store(p, 'result_r11', 11, 24, True)
            indirect_store(p, 'result_r12', 12, 32, True)
            p.add('advance', bytes.fromhex('4983c128'), 'generic')
            p.add('decrement', bytes.fromhex('41ffc8'), 'generic')
            p.branch('repeat', '0f85', 'loop')
            loop_names = [r['name'] for r in p.rows[len(setup_names):]]
            for name, reg, offset in (('final_count', 8, 0), ('final_pointer', 9, 8),
                                      ('final_r11', 11, 16), ('store_r12', 12, 24)):
                rip_store(p, name, reg, DATA+TRAILER+offset)
            tail(p, PAGE)
            code = p.finish()
            tail_names = [r['name'] for r in p.rows[len(setup_names)+len(loop_names):]]
            executed = setup_names+loop_names*k+tail_names
            by_name = {r['name']: r for r in p.rows}
            runs = (k if cache else 0)+3
            counts = dict(old=6, generic=13*k+5, cpuid=2*k, rdtscp=2*k, syscall=2,
                          main=14+(18 if cache else 17)*k, interpreter=2,
                          runs=runs, copied=2*runs, slots=4 if cache else 3,
                          hits=n if cache else 0, plan_misses=13*k+11)
            # These identities derive the route totals from the literal stream;
            # runtime totals must independently equal every value afterward.
            literal = {r: sum(by_name[x]['route'] == r for x in executed)
                       for r in ('old', 'generic', 'builtin', 'syscall')}
            assert literal['old']+1-2*runs == counts['old']
            assert literal['generic']+1 == counts['generic']
            assert literal['builtin'] == counts['cpuid']+counts['rdtscp']
            assert literal['syscall'] == 2 and len(executed)-runs == counts['main']
            assert counts['old']+counts['generic'] == counts['plan_misses']
            assert sum(counts[x] for x in ('old', 'generic', 'cpuid', 'rdtscp', 'syscall', 'runs')) == counts['main']+2
            assert k*RECORD_BYTES <= TRAILER and len(code) < PAGE
            assert guard_pc == run_pc+(6 if cache else 0)
            assert run_pc//PAGE == (guard_pc+1)//PAGE
            result.append(dict(name=f'{mode}_{n}', category='register_performance', entry=MAIN,
                pieces=[(MAIN, code)], rows=p.rows, executed=executed, counts=counts,
                mode=mode, steady_iterations=n, samples=k, output_bytes=PAGE,
                record_bytes=RECORD_BYTES, trailer_offset=TRAILER,
                loop_pc=p.labels['loop'], loop_run_pc=run_pc if cache else None,
                loop_guard_pc=guard_pc, literal=LITERAL, sentinels=list(SENTINELS),
                expected_values=[LITERAL, LITERAL] if cache else list(SENTINELS)))
    assert [s['name'] for s in result] == NAMES
    assert len({s['loop_run_pc'] for s in result if s['mode'] == 'cache'}) == 1
    return result


def make(directory):
    directory.mkdir()
    specs = [emit_stream(directory, s) for s in streams()]
    (directory/'images.json').write_text(json.dumps(specs, indent=2, sort_keys=True)+'\n')


if __name__ == '__main__':
    assert len(sys.argv) == 2 and not sys.flags.optimize
    make(Path(sys.argv[1]).resolve())
