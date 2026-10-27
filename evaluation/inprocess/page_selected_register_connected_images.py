#!/usr/bin/env python3
"""Three finite CPUID-guard streams for the separate register-run bridge."""
import json
from pathlib import Path
import struct
import sys
from page_selected_generic_images import Program, PAGE, MAIN, DATA, old, tail
from page_selected_embedded_images import emit_stream

LITERAL = 0x13579bdf2468ace0
NAMES = ['register_guard_direct', 'register_first_cross', 'register_guard_cross']


def streams():
    result = []
    for variant, name in enumerate(NAMES):
        setup = Program()
        setup.add('literal_r10', old.mov64(10, LITERAL), 'old')
        setup.add('iterations', old.mov32(8, 3), 'old')
        run_pc = setup.pc+2 if variant == 0 else MAIN+PAGE-(1 if variant == 1 else 7)
        loop_pc = run_pc-2
        if variant:
            setup.branch('enter_loop', 'e9', loop_pc)
        prefix = setup.finish()
        p = Program(loop_pc)
        p.label('loop')
        p.add('leaf_zero', bytes.fromhex('31c0'), 'generic')
        p.add('copy_r10_r11', bytes.fromhex('4d89d3'), 'old')
        p.add('copy_r11_r12', bytes.fromhex('4d89dc'), 'old')
        p.add('cpuid_guard', bytes.fromhex('0fa2'), 'builtin')
        p.add('decrement', bytes.fromhex('41ffc8'), 'generic')
        p.branch('repeat', '0f85', 'loop')
        for name_, reg, offset in [('a', 0, 0), ('b', 3, 8), ('c', 1, 16), ('d', 2, 24)]:
            p.store('store_'+name_, reg, DATA+offset)
        for name_, encoding, offset in [('r11', '4c891d', 32), ('r12', '4c8925', 40)]:
            p.add('store_'+name_, bytes.fromhex(encoding)+struct.pack('<i', DATA+offset-(p.pc+7)), 'generic')
        tail(p, 48)
        code = p.finish()
        rows = setup.rows+p.rows
        by_name = {r['name']: r for r in rows}
        assert len(rows) == len(by_name)
        loop_names = ['leaf_zero', 'copy_r10_r11', 'copy_r11_r12', 'cpuid_guard', 'decrement', 'repeat']
        executed = [r['name'] for r in setup.rows]+loop_names*3+[r['name'] for r in p.rows[6:]]
        # Count source instructions independently of the cache route. An actual
        # run copies two instructions and reaches its unexecuted guard by NX.
        cached_loop = variant != 2
        run_starts = (['copy_r10_r11']*3 if cached_loop else [])+['write_fd', 'write_size', 'exit_status']
        copies = [['copy_r10_r11', 'copy_r11_r12']]*3 if cached_loop else []
        copies += [['write_fd', 'write_address'], ['write_size', 'write_number'], ['exit_status', 'exit_number']]
        guards = ['cpuid_guard']*3 if cached_loop else []
        guards += ['write_size', 'write', 'exit']
        old_count = 3 if cached_loop else 9  # Includes interpreter MOV.
        generic_count = 16+(variant != 0)  # Includes interpreter indirect JMP.
        runs = 6 if cached_loop else 3
        counts = dict(old=old_count, generic=generic_count, cpuid=3, syscall=2,
                      main=28+(variant != 0)+(3 if not cached_loop else 0), interpreter=2,
                      runs=runs, copied=2*runs, slots=4 if cached_loop else 3,
                      hits=2 if cached_loop else 0, plan_misses=19+(variant != 0)+(6 if not cached_loop else 0))
        source_count = {k: sum(by_name[n]['route'] == k for n in executed) for k in ('old', 'generic', 'builtin', 'syscall')}
        assert source_count['old']+1-2*runs == old_count
        assert source_count['generic']+1 == generic_count and source_count['builtin'] == 3 and source_count['syscall'] == 2
        assert len(executed)-runs == counts['main']
        assert counts['old']+counts['generic']+counts['cpuid']+counts['syscall']+runs == counts['main']+2
        assert run_pc == by_name['copy_r10_r11']['pc'] and by_name['cpuid_guard']['pc'] == run_pc+6
        assert (run_pc % PAGE == PAGE-1) == (variant == 1)
        assert ((run_pc+6) % PAGE == PAGE-1) == (variant == 2)
        result.append(dict(name=name, category='register_connected', entry=MAIN,
            pieces=[(MAIN, prefix), (loop_pc, code)], rows=rows, executed=executed,
            counts=counts, literal=LITERAL, output_words=6, run_starts=run_starts,
            copied_groups=copies, guards=guards, loop_pc=loop_pc, loop_run_pc=run_pc,
            loop_guard_pc=run_pc+6, loop_guard_calls=3,
            first_instruction_crosses=variant == 1, guard_crosses=variant == 2,
            loop_falls_back_before_publication=not cached_loop))
    assert len(result) == 3
    return result


def make(directory):
    directory.mkdir()
    specs = [emit_stream(directory, s) for s in streams()]
    (directory/'images.json').write_text(json.dumps(specs, indent=2, sort_keys=True)+'\n')


if __name__ == '__main__':
    assert len(sys.argv) == 2 and not sys.flags.optimize
    make(Path(sys.argv[1]).resolve())
