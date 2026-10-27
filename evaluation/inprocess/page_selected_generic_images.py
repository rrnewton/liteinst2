#!/usr/bin/env python3
"""Five literal connected programs, appended to the unchanged 15-case source."""
import json
from pathlib import Path
import struct
import sys
import page_selected_images as old

PAGE, DATA, MAIN = old.PAGE, old.DATA, 0x401000
SENTINEL_B = 0x1122334455667788
SENTINEL_C = 0x8877665544332211


class Program:
    def __init__(self, base=MAIN):
        self.base, self.code, self.rows, self.labels, self.fixups = base, bytearray(), [], {}, []

    @property
    def pc(self):
        return self.base + len(self.code)

    def label(self, name):
        assert name not in self.labels
        self.labels[name] = self.pc

    def add(self, name, data, route):
        assert name not in {x['name'] for x in self.rows}
        self.rows.append(dict(name=name, pc=self.pc, bytes=data.hex(), route=route))
        self.code.extend(data)

    def branch(self, name, opcode, target):
        at = len(self.code)
        self.add(name, bytes.fromhex(opcode) + bytes(4), 'generic')
        self.fixups.append((at, len(bytes.fromhex(opcode)), target, len(self.rows)-1))

    def store(self, name, reg, address):
        # MOV qword [RIP+disp32], one of RAX/RBX/RCX/RDX; exact original PC.
        assert reg in (0, 1, 2, 3)
        self.add(name, bytes([0x48, 0x89, 0x05 | (reg << 3)]) + struct.pack('<i', address-(self.pc+7)), 'generic')

    def finish(self):
        for at, prefix, target, index in self.fixups:
            dest = self.labels[target] if isinstance(target, str) else target
            self.code[at+prefix:at+prefix+4] = struct.pack('<i', dest-(self.base+at+prefix+4))
            self.rows[index]['bytes'] = bytes(self.code[at:at+prefix+4]).hex()
        return bytes(self.code)


def tail(p, size):
    for name, reg, value in (('write_fd', 7, 1), ('write_address', 6, DATA),
                             ('write_size', 2, size), ('write_number', 0, 1)):
        p.add(name, old.mov32(reg, value), 'old')
    p.add('write', old.SYSCALL, 'syscall')
    p.add('exit_status', old.mov32(7, 0), 'old')
    p.add('exit_number', old.MOV_EAX_EXIT, 'old')
    p.add('exit', old.SYSCALL, 'syscall')


def poison(p):
    p.label('failure')
    p.add('poison_status', old.mov32(7, 99), 'old')
    p.add('poison_number', old.MOV_EAX_EXIT, 'old')
    p.add('poison_exit', old.SYSCALL, 'syscall')


def new_streams():
    result = []
    p = Program()
    p.add('data_pointer', old.mov32(6, DATA), 'old')
    p.add('ten', old.mov64(0, 10), 'old')
    p.add('store_ten', bytes.fromhex('488906'), 'generic')
    p.add('add_five', bytes.fromhex('48830605'), 'generic')
    p.add('load_fifteen', bytes.fromhex('488b1e'), 'generic')
    p.add('compare_fifteen', bytes.fromhex('4883fb0f'), 'generic')
    p.branch('not_taken', '0f85', 'failure')
    p.branch('taken', '0f84', 'success')
    poison(p)
    p.label('success')
    p.add('push', bytes.fromhex('53'), 'generic')
    p.add('pop', bytes.fromhex('59'), 'generic')
    p.add('store_popped', bytes.fromhex('48894e08'), 'generic')
    p.add('stack_reserve', bytes.fromhex('4883ec10'), 'generic')
    p.add('stack_store', bytes.fromhex('48890c24'), 'generic')
    p.add('stack_load', bytes.fromhex('488b1424'), 'generic')
    p.add('stack_restore', bytes.fromhex('4883c410'), 'generic')
    p.add('store_loaded', bytes.fromhex('48895610'), 'generic')
    tail(p, 24)
    code = p.finish()
    executed = [r['name'] for r in p.rows if not r['name'].startswith('poison_')]
    result.append(dict(name='branch_memory_stack', entry=MAIN, pieces=[(MAIN, code)], rows=p.rows,
                       executed=executed, expected_words=[15, 15, 15], builtin=0,
                       counters=dict(old=9, generic=15, builtin=0, syscall=2, main=24, interpreter=2)))

    # First main instruction ends exactly at page0's end. There is no prior
    # execution of the return page. Actual CALL targets a different NX page.
    call_pc, return_pc, callee_pc = MAIN+PAGE-5, MAIN+PAGE, MAIN+2*PAGE
    p = Program(call_pc)
    p.branch('boundary_call', 'e8', callee_pc)
    call = p.finish()
    ret = Program(return_pc)
    ret.add('save_result', bytes.fromhex('4889c3'), 'old')
    ret.add('load_pushed_return', bytes.fromhex('488b4424f8'), 'generic')
    ret.store('store_return', 0, DATA)
    ret.store('store_result', 3, DATA+8)
    tail(ret, 16)
    returned = ret.finish()
    callee = Program(callee_pc)
    callee.add('forty_one', old.mov32(0, 41), 'old')
    callee.add('add_one', bytes.fromhex('83c001'), 'generic')
    callee.add('return', bytes.fromhex('c3'), 'generic')
    callee_bytes = callee.finish()
    result.append(dict(name='boundary_call_ret', entry=call_pc,
                       pieces=[(call_pc, call), (return_pc, returned), (callee_pc, callee_bytes)],
                       rows=p.rows+ret.rows+callee.rows,
                       executed=['boundary_call']+[r['name'] for r in callee.rows]+[r['name'] for r in ret.rows],
                       expected_words=[return_pc, 42], builtin=0,
                       call=dict(pc=call_pc, next_pc=return_pc, target=callee_pc,
                                 return_page_previously_executed=False),
                       counters=dict(old=9, generic=7, builtin=0, syscall=2, main=16, interpreter=2)))

    for name, opcode, kind in (('cpuid0', '0fa2', 1), ('rdtsc', '0f31', 5), ('rdtscp', '0f01f9', 6)):
        p = Program()
        p.add('input_rax', old.mov64(0, 0xfeedface00000000), 'old')
        p.add('input_rcx', old.mov64(1, 0xdeadbeef00000000 if kind == 1 else SENTINEL_C), 'old')
        p.add('input_rbx', old.mov64(3, SENTINEL_B), 'old')
        p.add('flag_input', old.mov32(6, 7), 'old')
        p.add('flags_zf1_cf0', bytes.fromhex('83fe07'), 'generic')
        p.add('builtin', bytes.fromhex(opcode), 'builtin')
        p.branch('zf_preserved', '0f85', 'failure')
        p.branch('cf_preserved', '0f82', 'failure')
        for label, reg, address in (('a', 0, DATA), ('b', 3, DATA+8), ('c', 1, DATA+16), ('d', 2, DATA+24)):
            p.store('store_'+label, reg, address)
        tail(p, 32)
        poison(p)
        code = p.finish()
        result.append(dict(name=name, entry=MAIN, pieces=[(MAIN, code)], rows=p.rows,
                           executed=[r['name'] for r in p.rows if not r['name'].startswith('poison_')],
                           builtin=kind, output_words=4,
                           counters=dict(old=11, generic=8, builtin=1, syscall=2, main=20, interpreter=2)))
    assert len(result) == 5
    for spec in result:
        by_name = {r['name']: r for r in spec['rows']}
        assert len(by_name) == len(spec['rows']) and len(set(spec['executed'])) == len(spec['executed'])
        # Interpreter contributes one old MOV and one generic indirect JMP.
        actual = {k: sum(by_name[n]['route'] == k for n in spec['executed']) for k in ('old', 'generic', 'builtin', 'syscall')}
        actual['old'] += 1
        actual['generic'] += 1
        assert all(actual[k] == spec['counters'][k] for k in actual)
        assert len(spec['executed']) == spec['counters']['main']
    return result


def append(directory):
    old.make(directory)
    rows = json.loads((directory/'images.json').read_text())
    assert len(rows) == 15
    for spec in new_streams():
        here = directory/spec['name']
        here.mkdir()
        interp = (here/'interpreter.so').absolute()
        dynamic, strings = 0x400, 0x480
        dyn = b''.join(struct.pack('<qQ', t, v) for t, v in ((5, strings), (10, len(old.SONAME)+1), (14, 1), (0, 0)))
        interpreter_code = old.mov64(0, spec['entry']) + bytes.fromhex('ffe0')
        ip = [old.segment(1, 4, 0, 0, PAGE), old.segment(1, 5, PAGE, PAGE, 2*PAGE),
              old.segment(2, 4, dynamic, dynamic, len(dyn), 8), old.segment(0x6474e551, 6, 0, 0, 0, 16)]
        ih = old.emit(interp, 3, PAGE, ip, [(dynamic, dyn), (strings, b'\0'+old.SONAME), (PAGE, interpreter_code)], 3*PAGE)
        (here/old.SONAME[:-1].decode()).write_bytes(interp.read_bytes())
        path = str(interp).encode()+b'\0'
        assert len(path) <= 512
        md = b''.join(struct.pack('<qQ', t, v) for t, v in ((1, 1), (5, 0x400000+strings), (10, len(old.SONAME)+1), (0, 0)))
        mp = [old.segment(6, 4, old.EH.size, 0x400000+old.EH.size, 7*old.PH.size, 8),
              old.segment(3, 4, 0x500, 0x400500, len(path), 1), old.segment(1, 4, 0, 0x400000, PAGE),
              old.segment(1, 5, PAGE, MAIN, 3*PAGE), old.segment(1, 6, 4*PAGE, DATA, PAGE),
              old.segment(2, 4, dynamic, 0x400000+dynamic, len(md), 8), old.segment(0x6474e551, 6, 0, 0, 0, 16)]
        pieces = [(dynamic, md), (strings, b'\0'+old.SONAME), (0x500, path), (4*PAGE, b'\xa5'*PAGE)]
        for pc, code in spec.pop('pieces'):
            assert MAIN <= pc < pc+len(code) <= MAIN+3*PAGE
            pieces.append((PAGE+pc-MAIN, code))
        original = here/'original'
        mh = old.emit(original, 2, spec['entry'], mp, pieces, 5*PAGE)
        rows.append(dict(spec, category='generic_connected', original=str(original.absolute()),
                         interpreter=str(interp), library_root=str(here.absolute()),
                         original_sha256=mh, interpreter_sha256=ih, soname_sha256=ih,
                         entry_vaddr=PAGE, entry_file_offset=PAGE,
                         exact_stream_hex=interpreter_code.hex(), data_address=DATA,
                         data_initial_hex='a5'*PAGE))
    assert len(rows) == 20
    (directory/'images.json').write_text(json.dumps(rows, indent=2, sort_keys=True)+'\n')


if __name__ == '__main__':
    assert len(sys.argv) == 2 and sys.flags.optimize == 0
    append(Path(sys.argv[1]).resolve())
