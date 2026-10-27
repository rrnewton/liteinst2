#!/usr/bin/env python3
"""Independent saved-content audit of one complete controlled E9-null pair artifact."""
import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys

HEADS_SHA = '5e8f74c75c8274917f76c5663ad0badb7d1d7d31915fa716d29521e61e75e32c'
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
MIB, MASK, DEBUG = 1048576, (1 << 64) - 1, (1 << 8) | (1 << 16)
A, E = 0x600000000000, 0x600000100008
SS, SE = E - 32776, E + 32760
LO, HI = 0x400000, 0x425000
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
REGS = 'r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()
INHERITED = 'cs ss ds es fs gs fs_base gs_base'.split()
LOADS = [(0, 0x400000, 0x8b0, 0x8b0, 4), (0x1000, 0x401000, 0xa51, 0xa51, 5),
         (0x2000, 0x402000, 0xe1c, 0xe1c, 4), (0x3e00, 0x403e00, 0x20358, 0x20390, 6)]
CELLS = ('null-heap-write-unstripped', 'null-heap-write-stripped', 'null-jump-site-unstripped', 'null-jump-site-stripped')
LANES = ('stock-algorithm', 'bootstrap-patched-reference')
ORIGINALS = ('987b20efe393a0a2ca0293cd5601ba323b3f8292c9f1b5fab8a22b3124d3cff8',
             '1c7c66c58376c98df1dc3e5fd76d3c22a82ad7e96ef7aee1543a7c5b90a6f529')
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
ERRORS = (AssertionError, ValueError, KeyError, IndexError, OSError, struct.error, TypeError, OverflowError, UnicodeError)
LIVE_ONLY = [
    'The no-repair sequence, one hardware reference instruction, ptrace stop provenance, per-child timing/stop limits and task-count checks are live source assertions; saved states and ordered physical trace edges are rechecked here.',
    'Intermediate prefix registers are not serialized. Every prefix is independently authenticated as a stateless EB/E9 edge; both restored and final complete 64KiB stacks are checked without any scratch exemption.',
    'Each expanded CALL PUSH intermediate is serialized and independently compared, including the exact original return word, full registers, canonical XSAVE, data, owned stack and all image pages. These checks remain separate from the 528 cross-version comparisons.',
    'Fault signal/code/address tuples are saved in both child completion records. Full siginfo and raw wait records are not retained; reaped_echild is a native source assertion with separate helper and root-parent closure.',
    'Live CPUID/XGETBV and initial parent context are not separately captured. The finite admitted target/components are joined to every raw/canonical XSAVE; inherited selectors/bases remain equal across all352 children.',
    'Complete RPC/template, producer-statistics and selection-policy checks remain assertions of the pinned structural reader and its actual reviewed execution. This audit independently rechecks whole lane loader bytes, page ownership, every gateway/operation and all saved native state.',
    'NOREPLACE reservation and live descriptor stability are source-attested. Saved maps, whole pages, input/owner records and before/after observations are rechecked; controlled page materialization is not proof the E9 or system loader ran.',
]


def sha(b):
    return hashlib.sha256(b).hexdigest()



def loads(b):
    def unique(pairs):
        out = {}
        for k, v in pairs:
            assert k not in out, ('duplicate key', k)
            out[k] = v
        return out
    def bad(v):
        raise ValueError(('nonfinite JSON', v))
    return json.loads(b, object_pairs_hook=unique, parse_constant=bad)



def six(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]



def read_file(value):
    p = Path(value)
    assert p.is_absolute() and str(p) == value and '..' not in p.parts
    assert p.parent.resolve(strict=True) == p.parent
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        a = os.fstat(f.fileno())
        assert stat.S_ISREG(a.st_mode) and 0 <= a.st_size <= 128 * MIB
        b = f.read(128 * MIB + 1)
        assert six(a) == six(os.fstat(f.fileno())) == six(p.lstat()) and len(b) == a.st_size
    return b, dict(path=value, resolved=value, sha256=sha(b), stat=six(a))



class Saved:
    def __init__(self, pins, repo):
        self.pins, self.repo, self.seen = pins, Path(repo), {}
        assert self.repo.is_absolute() and self.repo.resolve(strict=True) == self.repo
    def read(self, value):
        value = str(value)
        assert value in self.pins and not Path(value).is_relative_to(self.repo / 'target')
        b, owner = read_file(value)
        assert self.pins[value] == dict(sha256=owner['sha256'], bytes=len(b), stat=owner['stat']), ('pin/owner', value)
        if value in self.seen:
            assert self.seen[value] == owner, ('drift', value)
        self.seen[value] = owner
        return b
    def json(self, p):
        return loads(self.read(p))
    def stable(self):
        for p in sorted(self.seen):
            self.read(p)



def tab(b):
    assert b.endswith(b'\n') and b'\r' not in b and b'\0' not in b
    return [r.split('\t') for r in b.decode('ascii').splitlines()]



def kv(b):
    result = {}
    for row in tab(b):
        assert len(row) == 2 and row[0] not in result
        result[row[0]] = row[1]
    return result



def tsv(rows):
    return ''.join('\t'.join(map(str, row)) + '\n' for row in rows).encode()



def num(s):
    assert re.fullmatch('[0-9]+', s)
    n = int(s); assert 0 <= n <= MASK
    return n



def tree(root):
    files, dirs = set(), set()
    assert root.resolve(strict=True) == root
    for current, children, members in os.walk(root, followlinks=False):
        for n in children + members:
            assert not (Path(current) / n).is_symlink()
        dirs |= {str((Path(current) / n).relative_to(root)) for n in children}
        files |= {str((Path(current) / n).relative_to(root)) for n in members}
    return files, dirs



def indexed(saved, root, index):
    for name, row in index.items():
        p = Path(name)
        assert not p.is_absolute() and '..' not in p.parts and str(p) == name
        b = saved.read(root / name)
        assert row == dict(sha256=sha(b), bytes=len(b), stat=saved.seen[str(root / name)]['stat'])



def image(data):
    assert len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<HHI', data, 16) == (2, 62, 1)
    assert struct.unpack_from('<HH', data, 52) == (64, 56)
    off, count = struct.unpack_from('<Q', data, 32)[0], struct.unpack_from('<H', data, 56)[0]
    assert 1 <= count <= 512 and off + count * 56 <= len(data)
    loads_, pages = [], {}
    for i in range(count):
        kind, flags, offset, va, _, fs, ms, align = struct.unpack_from('<IIQQQQQQ', data, off + i * 56)
        assert offset + fs <= len(data)
        if kind != 1:
            continue
        assert flags in (4, 5, 6) and 0 < ms and fs <= ms and align == 4096 and offset % 4096 == va % 4096
        lo, hi = va & ~4095, (va + ms + 4095) & ~4095
        assert 0 < lo < hi <= 1 << 47 and hi - lo <= 2048 * 4096
        loads_.append((offset, va, fs, ms, flags))
        for page in range(lo, hi, 4096):
            assert page not in pages
            at = (offset & ~4095) + page - lo; b = bytearray(4096)
            if page < (va + fs + 4095) & ~4095:
                n = min(4096, max(0, len(data) - at)); b[:n] = data[at:at+n]
            if ms > fs and page + 4096 > va + fs:
                start = max(0, va + fs - page); b[start:] = bytes(4096 - start)
            pages[page] = (flags, bytes(b))
    assert loads_[:4] == LOADS and set(range(LO, HI, 4096)) <= pages.keys()
    assert len(loads_) <= 261 and len(pages) <= 37 + 2048 and max(pages) + 4096 - min(pages) <= 1073741824
    assert all(flags != 6 for p, (flags, _) in pages.items() if not LO <= p < HI)
    base = b''.join(pages[p][1] for p in range(LO, HI, 4096))
    return loads_, pages, base



def at(pages, pc, length):
    out = bytearray()
    for a in range(pc, pc + length):
        flags, b = pages[a & ~4095]; assert flags == 5
        out.append(b[a & 4095])
    return bytes(out)



def target(b):
    rows = tab(b); assert rows[:2] == [['LI2TARGET', '1'], ['os', 'linux']]
    fixed = dict(isa='x86-64-legacy-evex', cet='unqualified', page_bytes='4096', bias_domain='1',
                 format='xsave64-standard', allocation_bytes='2496', image_bytes='2440', xcr0_mask='743', qualification_complete='false')
    assert rows[2:11] == [[k, v] for k, v in fixed.items()]
    components = [(4, 576, 256), (32, 832, 64), (64, 896, 512), (128, 1408, 1024), (512, 2432, 8)]
    assert rows[11:] == [['component', *map(str, r)] for r in components]
    return [(mask.bit_length() - 1, off, size) for mask, off, size in components]



def canonical(raw, components):
    assert 2440 <= len(raw) <= 65536 and raw[520:528] == bytes(8)
    used = struct.unpack_from('<Q', raw, 512)[0]
    x87 = raw[:24] if used & 1 else b'\x7f\x03' + bytes(22)
    out = x87[:5] + x87[6:24]
    out += b''.join(raw[32+16*i:42+16*i] if used & 1 else bytes(10) for i in range(8))
    out += raw[24:28] + (raw[160:416] if used & 2 else bytes(256))
    for bit, off, size in components:
        assert off >= 576 and off + size <= len(raw)
        out += struct.pack('<IQ', bit, size) + (raw[off:off+size] if used & (1 << bit) else bytes(size))
    assert len(out) == 2287
    return out



def seeded_xstate(seed, components):
    b = bytearray(2440); b[:2] = b'\x7f\x03'; b[4] = 255; b[24:28] = struct.pack('<I', 0x1f80)
    for i in range(8):
        b[32+16*i:40+16*i] = struct.pack('<Q', 0x8000000000000000 | seed | i)
        b[40+16*i:42+16*i] = b'\xff\x3f'
    b[160:416] = bytes((i * 29 + seed) & 255 for i in range(256))
    used = 3
    for bit, off, size in components:
        if bit in (2, 5, 6, 7):
            b[off:off+size] = bytes((i * 17 + seed + bit) & 255 for i in range(size)); used |= 1 << bit
    b[512:520] = struct.pack('<Q', used)
    return canonical(b, components)



def seed_case(i, heads):
    fault, hindex, state = i >= 174, (0 if i >= 174 else i // 2), i & 1
    h = heads[hindex]; seed = SEEDS[state]; array = ((13, 5, 21, 8), (7, 19, 3, 29))[state]
    r, value = {}, seed
    for reg in 'rax rbx rcx rdx rbp r8 r9 r10 r11 r12 r13 r14 r15'.split():
        value ^= (value << 13) & MASK; value ^= value >> 7; value ^= (value << 17) & MASK; r[reg] = value
    r.update(rsi=A+512, rdi=A, rsp=E+h['depth'], rip=h['pc'], eflags=(0x202, 0xad7)[state], orig_rax=MASK)
    saved = r.copy()
    overrides = {
        0x401840:dict(rdi=A,rsi=(1,3)[state],rdx=(0x1122334455667788,0x8877665544332211)[state]),
        0x401854:dict(rdi=A),0x401859:dict(rsi=4),0x401860:dict(rsi=4),0x40185c:dict(r12=4),0x401863:dict(rdx=0),
        0x401867:dict(rdx=0,r12=2),0x40186e:dict(r13=A,rbp=4,r12=2,rsi=0,rbx=1,rdx=array[1],r14=array[0]),
        0x401870:dict(r13=A),0x40187e:dict(r13=A),0x401873:dict(rdi=A,rsi=0,rdx=array[1]),0x401878:dict(r14=array[0]),
        0x40187b:dict(rbx=1),0x40188b:dict(rbx=1),0x401881:dict(rdi=A,rsi=1,rdx=array[0]),0x401886:dict(rbx=1,r12=2),
        0x40188e:dict(rsi=0),0x401892:dict(rsi=0),0x401896:dict(rax=0),0x40189a:dict(rax=0),0x40189e:dict(r13=A,rbx=1),
        0x4018a3:dict(rax=2,rbp=4),0x4018a8:dict(rcx=1),0x4018ac:dict(r13=A,rcx=16),0x4018b1:dict(rcx=array[2],rdx=array[1]),
        0x4018b6:dict(rcx=array[2]),0x4018b9:dict(rax=2),0x4018bc:dict(r13=A,rsi=0),0x4018c1:dict(r14=array[0],rdx=array[1]),
        0x4018d0:dict(rsi=4),0x4018d8:dict(rsi=4),0x4018e3:dict(rsi=4),0x4018dc:dict(r12=4),0x4018df:dict(rdi=A),
        0x4018e6:dict(rbp=A,rbx=4,r12=2),0x401907:dict(rbp=A,rbx=4,r12=2),0x4018f0:dict(r12=2),0x4018f4:dict(rbx=4),
        0x4018f7:dict(rbp=A),0x40191f:dict(rbp=A),0x40192d:dict(rbp=A),0x40193a:dict(rbp=A),0x4018fa:dict(r12=1),
        0x401902:dict(r12=1),0x4018fd:dict(rdi=A,rsi=4,rdx=1),0x401910:dict(rbp=A,rbx=4),0x401915:dict(rbp=A),
        0x40191b:dict(rbx=4),0x401922:dict(rdi=A,rsi=0,rdx=array[3]),0x401927:dict(r12=array[0]),0x40192a:dict(rbx=3),
        0x401937:dict(rbx=3),0x401942:dict(rbx=3),0x401930:dict(rdi=A,rsi=3,rdx=array[0]),0x40193d:dict(rdi=A,rsi=3,rdx=0),
    }
    r.update(overrides.get(h['pc'], {}))
    data = bytearray((n * 37 + (seed & 255)) & 255 for n in range(4096)); data[:32] = struct.pack('<4Q', *array)
    stack = bytearray((n * 29 + (seed & 255)) & 255 for n in range(65536))
    slots = {'Store':(), 'Sift':((-40,'rbx'),(-32,'rbp'),(-24,'r12'),(-16,'r13'),(-8,'r14')), 'Heap':((-24,'rbx'),(-16,'rbp'),(-8,'r12'))}
    for off, reg in slots[h['function']]:
        struct.pack_into('<Q', stack, E+off-SS, saved[reg])
    struct.pack_into('<Q', stack, E-SS, 0x401878)
    memory, effect, rsp = h['memory'], None, r['rsp']; kind = memory['kind']
    if kind == 'ArrayLoad':
        addr = r[memory['base']] + (r[memory['index']] if memory['index'] else 0) * memory['scale'] + memory['displacement']
        assert A <= addr and addr+8 <= A+32
        effect = ('Read', 'Array', addr, bytes(data[addr-A:addr-A+8]))
    elif kind == 'ArrayStore':
        addr = r['rdi'] + 8*r['rsi']; assert A <= addr and addr+8 <= A+32
        effect = ('FaultingWrite' if fault else 'Write', 'Array', addr, struct.pack('<Q', r['rdx']))
    elif kind in ('Push', 'Call'):
        rsp -= 8; value = r[memory['reg']] if kind == 'Push' else h['pc'] + h['length']
        effect = ('Write', 'Stack', rsp, struct.pack('<Q', value))
    elif kind in ('Pop', 'Return'):
        effect = ('Read', 'Stack', rsp, bytes(stack[rsp-SS:rsp-SS+8])); rsp += 8
    else:
        assert kind == 'None'
    if effect and effect[1] == 'Stack':
        assert E-128 <= effect[2] and effect[2]+8 <= E+8
    flow, cf, zf = h['flow'], bool(r['eflags'] & 1), bool(r['eflags'] & 64)
    pc = h['pc'] + h['length']
    if flow in ('Call','Jump') or (flow=='Jb' and cf) or (flow=='Jae' and not cf) or (flow=='Jbe' and (cf or zf)) or (flow=='Jne' and not zf):
        pc = h['target']
    if flow == 'Return':
        pc = struct.unpack('<Q', effect[3])[0]
    if fault:
        pc, rsp = h['pc'], r['rsp']
    assert pc in {h['pc'] for h in heads}
    after_data, after_stack = data.copy(), stack.copy()
    if effect and effect[0] == 'Write':
        buf, base = (after_data,A) if effect[1]=='Array' else (after_stack,SS)
        buf[effect[2]-base:effect[2]-base+8] = effect[3]
    fault_text = f'Some((11, 2, {effect[2]}))' if fault else 'None'
    effect_text = 'None' if not effect else f'Some(MemoryEffect {{ access: {effect[0]}, domain: {effect[1]}, address: {effect[2]}, bytes: {list(effect[3])} }})'
    completion = f'Fault {{ pc: {pc}, rsp: {rsp}, signal: 11, code: 2, address: {effect[2]} }}' if fault else f'OriginalPc {{ pc: {pc}, rsp: {rsp} }}'
    seed_rows = [('case',i),('head',hindex),('state',state),('seed',seed),('pc',h['pc']),('rsp',r['rsp']),('rflags',r['eflags']),('array',A),('frame',E),('stack_start',SS),('stack_end',SE),('comparison_start',E-128),('effect',effect_text),('completion',completion)]
    return dict(index=i,head=hindex,state=state,seed=seed,registers=r,data=bytes(data),stack=bytes(stack),after_data=bytes(after_data),after_stack=bytes(after_stack),pc=pc,rsp=rsp,fault=fault,fault_text=fault_text,seed_tsv=tsv(seed_rows))



def maps(b, fault, added):
    assert 0 < len(b) <= MIB and b.endswith(b'\n')
    rows = []
    for line in b.decode().splitlines():
        f = line.split(); assert len(f) >= 5
        lo, hi = (int(s,16) for s in f[0].split('-'))
        assert lo < hi and re.fullmatch('[r-][w-][x-][ps]',f[1])
        assert re.fullmatch('[0-9a-f]+:[0-9a-f]+',f[3]) and f[4].isdigit()
        assert not rows or rows[-1][1] <= lo
        rows.append((lo,hi,f))
    expected = [(va & ~4095,(va+ms+4095)&~4095,{4:'r--p',5:'r-xp',6:'rw-p'}[flags]) for _,va,_,ms,flags in LOADS]
    expected += [(A,A+4096,'r--p' if fault else 'rw-p'),(SS,SE,'rw-p'),(A-4096,A,'---p'),(A+4096,A+8192,'---p'),(SS-4096,SS,'---p'),(SE,SE+4096,'---p')]
    expected += [(p,p+4096,'r-xp' if flag==5 else 'r--p') for p,flag in added]
    for lo,hi,permission in expected:
        for p in range(lo,hi,4096):
            matches = [f for a,z,f in rows if a <= p and p+4096 <= z]
            assert len(matches)==1
            f=matches[0]; assert len(f)==5 and f[1]==permission and int(f[2],16)==0 and f[3:] == ['00:00','0']



def state(saved, root, stem, physical, logical, spec, components, base, generated, added):
    b = {n:saved.read(root/(stem+'.'+n)) for n in ('regs','xstate','xstate-raw','data','stack','stack-owned','loads','maps')}
    assert len(b['regs'])==216 and len(b['data'])==4096 and len(b['stack'])==32888 and len(b['stack-owned'])==65536
    r=dict(zip(REGS,struct.unpack('<27Q',b['regs']))); assert r['rip']==physical
    assert b['xstate']==canonical(b['xstate-raw'],components)
    assert b['stack']==b['stack-owned'][E-128-SS:] and b['loads']==base
    maps(b['maps'],spec['fault'],added)
    if generated is not None:
        assert saved.read(root/(stem+'.generated'))==generated
    return dict(r=r,logical=logical,canonical=b['xstate'],raw=b['xstate-raw'],data=b['data'],fixed=b['stack'],stack=b['stack-owned'])



def compare(a,b):
    assert a['logical']==b['logical']
    for reg in REGS:
        if reg=='rip':
            continue  # Physical RIP has already matched its exact predeclared boundary.
        mask=MASK ^ DEBUG if reg=='eflags' else MASK
        assert a['r'][reg]&mask==b['r'][reg]&mask, (reg,a['logical'])
    for k in ('canonical','data','fixed'):
        assert a[k]==b[k], (k,a['logical'])



def receipt(saved,d,request):
    r=saved.json(d/'receipt.json')
    assert set(r)=={'request_sha256','helper_sha256','exit','wall_timeout','unexpected_descendants','absence_proof','stdout_sha256','stderr_sha256','elapsed_seconds','cleanup_events','cleanup_error','aborted','inputs_unchanged'}
    assert type(r['exit']) is int and r['exit']==0 and r['request_sha256']==sha(saved.read(d/'request.json')) and r['helper_sha256']==HELPER_SHA
    assert r['wall_timeout'] is False and r['inputs_unchanged'] is True and r['absence_proof']=='ECHILD'
    assert r['unexpected_descendants']==r['cleanup_events']==[] and r['aborted'] is None and r['cleanup_error'] is None
    assert type(r['elapsed_seconds']) in (int,float) and math.isfinite(r['elapsed_seconds']) and 0<=r['elapsed_seconds']<=request['wall_seconds']
    for name in ('stdout','stderr'):
        b=saved.read(d/(name+'.txt'));assert sha(b)==r[name+'_sha256'] and len(b)<=request['file_bytes']
    return r



def hexbytes(value):
    assert type(value) is str and re.fullmatch('(?:[0-9a-f]{2})+', value)
    return bytes.fromhex(value)


def elf_rows(data):
    assert 64 <= len(data) <= 16*MIB and data[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<HHI', data, 16) == (2,62,1)
    assert struct.unpack_from('<HH', data, 52) == (64,56)
    entry, offset = struct.unpack_from('<QQ', data, 24)
    count = struct.unpack_from('<H',data,56)[0]
    assert 1 <= count <= 128 and offset+56*count <= len(data)
    rows = [struct.unpack_from('<IIQQQQQQ',data,offset+56*i) for i in range(count)]
    assert all(p[2]+p[5] <= len(data) for p in rows)
    return entry,offset,rows


def debug_records(raw, selected):
    address = r'(?:\[absolute\] )?-?0x[0-9a-f]+'
    success = re.compile(r'debug: patched instruction (0x[0-9a-f]+) \[size=([0-9]+), tactic=(B1|B2|T1|T2|T3), trampoline=('+address+r')\.\.('+address+r')\]')
    mapping = re.compile(r'debug: load (trampoline|refactoring): mmap\(('+address+r'), ([0-9]+), ((?:PROT_READ \| )?(?:PROT_WRITE \| )?(?:PROT_EXEC \| )?0), MAP_FIXED \| MAP_PRIVATE, fd, \+([0-9]+)\)')
    bypass = re.compile(r'debug: bypass (0x[0-9a-f]+) and jump directly to ('+address+')')
    def number(v):
        n=int(v.removeprefix('[absolute] '),16); assert 0 <= n < 1<<47
        return n
    outcomes, mappings, skips = [],[],[]
    assert raw.endswith(b'\n') and len(raw)<=16*MIB
    for line in raw.decode('ascii').splitlines():
        m=success.fullmatch(line)
        if m:
            pc,size,tactic,lo,hi=m.groups()
            assert lo.startswith('[absolute] ')==hi.startswith('[absolute] ')
            low,high=number(lo),number(hi); assert 0<high-low<=16*MIB
            outcomes.append(dict(pc=int(pc,16),length=int(size),tactic=tactic,low=low,high=high)); continue
        m=mapping.fullmatch(line)
        if m:
            kind,va,length,prot,offset=m.groups()
            protection=sum(bit for text,bit in [('PROT_READ',1),('PROT_WRITE',2),('PROT_EXEC',4)] if text in prot)
            mappings.append(dict(kind=kind,va=number(va),length=int(length),prot=protection,offset=int(offset))); continue
        m=bypass.fullmatch(line)
        assert m is not None, ('non-success or unrecognized backend record',line)
        skips.append((int(m[1],16),number(m[2])))
    assert [(r['pc'],r['length']) for r in outcomes]==[(h['pc'],h['length']) for h in sorted(selected,key=lambda h:h['file_offset'],reverse=True)]
    assert len(mappings)<=4096
    return outcomes,mappings,skips


def loader_pages(original,candidate,loader,lane,mappings):
    """Rebuild the whole lane-specific loader stream, then its ordered page view."""
    loader_pins={
        'stock-algorithm':'4d39f324ab8a3a9420d2436129ba941e17fd78aa2c4e35eff3d27311e0683477',
        'bootstrap-patched-reference':'126b6143c5668e4d390e0b9626824f5007b54d56e47a07bb72b415757b51773c'}
    tails={'stock-algorithm':'5f5e5a594159415a415b415c415d415e415f4158ffe0',
           'bootstrap-patched-reference':'5f5e5a5941584159415a415b415c415d415e415fffe0'}
    assert sha(loader)==loader_pins[lane]
    old_entry,phoff,old=elf_rows(original); entry,new_phoff,new=elf_rows(candidate)
    assert phoff==new_phoff and len(old)==len(new)
    changed=[i for i,(a,b) in enumerate(zip(old,new)) if a!=b]
    assert len(changed)==1 and old[changed[0]][0]==4
    p=new[changed[0]]; rounded=(len(original)+4095)&~4095
    assert p[:2]==(1,5) and p[3:5]==(0x20fedc000,0) and p[5]==p[6] and p[7]==4096
    assert p[2]%4096==0 and p[2]>=rounded and p[2]+p[5]==len(candidate) and entry==0x20fedc000
    assert mappings==[m for m in mappings if m['kind']=='trampoline']+[m for m in mappings if m['kind']=='refactoring']
    stream=loader+bytes.fromhex('ba0500000041ba12000000'); previous=(-1,5,-1)
    physical=set(); tail=rounded
    for i,m in enumerate(mappings):
        va,length,prot,off=(m[k] for k in ('va','length','prot','offset'))
        assert va%4096==length%4096==off%4096==0 and 0<length<=16*MIB and va+length<1<<47
        assert prot in (1,5) and off+length<=p[2]
        assert all(va+length<=q['va'] or q['va']+q['length']<=va for q in mappings[:i])
        stream+=(b'\xbf'+struct.pack('<i',va)) if va<1<<31 else (b'\x48\xbf'+struct.pack('<q',va))
        if length!=previous[0]: stream+=b'\xbe'+struct.pack('<i',length)
        if prot!=previous[1]: stream+=b'\xba'+struct.pack('<i',prot)
        if off!=previous[2]: stream+=(b'\x41\xb9'+struct.pack('<i',off)) if off<1<<31 else (b'\x49\xb9'+struct.pack('<q',off))
        stream+=bytes.fromhex('4489e80f054839f8740341ffe6'); previous=(length,prot,off)
        if m['kind']=='trampoline': physical.update(range(off,off+length,4096))
    for m in sorted((m for m in mappings if m['kind']=='refactoring'),key=lambda m:m['offset']):
        assert m['offset']==tail and m['prot']==5; tail+=m['length']
    assert physical==set(range(tail,p[2],4096)) and candidate[len(original):rounded]==bytes(rounded-len(original))
    stream+=bytes.fromhex('4c89c7b8030000000f05')
    stream+=(b'\xb8'+struct.pack('<I',old_entry)) if old_entry<1<<31 else (b'\x48\xb8'+struct.pack('<Q',old_entry))
    stream+=bytes.fromhex(tails[lane])
    assert candidate[p[2]:]==stream, 'whole lane-specific loader bytes'
    pages,records,order={},{},[]
    def put(page,flags,content,offset,count,zero):
        assert len(content)==4096 and page+4096<=1<<47
        assert all(page+4096<=lo or page>=hi for lo,hi in [(A-4096,A+8192),(SS-4096,SE+4096)])
        pages[page]=(flags,content)
        records[page]=dict(va=page,flags=flags,owner_order=len(order)-1,file_offset=offset,copied_bytes=count,zero_from=zero,sha256=sha(content))
        assert len(pages)<=2048
    original_loads=[]
    for index,p in enumerate(new):
        kind,flags,off,va,_,fs,ms,align=p
        if kind!=1: continue
        assert flags in (4,5,6) and 0<ms and fs<=ms and va+ms<1<<47 and off%4096==va%4096 and align==4096
        order.append(dict(kind='PT_LOAD',ph_index=index,offset=off,va=va,file_bytes=fs,memory_bytes=ms,flags=flags))
        original_loads.append((off,va,fs,ms,flags))
        for page in range(va&~4095,(va+ms+4095)&~4095,4096):
            assert page not in pages
            offset=(off&~4095)+page-(va&~4095)
            count=min(4096,max(0,len(candidate)-offset)) if page<(va+fs+4095)&~4095 else 0
            zero=min(4096,max(0,va+fs-page)) if ms>fs else 4096
            content=bytearray(4096);content[:count]=candidate[offset:offset+count];content[zero:]=bytes(4096-zero)
            put(page,flags,bytes(content),offset,count,zero)
    assert original_loads[:4]==LOADS
    for m in mappings:
        order.append(m)
        for page in range(m['va'],m['va']+m['length'],4096):
            assert (page in pages)==(m['kind']=='refactoring')
            if m['kind']=='refactoring': assert pages[page][0]==5 and LO<=page<HI
            offset=m['offset']+page-m['va'];put(page,5 if m['prot']==5 else 4,candidate[offset:offset+4096],offset,4096,4096)
    assert set(range(LO,HI,4096))<=pages.keys()
    assert all(flags in (4,5) for page,(flags,_) in pages.items() if not LO<=page<HI)
    return pages,order,[records[p] for p in sorted(records)],phoff+56*changed[0]


def rx(pages,pc,length):
    if not (0<length<=32 and 0<=pc< (1<<47)-length): return None
    if any((a&~4095) not in pages or pages[a&~4095][0]!=5 for a in range(pc,pc+length)): return None
    return bytes(pages[a&~4095][1][a&4095] for a in range(pc,pc+length))


def edge(pages,record):
    assert set(record)=={'pc','next','bytes'}
    pc,nxt,code=record['pc'],record['next'],hexbytes(record['bytes'])
    assert type(pc) is type(nxt) is int and 0<=pc<1<<47 and 0<=nxt<1<<47
    assert rx(pages,pc,len(code))==code
    if len(code)==2 and code[0]==0xeb:
        expected=pc+2+struct.unpack('<b',code[1:])[0]
    else:
        assert 5<=len(code)<=9 and code[:-5]==bytes([0x48,0x26,0x36,0x3e][:len(code)-5]) and code[-5]==0xe9
        expected=pc+len(code)+struct.unpack('<i',code[-4:])[0]
    assert nxt==expected
    return pc,nxt,code


def operation_bytes(h,body):
    old=hexbytes(h['bytes'])
    if body==h['pc']: return [old]
    flow=h['flow']
    if flow=='Call':
        assert old[0]==0xe8 and len(old)==5 and h['pc']+5<1<<31
        instructions=[b'\x68'+struct.pack('<I',h['pc']+5)];opcode=b'\xe9';where=body+5
    elif flow=='Jump':
        assert old[0]==0xeb and len(old)==2
        instructions=[];opcode=b'\xe9';where=body
    elif flow in ('Jb','Jae','Jbe','Jne'):
        assert len(old)==2 and old[0] in (0x72,0x73,0x75,0x76)
        instructions=[];opcode=bytes([0x0f,old[0]+0x10]);where=body
    else:
        return [old]
    delta=h['target']-(where+len(opcode)+4)
    if not -(1<<31)<=delta<1<<31: return None
    return instructions+[opcode+struct.pack('<i',delta)]


def heads_and_cases(report,heads,instructions,pages,opages,phchanged,outcomes,bypass):
    table=tab(instructions);assert len(table)==88 and all(len(row)==14 for row in table)
    assert len(report['heads'])==87 and len(report['cases'])==176
    by_pc={row['pc']:row for row in outcomes};allowed=set(range(LO+24,LO+32))|set(range(LO+phchanged,LO+phchanged+56))
    consumed=[];native=[]
    for i,(h,row,w) in enumerate(zip(heads,table[1:],report['heads']),1):
        identity=dict(id=i,pc=h['pc'],length=h['length'],file_offset=h['file_offset'],function=row[4],mnemonic=row[6],flow=row[7],target=h['target'],jump=row[11]=='true',heap=row[12]=='true')
        assert all(w[k]==v for k,v in identity.items()) and w['original_bytes']==h['bytes']
        assert int(row[0])==i and int(row[1],16)==h['pc'] and int(row[2])==h['length'] and int(row[3])==h['file_offset'] and row[5]==h['bytes']
        assert w['status']=='BYTE_WITNESS_COMPLETE' and w['reason'] is None
        assert len(w['prefix'])<=32
        pc=h['pc'];seen=set();walk=[]
        for r in w['prefix']:
            assert pc not in seen and r['pc']==pc;seen.add(pc)
            possible=operation_bytes(h,pc)
            eligible = pc==h['pc'] or (possible is not None and any(m['kind']=='trampoline' and m['va']<=pc and pc+sum(map(len,possible))+5<=m['va']+m['length'] for m in report['mapping_order']))
            assert not eligible or possible is None or rx(pages,pc,sum(map(len,possible)))!=b''.join(possible), 'prefix skips an earlier original operation'
            a,pc,b=edge(pages,r);walk.append((a,pc,b))
            allowed.update(a+j for j in range(len(b)) if any(x['pc']<=a+j<x['pc']+x['length'] for x in heads))
        assert pc==w['body'] and pc not in seen
        expected=operation_bytes(h,pc);assert expected is not None
        operations=[]
        for b in expected:
            assert rx(pages,pc,len(b))==b;operations.append(dict(pc=pc,bytes=b.hex()));pc+=len(b)
        assert w['operation']==operations
        outcome=by_pc.get(h['pc'])
        if outcome is not None: assert w['body']==outcome['low']
        continuation=w['continuation']
        if w['body']==h['pc']:
            assert continuation is None and not walk
        else:
            assert continuation is not None and set(continuation)=={'pc','next','bytes','logical_fallthrough','bypass_steps','executed_for_completion'}
            assert continuation['pc']==pc and continuation['logical_fallthrough']==h['pc']+h['length'] and continuation['executed_for_completion'] is False
            b=hexbytes(continuation['bytes']);assert len(b)==5 and b[0]==0xe9
            edge(pages,{k:continuation[k] for k in ('pc','next','bytes')})
            if outcome is not None: assert pc+5==outcome['high']
            # Every relocated operation and continuation belongs to a single actual trampoline mapping.
            owners=[m for m in report['mapping_order'] if m['kind']=='trampoline' and m['va']<=w['body'] and pc+5<=m['va']+m['length']]
            assert len(owners)==1
            logical=h['pc']+h['length'];cursor=logical;seen_b=set()
            assert len(continuation['bypass_steps'])<=32
            for r in continuation['bypass_steps']:
                assert cursor==r['pc'] and cursor not in seen_b;seen_b.add(cursor);_,cursor,_=edge(pages,r)
            assert cursor==continuation['next']
            if cursor!=logical: consumed.append((logical,cursor))
            else: assert continuation['bypass_steps']==[]
        native.append(dict(body=w['body'],walk=walk,operation=operations))
    assert Counter(consumed)==Counter(bypass)
    for page,(flags,before) in opages.items():
        assert pages[page][0]==flags
        assert all(a==b or page+i in allowed for i,(a,b) in enumerate(zip(before,pages[page][1]))), ('unowned original page',page)
    expected_cases=[]
    for i in range(176):
        spec=seed_case(i,heads);h=heads[spec['head']];w=native[spec['head']]
        operations=w['operation'];last=operations[-1]
        finish=w['body'] if spec['fault'] else (last['pc']+len(hexbytes(last['bytes'])) if spec['pc']==h['pc']+h['length'] and h['flow']!='Call' else spec['pc'])
        done=dict(kind='fault',physical_pc=finish,logical_pc=h['pc'],signal=11,code=2,address=A+[8,24][spec['state']]) if spec['fault'] else dict(kind='original-boundary',physical_pc=finish,logical_pc=spec['pc'],call_return_word=h['pc']+5 if h['flow']=='Call' else None)
        steps=[dict(step,next=operations[j+1]['pc'] if j+1<len(operations) else finish) for j,step in enumerate(operations)]
        if spec['fault']: assert len(steps)==1
        expected_cases.append(dict(case=i,head_id=spec['head']+1,state=spec['state'],seed=spec['seed'],rflags=spec['registers']['eflags'],fault=spec['fault'],status='BYTE_WITNESS_COMPLETE',prefix=report['heads'][spec['head']]['prefix'],operation=steps,completion=done,required=True))
    assert report['cases']==expected_cases
    return native,expected_cases


def projection(w,raw):
    rows=[['LI2COMMONE9NATIVE',1],['status',w['status']],['witness_json_sha256',sha(raw)],['scope',w['scope']]]
    rows += [[k,w[k]] for k in ('original_sha256','instructions_sha256','target_sha256','selection_sha256','candidate_sha256','source_seed_sha256')]
    rows += [['native_admission','false'],['qualification_complete','false']]
    for role,item in sorted(w['inputs'].items()): rows.append(['file',role,os.fsencode(item['path']).hex(),item['bytes'],item['sha256'],*item['owner']])
    for order,item in enumerate(w['mapping_order']):
        if item['kind']=='PT_LOAD': rows.append(['load',order,*[item[k] for k in ('ph_index','offset','va','file_bytes','memory_bytes','flags')]])
        else: rows.append(['mapping',order,*[item[k] for k in ('kind','va','length','prot','offset')]])
    rows += [['page',*[r[k] for k in ('va','flags','owner_order','file_offset','copied_bytes','zero_from','sha256')]] for r in w['final_pages']]
    for h in w['heads']:
        rows.append(['head',h['id'],h['pc'],h['body'],h['original_bytes']])
        rows += [['walk',h['id'],r['pc'],r['next'],r['bytes']] for r in h['prefix']]
        rows += [['op',h['id'],r['pc'],r['bytes']] for r in h['operation']]
        c=h['continuation']
        if c is not None:
            rows.append(['continue',h['id'],c['pc'],c['next'],c['bytes'],c['logical_fallthrough']])
            rows += [['bypass',h['id'],r['pc'],r['next'],r['bytes']] for r in c['bypass_steps']]
    for c in w['cases']:
        rows.append(['case',c['case'],c['head_id'],c['state'],c['seed'],c['rflags'],str(c['fault']).lower()])
        rows += [['step',c['case'],r['pc'],r['next'],r['bytes']] for r in c['operation']]
        d=c['completion'];rows.append(['done',c['case'],d['kind'],d['physical_pc'],d['logical_pc'],*[d.get(k) if d.get(k) is not None else 'none' for k in ('signal','code','address','call_return_word')]])
    return tsv(rows+[['complete',87,174,2]])


def capture_names(cases):
    names=['original.elf','instructions.tsv','runtime-target.tsv','e9-witness.json','e9-native.tsv','original-pages.bin','bundle-inputs.tsv','input-owners.tsv','candidate-pages.bin','page-plan.tsv','planned-cases.tsv','capture-inventory.tsv','complete.tsv']
    suffix=['regs','xstate','xstate-raw','data','stack','stack-owned','loads','maps']
    extra=0
    for i,c in enumerate(cases):
        p=f'case-{i:03}/'
        names += [p+n for n in ('pair.tsv','witness.tsv')]
        names += [p+'original/'+n for n in ('seed.tsv','complete.tsv')]
        names += [p+f'original/{s}.{x}' for s in ('before','after') for x in suffix]
        names += [p+'candidate/'+n for n in ('trace.tsv','complete.tsv')]
        names += [p+f'candidate/{s}.{x}' for s in ('before','restored','after') for x in suffix+['generated']]
        if len(c['operation'])==2:
            extra+=1;names += [p+'candidate/operation-00.'+x for x in suffix+['generated']]
    assert 0<=extra<=12 and extra%2==0 and len(names)==len(set(names))==8637+9*extra
    return names,extra


def capture_case(saved,cap,i,heads,witness,cases,components,original_base,candidate_base,generated,added,context):
    spec=seed_case(i,heads);h=heads[spec['head']];w=witness[spec['head']];c=cases[i];d=cap/f'case-{i:03}'
    finish=c['completion']['physical_pc'];pc=spec['pc'];fault=spec['fault'];extra=len(c['operation'])-1
    assert saved.read(d/'original/seed.tsv')==spec['seed_tsv']
    rows=[('original',h['pc']),('body',w['body']),('completion',finish),('logical',pc)]
    rows += [('prefix',a,n,b.hex()) for a,n,b in w['walk']]
    rows += [('operation',r['pc'],r['next'],r['bytes']) for r in c['operation']]
    assert saved.read(d/'witness.tsv')==tsv(rows)
    ob=state(saved,d/'original','before',h['pc'],h['pc'],spec,components,original_base,None,[])
    oa=state(saved,d/'original','after',pc,pc,spec,components,original_base,None,[])
    cb=state(saved,d/'candidate','before',h['pc'],h['pc'],spec,components,candidate_base,generated,added)
    cr=state(saved,d/'candidate','restored',w['body'],h['pc'],spec,components,candidate_base,generated,added)
    ca=state(saved,d/'candidate','after',finish,pc,spec,components,candidate_base,generated,added)
    for reg,value in spec['registers'].items():
        mask=MASK ^ DEBUG if reg=='eflags' else MASK
        assert ob['r'][reg]&mask==value&mask
    inherited=[ob['r'][r] for r in INHERITED]
    if not context: context.extend([inherited,len(ob['raw'])])
    assert context==[inherited,len(ob['raw'])]
    states=[ob,oa,cb,cr,ca]
    assert ob['canonical']==seeded_xstate(spec['seed'],components)==oa['canonical']
    assert ob['data']==spec['data'] and ob['stack']==cb['stack']==cr['stack']==spec['stack']
    assert oa['data']==spec['after_data'] and oa['stack']==ca['stack']==spec['after_stack'] and oa['r']['rsp']==spec['rsp']
    compare(ob,cb);compare(ob,cr);compare(oa,ca)
    if extra:
        assert extra==1 and h['flow']=='Call' and not fault
        middle=state(saved,d/'candidate','operation-00',c['operation'][1]['pc'],h['pc'],spec,components,candidate_base,generated,added)
        states.append(middle)
        stack=bytearray(ob['stack']);rsp=ob['r']['rsp']-8;word=struct.pack('<Q',h['pc']+5)
        assert SS<=rsp<=SE-8;stack[rsp-SS:rsp-SS+8]=word
        expected=dict(ob,r=dict(ob['r'],rsp=rsp),stack=bytes(stack),fixed=bytes(stack[E-128-SS:]))
        compare(expected,middle);assert middle['stack']==expected['stack']
    if h['flow']=='Call':
        assert ca['stack'][ca['r']['rsp']-SS:ca['r']['rsp']-SS+8]==struct.pack('<Q',h['pc']+5)
    for s in states: assert [s['r'][r] for r in INHERITED]==inherited and len(s['raw'])==context[1]
    if fault: compare(ob,oa);compare(cr,ca)
    trace=[['phase','before_pc','after_pc','bytes']]+[['prefix',a,n,b.hex()] for a,n,b in w['walk']]
    trace += [[f'operation-{j}',r['pc'],r['next'],r['bytes']] for j,r in enumerate(c['operation'])]
    assert saved.read(d/'candidate/trace.tsv')==tsv(trace) and len(w['walk'])+len(c['operation'])<=20000
    assert saved.read(d/'original/complete.tsv')==tsv([('LI2ORIGINALREFERENCE',1),('case',i),('steps',1),('normal',str(not fault).lower()),('fault',spec['fault_text']),('reaped_echild','true'),('paired_replay','UNIMPLEMENTED_UNRUN'),('qualification_complete','false')])
    assert saved.read(d/'candidate/complete.tsv')==tsv([('LI2E9PAIRCHILD',1),('case',i),('steps',len(w['walk'])+len(c['operation'])),('physical_completion',finish),('logical_completion',pc),('fault',spec['fault_text']),('comparisons',3),('call_intermediate_checks',extra),('reaped_echild','true'),('qualification_complete','false')])
    assert saved.read(d/'pair.tsv')==tsv([('LI2E9PAIR',1),('case',i),('comparisons',3),('children',2),('call_intermediate_checks',extra),('normal_loader_validation','false'),('qualification_complete','false')])
    return dict(status='PASS_SAVED_CONTENT',comparisons=3,head=spec['head'],state=spec['state'],fault=fault,physical_completion=finish,logical_completion=pc,call_intermediate_checks=extra,full_stack_bytes=65536)

def encode(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def admission(saved,path,authority,scope,revision):
    a=saved.json(path)
    assert type(a['schema']) is int and a['schema']==1
    assert a['authority']==authority and a['scope']==scope and a['source_revision']==revision
    assert a['review_binding'] in a['evidence_files'] and len(a['evidence_files'])==len(set(a['evidence_files']))>=2
    for p in a['evidence_files']: saved.read(p)
    return a


def held_witness(saved,run,cap,heads,pins,cell):
    directory=run/'witness';raw=saved.read(directory/'witness.json');w=loads(raw)
    assert raw==encode(w)+b'\n' and len(raw)<=16*MIB
    assert w['schema']==1 and w['format']=='LI2COMMONE9-1' and w['scope']=='STRUCTURAL_E9_NULL_COMPLETION_WITNESSES_ONLY'
    assert w['status']=='COMPLETE_BYTE_WITNESSES' and w['witness_complete'] is True
    assert w['native_admission'] is False and w['qualification_complete'] is False and w['actual_runtime'] is None
    assert w['unresolved_heads']==w['global_issues']==[] and w['required_heads']==87 and w['required_cases']==176
    assert w['reader_source_sha256']==pins['tools/elf-rewrite/e9-null-witness.py']
    assert w['source_seed_sha256']==pins['tests/support/e9_common_seed.rs']
    assert w['limits']==dict(input_bytes=16*MIB,mapped_pages=2048,prefix_edges=32,operation_edges=2,existing_native_seconds=15,existing_native_stops=20000)
    assert w['boundaries']==dict(raw_rip_must_match_before_logical_label=True,compare_flags_excluding_only_TF_RF=True,canonical_xsave_and_complete_data_and_fixed_stack_required=True,fixed_application_stack=[E-128,SE],native_state_comparison_performed=False,loader_execution_proved=False)
    product_roles={'original','selection','policy','candidate','frontend','backend','loader','transport_frontend','helper'}|{p+'_'+r for p in ('transport','producer') for r in ('request','receipt','stdout','stderr')}
    assert set(w['inputs'])=={'inputs','structural_envelope','instructions','target','structural_reader','witness_reader'}|{'producer/'+r for r in product_roles}
    blobs={}
    for role,row in w['inputs'].items():
        b=saved.read(row['path']);assert len(b)<=16*MIB
        assert row==dict(path=row['path'],bytes=len(b),sha256=sha(b),owner=saved.pins[row['path']]['stat'])
        blobs[role]=b
    wi=loads(blobs['inputs']);assert w['inputs']['inputs']['path']==str(run/'witness-inputs.json') and set(wi)=={'schema','structural_envelope','instructions','target'} and wi['schema']==1
    for role in ('structural_envelope','instructions','target'):
        assert wi[role]=={k:w['inputs'][role][k] for k in ('path','sha256','bytes')}
    envelope=loads(blobs['structural_envelope'])
    assert w['inputs']['structural_envelope']['path']==cell['structural_envelope']
    assert envelope['lane']==w['lane'] and w['lane'] in LANES and envelope['hook'] is None and set(envelope['files'])==product_roles
    for role in product_roles:
        assert envelope['files'][role]=={k:w['inputs']['producer/'+role][k] for k in ('path','sha256','bytes')}
    assert sha(blobs['structural_reader'])==pins['tools/elf-rewrite/e9-sites.py']
    assert sha(blobs['witness_reader'])==w['reader_source_sha256'] and sha(blobs['producer/helper'])==HELPER_SHA
    products={role:blobs['producer/'+role] for role in product_roles}
    product_pins={
        'stock-algorithm':('36b05e9a47c9193041d71ed4e14dda87e835e0e2b47e4a82a7d30a7c0d4eeb5e','890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb'),
        'bootstrap-patched-reference':('0fea3c8bc0701dffeb16b524e7159e458be9add11bcf3df5f47b9714c1005acc','3750339187ffc4a084d075de77d1c653c255abd96e396870ea691b495f0c5453')}
    assert tuple(sha(products[r]) for r in ('frontend','backend'))==product_pins[w['lane']]
    assert sha(products['transport_frontend'])==product_pins['bootstrap-patched-reference'][0]
    assert (envelope['reference_commit'],envelope['reference_tree'],envelope['archive_sha256'],envelope['capstone_revision'],envelope['abi_delta_patch_sha256'])==('0d5d36e4c4edcac37ca2499694d64302a391136f','b833c9dedd0aaaf8ed60ad1c041bd1535c55ccce','b9d82420ee00a7240f574645c229d91fb993d1f24305258e3cdc294e6df44f0f','e3f106739a6ae78d47772dff31062d644ea21078','66bfd1bbef8fd9f33656a8956d21fbe5cba6c27b6ff034be0084db76bafd9e0d')
    for role,key in [('original','original_sha256'),('candidate','candidate_sha256'),('selection','selection_sha256')]: assert sha(products[role])==w[key]
    assert sha(blobs['instructions'])==w['instructions_sha256']==pins['tests/support/e9_common_seed.instructions.tsv']
    assert sha(blobs['target'])==w['target_sha256']==cell['target_sha256']
    assert cell['candidate_sha256']==w['candidate_sha256'] and cell['candidate']==envelope['files']['candidate']['path']
    assert cell['original']==envelope['files']['original']['path'] and cell['inventory']+'/instructions.tsv'==w['inputs']['instructions']['path']
    for name,role in [('original.elf','producer/original'),('instructions.tsv','instructions'),('runtime-target.tsv','target')]:
        assert saved.read(cap/name)==blobs[role]
    assert saved.read(cap/'e9-witness.json')==raw
    components=target(blobs['target'])
    rows=tab(blobs['target']);fields={r[0]:r[1] for r in rows[1:] if len(r)==2};comps=[list(map(int,r[1:])) for r in rows if r[0]=='component']
    compact='target xsave64 743'+''.join(f' {f}:{o}:{s}' for f,o,s in comps)
    assert w['target']==dict(fields=fields,components=comps,compact=compact)
    assert [line for line in products['selection'].decode().splitlines() if line.startswith('target ')]==[compact]
    original=products['original'];assert sha(original) in ORIGINALS
    _,opages,original_base=image(original);assert len(opages)==37
    assert saved.read(cap/'original-pages.bin')==original_base
    for h in heads: assert original[h['file_offset']:h['file_offset']+h['length']]==at(opages,h['pc'],h['length'])==hexbytes(h['bytes'])
    policy=w['structural']['policy'];assert policy['instrumentation']=='null' and policy['selection_style'] in ('heap-write','jump-site')
    selected=[h for h in heads if h['flow'] in ('Jump','Jb','Jae','Jbe','Jne')] if policy['selection_style']=='jump-site' else [heads[0]]
    assert len(selected)==(9 if policy['selection_style']=='jump-site' else 1)
    outcomes,mappings,bypass=debug_records(products['producer_stderr'],selected)
    assert w['structural']['outcomes']==outcomes and w['structural']['selected_sites']==len(selected)
    assert w['structural']['candidate_sha256']==w['candidate_sha256'] and w['structural']['lane']==w['lane']
    assert w['structural']['scope']=='STRUCTURAL_CANDIDATE_SITE_INVENTORY_ONLY' and w['structural']['qualification_complete'] is False and w['structural']['runtime_executed_by_adapter'] is False
    site_wire=saved.read(directory/'sites.tsv');site_rows=tab(site_wire)
    assert sha(site_wire)==w['selected_site_wire_sha256']==w['structural']['site_inventory_sha256'] and len(site_rows)==7+len(selected)
    assert site_rows[:7]==[['LI2E9SITES','1']]+[[k,policy[k]] for k in ('original_sha256','selection_sha256','e9_revision','instrumentation','selection_style')]+[['site','pc','file_offset','length','outcome','reason_hex']]
    assert policy['original_sha256']==w['original_sha256'] and policy['selection_sha256']==w['selection_sha256']
    by_pc={r['pc']:r for r in outcomes}
    for h,row in zip(selected,site_rows[7:]):
        assert row[:5]==list(map(str,[heads.index(h)+1,h['pc'],h['file_offset'],h['length']]))+['trampoline']
        assert loads(bytes.fromhex(row[5]))==dict(backend_record=by_pc[h['pc']],classification='trampoline')
    pages,order,page_rows,phchanged=loader_pages(original,products['candidate'],products['loader'],w['lane'],mappings)
    assert w['mapping_order']==order and w['final_pages']==page_rows
    witness,cases=heads_and_cases(w,heads,blobs['instructions'],pages,opages,phchanged,outcomes,bypass)
    native=projection(w,raw)
    assert saved.read(directory/'native.tsv')==saved.read(cap/'e9-native.tsv')==native
    assert saved.json(directory/'files.json')=={n:dict(bytes=len(b),sha256=sha(b)) for n,b in [('witness.json',raw),('native.tsv',native),('sites.tsv',site_wire)]}
    assert tree(directory)==({'witness.json','native.tsv','sites.tsv','files.json'},set())
    files=[r for r in tab(native) if r[0]=='file'];assert len(files)==23
    assert saved.read(cap/'bundle-inputs.tsv')==tsv(files)
    owners=[['whole_hash_and_reader_projection_admission','CALLER_REQUIRED']]
    paths=[('original',w['inputs']['producer/original']['path']),('instructions',w['inputs']['instructions']['path']),('target',w['inputs']['target']['path']),('json',str(directory/'witness.json')),('tsv',str(directory/'native.tsv'))]
    paths += [(os.fsencode(row['path']).hex(),row['path']) for _,row in sorted(w['inputs'].items())]
    actual=tab(saved.read(cap/'input-owners.tsv'));assert len(actual)==29 and actual[0]==owners[0]
    for row,(key,path) in zip(actual[1:],paths):
        s=saved.pins[path]['stat'];mt,mn=divmod(s[4],1000000000);ct,cn=divmod(s[5],1000000000)
        assert len(row)==2 and row[0]==key and loads(row[1])==[s[0],s[1],s[2],s[3],mt,mn,ct,cn]
    candidate_base=b''.join(pages[p][1] for p in range(LO,HI,4096))
    added=[(p,pages[p][0]) for p in sorted(pages) if not LO<=p<HI]
    generated=b''.join(pages[p][1] for p,_ in added)
    assert len(added)<=2011 and saved.read(cap/'candidate-pages.bin')==candidate_base+generated
    assert saved.read(cap/'page-plan.tsv')==tsv([(p,f,HI-LO+4096*i) for i,(p,f) in enumerate(added)])
    return w,witness,cases,components,original_base,candidate_base,generated,added


def saved_producer_receipts(saved,w):
    files=w['inputs'];helper=files['producer/helper']['sha256'];requests=[]
    for phase in ('transport','producer'):
        get=lambda name: saved.read(files['producer/'+phase+'_'+name]['path'])
        request_raw=get('request');q=loads(request_raw);r=loads(get('receipt'))
        assert set(q)=={'argv','cwd','env','cpu_seconds','wall_seconds','file_bytes','stdout','stderr'}
        assert set(r)=={'request_sha256','helper_sha256','exit','wall_timeout','unexpected_descendants','absence_proof','stdout_sha256','stderr_sha256','elapsed_seconds','cleanup_events','cleanup_error','aborted','inputs_unchanged'}
        assert type(r['exit']) is int and r['exit']==0 and r['request_sha256']==sha(request_raw) and r['helper_sha256']==helper==HELPER_SHA
        assert r['wall_timeout'] is False and r['inputs_unchanged'] is True and r['absence_proof']=='ECHILD'
        assert r['unexpected_descendants']==r['cleanup_events']==[] and r['aborted'] is None and r['cleanup_error'] is None
        assert type(r['elapsed_seconds']) in (int,float) and math.isfinite(r['elapsed_seconds']) and 0<=r['elapsed_seconds']<=q['wall_seconds']
        for name in ('stdout','stderr'):
            b=get(name);assert q[name]==files['producer/'+phase+'_'+name]['path'] and len(b)<=q['file_bytes'] and sha(b)==r[name+'_sha256']
        requests.append(q)
    assert {k:v for k,v in requests[0].items() if k not in ('argv','stdout','stderr')}=={k:v for k,v in requests[1].items() if k not in ('argv','stdout','stderr')}
    envelope=saved.json(files['structural_envelope']['path']);common=envelope['common_argv'];p=lambda role:files['producer/'+role]['path']
    assert requests[0]['argv']==[p('transport_frontend'),*common,'--format=json','--output=-',p('original')]
    assert requests[1]['argv']==[p('frontend'),*common,'--format=binary','--output='+p('candidate'),'--backend='+p('backend'),'--option=--debug',p('original')]
    assert not saved.read(p('transport_stderr'))


def selected_build(saved,inputs,source,driver):
    build=admission(saved,inputs['build_admission'],'CALLER_AUTHENTICATED_OBSERVER_BUILD','original-common-app-observer-build-only',source['revision'])
    assert build['source_files_sha256']==sha(encode(source['files']))
    root=Path(build['directory']);summary=saved.json(root/'summary.json')
    assert summary['revision']==source['revision'] and summary['completed'] is True and summary['failure'] is None
    assert summary['observed_stages']==len(summary['planned_stages'])==12 and summary['cells_complete']==8 and summary['unrun_stages']==[] and summary['qualification_complete'] is False
    assert saved.read(root/'source.json')==saved.read(root/'source-after.json')
    built=saved.json(root/'source.json');assert built['revision']==source['revision'] and built['files']==source['files']
    archives=saved.json(root/'artifacts.json');assert set(archives)=={'native-compile','common-sites-compile'}
    selected={}
    for phase,archive in archives.items():
        assert saved.json(root/phase/'artifact-archive.json')==archive
        assert archive['source_revision']==source['revision'] and archive['source_files_sha256']==build['source_files_sha256']
        for field,name in [('command_result_sha256','result.json'),('cargo_stdout_sha256','stdout.txt')]: assert archive[field]==sha(saved.read(root/phase/name))
        for row in archive['artifacts'].values():
            assert sha(saved.read(row['path']))==row['sha256'] and saved.pins[row['path']]['stat']==row['archive_owner']
        for name,row in archive['selected'].items():
            assert all(source['files'][p]==r for p,r in row['source_bindings'].items())
            for item in ('product','depfile'): assert sha(saved.read(row[item]['path']))==row[item]['sha256']
            selected[name]=row['product']['path']
    assert set(selected)=={'elf-exec-oracle','liteinst-rewrite','common_sites'} and selected['elf-exec-oracle']==driver
    return build


def prior_records(saved,inputs,run,revision,cell,report):
    order=[key+'-'+lane for key in CELLS for lane in LANES];prior=saved.json(run/'prior-cells.json')
    assert len(prior)==len(inputs['prior_cells'])==order.index(cell)
    for key,path,a in zip(order,inputs['prior_cells'],prior):
        assert a==admission(saved,path,'CALLER_REVIEWED_E9_PAIR_ATTEMPT','closed-whole-artifact-attempt-with-content-review-if-complete',revision)
        assert a['cell']==key and a['parent_closed_reaped'] is True and a['parent_observation'] in a['evidence_files']
        if a['summary'] is None:
            assert a['status']=='UNRUN' and a['reason'] and a['results'] is None
            assert a['content_audit_passed'] is False and a['content_review_binding'] is None and a['capture_index'] is None and a['capture_index_sha256'] is None
            record=saved.json(a['attempt_record'])
            assert set(record)=={'schema','source_revision','cell','status','recipe_launched','reason','blocking_records'}
            assert record['schema']==1 and record['source_revision']==revision and record['cell']==key
            assert record['status']=='UNRUN' and record['recipe_launched'] is False and record['reason']==a['reason']
            assert record['blocking_records'] and a['attempt_record'] in a['evidence_files']
            for p in record['blocking_records']: assert p in a['evidence_files'];saved.read(p)
            continue
        assert a['attempt_record'] is None
        summary=saved.json(a['summary']);rows=saved.json(a['results'])
        assert summary['revision']==revision and summary['cell']==key and summary['cases']==176 and summary['heads']==87 and summary['planned_comparisons']==528
        assert [r['name'] for r in rows]==['verify','replay'] and summary['qualification_complete'] is False and summary['independent_content_review_required'] is True
        if summary['command_capture_schema_complete']:
            assert type(a['content_audit_passed']) is bool and a['status']==('PASS_CONTENT_REVIEWED' if a['content_audit_passed'] else 'FAILED')
            assert (a['reason']=='')==a['content_audit_passed'] and a['content_review_binding'] in a['evidence_files']
            assert rows[0]['status']=='PASS_STRUCTURAL_WITNESS' and rows[1]['status']=='PASS_COMMAND_AND_CAPTURE_SCHEMA'
            assert summary['capture_files']==8637+9*summary['call_intermediate_checks']
            assert a['capture_index_sha256']==sha(saved.read(a['capture_index']))
        else:
            assert a['status'] in ('FAILED','UNRUN') and a['reason'] and a['content_audit_passed'] is False
            assert a['capture_index'] is a['content_review_binding'] is a['capture_index_sha256'] is None
            assert all(r['status'] in ('UNRUN','FAILED','PASS_STRUCTURAL_WITNESS','PASS_COMMAND_AND_CAPTURE_SCHEMA') for r in rows)
    assert saved.json(run/'cell-plan.json')==[dict(cell=k,cases=176,status=prior[i]['status'] if i<len(prior) else 'UNRUN',reason=prior[i]['reason'] if i<len(prior) else 'not yet completed') for i,k in enumerate(order)]
    report['recorded_prior_cells']=prior;report['mandatory_cells']=order
    obligations=saved.json(run/'obligations.json');assert obligations==inputs['obligations']
    counts=dict(original=16,production=74,ordinary=192,core_null=704,E9_null=1408,recording_pairs=2112)
    assert set(obligations)==set(counts)
    for k,n in counts.items():
        o=obligations[k];assert set(o)=={'denominator','status','record'} and o['denominator']==n and o['status'] in ('UNRUN','FAILED','PARTIAL','CLOSED_REVIEWED')
        if o['record'] is None: assert o['status']=='UNRUN'
        else: saved.read(o['record'])
    report['recorded_obligations']=obligations
    report['recorded_production_status']=saved.json(run/'production-status.json')
    report['recorded_ordinary_status']=saved.json(run/'ordinary-status.json')

def upstream_records(saved,inputs,source,cell,evidence,report):
    revision=source['revision']
    production=admission(saved,inputs['production_admission'],'CALLER_ADMITTED_COMMON_PRODUCTION_ARTIFACTS','closed-production-artifacts-only',revision)
    ordinary=admission(saved,inputs['ordinary_content_admission'],'CALLER_ADMITTED_COMMON_ORDINARY_CONTENT','closed-192-case-output-and-journal-records',revision)
    original=admission(saved,inputs['observation_content_admission'],'CALLER_ADMITTED_ORIGINAL_OBSERVATION_CONTENT_AUDIT','all-sixteen-original-capture-contents-and-ordered-pc-streams',revision)
    assert production['review_binding'] in evidence['producer_review'] and ordinary['review_binding'] in evidence['ordinary_review']
    for a in (production,ordinary,original): assert a['parent_closed_reaped'] is True and a['parent_observation'] in a['evidence_files']
    assert original['architectural_equivalence_claim'] is False
    keys=['-'.join(x) for x in ((h,s,v) for h in ('null','journal') for s in ('jump-site','heap-write') for v in ('unstripped','stripped'))]
    expected=[]
    for i,key in enumerate(keys):
        if i==4: expected+=['hook-compile','hook-link']
        expected += [key+'-core']+[key+'-'+lane+'-'+phase for lane in LANES for phase in ('transport','producer','adapter','compare')]
    root=Path(production['directory']);ps=saved.json(root/'summary.json');rows=saved.json(root/'results.json')
    assert ps['revision']==revision and ps['fatal'] is None and ps['planned_stages']==74
    assert ps['ordinary_dataset_executions']==ps['native_executions']==0 and ps['qualification_complete'] is False
    assert saved.read(root/'source-before.json')==saved.read(root/'source-after.json') and saved.json(root/'source-before.json')['files']==source['files']
    assert [r['name'] for r in rows]==expected and len(rows)==74
    assert all(r['status'] in ('PASS','FAILED','UNRUN') for r in rows) and ps['successful']==all(r['status']=='PASS' for r in rows)
    assert report['recorded_production_status']==dict(summary=ps,stages=rows)
    selected=cell['cell'];by_name={r['name']:r for r in rows}
    for phase in ('transport','producer','adapter'):
        row=by_name[selected+'-'+phase];assert row['status']=='PASS' and row['exit']==0
        assert row['receipt_sha256']==sha(saved.read(root/row['name']/'receipt.json'))
    key,lane=next((k,l) for k in CELLS for l in LANES if k+'-'+l==selected)
    assert cell['structural_envelope']==str(root/key/lane/'envelope.json')
    # The selected comparator may be FAILED because core refused a required site.
    # Its original row is retained; no structural E9 result turns it into PASS.
    report['recorded_selected_comparison']=by_name[selected+'-compare']
    other=Path(ordinary['directory']);osummary=saved.json(other/'summary.json');orows=saved.json(other/'results.json')
    assert osummary['revision']==revision and osummary['planned_cases']==192 and osummary['artifact_cells']==24 and osummary['datasets_per_artifact']==8
    assert osummary['selected_owners_unchanged'] is True and osummary['qualification_complete'] is False
    assert saved.read(other/'source.json')==saved.read(other/'source-after.json') and saved.json(other/'source.json')==source
    supplied=saved.json(other/'inputs.json');assert supplied['production_admission']==inputs['production_admission']
    datasets=saved.json(saved.repo/'evaluation/e9-common-app/datasets.json')['datasets']
    assert [d['name'] for d in datasets]==['empty','singleton','pair-reverse','equal-17','sorted-17','reverse-17','duplicates-17','mixed-64']
    expected=['run-'+k+'-'+l+'-'+d['name'] for k in keys for l in ('core',*LANES) for d in datasets]
    assert len(orows)==192 and [r['name'] for r in orows]==expected and saved.json(other/'stage-inventory.json')==expected
    assert all(r['status'] in ('PASS_ORDINARY_OUTPUT_AND_JOURNAL','FAILED','UNRUN') for r in orows)
    assert osummary['passed_cases']==sum(r['status']=='PASS_ORDINARY_OUTPUT_AND_JOURNAL' for r in orows)
    assert osummary['failed_cases']==sum(r['status']=='FAILED' for r in orows) and osummary['unrun_cases']==[r['name'] for r in orows if r['status']=='UNRUN']
    assert osummary['ordinary_cases_complete']==(osummary['fatal'] is None and osummary['passed_cases']==192)
    assert report['recorded_ordinary_status']==dict(summary=osummary,cases=orows)
    chosen=[r for r in orows if r['artifact']==selected];assert [r['dataset'] for r in chosen]==[d['name'] for d in datasets]
    for row,d in zip(chosen,datasets):
        assert row['status']=='PASS_ORDINARY_OUTPUT_AND_JOURNAL' and row['strict_closure'] is True and row['exit']==0
        run=other/row['name'];q=saved.json(run/'request.json');receipt(saved,run,q)
        assert row['receipt_sha256']==sha(saved.read(run/'receipt.json'))
        assert saved.read(run/'stdout.txt')==d['expected_stdout'].encode() and not saved.read(run/'stderr.txt')
    report['upstream_content_authority']='Original16 and ordinary192 content reviews are explicit caller-admitted records. Their prior output/journal content authority is not recreated or relabelled by this E9 pair audit.'


def audit(saved,envelope,heads,pins,runner_sha,report):
    run=Path(envelope['run']);cap=run/'captures';repo=saved.repo
    assert run.is_relative_to(repo/'ignored') and envelope['authority']=='CALLER_ADMITTED_CLOSED_E9_PAIR_CAPTURE'
    inputs=saved.json(run/'inputs.json');source=saved.json(run/'source.json');summary=saved.json(run/'summary.json')
    revision=source['revision'];assert re.fullmatch('[0-9a-f]{40}',revision)
    assert saved.read(run/'source.json')==saved.read(run/'source-after.json') and saved.json(inputs['source_epoch'])==source
    activation=admission(saved,inputs['activation'],'CALLER_REVIEWED_COMMITTED_E9_PAIR_SOURCE','exact-reviewed-source-and-runner-activation',revision)
    assert activation['status']=='REVIEWED_COMMITTED' and activation['source_files_sha256']==sha(encode(source['files']))
    assert re.fullmatch('[0-9a-f]{64}',runner_sha) and activation['runner_sha256']==runner_sha==sha(saved.read(activation['runner']))
    assert activation['review_binding'] in envelope['evidence']['source_review']
    assert summary['recipe_sha256']==runner_sha and summary['revision']==revision and summary['cell'] in [k+'-'+lane for k in CELLS for lane in LANES]
    assert set(envelope['sources'])==set(pins)
    for name,digest in pins.items():
        assert sha(saved.read(envelope['sources'][name]))==digest
        if name=='evaluation/e9-common-app/run_e9_pairs.py':
            assert envelope['sources'][name]==activation['runner']
        else:
            assert source['files'][name]['sha256']==digest
    assert all(activation['source_pins'][p]==source['files'][p] for p in activation['source_pins'])
    assert set(activation['source_pins'])==set(pins)-{'evaluation/e9-common-app/run_e9_pairs.py'}
    assert pins['evaluation/e9-common-app/run_e9_pairs.py']==runner_sha
    assert set(source['files'])==set(source['owners'])
    for name,row in source['files'].items():
        path=str(repo/name);b=saved.read(path);assert row==dict(sha256=sha(b),bytes=len(b),mode='100755' if saved.pins[path]['stat'][2]&0o111 else '100644')
        assert source['owners'][name]==saved.seen[path]
    for p,owner in inputs['files'].items(): saved.read(p);assert saved.pins[p]==owner
    evidence=envelope['evidence']
    assert set(evidence)=={'source_review','build_review','producer_review','ordinary_review','runner_review','parent_closure'}
    for paths in evidence.values():
        assert type(paths) is list and paths and len(paths)==len(set(paths))
        for p in paths: saved.read(p)
    assert len(evidence['parent_closure'])==1
    parent=saved.json(evidence['parent_closure'][0]);assert type(parent['exit']) is int and parent['exit']==0 and parent['parent_wait_returned'] is True
    # These supplied, hash-bound review/admission records are caller authority;
    # neither this script nor a matching executable hash manufactures approval.
    rawindex=saved.json(run/'raw-files.json');indexed(saved,run,rawindex)
    assert tree(run)[0]==set(rawindex)|{'raw-files.json'}
    report['source_revision']=revision;report['source_files_sha256']=sha(encode(source['files']))
    report['source_files']=source['files'];report['cell']=summary['cell']
    prior_records(saved,inputs,run,revision,summary['cell'],report)
    assert summary['command_capture_schema_complete'] is True and summary['selected_owners_unchanged'] is True and summary['fatal'] is None
    for k,v in dict(cases=176,normal_cases=174,fault_cases=2,heads=87,planned_children=352,planned_comparisons=528,qualification_complete=False,full_a3=False,normal_loader_validation=False,independent_content_review_required=True,core_pairs='MANDATORY_SEPARATE',recording_pairs='MANDATORY_SEPARATE',ordinary_cases=192,operational_timings_not_performance=True).items(): assert summary[k]==v
    previous={}
    for path in [run/'before.json',run/'verify/before.json',run/'verify/after.json',run/'replay/before.json',run/'replay/after.json',run/'after.json']:
        snap=saved.json(path);assert snap['source']==source
        if previous:
            assert all(snap['owners'][k]==v for k,v in previous['owners'].items())
            assert {k:v for k,v in snap.items() if k!='owners'}=={k:v for k,v in previous.items() if k!='owners'}
        for p,row in snap['owners'].items(): saved.read(p);assert saved.seen[p]==row
        previous=snap
    results=saved.json(run/'results.json');assert [r['name'] for r in results]==['verify','replay'] and saved.json(run/'stage-inventory.json')==['verify','replay']
    requests=[]
    for i,name in enumerate(('verify','replay')):
        d=run/name;q=saved.json(d/'request.json');receipt(saved,d,q)
        cpu,wall,limit,outer,wait=(20,30,16*MIB,40,55) if i==0 else (60,90,64*MIB,100,115)
        assert set(q)=={'argv','cwd','env','cpu_seconds','wall_seconds','file_bytes','stdout','stderr'}
        assert q['cwd']==str(repo) and q['env']==dict(ENV,TMPDIR=str(d/'tmp')) and (q['cpu_seconds'],q['wall_seconds'],q['file_bytes'])==(cpu,wall,limit)
        assert q['stdout']==str(d/'stdout.txt') and q['stderr']==str(d/'stderr.txt') and not saved.read(d/'stderr.txt')
        outer_argv=[inputs['tools']['timeout'],'--signal=TERM','--kill-after=10s',str(outer)+'s',inputs['tools']['helper_python'],'-B',str(repo/'tools/unwind-oracle/bounded_command.py'),'--request',str(d/'request.json'),'--receipt',str(d/'receipt.json')]
        assert saved.json(d/'command.json')==dict(request=q,outer_argv=outer_argv,outer_env=ENV,cwd=str(repo),parent_timeout_seconds=wait)
        o=saved.json(d/'outer.json');assert o['exit']==0 and o['parent_timeout'] is False and math.isfinite(o['operational_seconds']) and 0<=o['operational_seconds']<=wait
        terminal=dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True)
        assert saved.read(d/'helper.stdout')==(json.dumps(terminal)+'\n').encode() and not saved.read(d/'helper.stderr')
        row=saved.json(d/'result.json');assert row==results[i] and row['exit']==0 and row['launched'] is True and row['strict_closure'] is True and row['reason']==''
        assert row['receipt_sha256']==sha(saved.read(d/'receipt.json')) and row['status']==('PASS_STRUCTURAL_WITNESS' if i==0 else 'PASS_COMMAND_AND_CAPTURE_SCHEMA')
        requests.append(q)
    v,r=(q['argv'] for q in requests)
    assert len(v)==9 and v==[inputs['tools']['python'],'-B',str(repo/'tools/elf-rewrite/e9-null-witness.py'),str(run/'witness-inputs.json'),str(run/'witness'),'--inputs-sha256',sha(saved.read(run/'witness-inputs.json')),'--structural-reader',str(repo/'tools/elf-rewrite/e9-sites.py')]
    assert len(r)==8 and r[1]=='replay-common-e9' and r[5:]==[str(run/'witness/witness.json'),str(run/'witness/native.tsv'),str(cap)]
    cell=admission(saved,inputs['cell_admission'],'CALLER_ADMITTED_E9_NULL_PAIR_INPUTS','one-complete-e9-null-artifact',revision)
    assert cell['cell']==summary['cell'] and cell['eligible'] is True and r[2:5]==[cell['original'],cell['inventory']+'/instructions.tsv',cell['target']]
    assert cell['driver_sha256']==sha(saved.read(r[0])) and cell['witness_reader_sha256']==pins['tools/elf-rewrite/e9-null-witness.py']
    for key in ('production_admission','ordinary_content_admission','observation_content_admission','build_admission'): assert cell[key+'_sha256']==sha(saved.read(inputs[key]))
    build=selected_build(saved,inputs,source,r[0]);assert build['review_binding'] in evidence['build_review']
    upstream_records(saved,inputs,source,cell,evidence,report)
    runtime=admission(saved,inputs['runtime_admission'],'CALLER_PINNED_PAIR_HOST_RUNTIME_EPOCH','selected-host-executable-interpreter-library-cache-owners',revision)
    assert runtime['executables']==dict(driver=r[0],python=inputs['tools']['python'],helper_python=inputs['tools']['helper_python'])
    assert '/etc/ld.so.cache' in runtime['owners'] and len(set(runtime['owners']))==len(runtime['owners'])>=2
    for p in runtime['owners']: saved.read(p)
    assert previous['interpreter_lookups']==runtime['interpreter_lookups']
    for p in runtime['executables'].values():
        b=saved.read(p)
        assert b[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HHI',b,16) in ((2,62,1),(3,62,1)) and struct.unpack_from('<HH',b,52)==(64,56)
        off=struct.unpack_from('<Q',b,32)[0];count=struct.unpack_from('<H',b,56)[0]
        assert 1<=count<=128 and off+56*count<=len(b)
        ph=[struct.unpack_from('<IIQQQQQQ',b,off+56*i) for i in range(count)]
        assert all(x[2]+x[5]<=len(b) for x in ph)
        interpreters=[b[x[2]:x[2]+x[5]] for x in ph if x[0]==3]
        assert len(interpreters)==1 and interpreters[0].endswith(b'\0') and b'\0' not in interpreters[0][:-1]
        name=os.fsdecode(interpreters[0][:-1]);assert runtime['interpreter_lookups'][name]['resolved'] in runtime['owners']
    report['runtime_owner_scope']='Selected executable/interpreter/library/cache owners; saved lookup epoch only, not complete live loader mapping coverage.'
    w,witness,cases,components,obase,cbase,generated,added=held_witness(saved,run,cap,heads,pins,cell)
    saved_producer_receipts(saved,w)
    names,expanded=capture_names(cases)
    assert summary['call_intermediate_checks']==expanded and summary['snapshots']==880+expanded and summary['capture_files']==len(names)
    assert summary['cell'].endswith('-'+w['lane']) and (('heap-write' in summary['cell'])==(w['structural']['policy']['selection_style']=='heap-write'))
    original_index=0 if '-unstripped-' in summary['cell'] else 1;assert w['original_sha256']==ORIGINALS[original_index]
    assert results[0]['witness_sha256']==sha(saved.read(run/'witness/witness.json')) and results[0]['native_tsv_sha256']==sha(saved.read(run/'witness/native.tsv'))
    assert results[0]['added_page_bytes']==len(generated) and results[0]['call_intermediate_checks']==expanded
    assert results[1]['capture_index_sha256']==sha(saved.read(run/'capture-files.json')) and results[1]['capture_files']==len(names) and results[1]['call_intermediate_checks']==expanded and results[1]['content_review_required'] is True
    index=saved.json(run/'capture-files.json');assert set(index)==set(names)
    assert {k[9:]:v for k,v in rawindex.items() if k.startswith('captures/')}==index
    assert tree(cap)==(set(names),{str(p) for n in names for p in Path(n).parents if str(p)!='.'})
    inventory=('\n'.join(names)+'\n').encode();assert saved.read(cap/'capture-inventory.tsv')==saved.read(run/'expected-captures.tsv')==inventory
    complete=tsv([('LI2COMMONE9PAIRS',1),('heads',87),('normal_pairs',174),('fault_pairs',2),('children',352),('comparisons',528),('call_intermediate_checks',expanded),('snapshots',880+expanded),('files',len(names)),('recording_hooks','UNIMPLEMENTED_UNRUN'),('normal_loader_validation','false'),('qualification_complete','false')])
    assert saved.read(cap/'complete.tsv')==complete
    assert saved.read(run/'verify/stdout.txt')==b'E9 null witnesses: 87 required heads; 176 required cases; COMPLETE_BYTE_WITNESSES\n'
    assert saved.read(run/'replay/stdout.txt')==f'E9 null pairs complete: heads=87 normal=174 faults=2 comparisons=528 call_intermediates={expanded} files={len(names)} qualification_complete=false\n'.encode()
    resource=saved.json(run/'resource-actual.json')
    assert resource['added_page_bytes']==len(generated) and resource['expanded_call_cases']==expanded and resource['snapshots']==880+expanded
    assert resource['witness_bytes']==sum(len(saved.read(run/'witness'/n)) for n in ('witness.json','native.tsv','sites.tsv','files.json'))
    assert resource['canonical_xstate_bytes']==2287 and resource['raw_xstate_max_bytes']==65536 and resource['maps_max_bytes']==MIB and resource['rss_enforced'] is False and resource['arbitrary_failure_disk_guarantee'] is False
    before=saved.json(run/'before.json');metadata=12*(len(encode(before))+65536)+8*len(saved.read(run/'inputs.json'))+16*MIB+9000*(len(str(run))+256)
    payload=sum(row['bytes'] for role,row in w['inputs'].items() if role!='inputs')
    growth=(880+expanded)*(254288+2287+65536+MIB)+(529+expanded)*len(generated)+2*resource['witness_bytes']+64*MIB+metadata
    memory=2*(payload+resource['witness_bytes']+4*len(generated)+32*MIB+237568)
    assert resource['metadata_bound_bytes']==metadata and resource['input_payload_bytes']==payload
    assert resource['logical_growth_bound_bytes']==growth and resource['allocation_reserve_bytes']==512*MIB and resource['required_growth_bytes']==growth+512*MIB and resource['live_payload_allowance_bytes']==memory
    capacity=saved.json(inputs['capacity_admission'])
    assert capacity['schema']==1 and capacity['authority']=='CALLER_RESERVED_E9_PAIR_RESOURCES' and capacity['source_revision']==revision and capacity['cell']==summary['cell'] and capacity['exclusive_slot_writer'] is True
    saved.read(capacity['observation'])
    assert capacity['slot_cap_bytes']==20000000000 and capacity['slot_used_bytes']+resource['required_growth_bytes']<=capacity['slot_cap_bytes']
    assert capacity['free_disk_bytes']>=resource['required_growth_bytes'] and capacity['free_memory_bytes']>=memory
    plan=[['case','head','state','original_pc','body_pc','completion_pc','logical_completion','operation_steps']]
    context=[]
    for i,c in enumerate(cases):
        h=heads[(i//2) if i<174 else 0]
        plan.append([i,c['head_id']-1,c['state'],h['pc'],witness[c['head_id']-1]['body'],c['completion']['physical_pc'],c['completion']['logical_pc'],len(c['operation'])])
        try:
            report['cases'][i]=capture_case(saved,cap,i,heads,witness,cases,components,obase,cbase,generated,added,context)
        except ERRORS as error:
            report['cases'][i]=dict(status='CONTENT_FAILURE',comparisons=0,error=repr(error))
    assert saved.read(cap/'planned-cases.tsv')==tsv(plan)
    report['completed_cases']=sum(c['status']=='PASS_SAVED_CONTENT' for c in report['cases'])
    report['comparisons']=sum(c['comparisons'] for c in report['cases'])
    report['children']=2*report['completed_cases']
    report['call_intermediate_checks']=sum(c.get('call_intermediate_checks',0) for c in report['cases'])
    report.update(candidate_sha256=w['candidate_sha256'],witness_sha256=sha(saved.read(run/'witness/witness.json')),native_tsv_sha256=sha(saved.read(run/'witness/native.tsv')),capture_index_sha256=sha(saved.read(run/'capture-files.json')),capture_files=len(names),snapshots=880+expanded,generated_page_bytes=len(generated),expected_call_intermediate_checks=expanded,expected_capture_files=len(names),expected_snapshots=880+expanded)
    report['completed']=report['completed_cases']==176 and report['comparisons']==528 and report['call_intermediate_checks']==expanded
    report['status']='PASS_SAVED_CONTENT' if report['completed'] else 'CONTENT_FAILURE'


def main():
    if sys.flags.optimize:
        raise SystemExit('optimized Python is unsupported; assertions are required')
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--inputs',required=True);ap.add_argument('--inputs-sha256',required=True);ap.add_argument('--raw',required=True)
    args=ap.parse_args();ib,io=read_file(args.inputs)
    assert re.fullmatch('[0-9a-f]{64}',args.inputs_sha256) and sha(ib)==args.inputs_sha256
    envelope=loads(ib);assert set(envelope)=={'schema','authority','repo','run','files','sources','evidence'} and type(envelope['schema']) is int and envelope['schema']==1
    saved=Saved(envelope['files'],envelope['repo']);out=Path(args.raw);run=Path(envelope['run'])
    assert out.is_absolute() and out.parent.resolve(strict=True)==out.parent and not out.exists() and out.is_relative_to(saved.repo/'ignored')
    assert '..' not in out.parts and not out.is_relative_to(run) and not run.is_relative_to(out)
    script=Path(__file__).resolve();sb,so=read_file(str(script))
    support={n:read_file(str(script.parent/n)) for n in ('e9-pair-heads.json','e9-pair-source-pins.json')}
    assert sha(support['e9-pair-heads.json'][0])==HEADS_SHA
    descriptor=loads(support['e9-pair-heads.json'][0]);material=loads(support['e9-pair-source-pins.json'][0]);pins=material['files'];heads=descriptor['heads']
    assert material['schema']==1 and len(heads)==87 and descriptor['source_sha256']==pins['tests/support/e9_common_seed.rs'] and descriptor['instructions_sha256']==pins['tests/support/e9_common_seed.instructions.tsv']
    assert len({h['pc'] for h in heads})==87 and sum(h['memory']['kind']!='None' for h in heads)==32
    out.mkdir(mode=0o700)
    report=dict(schema=1,status='INCOMPLETE',completed=False,cases=[dict(status='UNCHECKED',comparisons=0) for _ in range(176)],completed_cases=0,children=0,comparisons=0,call_intermediate_checks=0,mandatory_cells=[k+'-'+lane for k in CELLS for lane in LANES],expected_cases=176,expected_children=352,expected_comparisons=528,expected_capture_files=None,expected_snapshots=None,qualification_complete=False,normal_loader_validation=False,full_a3=False,core_pairs='MANDATORY_SEPARATE',recording_pairs='MANDATORY_SEPARATE',source_attested_not_independently_saved=LIVE_ONLY)
    try:
        assert saved.read(script)==sb
        for name,(b,_) in support.items(): assert saved.read(script.parent/name)==b
        report['recorded_runner_results']=saved.json(run/'results.json');report['recorded_runner_summary']=saved.json(run/'summary.json')
        for p in sorted(saved.pins): saved.read(p)
        if str(run/'witness/witness.json') in saved.pins:
            report['recorded_not_yet_validated_witness']=saved.json(run/'witness/witness.json')
        audit(saved,envelope,heads,pins,material['runner_sha256'],report)
    except ERRORS as error:
        report.update(status='INPUT_OR_CONTENT_FAILURE',completed=False,error=repr(error))
    try:
        saved.stable();assert read_file(args.inputs)==(ib,io) and read_file(str(script))==(sb,so)
        for name,old in support.items(): assert read_file(str(script.parent/name))==old
    except ERRORS as error:
        report.update(status='INPUT_DRIFT',completed=False,drift_error=repr(error))
    def write(name,value):
        b=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
        with (out/name).open('xb') as f:f.write(b)
        return sha(b)
    read_sha=write('read-inputs.json',dict(envelope=io,files=saved.seen,script=so,support={n:o for n,(_,o) in support.items()}))
    audit_sha=write('audit.json',report)
    write('binding.json',dict(schema=1,status=report['status'],completed=report['completed'],auditor_sha256=sha(sb),inputs_sha256=sha(ib),read_inputs_sha256=read_sha,audit_sha256=audit_sha,scope='One caller-admitted controlled E9-null artifact, all176 cases. Saved-content checks; independent actual execution review and remaining seven artifacts are separate.',qualification_complete=False))
    print(json.dumps(dict(status=report['status'],completed=report['completed'],audit_sha256=audit_sha),sort_keys=True))
    return 0 if report['completed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
