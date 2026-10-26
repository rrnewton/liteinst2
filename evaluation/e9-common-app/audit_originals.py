#!/usr/bin/env python3
"""Offline saved-content audit of the fixed sixteen original heap-sort observations."""
import argparse
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys

PREPARED = 'ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05'
OBSERVER_ORIGIN = 'bab4df624f6ff51e0ae0c6c10cc5f4629fd1d4c8'
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
NAMES = ('li2_array_store', 'li2_sift_down', 'li2_heap_sort')
DATASETS = ('empty','singleton','pair-reverse','equal-17','sorted-17','reverse-17','duplicates-17','mixed-64')
VARIANTS = ('unstripped','stripped')
CAP = 128 * 1024 * 1024
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
CASE_NAMES = tuple('observe-'+v+'-'+d for v in VARIANTS for d in DATASETS)
ERRORS = (AssertionError, ValueError, KeyError, IndexError, OSError, struct.error, TypeError, OverflowError)
INVENTORY_FILES = {'COMPLETE','instructions.tsv','sites.tsv','memory-writes.tsv','blocks.tsv','padding.tsv','policy.txt','target.txt','status.tsv','selection.txt'}
HEAD_COLUMNS = 'id pc length file_offset function bytes mnemonic flow direct_target block_start block_end jump_site heap_write rsp_depth'.split()
LIVE_ONLY = [
 'Full RX mapping bytes, bytes read at each executed instruction PC, and the actual eight-byte breakpoint restoration were asserted live, not serialized.',
 'Intermediate complete registers, actual RSP, actual stack return words, and call argument register values were asserted live, not serialized.',
 'Recorded callee RSP and store register values are observer reports; this audit rechecks their saved arithmetic and stream relationships, not absent raw registers.',
 'Single-task membership and live proc-exe/FD/path identity checks are source-attested; saved provider/map records permit the joins reported separately.',
 'No architectural state equivalence, manual replay, rewritten/E9 execution, performance or full-A3 qualification follows.'
]
SOURCE_PINS = {'evaluation/e9-common-app/BUILD.md': '0fc9c7f1a7cd0ec0dbf4a4be15a8eefdfb6530acdef6235d4b11f6f44fdf4ad9',
 'evaluation/e9-common-app/PREPARATION.md': '2f1d0b8264c311dc987f1f053ec675bfb58bc62d52de5ed61ad8626f7de0ed99',
 'evaluation/e9-common-app/PRODUCTION.md': '32d4cb61361c717d0353d19c99a4d901070739e64af01c807f8570f959068bd6',
 'evaluation/e9-common-app/README.md': '52222b130c915cccf4bae5b78247dc55f700fe7c3d18219a3477ddfe93eb6865',
 'evaluation/e9-common-app/build_inventory.py': '01a500aa807b131c94d158efb95a625eb777b11846013cd14fbddf33f63ee1b9',
 'evaluation/e9-common-app/contract.json': 'c3817d7c206e3ab2433f4752891334a3194f82c3ac56f55cddf5ffc64f20b271',
 'evaluation/e9-common-app/datasets.h': '4dff04a7d1f3bc245daf9037eca58d7fc59913063c49348eef5a3eeee0839ea6',
 'evaluation/e9-common-app/datasets.json': '4da40a6ddbf7a5330cdab9ae63e7800cdf2f72908c1c24f55319e75320e43334',
 'evaluation/e9-common-app/e9_hook.c': 'df39130ffdb17cb07e7b279aafb543dbbfa8d501be84744407dec788c10579e7',
 'evaluation/e9-common-app/expected/duplicates-17.stdout': 'f1712298c1a43edbb177339b90254305fec91ae6614068b5e5f69be662e18048',
 'evaluation/e9-common-app/expected/empty.stdout': '8cce7ab10bb13d2966c58b14f213f8d57e714c814f95d145e69a7d2056832bb1',
 'evaluation/e9-common-app/expected/equal-17.stdout': 'ef6622e734312559059272cba7fb180189b9de4a6e36ddc5a7469172a2f33040',
 'evaluation/e9-common-app/expected/mixed-64.stdout': '7843961fdbf66c50c2f5821f7fc812678dc0282baa59ab7bc6fbb3053b2394eb',
 'evaluation/e9-common-app/expected/pair-reverse.stdout': 'f25c5af943d7693b7884e06a965d3216390429e7f5dd2996dca0d42deeb1b170',
 'evaluation/e9-common-app/expected/reverse-17.stdout': '233ede9f9c673cfb92f906a2352170142a2a085c8fe8d4127e0e983a7a1c065f',
 'evaluation/e9-common-app/expected/singleton.stdout': '9b4999e24e893018cb4c8a1aa2f1465c27002fc81870d620a7ece24e19f2e147',
 'evaluation/e9-common-app/expected/sorted-17.stdout': '82c7d0f0e9d4fe3043642894680dee06774431e88b58ad2463af63967b060d04',
 'evaluation/e9-common-app/heap_sort.c': '62ae1639206838d5471fb27b54281d4262e6542973a4259066250cd9add2c902',
 'evaluation/e9-common-app/journal.h': '3d27763501ff98748d69edcae2e6d12e1a0a2b0ef5c31777c194fa6a1fe8cca8',
 'evaluation/e9-common-app/observe_originals.py': '3edebec0e1444412c9bce4877f1690beeb4bb8b85fb8140584b817b6216da4f7',
 'evaluation/e9-common-app/prepare_subject.py': '79945a0bfdc7ffa9b1ea2ed265669709e278bb6d82c5676731dab547eadc278c',
 'evaluation/e9-common-app/produce.py': '62642769cf14c5a8baccd887942403d5e5b313b1060d823b5bc240d7261fd59c',
 'tests/support/e9_common_app.rs': 'faec58111347cc1c0d41c0fa47862207ae8938f7b4caddad98b4afc3043699ae',
 'tests/support/e9_common_app_data.rs': '92bca80e47c0d20825a4ec278f0de47a178dd1f11b0062bf01b2bbfa12659bf4',
 'tests/support/elf_exec_driver.rs': 'e94b0768b83873481dfd723c01fa2c376de0c8272939fbd523bd6a7ba6130feb',
 'tests/support/elf_exec_oracle.rs': '22d63acfd7ef6576e588791623cdc82231248c9c345305144319a6dec94ccedb',
 'tests/support/elf_exec_provider.rs': '9b5562034fc6bbdc32f889ab64df7f414e96ee5d9a99c06e39bf6728f128e730',
 'tools/elf-rewrite/examples/common_sites.rs': '838c795e3a107bee340a0d29c349b1f6f3c05123b3c6e4d14d5a850973ae8831',
 'tools/unwind-oracle/bounded_command.py': 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'}
HEADS = [
    (4200512, '488914f7', 'li2_array_store', 'Next', None, 0),
    (4200516, 'c3', 'li2_array_store', 'Return', None, 0),
    (4200528, '4156', 'li2_sift_down', 'Next', None, 0),
    (4200530, '4155', 'li2_sift_down', 'Next', None, -8),
    (4200532, '4989fd', 'li2_sift_down', 'Next', None, -16),
    (4200535, '4154', 'li2_sift_down', 'Next', None, -16),
    (4200537, '4989f4', 'li2_sift_down', 'Next', None, -24),
    (4200540, '49d1ec', 'li2_sift_down', 'Next', None, -24),
    (4200543, '55', 'li2_sift_down', 'Next', None, -24),
    (4200544, '4889f5', 'li2_sift_down', 'Next', None, -32),
    (4200547, '4889d6', 'li2_sift_down', 'Next', None, -32),
    (4200550, '53', 'li2_sift_down', 'Next', None, -32),
    (4200551, '4c39e2', 'li2_sift_down', 'Next', None, -40),
    (4200554, '7222', 'li2_sift_down', 'ConditionalBranch', 4200590, -40),
    (4200556, 'eb58', 'li2_sift_down', 'UnconditionalBranch', 4200646, -40),
    (4200558, '6690', 'li2_sift_down', 'Next', None, None),
    (4200560, '4c89ef', 'li2_sift_down', 'Next', None, -40),
    (4200563, 'e8c8ffffff', 'li2_sift_down', 'Call', 4200512, -40),
    (4200568, '4c89f2', 'li2_sift_down', 'Next', None, -40),
    (4200571, '4889de', 'li2_sift_down', 'Next', None, -40),
    (4200574, '4c89ef', 'li2_sift_down', 'Next', None, -40),
    (4200577, 'e8baffffff', 'li2_sift_down', 'Call', 4200512, -40),
    (4200582, '4c39e3', 'li2_sift_down', 'Next', None, -40),
    (4200585, '733b', 'li2_sift_down', 'ConditionalBranch', 4200646, -40),
    (4200587, '4889de', 'li2_sift_down', 'Next', None, -40),
    (4200590, '488d0436', 'li2_sift_down', 'Next', None, -40),
    (4200594, '488d4e01', 'li2_sift_down', 'Next', None, -40),
    (4200598, '488d5801', 'li2_sift_down', 'Next', None, -40),
    (4200602, '4883c002', 'li2_sift_down', 'Next', None, -40),
    (4200606, '498b54dd00', 'li2_sift_down', 'Next', None, -40),
    (4200611, '4839e8', 'li2_sift_down', 'Next', None, -40),
    (4200614, '7314', 'li2_sift_down', 'ConditionalBranch', 4200636, -40),
    (4200616, '48c1e104', 'li2_sift_down', 'Next', None, -40),
    (4200620, '498b4c0d00', 'li2_sift_down', 'Next', None, -40),
    (4200625, '4839d1', 'li2_sift_down', 'Next', None, -40),
    (4200628, '7606', 'li2_sift_down', 'ConditionalBranch', 4200636, -40),
    (4200630, '4889ca', 'li2_sift_down', 'Next', None, -40),
    (4200633, '4889c3', 'li2_sift_down', 'Next', None, -40),
    (4200636, '4d8b74f500', 'li2_sift_down', 'Next', None, -40),
    (4200641, '4939d6', 'li2_sift_down', 'Next', None, -40),
    (4200644, '72aa', 'li2_sift_down', 'ConditionalBranch', 4200560, -40),
    (4200646, '5b', 'li2_sift_down', 'Next', None, -40),
    (4200647, '5d', 'li2_sift_down', 'Next', None, -32),
    (4200648, '415c', 'li2_sift_down', 'Next', None, -24),
    (4200650, '415d', 'li2_sift_down', 'Next', None, -16),
    (4200652, '415e', 'li2_sift_down', 'Next', None, -8),
    (4200654, 'c3', 'li2_sift_down', 'Return', None, 0),
    (4200656, '4883fe01', 'li2_heap_sort', 'Next', None, 0),
    (4200660, '767a', 'li2_heap_sort', 'ConditionalBranch', 4200784, 0),
    (4200662, '4154', 'li2_heap_sort', 'Next', None, 0),
    (4200664, '4989f4', 'li2_heap_sort', 'Next', None, -8),
    (4200667, '55', 'li2_heap_sort', 'Next', None, -8),
    (4200668, '49d1ec', 'li2_heap_sort', 'Next', None, -16),
    (4200671, '4889fd', 'li2_heap_sort', 'Next', None, -16),
    (4200674, '53', 'li2_heap_sort', 'Next', None, -16),
    (4200675, '4889f3', 'li2_heap_sort', 'Next', None, -24),
    (4200678, '662e0f1f840000000000', 'li2_heap_sort', 'Next', None, -24),
    (4200688, '4983ec01', 'li2_heap_sort', 'Next', None, -24),
    (4200692, '4889de', 'li2_heap_sort', 'Next', None, -24),
    (4200695, '4889ef', 'li2_heap_sort', 'Next', None, -24),
    (4200698, '4c89e2', 'li2_heap_sort', 'Next', None, -24),
    (4200701, 'e84effffff', 'li2_heap_sort', 'Call', 4200528, -24),
    (4200706, '4d85e4', 'li2_heap_sort', 'Next', None, -24),
    (4200709, '75e9', 'li2_heap_sort', 'ConditionalBranch', 4200688, -24),
    (4200711, '660f1f840000000000', 'li2_heap_sort', 'Next', None, -24),
    (4200720, '488b54ddf8', 'li2_heap_sort', 'Next', None, -24),
    (4200725, '4c8b6500', 'li2_heap_sort', 'Next', None, -24),
    (4200729, '31f6', 'li2_heap_sort', 'Next', None, -24),
    (4200731, '4883eb01', 'li2_heap_sort', 'Next', None, -24),
    (4200735, '4889ef', 'li2_heap_sort', 'Next', None, -24),
    (4200738, 'e819ffffff', 'li2_heap_sort', 'Call', 4200512, -24),
    (4200743, '4c89e2', 'li2_heap_sort', 'Next', None, -24),
    (4200746, '4889de', 'li2_heap_sort', 'Next', None, -24),
    (4200749, '4889ef', 'li2_heap_sort', 'Next', None, -24),
    (4200752, 'e80bffffff', 'li2_heap_sort', 'Call', 4200512, -24),
    (4200757, '31d2', 'li2_heap_sort', 'Next', None, -24),
    (4200759, '4889de', 'li2_heap_sort', 'Next', None, -24),
    (4200762, '4889ef', 'li2_heap_sort', 'Next', None, -24),
    (4200765, 'e80effffff', 'li2_heap_sort', 'Call', 4200528, -24),
    (4200770, '4883fb01', 'li2_heap_sort', 'Next', None, -24),
    (4200774, '75c8', 'li2_heap_sort', 'ConditionalBranch', 4200720, -24),
    (4200776, '5b', 'li2_heap_sort', 'Next', None, -24),
    (4200777, '5d', 'li2_heap_sort', 'Next', None, -16),
    (4200778, '415c', 'li2_heap_sort', 'Next', None, -8),
    (4200780, 'c3', 'li2_heap_sort', 'Return', None, 0),
    (4200781, '0f1f00', 'li2_heap_sort', 'Next', None, None),
    (4200784, 'c3', 'li2_heap_sort', 'Return', None, 0),
]
FUNCTIONS = [('li2_array_store', 4200512, 4200517, '8e33a6be5d373fe9df36d49b0a4cb90321c38a99369422c92831df6c28760728'),
 ('li2_sift_down', 4200528, 4200655, 'c4f371228e7f5a5ceec925101dc051f93676e3b07515637fa75d31a1820e410f'),
 ('li2_heap_sort', 4200656, 4200785, 'e840107b12c5fa0a59fc26e0a113c49b1b157491e1039bc697e1d30368f5b4fa')]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def encode(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def loads(b):
    def unique(pairs):
        out = {}
        for k, v in pairs:
            assert k not in out, ('duplicate key', k)
            out[k] = v
        return out
    def bad(x):
        raise AssertionError(('nonfinite JSON', x))
    return json.loads(b, object_pairs_hook=unique, parse_constant=bad)


def number(s, signed=False):
    assert type(s) is str and re.fullmatch(r'-?[0-9]+|0x[0-9a-f]+', s)
    x = int(s, 16 if s.startswith('0x') else 10)
    assert (-65536 if signed else 0) <= x < 2**64
    return x


def rows(b, columns):
    assert b.endswith(b'\n') and b'\r' not in b and b'\0' not in b
    lines = b.decode('ascii').splitlines()
    assert lines and lines[0].split('\t') == columns
    out = []
    for line in lines[1:]:
        parts = line.split('\t'); assert len(parts) == len(columns)
        out.append(dict(zip(columns, parts)))
    return out


def fields(b):
    assert b.endswith(b'\n') and b'\r' not in b and b'\0' not in b
    out = {}
    for line in b.decode().splitlines():
        k, v = line.split('\t'); assert k not in out; out[k] = v
    return out


def words(b):
    assert len(b) % 8 == 0
    return list(struct.unpack('<' + 'Q' * (len(b)//8), b))


def six(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read_file(value):
    p = Path(value)
    assert p.is_absolute() and str(p) == value and '..' not in p.parts
    assert p.parent.resolve(strict=True) == p.parent
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
        a = os.fstat(f.fileno()); assert stat.S_ISREG(a.st_mode) and 0 <= a.st_size <= CAP
        b = f.read(CAP+1); z = os.fstat(f.fileno())
        assert six(a) == six(z) == six(p.lstat()) and len(b) == a.st_size
    return b, dict(path=value,resolved=value,sha256=sha(b),stat=six(a))


class Saved:
    def __init__(self, pins, repo):
        self.pins, self.repo, self.seen = pins, Path(repo), {}
        assert self.repo.is_absolute() and self.repo.resolve(strict=True) == self.repo
    def read(self, value):
        value = str(value)
        assert value in self.pins, ('unlisted input', value)
        assert not Path(value).is_relative_to(self.repo/'target'), 'saved records only; no target'
        b, owner = read_file(value); row = self.pins[value]
        assert row == dict(sha256=sha(b),bytes=len(b)), ('pin mismatch', value)
        if value in self.seen:
            assert self.seen[value] == owner, ('owner drift', value)
        self.seen[value] = owner
        return b
    def json(self, value):
        return loads(self.read(value))
    def stable(self):
        for p in sorted(self.seen):
            self.read(p)


def elf(b):
    assert len(b) >= 64 and b[:7] == b'\x7fELF\x02\x01\x01'
    kind, machine, version = struct.unpack_from('<HHI', b, 16)
    assert kind in (2,3) and machine == 62 and version == 1
    off = struct.unpack_from('<Q',b,32)[0]; eh,ent,n = struct.unpack_from('<HHH',b,52)
    assert (eh,ent)==(64,56) and 1 <= n <= 128 and off+ent*n <= len(b)
    out, interp = [], None
    for i in range(n):
        k,flags,offset,address,_,fs,ms,align = struct.unpack_from('<IIQQQQQQ',b,off+56*i)
        if k == 1:
            assert flags in (4,5,6) and 0 <= fs <= ms and ms > 0 and offset+fs <= len(b)
            assert address+ms < 2**64 and address%4096 == offset%4096 and align >= 4096 and align&(align-1)==0
            out.append(dict(offset=offset,address=address,file=fs,memory=ms,flags=flags))
        elif k == 3:
            assert interp is None and 1 < fs <= 4096 and offset+fs <= len(b)
            v=b[offset:offset+fs]; assert v[-1:]==b'\0' and b'\0' not in v[:-1]
            interp=v[:-1].decode(); assert interp.startswith('/')
        elif k == 0x6474e551:
            assert flags == 6
    out.sort(key=lambda l:l['address']); assert 1 <= len(out) <= 8
    assert all(a['address']+a['memory'] <= z['address'] for a,z in zip(out,out[1:]))
    return dict(kind=kind,loads=out,interpreter=interp,bytes=b)


def image_slice(image, pc, size, flags=5):
    selected=[l for l in image['loads'] if l['flags']==flags and l['address']<=pc and pc+size<=l['address']+l['file']]
    assert len(selected)==1
    l=selected[0]; off=l['offset']+pc-l['address']
    return off,image['bytes'][off:off+size]


def layout(b, image):
    lines=b.decode().splitlines()
    assert len(lines)==10 and lines[0]=='LI2COMMONOBSERVER\t1' and lines[-1]=='END'
    expected=[('function',n) for n in NAMES+('main',)]+[('marker',n) for n in ('li2_before_sort','li2_after_sort')]+[('object',n) for n in ('li2_run','li2_journal')]
    out={}
    for line,(tag,name) in zip(lines[1:-1],expected):
        f=line.split('\t'); assert len(f)==4 and f[:2]==[tag,name]
        pc,size=number(f[2]),number(f[3]); assert 0<size<=131144
        out[name]=(pc,size)
        if tag=='object':
            assert sum(l['flags']==6 and l['address']<=pc and pc+size<=l['address']+l['memory'] for l in image['loads'])==1
        else:
            image_slice(image,pc,size)
    for name,start,end,digest in FUNCTIONS:
        assert out[name]==(start,end-start) and sha(image_slice(image,start,end-start)[1])==digest
    assert out['main']==(0x401100,0x4ad)
    for name in ('li2_before_sort','li2_after_sort'):
        pc,size=out[name]; assert size==1 and image_slice(image,pc,1)[1]==b'\xc3'
    assert out['li2_run'][1]==88 and out['li2_journal'][1]==131144
    assert all(a+n<=z or z+m<=a for i,(a,n) in enumerate(out.values()) for z,m in list(out.values())[i+1:])
    return out


def head_table(b, image):
    table=rows(b,HEAD_COLUMNS); assert len(table)==len(HEADS)
    out={}
    for ident,(row,expected) in enumerate(zip(table,HEADS),1):
        pc,hexbytes,name,flow,target,depth=expected; raw=bytes.fromhex(hexbytes)
        assert [number(row[k]) for k in ('id','pc','length','file_offset')]==[ident,pc,len(raw),image_slice(image,pc,len(raw))[0]]
        assert row['function']==name and row['bytes']==hexbytes and image_slice(image,pc,len(raw))[1]==raw
        assert row['flow']==flow and row['direct_target']==('none' if target is None else hex(target))
        assert row['jump_site']==str(flow in ('ConditionalBranch','UnconditionalBranch')).lower()
        assert row['heap_write']==str(pc==FUNCTIONS[0][1]).lower()
        assert row['rsp_depth']==('unproven' if depth is None else str(depth))
        # Canonical mnemonic is checked where it controls selection; other
        # decoder labels are source-attested, exact bytes/lengths are independent.
        assert row['mnemonic'].lower().startswith('j') == (row['jump_site']=='true')
        if depth is None: assert row['mnemonic']=='Nop'
        start,stop=number(row['block_start']),number(row['block_end']); f=FUNCTIONS[NAMES.index(name)]
        assert f[1]<=start<=pc<pc+len(raw)<=stop<=f[2]
        out[pc]=dict(row,pc_int=pc,len_int=len(raw),target_int=target,depth_int=depth,fi=NAMES.index(name))
    return table,out


def provider(fdinfo, mountinfo, inode):
    assert fdinfo.endswith(b'\n') and len(fdinfo)<=4096 and mountinfo.endswith(b'\n') and len(mountinfo)<=1048576
    def field(key):
        hits=[r[len(key):].strip() for r in fdinfo.decode().splitlines() if r.startswith(key)]
        assert len(hits)==1 and re.fullmatch('[0-9]+',hits[0]); return int(hits[0])
    ident=field('mnt_id:'); assert ident>0 and field('ino:')==inode>0
    found=[]
    for line in mountinfo.decode().splitlines():
        f=line.split(); assert f and f[0].isdigit()
        if int(f[0])!=ident: continue
        assert len(f)>=10 and f.count('-')==1
        at=f.index('-'); assert at>=6 and at+4==len(f) and f[1].isdigit() and int(f[1])>0
        assert f[3].startswith('/') and f[4].startswith('/') and re.fullmatch('[0-9]+:[0-9]+',f[2])
        found.append(dict(mount_id=ident,device=list(map(int,f[2].split(':'))),mount_record=line+'\n'))
    assert len(found)==1; return found[0]


def captured_owner(b, expected):
    first,second,length,rest=b.split(b'\n',3)
    assert first==('path_hex\t'+expected['observed_path_hex']).encode()
    assert bytes.fromhex(expected['observed_path_hex'])==expected['path'].encode()
    assert second.startswith(b'stat\t') and loads(second[5:])==expected['descriptor_stat']==expected['pathname_stat']
    assert length.startswith(b'fdinfo_bytes\t'); n=number(length.split(b'\t')[1].decode())
    fdinfo,rest=rest[:n],rest[n:]; length,mount=rest.split(b'\n',1)
    assert length.startswith(b'mount_record_bytes\t') and len(mount)==number(length.split(b'\t')[1].decode())
    assert provider(fdinfo,mount,expected['descriptor_stat'][1])==expected['provider']
    return fdinfo


def page_end(n):
    return (n+4095)&~4095


def map_content(b, links, mounts, owners, images, fdinfos, all_owners):
    assert b.endswith(b'\n') and len(b)<=131072
    observed=set(); biases={}; result=[]; expected_links=[]
    for line in b.decode().splitlines():
        f=line.split(); assert len(f) in (5,6)
        a,z=[int(x,16) for x in f[0].split('-')]; off=int(f[2],16); dev=[int(x,16) for x in f[3].split(':')];ino=number(f[4]);name=f[5] if len(f)==6 else '';perm=f[1]
        assert a<z and a%4096==z%4096==0 and re.fullmatch('[r-][w-][x-]p',perm)
        assert not ('w' in perm and 'x' in perm)
        assert not result or result[-1]['end']<=a
        if ino:
            matches=[i for i,o in enumerate(owners) if o['path']==name]; assert len(matches)==1
            i=matches[0]; o=owners[i]; observed.add(i)
            assert ino==o['descriptor_stat'][1] and dev==o['provider']['device']
            assert provider(fdinfos[i],mounts,ino)==o['provider']
            expected_links.append(f"{a:x}-{z:x}\t{i}\t{name.encode().hex()}\n")
            possible=set()
            for l in images[i]['loads']:
                lo=l['offset']&~4095;hi=page_end(l['offset']+l['file'])
                if lo<=off<hi and off+z-a<=hi:
                    va=(l['address']&~4095)+off-lo
                    if a>=va:possible.add(a-va)
            if i not in biases:
                zero=[l for l in images[i]['loads'] if l['offset']&~4095==0 and off==0];assert len(zero)==1
                bias=a-(zero[0]['address']&~4095);assert bias>=0 and bias in possible
                if i==0:assert bias==0
                biases[i]=bias
            assert biases[i] in possible
            assert any(biases[i]+(l['address']&~4095)<=a and z<=biases[i]+page_end(l['address']+l['memory']) and ('x' not in perm or l['flags']&1) and ('w' not in perm or l['flags']&2) for l in images[i]['loads'])
        else:
            assert dev==[0,0] and name in ('','[heap]','[stack]','[vdso]','[vvar]','[vvar_vclock]','[vsyscall]')
            assert 'x' not in perm or name in ('[vdso]','[vsyscall]')
        result.append(dict(start=a,end=z,offset=off,device=dev,inode=ino,name=name,permissions=perm))
    assert len(result)<=512 and 0 in observed and (not all_owners or observed==set(range(len(owners))))
    assert links==''.join(expected_links).encode()
    for l in images[0]['loads']:
        at=l['address']&~4095;stop=page_end(l['address']+l['memory'])
        while at<stop:
            ms=[m for m in result if m['start']<=at<m['end']];assert len(ms)==1;m=ms[0]
            assert m['permissions'].startswith('r')
            for pg in range(at,min(m['end'],stop),4096):
                if pg<page_end(l['address']+l['file']):
                    assert (m['inode'],m['device'],m['name'])==(owners[0]['descriptor_stat'][1],owners[0]['provider']['device'],owners[0]['path'])
                    assert m['offset']+pg-m['start']==(l['offset']&~4095)+pg-(l['address']&~4095)
                else:assert m['inode']==0 and m['name']==''
            if l['flags']&1:assert m['permissions']=='r-xp'
            at=min(m['end'],stop)
    return result


def owns(maps, start, size, permissions):
    stop=start+size; assert stop<2**64
    while start<stop:
        found=[m for m in maps if m['start']<=start<m['end']];assert len(found)==1;m=found[0]
        assert (m['permissions'],m['inode'],m['device'],m['offset'],m['name'])==(permissions,0,[0,0],0,'')
        start=min(m['end'],stop)


def journal(active):
    return struct.pack('<8Q',0x6c69326a6f75726e,1,16384,active,0,0,0,0)+bytes(16384*8)+struct.pack('<Q',0x7265636f72647321)


def strict_receipt(saved, directory, request):
    r=saved.json(directory/'receipt.json')
    assert set(r)=={'request_sha256','helper_sha256','exit','wall_timeout','unexpected_descendants','absence_proof','stdout_sha256','stderr_sha256','elapsed_seconds','cleanup_events','cleanup_error','aborted','inputs_unchanged'}
    assert type(r['exit']) is int and r['exit']==0 and r['request_sha256']==sha(saved.read(directory/'request.json')) and r['helper_sha256']==HELPER_SHA
    assert r['wall_timeout'] is False and r['inputs_unchanged'] is True and r['absence_proof']=='ECHILD'
    assert r['unexpected_descendants']==r['cleanup_events']==[] and r['aborted'] is None and r['cleanup_error'] is None
    assert type(r['elapsed_seconds']) in (int,float) and math.isfinite(r['elapsed_seconds']) and 0<=r['elapsed_seconds']<=request['wall_seconds']
    for stream in ('stdout','stderr'):
        b=saved.read(directory/(stream+'.txt'));assert sha(b)==r[stream+'_sha256'] and len(b)<=request['file_bytes']
    return r


def recorded_index(saved, directory, index):
    assert directory.resolve(strict=True)==directory
    assert set(p.name for p in directory.iterdir())==set(index)
    for name,row in index.items():
        assert Path(name).name==name and name not in ('.','..')
        p=directory/name;b=saved.read(p)
        assert row['path']==row['resolved']==str(p) and row['sha256']==sha(b) and row['stat'][3]==len(b)
        assert row==saved.seen[str(p)], 'capture owner changed since closed recipe'


def audit_case(saved, directory, dataset, variant, image, lay, table, heads, runtime, request, originals):
    capture=directory/'captures';index=saved.json(directory/'capture-files.json')
    recorded_index(saved,capture,index)
    read=lambda name:saved.read(capture/name)
    owner_rows=runtime['variants'][variant]['owners']
    fixed={'budget.tsv','events.bin','all-pcs.bin','jump-pcs.bin','heap-pcs.bin','calls.tsv','stores.tsv','coverage.tsv','observations.tsv','complete.tsv','inputs-unchanged','markers.tsv','stdout','stderr','journal.bin','breakpoint.original','breakpoint.installed','breakpoint.trapped.regs','breakpoint.restored.regs','breakpoint.trapped.xstate','breakpoint.restored.xstate'}
    fixed|={f'{phase}.{kind}' for phase in ('exec','before','after') for kind in ('maps','mountinfo','map-files')}
    fixed|={f'{phase}.{kind}' for phase in ('before','after') for kind in ('run','middle','journal')}
    fixed|={f'input-{i}.txt' for i in range(1,6)}|{f'consumed-{i}.bin' for i in range(13)}|{f'owner-{i}.txt' for i in range(len(owner_rows))}
    assert set(index)==fixed
    input_paths=request['argv'][2:8]
    assert len(input_paths)==6 and input_paths[0]==originals[variant]
    for i in range(1,6):assert read(f'input-{i}.txt')==saved.read(input_paths[i])
    consumed=input_paths[1:]
    for p in (Path(input_paths[3]).parent,Path(input_paths[4]).parent):
        consumed += [str(p/n) for n in ('instructions.tsv','status.tsv','selection.txt','COMPLETE')]
    assert len(consumed)==13
    for i,p in enumerate(consumed):assert read(f'consumed-{i}.bin')==saved.read(p)
    fdinfos=[captured_owner(read(f'owner-{i}.txt'),o) for i,o in enumerate(owner_rows)]
    images=[elf(saved.read(o['path'])) for o in owner_rows]
    maps={phase:map_content(read(phase+'.maps'),read(phase+'.map-files'),read(phase+'.mountinfo'),owner_rows,images,fdinfos,phase!='exec') for phase in ('exec','before','after')}
    n=len(dataset['input']);calls=0 if n<2 else n//2+n-1;levels=0 if n<2 else n.bit_length()-1;iterations=calls*levels;store_bound=0 if n<2 else 2*(iterations+n-1)
    bounds=[store_bound,iterations+calls,1 if n<2 else n//2+n]
    limit=sum(bounds[h['fi']] for h in heads.values())+128;assert limit<=1048576
    budget=f'n\t{n}\nsift_calls\t{calls}\nsift_iterations\t{iterations}\nstore_calls\t{store_bound}\nper_head\t{bounds[0]}\t{bounds[1]}\t{bounds[2]}\nderived_steps\t{limit}\nhard_steps\t1048576\nwall_seconds\t60\nbridge_steps\t128\n'
    assert read('budget.tsv')==budget.encode()
    before,after=lay['li2_before_sort'][0],lay['li2_after_sort'][0]
    marker_lines=read('markers.tsv').decode().splitlines();assert len(marker_lines)==2
    markers={}
    for line,tag,pc in zip(marker_lines,('before','after'),(before,after)):
        f=line.split('\t');assert len(f)==3 and f[:2]==[tag,hex(pc)]
        ret=number(f[2]);call=ret-5; assert lay['main'][0]<=call<ret<=sum(lay['main'])
        raw=image_slice(image,call,5)[1];assert raw[0]==0xe8 and ret+int.from_bytes(raw[1:],'little',signed=True)==pc
        markers[tag]=ret
    assert markers==dict(before=0x4012e6,after=0x4012f7)
    # Fixed prepared main bridge: exact original bytes, not an inferred decoder.
    bridge={0x4012e6:(bytes.fromhex('488b3c24'),'Next',None),0x4012ea:(bytes.fromhex('4c89f6'),'Next',None),0x4012ed:(bytes.fromhex('e8de050000'),'Call',FUNCTIONS[2][1]),0x4012f2:(bytes.fromhex('e8b9030000'),'Call',after)}
    for pc,(b,_,_) in bridge.items():assert image_slice(image,pc,len(b))[1]==b
    aligned=before&~7;off=before-aligned;orig=image_slice(image,aligned,8)[1];installed=bytearray(orig);assert orig[off]==0xc3;installed[off]=0xcc
    assert read('breakpoint.original')==orig and read('breakpoint.installed')==installed
    trapped,restored=words(read('breakpoint.trapped.regs')),words(read('breakpoint.restored.regs'))
    assert len(trapped)==len(restored)==27 and trapped[16]==before+1 and restored[16]==before
    expected=trapped.copy();expected[16]=before;assert restored==expected
    xstate=read('breakpoint.trapped.xstate');assert 576<=len(xstate)<=65536 and read('breakpoint.restored.xstate')==xstate
    observed=fields(read('observations.tsv'))
    assert read('complete.tsv')==read('observations.tsv') and read('inputs-unchanged')==b'complete\n'
    assert observed.keys()=={'status','dataset','static_heads','static_jump_sites','static_heap_sites','steps','events','heap_calls','store_calls','original_only','full_architectural_equivalence'}
    assert observed['status']=='passed' and observed['dataset']==dataset['name'] and observed['original_only']=='true' and observed['full_architectural_equivalence']=='false'
    steps,events_count=number(observed['steps']),number(observed['events'])
    pcs=words(read('all-pcs.bin'));assert len(pcs)==steps and 0<steps<=limit and pcs[0]==before
    eb=read('events.bin');assert len(eb)==40*events_count and events_count==steps+4
    events=list(struct.iter_unpack('<IiQQiIQ',eb))
    assert all(e[5]==0 for e in events)
    first=events[0]; assert first[0]==0 and first[1]==0x57f and first[3]==0 and first[6]==0
    assert any(m['start']<=first[2]<m['end'] and 'x' in m['permissions'] for m in maps['exec'])
    assert events[1] in ((7,0x57f,before+1,0,1,0,0),(7,0x57f,before+1,0,128,0,0))
    for i,e in enumerate(events[2:-2]):
        assert e==(9,0x57f,pcs[i+1] if i+1<len(pcs) else after,i+1,2,0,0)
    assert events[-2][0:2]==(7,(6<<16)|0x57f) and events[-2][3:]==(steps,0,0,0)
    assert events[-1]==(7,0,0,steps,0,0,0)
    assert pcs[1]==markers['before']
    run=words(read('before.run'));assert len(run)==11 and read('before.run')==read('after.run')
    assert (run[0],run[10])==(0x72616e67652d6c6f,0x72616e67652d6869)
    assert (run[2],run[4],run[7],run[8],run[9])==(12288,4096,n,dataset['id'],1)
    assert run[1]%4096==0 and run[3]==run[1]+4096 and run[5]==run[3]+64 and run[6]==run[5]+n*8
    middle=bytearray([0xa5]*4096);middle[64:64+8*n]=struct.pack('<'+'Q'*n,*dataset['input'])
    assert read('before.middle')==middle
    for phase in ('before','after'):
        owns(maps[phase],run[1],4096,'---p');owns(maps[phase],run[3],4096,'rw-p');owns(maps[phase],run[3]+4096,4096,'---p')
        assert read(phase+'.journal')==journal(1)
    stacks=[m for m in maps['before'] if m['name']=='[stack]' and m['permissions']=='rw-p'];assert len(stacks)==1;stack=stacks[0]
    assert stack['start']<=restored[19] and restored[19]+8<=stack['end']
    assert any(m['name']=='[stack]' and m['permissions']=='rw-p' and m['start']<=restored[19] and restored[19]+8<=m['end'] for m in maps['after'])
    calls_rows=rows(read('calls.tsv'),'step call_pc callee return_pc callee_rsp'.split())
    stores_rows=rows(read('stores.tsv'),'step call_pc store_pc base index value ea old new'.split())
    ci=si=0;frames=[];visits=collections.Counter();bridge_pcs=[];rsp=restored[19]+8;heap_calls=0
    for i,pc in enumerate(pcs[1:],1):
        assert stack['start']<=rsp-128 and rsp+8<=stack['end']
        h=heads.get(pc)
        if h is not None:
            assert frames and frames[-1]['fi']==h['fi'] and h['depth_int'] is not None
            assert rsp==frames[-1]['rsp']+h['depth_int']
            visits[pc]+=1;assert visits[pc]<=bounds[h['fi']]
            raw=bytes.fromhex(h['bytes']);flow=h['flow'];to=h['target_int'];length=h['len_int']
        else:
            assert not frames and pc in bridge
            bridge_pcs.append(pc);raw,flow,to=bridge[pc];length=len(raw)
        nxt=pcs[i+1] if i+1<len(pcs) else after
        if flow=='Call':
            assert nxt==to
            if to in [f[1] for f in FUNCTIONS]:
                fi=[f[1] for f in FUNCTIONS].index(to);assert all(f['fi']!=fi for f in frames)
                if not frames:assert fi==2;heap_calls+=1;assert heap_calls==1
                expected=dict(step=str(i),call_pc=hex(pc),callee=hex(to),return_pc=hex(pc+length),callee_rsp=hex(rsp-8))
                assert ci<len(calls_rows) and calls_rows[ci]==expected;ci+=1
                frames.append(dict(fi=fi,rsp=rsp-8,ret=pc+length,call=pc));assert len(frames)<=3
            else:assert not frames and heap_calls==1 and to==after
            rsp-=8
        elif flow=='Return':
            assert frames;fr=frames.pop();assert rsp==fr['rsp'] and nxt==fr['ret'];rsp+=8
        elif flow=='ConditionalBranch':assert nxt in (to,pc+length)
        elif flow=='UnconditionalBranch':assert nxt==to
        else:
            assert flow=='Next' and nxt==pc+length
            # The complete fixed inventory admits only these explicit RSP changes.
            if raw in (b'\x41\x56',b'\x41\x55',b'\x41\x54',b'\x55',b'\x53'):rsp-=8
            if raw in (b'\x5b',b'\x5d',b'\x41\x5c',b'\x41\x5d',b'\x41\x5e'):rsp+=8
        if h is not None and h['heap_write']=='true':
            assert si<len(stores_rows) and frames and frames[-1]['fi']==0
            row=stores_rows[si];si+=1
            vals={k:number(v) for k,v in row.items()}
            assert vals['step']==i and vals['call_pc']==frames[-1]['call'] and vals['store_pc']==pc
            assert vals['base']==run[5] and vals['index']<n and vals['ea']==run[5]+8*vals['index'] and vals['ea']+8<=run[6]
            at=64+8*vals['index'];old=struct.unpack_from('<Q',middle,at)[0]
            assert vals['old']==old and vals['new']==vals['value'];struct.pack_into('<Q',middle,at,vals['new'])
    assert not frames and heap_calls==1 and rsp==restored[19]
    assert bridge_pcs==list(bridge) and len(bridge_pcs)+1<=128
    assert ci==len(calls_rows) and si==len(stores_rows)<=store_bound
    assert si==sum(number(r['callee'])==FUNCTIONS[0][1] for r in calls_rows)
    assert read('after.middle')==middle
    expected=bytearray([0xa5]*4096);expected[64:64+n*8]=struct.pack('<'+'Q'*n,*dataset['expected']);assert middle==expected
    jumps=[pc for pc in pcs if pc in heads and heads[pc]['jump_site']=='true'];heaps=[pc for pc in pcs if pc in heads and heads[pc]['heap_write']=='true']
    assert words(read('jump-pcs.bin'))==jumps and words(read('heap-pcs.bin'))==heaps and len(heaps)==si
    coverage=rows(read('coverage.tsv'),'id pc jump_site heap_write visits'.split())
    assert coverage==[{k:r[k] for k in ('id','pc','jump_site','heap_write')}|dict(visits=str(visits[number(r['pc'])])) for r in table]
    assert number(observed['static_heads'])==len(heads) and number(observed['static_jump_sites'])==sum(r['jump_site']=='true' for r in table)
    assert observed['static_heap_sites']==observed['heap_calls']=='1' and number(observed['store_calls'])==si
    assert read('stdout')==dataset['expected_stdout'].encode() and not read('stderr') and read('journal.bin')==journal(0)
    return dict(status='PASS_SAVED_CONTENT',static_heads=len(heads),static_jump_sites=sum(r['jump_site']=='true' for r in table),static_heap_sites=1,steps=steps,events=events_count,heap_calls=1,store_calls=si,call_records=ci,jump_visits=len(jumps),zero_visit_heads=sum(visits[p]==0 for p in heads),capture_files=len(index),capture_index_sha256=sha(saved.read(directory/'capture-files.json')),jump_stream_sha256=sha(read('jump-pcs.bin')),heap_stream_sha256=sha(read('heap-pcs.bin')),coverage_sha256=sha(read('coverage.tsv')))


def inventories(saved, cells, originals, common_sites):
    expected={'-'.join((hook,style,v)) for hook in ('null','journal') for style in ('jump-site','heap-write') for v in VARIANTS}
    assert set(cells)==expected
    common=None;styles={};result={}
    for hook in ('null','journal'):
        for style in ('jump-site','heap-write'):
            for variant in VARIANTS:
                key='-'.join((hook,style,variant));cell=cells[key];directory=Path(cell['directory'])
                assert set(cell)=={'directory','run_directory','provenance'}
                assert set(p.name for p in directory.iterdir())==INVENTORY_FILES
                data={n:saved.read(directory/n) for n in INVENTORY_FILES}
                assert data['COMPLETE']==('LI2COMMONFILES\t1\n'+''.join(f'{sha(data[n])}\t{len(data[n])}\t{n}\n' for n in sorted(INVENTORY_FILES-{'COMPLETE'}))).encode()
                table,heads=head_table(data['instructions.tsv'],elf(originals[variant]))
                site=rows(data['sites.tsv'],'id pc length file_offset function style'.split())
                flag='jump_site' if style=='jump-site' else 'heap_write'
                assert site==[{k:r[k] for k in ('id','pc','length','file_offset','function')}|dict(style=style) for r in table if r[flag]=='true']
                if style in styles:assert styles[style]==data['sites.tsv']
                styles[style]=data['sites.tsv']
                identical={n:data[n] for n in ('instructions.tsv','memory-writes.tsv','blocks.tsv','padding.tsv','target.txt')}
                if common is not None:assert common==identical
                common=identical
                st=fields(data['status.tsv']);assert st.pop('LI2COMMONRESULT')=='1'
                assert st==dict(original_sha256=sha(originals[variant]),policy_sha256=sha(data['policy.txt']),caller_provenance_sha256=sha(saved.read(cell['provenance'])),target_sha256=sha(data['target.txt']),style=style,hook=hook,instruction_heads=str(len(table)),selected_sites=str(len(site)),complete_static_policy='true',qualification_complete='false',selection_sha256=sha(data['selection.txt']))
                selections=[r.split() for r in data['selection.txt'].decode().splitlines()];assert selections[0]==['LI2TOOL','1']
                selected=[r for r in selections if r[0]=='site']
                assert [(number(r[1]),number(r[2]),number(r[3]),number(r[4])) for r in selected]==[(number(r['id']),number(r['pc']),number(r['length']),number(r['file_offset'])) for r in site]
                run=Path(cell['run_directory']);req=saved.json(run/'request.json')
                assert len(req['argv'])==7 and req['argv'][0]==common_sites
                assert req['argv'][4:]==[style,hook,str(directory)] and saved.read(req['argv'][1])==originals[variant]
                assert saved.read(req['argv'][2])==data['policy.txt'] and saved.read(req['argv'][3])==data['target.txt']
                assert (req['cpu_seconds'],req['wall_seconds'],req['file_bytes'])==(20,30,16*1024*1024)
                strict_receipt(saved,run,req)
                assert saved.read(run/'stdout.txt')==f'common sites: heads={len(table)} selected={len(site)} style={style} hook={hook} complete_static_policy=true qualification_complete=false\n'.encode() and not saved.read(run/'stderr.txt')
                result[key]=dict(table=table,heads=heads,directory=directory,complete_sha256=sha(data['COMPLETE']))
    return result


def snapshot(saved, value, source, runtime):
    assert set(value)=={'owners','source','runtime'} and value['source']==source
    for p,row in value['owners'].items():
        b=saved.read(p);assert row==saved.seen[p], ('saved input owner changed',p)
    assert set(value['runtime'])==set(VARIANTS)
    for v in VARIANTS:
        actual=value['runtime'][v];expected=runtime['variants'][v]
        assert set(actual)=={'owners','interpreter_lookup'}
        assert actual['interpreter_lookup']==expected['interpreter_lookup']
        assert [x['identity'] for x in actual['owners']]==expected['owners']
        for r,o in zip(actual['owners'],expected['owners']):
            assert provider(r['fdinfo'].encode(),o['provider']['mount_record'].encode(),o['descriptor_stat'][1])==o['provider']


def audit(saved, envelope, out):
    raw=Path(envelope['observation']);repo=saved.repo
    summary=saved.json(raw/'summary.json');source=saved.json(raw/'source.json');obs_inputs=saved.json(raw/'inputs.json')
    results=saved.json(raw/'results.json')
    out['recorded_recipe_results']=results
    assert set(results)==set(CASE_NAMES)
    for name in CASE_NAMES:out['cases'][name]['recipe_result']=results[name]
    runtime=saved.json(obs_inputs['runtime_admission']);build=saved.json(obs_inputs['build_admission'])
    assert summary['revision']==source['revision']==build['source_revision']==runtime['source_revision']
    assert re.fullmatch('[0-9a-f]{40}',summary['revision']) and summary['preparation_revision']==PREPARED
    assert summary['planned_stages']==16 and summary['capture_content_audit_required'] is True
    assert summary['full_architectural_equivalence'] is False and summary['rewritten_application_runs']==summary['e9_application_runs']==0 and summary['qualification_complete'] is False
    assert build['authority']=='CALLER_AUTHENTICATED_OBSERVER_BUILD' and build['scope']=='original-common-app-observer-build-only'
    assert runtime['authority']=='CALLER_AUTHENTICATED_ORIGINAL_RUNTIME_OWNERS' and runtime['scope']=='selected-original-interpreter-library-owners-only'
    assert build['source_files_sha256']==sha(encode(source['files']))
    assert build['review_binding'] in envelope['evidence']['build_review']
    for value,pin in obs_inputs['files'].items():
        data=saved.read(value);assert pin==dict(sha256=sha(data),bytes=len(data))
    assert set(source)=={'revision','files','owners'} and set(source['files'])==set(source['owners'])
    for name,row in source['files'].items():
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        data=saved.read(repo/name);owner=saved.seen[str(repo/name)]
        assert row==dict(sha256=sha(data),bytes=len(data),mode=row['mode']) and row['mode'] in ('100644','100755')
        assert bool(owner['stat'][2]&0o111)==(row['mode']=='100755') and owner==source['owners'][name]
    for name,digest in SOURCE_PINS.items():
        assert source['files'][name]['sha256']==digest and sha(saved.read(repo/name))==digest
    assert sha(saved.read(build['driver']))==runtime['observer_sha256']
    build_dir=Path(build['directory']);build_summary=saved.json(build_dir/'summary.json')
    assert build_summary['revision']==source['revision'] and build_summary['completed'] is True and build_summary['failure'] is None
    assert build_summary['observed_stages']==len(build_summary['planned_stages'])==12 and build_summary['cells_complete']==8 and build_summary['unrun_stages']==[]
    assert saved.read(build_dir/'source.json')==saved.read(build_dir/'source-after.json')
    built=saved.json(build_dir/'source.json');assert built['revision']==source['revision'] and built['files']==source['files']
    archives=saved.json(build_dir/'artifacts.json')
    for product,phase,name in ((build['driver'],'native-compile','elf-exec-oracle'),(build['common_sites'],'common-sites-compile','common_sites')):
        selected=archives[phase]['selected'][name]
        assert selected['product']['path']==product and selected['product']['sha256']==sha(saved.read(product))
        assert archives[phase]['source_revision']==source['revision'] and archives[phase]['source_files_sha256']==build['source_files_sha256']
        assert all(source['files'][p]==r for p,r in selected['source_bindings'].items())
        saved.read(selected['depfile']['path'])
    prep=obs_inputs['preparation'];prep_summary=saved.json(prep['summary']);prep_source=saved.json(prep['source'])
    assert saved.read(prep['source'])==saved.read(prep['source_after']) and prep_source['revision']==PREPARED==prep_summary['revision']
    assert prep_summary['completed'] is True and prep_summary['qualified'] is False
    assert (prep_summary['planned_stages'],prep_summary['observed_stages'],prep_summary['ordinary_original_runs'],prep_summary['required_refusals'],prep_summary['rewriting_runs'])==(30,30,16,6,0)
    old={p:h for p,h in prep_source['files'].items() if p.startswith('evaluation/e9-common-app/')};assert len(old)==17
    assert all(source['files'][p]['sha256']==h for p,h in old.items())
    originals={v:saved.read(prep['originals'][v]) for v in VARIANTS}
    assert all(prep_summary['artifacts'][v]==dict(sha256=sha(b),bytes=len(b)) for v,b in originals.items())
    datasets=loads(saved.read(repo/'evaluation/e9-common-app/datasets.json'))['datasets']
    assert [d['name'] for d in datasets]==list(DATASETS) and [d['id'] for d in datasets]==list(range(8))
    for d in datasets:
        assert d['expected']==sorted(d['input']) and len(d['input'])<=64
        assert saved.read(repo/'evaluation/e9-common-app/expected'/ (d['name']+'.stdout'))==d['expected_stdout'].encode()
    cells=saved.json(build_dir/'cells.json');invs=inventories(saved,cells,originals,build['common_sites'])
    layout_path=build_dir/'observer-layout.tsv';lays={v:layout(saved.read(layout_path),elf(b)) for v,b in originals.items()}
    for v in VARIANTS:
        vr=runtime['variants'][v];owners=vr['owners'];assert 2<=len(owners)<=16 and owners[0]['path']==prep['originals'][v]
        assert len({o['path'] for o in owners})==len({tuple(o['descriptor_stat'][:2]) for o in owners})==len(owners)
        assert saved.read(vr['owners_file'])==('LI2COMMONOWNERS\t1\n'+''.join(o['path']+'\n' for o in owners)).encode()
        im=elf(originals[v]);assert im['kind']==2 and vr['interpreter_lookup']['path']==im['interpreter']
        assert vr['interpreter_lookup']['resolved'] in [o['path'] for o in owners[1:]]
        for o in owners:
            b=saved.read(o['path']);assert sha(b)==o['sha256'] and len(b)==o['bytes']
            assert o['descriptor_stat']==o['pathname_stat'] and len(o['descriptor_stat'])==8 and o['descriptor_stat'][3]==len(b)
            assert o['observed_path_hex']==o['path'].encode().hex()
    names=list(CASE_NAMES)
    assert saved.json(raw/'stage-inventory.json')==names and set(results)==set(names)
    out.update(schema=1,status='INCOMPLETE',completed=False,observation_revision=source['revision'],build_revision=build_summary['revision'],preparation_revision=PREPARED,observer_origin_revision=OBSERVER_ORIGIN,recipe_sha256=SOURCE_PINS['evaluation/e9-common-app/observe_originals.py'],observer_source_sha256=SOURCE_PINS['tests/support/e9_common_app.rs'],source_files_sha256=sha(encode(source['files'])),observation_summary_sha256=sha(saved.read(raw/'summary.json')),hardware_sha256=sha(saved.read(raw/'hardware.json')),runtime_admission_sha256=sha(saved.read(obs_inputs['runtime_admission'])),build_admission_sha256=sha(saved.read(obs_inputs['build_admission'])),cases={n:dict(status=results[n]['status'] if results[n]['status'] in ('FAILED','UNRUN') else 'UNCHECKED',recipe_result=results[n]) for n in names},static_inventories={k:dict(directory=str(v['directory']),complete_sha256=v['complete_sha256']) for k,v in invs.items()},source_attested_not_independently_saved=LIVE_ONLY,caller_evidence={k:{p:sha(saved.read(p)) for p in paths} for k,paths in envelope['evidence'].items()},caller_evidence_adjudication='Named records only; caller separately authenticates parent closure, source/build review and this audit execution/review. No authority is synthesized.',full_architectural_equivalence=False,qualification_complete=False)
    first=saved.json(raw/'before.json');snapshot(saved,first,source,runtime)
    extra=set(first['owners'])-set(obs_inputs['files'])
    assert set(obs_inputs['files'])<=set(first['owners']) and len(extra)==1
    assert saved.read(next(iter(extra)))==saved.read(raw/'inputs.json')
    prior=set(first['owners'])|{str(raw/n) for n in ('inputs.json','source.json','before.json','hardware.json','stage-inventory.json')}
    for v in VARIANTS:
        for d in datasets:
            name='observe-'+v+'-'+d['name'];directory=raw/name;record=results[name]
            assert record['name']==name and record['status'] in ('UNRUN','FAILED','PASS_COMMAND_AND_CAPTURE_SCHEMA')
            expected_watch=prior|{str(directory/n) for n in ('request.json','command.json')}
            if record['status']!='UNRUN':
                prior=expected_watch|{str(p) for p in directory.iterdir() if p.is_file()}
                if str(directory/'capture-files.json') in saved.pins:
                    prior|={str(directory/'captures'/n) for n in saved.json(directory/'capture-files.json')}
            if record['status']!='PASS_COMMAND_AND_CAPTURE_SCHEMA':
                out['cases'][name]=dict(status=record['status'],recipe_result=record,content_pass=False)
                key=str(directory/'capture-files.json')
                if key in saved.pins:
                    try:
                        ix=saved.json(key);recorded_index(saved,directory/'captures',ix)
                        out['cases'][name]['partial_capture_index_sha256']=sha(saved.read(key))
                    except ERRORS as error:out['cases'][name]['partial_capture_error']=repr(error)
                continue
            try:
                assert record['strict_closure'] is True and record['exit']==0 and record['reason']==''
                assert saved.json(directory/'result.json')==record and record['receipt_sha256']==sha(saved.read(directory/'receipt.json'))
                jump=invs['null-jump-site-'+v];heap=invs['null-heap-write-'+v]
                req=dict(argv=[build['driver'],'observe-common-app',prep['originals'][v],str(layout_path),str(jump['directory']/'instructions.tsv'),str(jump['directory']/'sites.tsv'),str(heap['directory']/'sites.tsv'),runtime['variants'][v]['owners_file'],d['name'],str(directory/'captures')],cwd=str(repo),env=dict(ENV,TMPDIR=str(directory/'tmp')),cpu_seconds=60,wall_seconds=90,file_bytes=64*1024*1024,stdout=str(directory/'stdout.txt'),stderr=str(directory/'stderr.txt'))
                assert saved.json(directory/'request.json')==req
                tools=obs_inputs['tools'];outer=[tools['timeout'],'--signal=TERM','--kill-after=10s','100s',tools['helper_python'],'-B',str(repo/'tools/unwind-oracle/bounded_command.py'),'--request',str(directory/'request.json'),'--receipt',str(directory/'receipt.json')]
                assert saved.json(directory/'command.json')==dict(request=req,outer_argv=outer,outer_env=ENV,cwd=str(repo),parent_timeout_seconds=115)
                r=strict_receipt(saved,directory,req);oc=saved.json(directory/'outer.json')
                assert set(oc)=={'exit','parent_timeout','operational_seconds'} and type(oc['exit']) is int and oc['exit']==0 and oc['parent_timeout'] is False
                assert type(oc['operational_seconds']) in (int,float) and math.isfinite(oc['operational_seconds']) and oc['operational_seconds']>=0
                terminal=dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True)
                assert saved.read(directory/'helper.stdout')==(json.dumps(terminal)+'\n').encode() and not saved.read(directory/'helper.stderr')
                assert saved.read(directory/'stdout.txt')==f"PASS original common-app dataset={d['name']} complete static inventory and ordered jump/store observations\n".encode() and not saved.read(directory/'stderr.txt')
                before=saved.json(directory/'before.json');after=saved.json(directory/'after.json')
                snapshot(saved,before,source,runtime);snapshot(saved,after,source,runtime)
                assert before['owners']==after['owners'] and set(before['owners'])==expected_watch
                content=audit_case(saved,directory,d,v,elf(originals[v]),lays[v],jump['table'],jump['heads'],runtime,req,prep['originals'])
                schema=saved.json(directory/'capture-schema.json')
                expected={k:content[k] for k in ('static_heads','static_jump_sites','static_heap_sites','steps','events','store_calls','zero_visit_heads')};expected['content_audit_required']=True
                assert schema==expected and content['capture_files']==record['capture_files']
                out['cases'][name]=dict(content,recipe_result=record,receipt_sha256=sha(saved.read(directory/'receipt.json')))
            except ERRORS as error:
                out['cases'][name]=dict(status='CONTENT_MISMATCH',recipe_result=record,error=repr(error),content_pass=False)
    final=saved.json(raw/'after.json');snapshot(saved,final,source,runtime)
    if all(r['status']=='PASS_COMMAND_AND_CAPTURE_SCHEMA' for r in results.values()):assert prior==set(final['owners'])
    else:assert set(first['owners'])<=set(final['owners'])
    good=sum(c['status']=='PASS_SAVED_CONTENT' for c in out['cases'].values())
    assert summary['successful_observations']==sum(r['status']=='PASS_COMMAND_AND_CAPTURE_SCHEMA' for r in results.values())
    assert summary['unrun_stages']==[n for n in names if results[n]['status']=='UNRUN']
    out['successful_content_cases']=good
    out['completed']=good==16 and summary['completed'] is True and summary['selected_owners_unchanged'] is True and summary['fatal'] is None and not summary['unrun_stages']
    out['status']='PASS_SAVED_CONTENT' if out['completed'] else 'INCOMPLETE'
    return out


def main():
    assert not sys.flags.optimize
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--inputs',required=True);ap.add_argument('--inputs-sha256',required=True);ap.add_argument('--raw',required=True)
    args=ap.parse_args();data,owner=read_file(args.inputs)
    assert re.fullmatch('[0-9a-f]{64}',args.inputs_sha256) and sha(data)==args.inputs_sha256
    envelope=loads(data)
    assert set(envelope)=={'schema','repo','observation','files','evidence'} and type(envelope['schema']) is int and envelope['schema']==1
    assert set(envelope['evidence'])=={'source_review','build_review','parent_closure'}
    assert all(type(v) is list and v and len(v)==len(set(v)) for v in envelope['evidence'].values())
    saved=Saved(envelope['files'],envelope['repo']);output=Path(args.raw);observation=Path(envelope['observation'])
    assert output.is_absolute() and '..' not in output.parts and output.parent.resolve(strict=True)==output.parent and not output.exists()
    assert output.is_relative_to(saved.repo/'ignored') and not output.is_relative_to(observation) and not observation.is_relative_to(output)
    output.mkdir(mode=0o700)
    script,script_owner=read_file(str(Path(__file__).resolve()))
    report=dict(schema=1,status='INCOMPLETE',completed=False,cases={n:dict(status='UNCHECKED',recipe_result=None,content_pass=False) for n in CASE_NAMES},qualification_complete=False,full_architectural_equivalence=False,source_attested_not_independently_saved=LIVE_ONLY)
    try:
        # Preserve every recorded mandatory status even if a later global join fails.
        recorded=saved.json(observation/'results.json');report['recorded_recipe_results']=recorded
        for n in CASE_NAMES:
            if n in recorded:
                report['cases'][n]['recipe_result']=recorded[n]
                if type(recorded[n]) is dict and recorded[n].get('status') in ('UNRUN','FAILED'):report['cases'][n]['status']=recorded[n]['status']
        for p in sorted(saved.pins):saved.read(p)
        audit(saved,envelope,report)
    except ERRORS as error:
        report.update(status='INPUT_OR_CONTENT_FAILURE',completed=False,error=repr(error))
    try:
        saved.stable();assert read_file(args.inputs)==(data,owner)
        assert read_file(str(Path(__file__).resolve()))==(script,script_owner)
    except ERRORS as error:
        report.update(status='INPUT_DRIFT',completed=False,drift_error=repr(error))
    def write(name,obj):
        b=(json.dumps(obj,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
        with (output/name).open('xb') as f:f.write(b)
        return sha(b)
    inputs_sha=write('read-inputs.json',dict(request=dict(path=args.inputs,sha256=sha(data),owner=owner),files=saved.seen))
    result_sha=write('audit.json',report)
    binding=dict(schema=1,auditor_sha256=sha(script),auditor_owner=script_owner,inputs_sha256=sha(data),read_inputs_sha256=inputs_sha,audit_sha256=result_sha,status=report['status'],completed=report['completed'],scope='Saved original-observation content only; caller authenticates this invocation/review and separate source/build/parent evidence.',source_attested_not_independently_saved=LIVE_ONLY,qualification_complete=False)
    write('binding.json',binding)
    print(json.dumps(dict(status=report['status'],completed=report['completed'],audit_sha256=result_sha),sort_keys=True))
    if not report['completed']:raise SystemExit(1)


if __name__=='__main__':
    main()
