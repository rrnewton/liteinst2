#!/usr/bin/env python3
"""Bind a finite three-resident direct graph to its complete actual ELF and source policy."""
import hashlib
import json
from pathlib import Path
import sys
import struct

from persistent_direct_frontier_binding import LEAVES as DIRECT_LEAVES
from persistent_group_binding import image_identity, need, fact

LEAVES = tuple({'build-persistent-direct-frontier.sh':'build-resident-three-flags.sh',
                'persistent_direct_frontier_binding.py':'resident_three_flags_binding.py'}.get(n,n)
               for n in DIRECT_LEAVES) + (
    'sealed_generation.h','sealed_generation.inc','private_code_query.h','private_code_query.inc',
    'resident_source_lease.h','resident_source_lease.inc','resident_source_owner.inc','resident_source_resident.inc',
    'resident_three_owner.h','resident_three_owner.inc','resident_three_storage.inc',
    'resident_three_controller.inc','resident_three_rseq.inc','readonly_query.h','native_policy.c',
    'resident_three_observe.h','resident_three_observe.inc','resident_three_memory.h','resident_three_memory.inc',
    'maps_view.inc','tf_chain.inc') + ('flag_stack.h', 'flag_stack.c', 'flag_stack_storage.h', 'flag_stack_query.inc', 'flag_stack_owner.inc', 'helper_tf.h', 'helper_tf.c', 'tf_owner.inc', 'tf_entry_route.inc', 'rseq_guard.h', 'entry.S')


def configuration(data):
    def take(at,count):
        need(type(at) is int and type(count) is int and 0 <= at <= len(data) and
             0 <= count <= len(data)-at,'whole actual fixture ELF range')
        return data[at:at+count]
    h=struct.unpack('<16sHHIQQQIHHHHHH',take(0,64))
    need(h[0][:7]==b'\x7fELF\2\1\1' and h[1:4]==(2,62,1) and h[8:10]==(64,56) and
         0<h[10]<=32 and h[11]==64 and 0<h[12]<=256,'bounded ET_EXEC x86-64 fixture')
    loads=[struct.unpack('<IIQQQQQQ',take(h[5]+56*i,56)) for i in range(h[10])]
    sections=[struct.unpack('<IIQQQQIIQQ',take(h[6]+64*i,64)) for i in range(h[12])]
    tables=[x for x in sections if x[1]==2]
    need(len(tables)==1,'one complete actual fixture symbol table')
    t=tables[0];need(t[9]==24 and t[5]%24==0 and 0<t[6]<len(sections),'whole symbols and string index')
    ns=sections[t[6]];need(ns[1]==3,'actual symbol names');names=take(ns[4],ns[5]);symbols={};capture={}
    expected={'region_app_page':(0x410000,0),'region_app_source_end':(0x416000,0),
        'region_app_predecessor':(0x4101fe,0),'region_app_head':(0x410200,9),
        'region_app_block_b':(0x412200,9),'region_app_block_c':(0x414200,17),
        'region_app_terminal':(0x41420e,0)}
    for off in range(t[4],t[4]+t[5],24):
        name,info,other,section,address,size=struct.unpack('<IBBHQQ',take(off,24))
        need(name<len(names) and b'\0' in names[name:],'bounded complete symbol name')
        name=names[name:names.index(b'\0',name)].decode('ascii')
        if name in ('region_app_capture_high','region_app_capture_pointer'):
            need(name not in capture and 0<section<len(sections) and other==0,
                 'unique defined actual capture symbol')
            s=sections[section]
            if name=='region_app_capture_high':
                need(info==18 and 0<size<4096 and 0x200021000<=address<address+size<=0x200022000 and
                     s[1]==1 and s[2]&7==6 and s[3]<=address and address+size<=s[3]+s[5],
                     'actual bounded capture function in the fixed high machine page')
            else:
                need(info==16 and size==0 and 0x200010000<=address<=0x200011000-8 and
                     s[1]==1 and s[2]&7==2 and s[3]<=address and address+8<=s[3]+s[5],
                     'actual constant capture pointer in the fixed readonly page')
            capture[name]=(address,size)
        if name in expected:
            need(name not in symbols and 0<section<len(sections) and other==0 and
                 (info==18 if expected[name][1] else info==16),'one actual global defined fixture symbol')
            s=sections[section]
            need(s[1]==1 and s[2]&7==6 and s[3]<=address<=s[3]+s[5] and
                 (address,size)==expected[name],'exact fixture symbol body and executable section')
            symbols[name]=(address,size)
    need(symbols==expected,'complete independently specified three-region symbol geometry')
    rows=[x for x in loads if x[0]==1 and x[1]==5 and x[5]<=x[6] and
          x[3]<=0x410000 and 0x416000<=x[3]+x[5]]
    need(len(rows)==1,'entire six-page source belongs to one actual file-backed RX LOAD')
    row=rows[0];source=take(row[2]+0x410000-row[3],6*4096)
    expected_source=bytearray([0xcc])*(6*4096)
    expected_source[0x1fe:0x200]=b'\xff\xe3'
    for at,add,target in ((0x200,1,0x2200),(0x2200,2,0x4200)):
        expected_source[at:at+9]=b'\x48\x83\xc0'+bytes([add])+b'\xe9'+struct.pack('<i',target-at-9)
    expected_source[0x4200:0x4211]=(b'\x48\x83\xc0\x04\x48\x83\xe9\x01\x0f\x85'+
        struct.pack('<i',0x200-0x420e)+b'\x41\xff\x23')
    need(source==bytes(expected_source),'complete six source pages including every guard/padding byte')
    need(set(capture)=={'region_app_capture_high','region_app_capture_pointer'},
         'both complete actual continuation symbols')
    endpoint=capture['region_app_capture_high'][0];pointer=capture['region_app_capture_pointer'][0]
    capture_loads=[x for x in loads if x[0]==1 and x[1]==5 and x[5]<=x[6] and
                   x[3]<=endpoint<endpoint+capture['region_app_capture_high'][1]<=x[3]+x[5]]
    pointer_loads=[x for x in loads if x[0]==1 and x[1]==4 and x[5]<=x[6] and
                   x[3]<=pointer<pointer+8<=x[3]+x[5]]
    need(len(capture_loads)==len(pointer_loads)==1,'whole capture function and readonly pointer LOADs')
    pr=pointer_loads[0]
    need(take(pr[2]+pointer-pr[3],8)==struct.pack('<Q',endpoint),'actual literal continuation target')
    root=symbols['region_app_head'][0]
    text=('#ifndef LI2_RESIDENT_THREE_CONFIG_H\n#define LI2_RESIDENT_THREE_CONFIG_H\n'
          '#define LI2_R3_CONFIG_VERSION 1\n#define LI2_R3_ROOT_RVA 0x'+format(root,'x')+'ULL\n'
          '#define LI2_R3_TERMINAL_RVA 0x41420eULL\n'
          '#define LI2_R3_CAPTURE_RVA 0x'+format(endpoint,'x')+'ULL\n'
          '#define LI2_R3_CAPTURE_POINTER_RVA 0x'+format(pointer,'x')+'ULL\n#endif\n')
    return text,dict(root=root,roots=[root,0x412200,0x414200],source=fact(source),symbols=symbols,capture_symbols=capture)


def main():
    need(len(sys.argv) == 5,
         'selected directory, actual archive, original image, output directory')
    selected, archive, image, output = (Path(x).resolve(strict=True) for x in sys.argv[1:])
    mode = 'release'
    need(selected.is_dir() and archive.is_file() and image.is_file() and output.is_dir(),
         'actual active-domain binding inputs')
    leaves = LEAVES
    need(len(leaves)==len(set(leaves)), 'distinct complete three-resident source policy')
    values = []
    for name in leaves:
        path = selected / name
        need(not path.is_symlink() and path.is_file(), 'regular active-domain policy source')
        values.append(dict(path=name, **fact(path.read_bytes())))
    data = image.read_bytes()
    original = image_identity(data)
    resident, geometry = configuration(data)
    policy = hashlib.sha256(json.dumps(dict(sources=values, original=original, mode=mode),
                          sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    actual_archive = fact(archive.read_bytes())
    literal = lambda value: '{' + ','.join('0x' + value[i:i+2] for i in range(0, 64, 2)) + '}'
    linked = ('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n'
              '#define LI2_LINK_BINDING_VERSION 1\n'
              '#define LI2_LINK_ARCHIVE_SHA256 ' + literal(actual_archive['sha256']) + '\n'
              '#define LI2_LINK_POLICY_SHA256 ' + literal(policy) + '\n#endif\n')
    persistent = ('#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n'
                  '#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION 4\n'
                  '#define LI2_PG_ARCHIVE_SHA256 ' + literal(actual_archive['sha256']) + '\n'
                  '#define LI2_PG_POLICY_SHA256 ' + literal(policy) + '\n#endif\n')
    headers = {'linked_epoch_config.h': linked, 'persistent_group_config.h': persistent,
               'resident_three_config.h': resident}
    record = dict(version=1, profile='resident-three-direct-flags-capture-v1', mode=mode, native_probe=True, parse_memo=True, unregistered=True, subentry=True, cross_pair=True, direct_frontier=True,
                  archive=actual_archive, policy_sha256=policy, original=original, sources=values,
                  resident_three=True, sealed_storage=True, source_lease=True, flag_stack=True, helper_tf=True, geometry=geometry,
                  headers={name: fact(text.encode()) for name, text in headers.items()})
    paths = [output / name for name in headers] + [output / 'resident_three_binding.json']
    need(not any(path.exists() for path in paths), 'fresh exclusive active-domain outputs')
    for name, text in headers.items():
        with (output / name).open('x') as stream:
            stream.write(text)
    with paths[-1].open('x') as stream:
        stream.write(json.dumps(record, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
