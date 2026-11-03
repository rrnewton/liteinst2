#!/usr/bin/env python3
"""Bind the distinct two-activation RX observation to its actual image/source."""
import hashlib,json,struct,sys
from pathlib import Path
from resident_generation_binding import configuration,LEAVES as GENERATION_LEAVES
from persistent_group_binding import image_identity,need,fact

LEAVES=tuple({'build-resident-generation.sh':'build-resident-rx.sh',
    'resident_generation_binding.py':'resident_rx_binding.py',
    'resident_generation_observe.inc':'resident_rx_observe.inc'}.get(x,x)
    for x in GENERATION_LEAVES)+('resident_rx.h','resident_rx.inc',
    'resident_generation_binding.py','tests/resident_rx_app/controls.h','resident_rx_replace_control.inc')


def causal_configuration(data):
    """All addresses come from exact LOAD/symbol/byte joins, never caller input."""
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    loads=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)for i in range(h[10])]
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,h[6]+64*i)for i in range(h[12])]
    tables=[x for x in sections if x[1]==2];need(len(tables)==1,'one real symbol table')
    t=tables[0];strings=sections[t[6]];names=data[strings[4]:strings[4]+strings[5]]
    found={};wanted={'rrx_case_id','rrx_mailbox','rrx_attack','rrx_after_attack'}
    for at in range(t[4],t[4]+t[5],24):
        name,info,other,section,address,size=struct.unpack_from('<IBBHQQ',data,at)
        need(name<len(names)and b'\0'in names[name:],'whole bounded causal symbol name')
        name=names[name:names.index(b'\0',name)].decode('ascii')
        if name in wanted:
            need(name not in found and 0<section<len(sections)and not other,
                 'unique defined causal symbol')
            found[name]=(info,address,size,section)
    source=[x for x in loads if x[0]==1 and x[1]==5 and
        x[3]<=0x410000<0x416000<=x[3]+x[5]]
    need(len(source)==1,'whole original six-page file source')
    source_offset=source[0][2]+0x410000-source[0][3]
    need(source_offset%4096==0,'actual page-aligned source file offset')
    if not found:return dict(case=0,mailbox=0,mailbox_bytes=0,attack=0,
        after_attack=0,source_offset=source_offset,symbols={})
    def file_bytes(name,prot,size):
        info,address,actual,section=found[name]
        need(info==(17 if name=='rrx_case_id'else 18)and actual==size,
             'actual causal object/function type and complete size')
        rows=[x for x in loads if x[0]==1 and x[1]==prot and
            x[3]<=address<address+size<=x[3]+x[5]]
        need(len(rows)==1,'whole causal bytes in one exact LOAD')
        at=rows[0][2]+address-rows[0][3]
        return data[at:at+size]
    need('rrx_case_id'in found and 'rrx_mailbox'in found,'complete finite causal interface')
    case=int.from_bytes(file_bytes('rrx_case_id',4,8),'little')
    need(case in range(1,8),'seven exact additive subjects in six risk categories')
    info,mailbox,size,section=found['rrx_mailbox'];s=sections[section]
    need(info==17 and size==80 and s[1]==8 and s[2]&7==3 and
        0x200030000<=mailbox<mailbox+80<=0x200032000 and
        any(x[0]==1 and x[1]==6 and x[3]<=mailbox<mailbox+80<=x[3]+x[6]and
            mailbox>=x[3]+x[5]for x in loads),
        'whole zero-initialized mailbox in original anonymous RW/NX LOAD')
    expected={'rrx_case_id','rrx_mailbox'}
    if case not in(5,7):expected.add('rrx_attack')
    if case==4:expected.add('rrx_after_attack')
    need(set(found)==expected,'all and only actual selected causal symbols')
    attack=found['rrx_attack'][1]if case not in(5,7) else 0
    if case not in(5,7):
        expected_bytes={1:b'\xff\xe7',2:b'\xc6\x07\x5a',3:b'\x0f\x05',
                        4:b'\x0f\x05',6:b'\x8e\xd0'}[case]
        need(file_bytes('rrx_attack',5,len(expected_bytes))==expected_bytes,
             'actual guest attack instruction, never synthetic frame injection')
    after=found['rrx_after_attack'][1]if case==4 else 0
    if case==4:
        need(after==attack+2 and found['rrx_after_attack'][2]==0,
             'actual immediate post-syscall coordinate')
    return dict(case=case,mailbox=mailbox,mailbox_bytes=80,attack=attack,
        after_attack=after,source_offset=source_offset,symbols=found)


def main():
    need(len(sys.argv)==5,'selected directory, actual archive, original image, output')
    selected,archive,image,output=(Path(x).resolve(strict=True)for x in sys.argv[1:])
    need(selected.is_dir()and archive.is_file()and image.is_file()and output.is_dir(),
         'whole real binding inputs')
    need(len(LEAVES)==len(set(LEAVES)),'distinct complete RX source policy')
    values=[]
    for name in LEAVES:
        p=selected/name;need(p.is_file()and not p.is_symlink(),'regular policy source')
        values.append(dict(path=name,**fact(p.read_bytes())))
    data=image.read_bytes();original=image_identity(data)
    resident,geometry=configuration(data);causal=causal_configuration(data)
    mode='release';policy=hashlib.sha256(json.dumps(dict(sources=values,
        original=original,mode=mode),sort_keys=True,separators=(',',':')).encode()).hexdigest()
    actual_archive=fact(archive.read_bytes())
    literal=lambda v:'{'+','.join('0x'+v[i:i+2]for i in range(0,64,2))+'}'
    headers={
        'linked_epoch_config.h':('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n'
            '#define LI2_LINK_BINDING_VERSION 1\n#define LI2_LINK_ARCHIVE_SHA256 '+literal(actual_archive['sha256'])+
            '\n#define LI2_LINK_POLICY_SHA256 '+literal(policy)+'\n#endif\n'),
        'persistent_group_config.h':('#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n'
            '#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION 4\n'
            '#define LI2_PG_ARCHIVE_SHA256 '+literal(actual_archive['sha256'])+
            '\n#define LI2_PG_POLICY_SHA256 '+literal(policy)+'\n#endif\n'),
        'resident_three_config.h':resident,
        'resident_rx_config.h':('#ifndef LI2_RESIDENT_RX_CONFIG_H\n#define LI2_RESIDENT_RX_CONFIG_H\n'+
            ''.join('#define LI2_RRX_'+name.upper()+' '+hex(causal[name])+'ULL\n'
                    for name in('case','mailbox','mailbox_bytes','attack','after_attack','source_offset'))+
            '#endif\n')}
    record=dict(version=1,profile='resident-rx-two-flags-capture-v1',mode=mode,
        archive=actual_archive,policy_sha256=policy,original=original,sources=values,
        native_probe=True,parse_memo=True,unregistered=True,subentry=True,cross_pair=True,
        direct_frontier=True,resident_three=True,sealed_storage=True,source_lease=True,
        flag_stack=True,helper_tf=True,tf_nx_page_boundary=True,stable_generation=True,
        resident_rx=True,rx_capture=True,activations=2,geometry=geometry,causal=causal,
        headers={name:fact(text.encode())for name,text in headers.items()})
    paths=[output/name for name in headers]+[output/'resident_three_binding.json']
    need(not any(x.exists()for x in paths),'fresh exclusive binding outputs')
    for name,text in headers.items():
        with(output/name).open('x')as f:f.write(text)
    with paths[-1].open('x')as f:f.write(json.dumps(record,sort_keys=True)+'\n')

if __name__=='__main__':main()
