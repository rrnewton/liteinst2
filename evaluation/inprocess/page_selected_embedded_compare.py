"""Additive exact alternate-entry checks; no weakened old connected predicate."""
import hashlib
import struct
import page_selected_generic_compare as generic

need=generic.need
PAGE=4096
MAIN=0x401000
DATA=0x600000
LITERAL=0x9090909006eba20f
NAMES=('embedded_cpuid_direct','embedded_cpuid_cross_indirect')


def authenticate(spec,image,observed):
    need(spec['name'] in NAMES,'closed embedded name')
    cross=spec['name']==NAMES[1];pc=MAIN+PAGE-3 if cross else MAIN
    need(spec['entry']==pc and hashlib.sha256(image).hexdigest()==spec['original_sha256'],'bound actual original')
    need(len(image)==5*PAGE and image[:6]==b'\x7fELF\x02\x01','ELF extent/ABI')
    eh=struct.unpack_from('<16sHHIQQQIHHHHHH',image)
    need(eh[1:3]==(2,62) and eh[4]==pc and eh[5]==64 and eh[9]==56 and eh[10]==7,'actual ELF entry/PHDR')
    ph=[struct.unpack_from('<IIQQQQQQ',image,eh[5]+i*eh[9]) for i in range(eh[10])]
    need([p for p in ph if p[0]==1 and p[1]&1]==[(1,5,PAGE,MAIN,MAIN,3*PAGE,3*PAGE,PAGE)],'actual sole main RX extent')
    rows={r['name']:r for r in spec['rows']};need(len(rows)==len(spec['rows']),'unique stream rows')
    for row in rows.values():
        b=bytes.fromhex(row['bytes']);offset=PAGE+row['pc']-MAIN
        need(b and MAIN<=row['pc']<row['pc']+len(b)<=MAIN+3*PAGE and image[offset:offset+len(b)]==b,'actual row source')
    expected={'enclosing_mov':(pc,'49ba0fa2eb0690909090','old'),
              'skip_embedded_ret':(pc+10,'eb01','generic'),'embedded_ret':(pc+12,'c3','generic'),
              'embedded_cpuid':(pc+2,'0fa2','builtin'),'embedded_jump':(pc+4,'eb06','generic')}
    for name,want in expected.items():
        row=rows[name];need((row['pc'],row['bytes'],row['route'])==want,'exact embedded geometry '+name)
    pairs=[]
    values=list(rows.values())
    for i,a in enumerate(values):
        for b in values[i+1:]:
            if max(a['pc'],b['pc'])<min(a['pc']+len(bytes.fromhex(a['bytes'])),b['pc']+len(bytes.fromhex(b['bytes']))):pairs.append(sorted((a['name'],b['name'])))
    want_pairs=sorted([sorted(('enclosing_mov','embedded_cpuid')),sorted(('enclosing_mov','embedded_jump'))])
    need(sorted(pairs)==sorted(spec['embedded']['overlap_pairs'])==want_pairs,'only declared immediate overlaps')
    e=spec['embedded'];need(e['enclosing_pc']==pc and e['selected_pc']==pc+2 and e['ret_pc']==pc+12 and e['setup_pc']==pc+13 and e['literal']==LITERAL and e['selected_hex']=='0fa2' and e['enclosing_hex']==expected['enclosing_mov'][1] and e['selected_crosses_page'] is cross,'declared exact alternate-entry contract')
    call=rows['call_embedded'];b=bytes.fromhex(call['bytes']);c=spec['call']
    need(c['pc']==call['pc'] and c['next_pc']==call['pc']+len(b) and c['target']==pc+2 and c['indirect'] is cross and c['return_word_checked'] is True and c['opcode_hex']==b.hex(),'call association')
    if cross:
        need(b==bytes.fromhex('41ffd3') and bytes.fromhex(rows['indirect_target']['bytes'])==bytes.fromhex('49bb')+struct.pack('<Q',pc+2),'actual R11 indirect target')
        need((pc+2)%PAGE==PAGE-1,'actual crossing CPUID starts at final byte')
    else:need(b[:1]==b'\xe8' and len(b)==5 and c['next_pc']+struct.unpack('<i',b[1:])[0]==pc+2,'actual direct target')
    need(bytes.fromhex(rows['read_actual_call_word']['bytes'])==bytes.fromhex('4c8b5c24f8') and bytes.fromhex(rows['compare_actual_return']['bytes'])==bytes.fromhex('4981fb')+struct.pack('<I',c['next_pc']),'actual return-word comparison')
    for name,address in (('save_enclosing_literal',DATA+32),('store_r10_after',DATA+32)):
        row=rows[name];b=bytes.fromhex(row['bytes'])
        need(b[:3]==bytes.fromhex('4c8915') and len(b)==7 and row['pc']+7+struct.unpack('<i',b[3:])[0]==address,'actual R10 store')
    for name,opcode in (('zf_preserved',b'\x0f\x85'),('cf_preserved',b'\x0f\x82'),('return_word_matches',b'\x0f\x85')):
        branch=rows[name];b=bytes.fromhex(branch['bytes'])
        need(len(b)==6 and b[:2]==opcode and branch['pc']+6+struct.unpack('<i',b[2:])[0]==rows['poison_status']['pc'],'actual poison branch '+name)
    need(rows['poison_status']['bytes']=='bf63000000' and rows['poison_number']['bytes']=='b83c000000' and rows['poison_exit']['bytes']=='0f05','actual failure exit99')
    expected_counts=dict(old=12 if cross else 11,generic=17,builtin=1,syscall=2,main=30 if cross else 29,interpreter=2)
    need(spec['counters']==expected_counts and spec['builtin']==1 and spec['output_words']==5,'literal per-case counters')
    executed=spec['executed'];need(len(executed)==expected_counts['main'] and len(set(executed))==len(executed),'exact successful path extent')
    call_index=executed.index('call_embedded')
    need(executed[:2]==['enclosing_mov','skip_embedded_ret'] and executed[call_index+1:call_index+4]==['embedded_cpuid','embedded_jump','embedded_ret'] and executed[call_index+4]=='zf_preserved','real alternate-entry order')
    need(executed.count('embedded_cpuid')==1 and sum(rows[n]['route']=='builtin' for n in executed)==1,'exactly one requested CPUID')
    need(set(observed)==set(('enclosing_mov','embedded_cpuid','call_embedded','embedded_jump','embedded_ret')),'complete independent decode set')
    for name,d in observed.items():
        row=rows[name];n=len(bytes.fromhex(row['bytes']))
        need(d['pc']==row['pc'] and d['next_pc']==row['pc']+n and d['abi']==1 and d['decode_status']==0 and d['length']==n,'actual independent decode '+name)
        need(d['kind']==(1 if name=='embedded_cpuid' else 0),'actual decoded class '+name)
    need(observed['enclosing_mov']['step_disposition']==1 and observed['embedded_cpuid']['step_disposition']==8,'enclosing ordinary / embedded selected')
    return c['next_pc']


def check(spec,row,command,stdout,native,before,after,decoded,image,observed):
    return_pc=authenticate(spec,image,observed)
    need(len(stdout)==len(native['stdout'])==40,'complete actual ABCD+R10 output')
    need(struct.unpack_from('<Q',stdout,32)[0]==struct.unpack_from('<Q',native['stdout'],32)[0]==LITERAL,'enclosing immediate and unaffected R10')
    # A closed length40 format is authenticated first. Reuse every existing
    # owner/counter/flag/native-hardware predicate on its exact ABCD field.
    baseline=dict(native,stdout=native['stdout'][:32])
    result=generic.check_connected(spec,row,command,stdout[:32],baseline,before,after,decoded)
    need(row['cpuid']==1 and row['rdtsc']==row['rdtscp']==0,'one selected callback, none for enclosing MOV')
    return dict(result,r10=LITERAL,actual_call_return_pc=return_pc,source_patches=0,
                evidence='actual overlapping entries; not explicit-trap or strict-block reference completion')
