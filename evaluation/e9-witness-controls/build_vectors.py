#!/usr/bin/env python3
"""Author fixed expectation data; does not import or call the witness reader."""
from pathlib import Path
import json
import struct

HERE = Path(__file__).resolve().parent
rows = [line.split('\t') for line in (HERE / 'instructions.tsv').read_text().splitlines()]
HEADS = []
for r in rows[1:]:
    HEADS.append(dict(id=int(r[0]), pc=int(r[1],16), length=int(r[2]), file_offset=int(r[3]),
                      function=r[4], code=r[5], mnemonic=r[6], flow=r[7],
                      target=None if r[8]=='none' else int(r[8],16), jump=r[11]=='true', heap=r[12]=='true'))
assert len(HEADS) == 87
BY_PC = {h['pc']:h for h in HEADS}
F = json.loads((HERE/'FIXTURES.json').read_text())
V = []

def add(name, category, action, expected, **inputs):
    V.append(dict(name=name, category=category, action=action, inputs=inputs, expected=expected))

def edge(pc,to,code):
    return dict(pc=pc,next=to,bytes=code)

def e9(pc,to,prefix=''):
    return prefix + 'e9' + struct.pack('<i',to-pc-len(bytes.fromhex(prefix))-5).hex()

def eb(pc,to):
    return 'eb' + struct.pack('<b',to-pc-2).hex()

def seg(pc,raw):
    return [pc,raw]

def record(h, body=None, parts=None, prefix=(), continuation=None, reason=None):
    r = {k:v for k,v in h.items() if k!='code'}
    r.update(original_bytes=h['code'],status='REQUIRED_UNRESOLVED' if reason else 'BYTE_WITNESS_COMPLETE',
             prefix=list(prefix),body=body,operation=[] if parts is None else parts,
             continuation=continuation,reason=reason)
    return r

def case_record(case, h, operation, physical, logical, prefix=(), fault=False):
    state=case%2
    r=dict(case=case,head_id=h['id'],state=state,seed=[0x1234567887654320,0xfedcba9801234567][state],
           rflags=[0x202,0xad7][state],fault=fault,status='BYTE_WITNESS_COMPLETE',prefix=list(prefix),
           operation=operation,required=True)
    if fault:
        r['completion']=dict(kind='fault',physical_pc=physical,logical_pc=logical,signal=11,code=2,
                             address=[0x600000000008,0x600000000018][state])
    else:
        r['completion']=dict(kind='original-boundary',physical_pc=physical,logical_pc=logical,
                             call_return_word=h['pc']+h['length'] if h['flow']=='Call' else None)
    return r

# This independent fixed truth table is not read from the reader.
TAKEN = {'Jb':(False,True),'Jae':(True,False),'Jbe':(False,True),'Jne':(True,False)}
DIRECT = [record(h,h['pc'],[dict(pc=h['pc'],bytes=h['code'])]) for h in HEADS]
DIRECT_CASES=[]
for h in HEADS:
    for state in (0,1):
        fall=h['pc']+h['length']
        dest=(h['target'] if h['flow'] in ('Call','UnconditionalBranch') else
              0x401878 if h['flow']=='Return' else
              h['target'] if TAKEN.get(h['mnemonic'],(False,False))[state] else fall)
        DIRECT_CASES.append(case_record(2*(h['id']-1)+state,h,[edge(h['pc'],dest,h['code'])],dest,dest))
for n in (174,175):
    h=HEADS[0]
    DIRECT_CASES.append(case_record(n,h,[edge(h['pc'],h['pc'],h['code'])],h['pc'],h['pc'],fault=True))
add('direct-all-87-heads','positive-direct','direct-heads','DIRECT_HEADS')
add('direct-all-176-case-records','positive-direct','cases','DIRECT_CASES')

RELOC={}
for f in F['operations']:
    h=BY_PC[f['original_pc']]; b=f['body_pc']; raw=''.join(f['operation_hex']); end=f['operation_end']
    assert h['code']==f['original_hex'] and h['target']==f['original_target']
    assert end==b+len(bytes.fromhex(raw)) and f['original_next']==h['pc']+h['length']
    parts=[]; at=b
    for code in f['operation_hex']:
        parts.append(dict(pc=at,bytes=code)); at+=len(bytes.fromhex(code))
    gateway=e9(h['pc'],b); prefix=[edge(h['pc'],b,gateway)]
    cont=dict(pc=end,next=f['original_next'],bytes=f['ordinary_continue_hex'],
              logical_fallthrough=f['original_next'],bypass_steps=[],executed_for_completion=False)
    expected=record(h,b,parts,prefix,cont)
    inp=dict(head_id=h['id'],segments=[seg(h['pc'],gateway),seg(b,raw+f['ordinary_continue_hex'])],
             trampoline=[[b,end+5]],outcome=dict(tactic='synthetic-null',low=b,high=end+5),bypass=[])
    RELOC[f['name']]=(f,h,expected,inp)
    add('operation-direct-'+f['name'],'positive-copy','operation',[h['code']],head_id=h['id'],body=h['pc'])
    add('operation-relocated-'+f['name'],'positive-copy','operation',f['operation_hex'],head_id=h['id'],body=b)
    add('derive-relocated-'+f['name'],'positive-copy','derive',expected,**inp)
    overrides={}
    for state in (0,1):
        taken=TAKEN.get(h['mnemonic'],(False,False))[state]
        branch=taken or h['flow'] in ('Call','UnconditionalBranch','Return')
        dest=(h['target'] if taken or h['flow'] in ('Call','UnconditionalBranch') else
              0x401878 if h['flow']=='Return' else h['pc']+h['length'])
        physical=dest if branch else end
        steps=[edge(p['pc'],parts[i+1]['pc'] if i+1<len(parts) else physical,p['bytes']) for i,p in enumerate(parts)]
        n=2*(h['id']-1)+state
        overrides[str(n)]=case_record(n,h,steps,physical,dest,prefix)
    if f['name']=='copied-store':
        for n in (174,175):
            overrides[str(n)]=case_record(n,h,[edge(b,b,f['operation_hex'][0])],b,h['pc'],prefix,fault=True)
    add('case-completions-'+f['name'],'fault-preservation' if f['name']=='copied-store' else 'positive-copy',
        'cases',dict(overrides=overrides),head_override=expected)

f,h,base,inp=RELOC['copied-store']; body=f['body_pc']; end=f['operation_end']
# All accepted prefix spellings are fixed by the predecessor fixture list.
for prefix in F['gateway_prefixes_hex']:
    code=e9(h['pc'],body,prefix); walk=[edge(h['pc'],body,code)]
    add('jump-prefix-'+(prefix or 'none'),'positive-prefixes','jump',[code,body],
        segments=[seg(h['pc'],code)],pc=h['pc'])
    p=dict(inp,segments=[seg(h['pc'],code),inp['segments'][1]])
    r=dict(base,prefix=walk)
    add('derive-prefix-'+(prefix or 'none'),'positive-prefixes','derive',r,**p)
short_at=0x80000;short_to=short_at+100;short=eb(short_at,short_to)
add('jump-short-eb','positive-prefixes','jump',[short,short_to],segments=[seg(short_at,short)],pc=short_at)
relay=h['pc']+0x40
relay_code=eb(h['pc'],relay);relay_end=e9(relay,body)
walk=[edge(h['pc'],relay,relay_code),edge(relay,body,relay_end)]
add('derive-eb-relay-e9','positive-prefixes','derive',dict(base,prefix=walk),
    **dict(inp,segments=[seg(h['pc'],relay_code),seg(relay,relay_end),inp['segments'][1]]))
for bad in ('26','3648','48263e','4848'):
    code=e9(short_at,short_to,bad)
    add('reject-unsupported-prefix-'+bad,'positive-prefixes','jump',None,segments=[seg(short_at,code)],pc=short_at)
for name,code in [('short','eb'),('near','e9000000'),('prefix','4826363ee900')]:
    add('reject-truncated-jump-'+name,'wrong-gateway','jump',None,segments=[seg(short_at,code)],pc=short_at)

for count in (32,33):
    nodes=[h['pc']]+[0x500000+16*i for i in range(count-1)]+[body]
    chain=[edge(a,b,e9(a,b)) for a,b in zip(nodes,nodes[1:])]
    segments=[seg(p['pc'],p['bytes']) for p in chain]
    add('route-'+str(count)+'-edges','gateway-cycle','route',chain if count==32 else None,
        segments=segments,start=h['pc'],target=body)
    expected=dict(base,prefix=chain) if count==32 else record(h,prefix=chain[:32],reason='fixed_prefix_bound')
    add('derive-'+str(count)+'-edges','gateway-cycle','derive',expected,
        **dict(inp,segments=segments+[inp['segments'][1]]))
for name,nodes in [('self',[h['pc'],h['pc']]),('two',[h['pc'],0x500000,h['pc']])]:
    chain=[edge(a,b,e9(a,b)) for a,b in zip(nodes,nodes[1:])]
    segments=[seg(p['pc'],p['bytes']) for p in chain]
    add('route-'+name+'-cycle','gateway-cycle','route',None,segments=segments,start=h['pc'],target=body)
    add('derive-'+name+'-cycle','gateway-cycle','derive',record(h,prefix=chain,reason='gateway_cycle'),
        **dict(inp,segments=segments+[inp['segments'][1]]))
add('route-empty','positive-prefixes','route',[],segments=[],start=body,target=body)
add('derive-wrong-gateway-destination','wrong-gateway','derive',
    record(h,prefix=[edge(h['pc'],body+128,e9(h['pc'],body+128))],reason='unsupported_actual_instruction_shape'),
    **dict(inp,segments=[seg(h['pc'],e9(h['pc'],body+128)),inp['segments'][1]]))
add('derive-body-without-trampoline-owner','mapping-owner','derive',
    record(h,prefix=base['prefix'],reason='unsupported_actual_instruction_shape'),**dict(inp,trampoline=[]))
add('derive-refused-selected-site','refused-site','derive',record(h,reason='selected_site_refused'),
    **dict(inp,outcome=dict(tactic=None,low=body,high=end+5)))
add('derive-wrong-selected-entry','refused-site','derive',
    record(h,prefix=base['prefix'],reason='selected_body_differs_from_actual_trampoline_entry'),
    **dict(inp,outcome=dict(tactic='synthetic-null',low=body+1,high=end+5)))
add('derive-wrong-selected-extent','refused-site','derive',
    record(h,prefix=base['prefix'],reason='selected_extent_not_exact_null_template'),
    **dict(inp,outcome=dict(tactic='synthetic-null',low=body,high=end+6)))
# Continuation is authenticated but must never be counted as this operation.
for name,raw,reason in [('opcode','90'+f['ordinary_continue_hex'][2:],'missing_exact_continue'),
                        ('missing','','missing_exact_continue'),
                        ('unowned-target',e9(end,h['pc']+h['length']+64),'unowned_continue_bypass')]:
    add('derive-continuation-'+name,'wrong-continuation','derive',record(h,prefix=base['prefix'],reason=reason),
        **dict(inp,segments=[inp['segments'][0],seg(body,f['operation_hex'][0]+raw)]))
logical=h['pc']+h['length']; to=logical+0x70
bypass_code=eb(logical,to); cont_code=e9(end,to)
walk=[edge(h['pc'],body,eb(h['pc'],h['pc']+0x40)),edge(h['pc']+0x40,body,e9(h['pc']+0x40,body))]
# Short source gateway avoids overlapping the independently declared fallthrough route.
walk[0]['next']=h['pc']+0x40
segments=[seg(walk[0]['pc'],walk[0]['bytes']),seg(walk[1]['pc'],walk[1]['bytes']),
          seg(body,f['operation_hex'][0]+cont_code),seg(logical,bypass_code)]
bypass_edge=edge(logical,to,bypass_code)
cont=dict(pc=end,next=to,bytes=cont_code,logical_fallthrough=logical,bypass_steps=[bypass_edge],executed_for_completion=False)
expected=record(h,body,base['operation'],walk,cont)
add('derive-owned-continue-bypass','positive-bypass','derive',expected,
    **dict(inp,segments=segments,bypass=[[logical,to]]))
add('derive-missing-bypass-record','wrong-continuation','derive',
    record(h,prefix=walk,reason='unowned_continue_bypass'),**dict(inp,segments=segments))
add('derive-bypass-record-without-route','wrong-continuation','derive',
    record(h,prefix=walk,reason='unowned_continue_bypass'),
    **dict(inp,segments=segments[:-1],bypass=[[logical,to]]))
# Same literal nine-fixture operation records; one byte corruption per refusal.
for fixture,name,category,mutate in [
    ('call','return-immediate','wrong-call-word',lambda b: b[:1]+bytes([b[1]^1])+b[2:]),
    ('call','relocated-e8','wrong-call-word',lambda b:bytes.fromhex('e83bb83e00')+b[5:]),
    ('call','callee','wrong-call-callee',lambda b:b[:6]+bytes([b[6]^1])+b[7:]),
    ('jb','condition','wrong-condition',lambda b:b[:1]+b'\x83'+b[2:]),
    ('jb','target','wrong-condition',lambda b:b[:2]+bytes([b[2]^1])+b[3:]),
]:
    ff,hh,rr,ii=RELOC[fixture]
    raw=mutate(bytes.fromhex(''.join(ff['operation_hex'])))
    add('derive-wrong-'+name,category,'derive',record(hh,prefix=rr['prefix'],reason='unsupported_actual_instruction_shape'),
        **dict(ii,segments=[ii['segments'][0],seg(ff['body_pc'],raw.hex()+ff['ordinary_continue_hex'])]))
# rel32 range refusal is distinct from an arbitrary target exemption.
call=RELOC['call'][1];jb=RELOC['jb'][1];jmp=RELOC['jump'][1]
for name,hh in [('call',call),('jcc',jb),('jmp',jmp)]:
    add('operation-out-of-rel32-'+name,'wrong-gateway','operation',None,head_id=hh['id'],body=1<<40)

fields=[('os','linux'),('isa','x86-64-legacy-evex'),('cet','unqualified'),('page_bytes','4096'),
        ('bias_domain','1'),('format','xsave64-standard'),('allocation_bytes','2496'),('image_bytes','2440'),
        ('xcr0_mask','743'),('qualification_complete','false')]
components=[[4,576,256],[32,832,64],[64,896,512],[128,1408,1024],[512,2432,8]]
full='LI2TARGET\t1\n'+''.join(k+'\t'+v+'\n' for k,v in fields)+''.join('component\t'+'\t'.join(map(str,r))+'\n' for r in components)
compact='target xsave64 743 4:576:256 32:832:64 64:896:512 128:1408:1024 512:2432:8'
add('target-exact-xsave','bad-target','target',dict(fields=dict(fields),components=components,compact=compact),full=full,selection=compact+'\n')
fxfields=dict(fields,format='fxsave64',allocation_bytes='512',image_bytes='512',xcr0_mask='3')
fx='LI2TARGET\t1\n'+''.join(k+'\t'+v+'\n' for k,v in fxfields.items())
add('target-exact-fxsave','bad-target','target',dict(fields=fxfields,components=[],compact='target fxsave64'),full=fx,selection='target fxsave64\n')
for name,bad_full,bad_compact in [
    ('component-size',full.replace('512\t2432\t8','512\t2432\t7'),compact+'\n'),
    ('missing-mask-bit',full.replace('xcr0_mask\t743','xcr0_mask\t231'),compact+'\n'),
    ('missing-component',full.replace('component\t512\t2432\t8\n',''),compact+'\n'),
    ('duplicate-component',full+'component\t512\t2432\t8\n',compact+'\n'),
    ('compact-mismatch',full,compact.replace('743','231')+'\n'),
    ('duplicate-compact',full,compact+'\n'+compact+'\n'),
]:
    add('target-refuse-'+name,'bad-target','target',{'raises':'AssertionError'},full=bad_full,selection=bad_compact)

assert len({x['name'] for x in V})==len(V)
result=dict(schema=1,status='UNEXECUTED_FIXED_SYNTHETIC_EXPECTATIONS',heads=HEADS,direct_heads=DIRECT,
            direct_cases=DIRECT_CASES,controls=V)
(HERE/'vectors.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print('Source-data generation only:',len(V),'controls;',len(HEADS),'heads;',len(DIRECT_CASES),'case records')
