"""Versioned saved-completion semantics rebuilt from actual saved source.

PF11's old direction rule is reachable only after complete NO_ENVELOPE.
Policy12 uses the independently rebuilt interval/BFS and its exact typed
external arms. No live slot or captured mask supplies historical authority.
"""
import importlib.util
import struct
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
chooser=load('loop_saved_chooser',HERE/'chooser.py')
old=load('loop_old_saved_pf',HERE.parent/'persistent_fused_owner/direct_history.py')
fused=load('loop_bound_saved_pf',HERE/'fused_history.py')
need=old.need


def member_source(check,member):
    header=check.f(member,'pda_member_completion','header')
    check.eq(header,'pe_header',version=2)
    policy=check.i(header,'pe_header','plan_policy')
    need(policy in(11,12),'explicit exact immutable per-certificate policy')
    key=check.f(member,'pda_member_completion','source')
    root=check.i(key,'li2_pg_source_key','entry')
    rows=check.r.items(key,'li2_pg_source_key','page','li2_pg_source_page')
    pages=tuple(check.i(check.f(s,'li2_pg_source_page','identity'),'li2_fetch_page','address')for s in rows)
    source=b''.join(check.f(s,'li2_pg_source_page','bytes')for s in rows)
    chosen=chooser.choose(pages,source,root)
    need(chosen['result']==(0 if policy==12 else 1),
         'historical policy12 selected winner or exact complete PF11 NO_ENVELOPE')
    return policy,key,chosen


def direct_history(check,completion):
    members=check.r.items(completion,'pda_completion','member','pda_member_completion')
    count=check.i(completion,'pda_completion','count')
    need(count in(1,2)and len(members)==2,'complete bounded mixed-policy historical member roster')
    rebuilt=[member_source(check,m)for m in members[:count]]
    e=check.f(completion,'pda_completion','direct_exit')
    need(len(e)==528,'whole historical direct-exit storage')
    if not any(e):return dict(complete=0,member=None,arm=None,pc=None,target=None,raw=e,
                             policies=tuple(p for p,_,_ in rebuilt))
    complete,member,heads,head,exits,index,arm,reserved=struct.unpack_from('<8I',e)
    need(complete==1 and member<count and reserved==0 and 1<=heads<=128 and
         head<heads and 1<=exits<=8 and index<exits and arm<2,
         'bounded whole historical direct identity')
    policy,key,chosen=rebuilt[member]
    if policy==11:
        result=fused.direct_history(check,completion)
        result.update(policy=11,chooser_result=1,policies=tuple(p for p,_,_ in rebuilt))
        return result
    s=chosen['selected'];c=s['choice']
    need(heads==c['heads']and exits==c['exits'],'saved policy12 dimensions equal complete selected graph')
    h=s['head'][head];pc,decoded,kind,flow,successors,k0,k1,mask,_=h
    need(kind==1 and flow in(1,2)and mask and arm<successors and
         (k0,k1)[arm]==128+index and s['exit'][index]==(chosen['nodes'][decoded]['target']if arm==0 else chosen['nodes'][decoded]['next_pc'],head,arm),
         'exact historical policy12 selected external branch arm')
    d=chosen['nodes'][decoded];original=d['bridge'];flags=struct.unpack_from('<Q',e,32)[0]
    need(flags&(0x100|0x10000)==0x10000,'actual historical RF/TF bits are retained literally')
    condition=d['row']['condition'];target=d['target'];next_pc=d['next_pc']
    if flow==2:chosen_arm=0
    else:
        cf=flags&1;pf=(flags>>2)&1;zf=(flags>>6)&1;sf=(flags>>7)&1;of=(flags>>11)&1
        conditions=(of,cf,zf,cf|zf,sf,pf,sf^of,zf|(sf^of))
        chosen_arm=0 if conditions[condition//2]^(condition&1)else 1
    need(arm==chosen_arm,'actual saved flags independently select historical external arm')
    page=next((i for i,p in enumerate(chosen['pages'])if p<=pc<p+4096),None)
    need(page is not None,'saved branch belongs to the actual source pair')
    # Saved layout is immutable member identity already checked by the
    # enclosing completion validator. Source and exact generated PC determine
    # one canonical adapter; a captured length/version cannot choose it.
    header=check.f(members[member],'pda_member_completion','header')
    raw_layout=check.f(header,'pe_header','layout')
    need(len(raw_layout)==48,'whole historical generated layout')
    layout=struct.unpack('<6Q',raw_layout)
    need(all(4096<=x<(1<<47)and x%4096==0 for x in layout),
         'canonical aligned historical generated layout addresses')
    generated=layout[head//64]+512*(head%64)
    prefix=0 if flow==2 else 21 if mask==3 else 11
    delta=pc-(generated+153+prefix+5)
    far=not -(1<<31)<=delta<(1<<31)
    generated_length=206+prefix+9*far
    row=struct.pack('<8I',5,page,pc-chosen['pages'][page],d['length'],successors,k0,k1,generated_length)
    available=struct.unpack_from('<I',original,44)[0]
    targets=(target,next_pc if flow==1 else 0)
    description=original[:72]+struct.pack('<2Q8I',*targets,1,1,0,available,flow,condition,mask,0)
    need(e[40:72]==row and e[72:408]==original and e[408:]==description,
         'every saved typed head/original/direct byte independently rebuilt from complete source chooser')
    return dict(complete=1,policy=12,chooser_result=0,policies=tuple(p for p,_,_ in rebuilt),
        member=member,heads=heads,head=head,exits=exits,index=index,arm=arm,pc=pc,
        target=targets[arm],targets=targets,tokens=(k0,k1)[:successors],external_mask=mask,
        flags=flags,flow=flow,condition=condition,code=d['code'],available=available,
        length=d['length'],generated_length=generated_length,pages=chosen['pages'],
        entry=chosen['entry'],window=original[56:56+available],source_key=key,row=row,
        decoded=original[:72],original=original,description=description,raw=e)
