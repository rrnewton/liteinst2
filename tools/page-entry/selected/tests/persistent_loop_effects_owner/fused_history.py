"""Independent by-value historical direct-exit validation.

Only bytes in the supplied immutable completion are read. No current slot,
live sibling, production decoder/emitter, or finite-fixture plan is consulted.
"""
import struct
import importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
HERE=Path(__file__).resolve().parent
decoder=load('loop_fused_saved_decoder',HERE/'source_decode12.py')
direct=load('loop_fused_saved_direct',HERE.parent/'persistent_loop_owner/direct_model.py')

PAGE=4096
LIMIT=1<<47
TF=0x100
RF=0x10000
READ_FLAGS=(0x800,1,0x40,0x41,0x80,4,0x880,0x8c0)


def need(value,message):
    if not value:raise ValueError(message)


def unsupported_frontier(rebuilt,head,ordinal):
    """Map only a source-proved ordinary Jcc fallthrough to its original PC."""
    heads,exits=rebuilt['heads'],rebuilt['exits']
    need(0<=head<len(heads),'ordinary frontier belongs to a reconstructed head')
    h=heads[head]
    need(h['kind']==5 and h['flow']==1 and ordinal==1 and
         len(h['successors'])==2 and h['external']==1,
         'only the nondirectional conditional fallthrough may name an unsupported frontier')
    k=h['successors'][ordinal]
    need(128<=k<128+len(exits),'ordinary frontier has an exact bounded exit token')
    f=exits[k-128];target=h['targets'][ordinal]
    need(target==struct.unpack_from('<Q',h['original'],8)[0]and
         f['pc']==target and f['head']is None and f['arm']is None and
         struct.unpack_from('<Q',f['original'])[0]==target and
         struct.unpack_from('<I',f['original'],260)[0]==0 and
         struct.unpack_from('<I',f['original'],264)[0]!=0,
         'complete reconstructed unsupported frontier equals the original fallthrough PC')
    return target


def local_history(check,c):
    """Return normalized facts after validating all 528 saved exit bytes.

    The enclosing completion reader retains its existing source/backing,
    lifetime, member identity, closure and claim checks. This helper adds the
    saved direct-row/descriptor/arm contract without replacing those checks.
    """
    e=check.f(c,'pda_completion','direct_exit')
    need(len(e)==528,'whole historical direct-exit extent')
    complete,member,heads,head,exits,index,arm,reserved=struct.unpack_from('<8I',e)
    if not complete:
        need(not any(e),'incomplete historical direct exit is wholly zero')
        return dict(complete=0,member=None,arm=None,pc=None,target=None,raw=e)
    count=check.i(c,'pda_completion','count')
    need(complete==1 and not reserved and count in(1,2)and member<count and
         1<=heads<=128 and head<heads and 1<=exits<=8 and index<exits and arm<2,
         'bounded complete historical direct-exit identity')
    flags=struct.unpack_from('<Q',e,32)[0]
    need(flags&(TF|RF)==RF,'historical direct exit retains actual RF and cleared TF')
    members=check.r.items(c,'pda_completion','member','pda_member_completion')
    need(len(members)==2,'whole two-member historical completion storage')
    key=check.f(members[member],'pda_member_completion','source')
    entry=check.i(key,'li2_pg_source_key','entry')
    source=check.r.items(key,'li2_pg_source_key','page','li2_pg_source_page')
    need(len(source)==2,'whole historical direct source pair')
    pages=tuple(check.i(check.f(s,'li2_pg_source_page','identity'),'li2_fetch_page','address')for s in source)
    data=tuple(check.f(s,'li2_pg_source_page','bytes')for s in source)
    need(all(PAGE<=p<=LIMIT-PAGE and p%PAGE==0 for p in pages)and pages[0]<pages[1]and
         all(len(b)==PAGE for b in data),'historical direct pair geometry and complete source bytes')
    row=e[40:72]
    kind,page,offset,length,successors,k0,k1,generated_length=struct.unpack('<8I',row)
    need(kind==5 and page<2 and offset<PAGE and 1<=length<=15 and 1<=generated_length<=512,
         'complete historical typed direct head geometry')
    pc=pages[page]+offset
    need((pc==entry)if head==0 else(pc!=entry),'historical direct compiled root versus nonroot head')
    window=bytearray()
    for n in range(15):
        owners=[j for j,p in enumerate(pages)if p<=pc+n<p+PAGE]
        need(len(owners)<=1,'unambiguous historical direct source window')
        if not owners:break
        j=owners[0];window.append(data[j][pc+n-pages[j]])
    available=len(window)
    need(0<available<=15 and length<=available and pc+available<=LIMIT,
         'complete bounded historical direct instruction window')
    raw=bytes(window)
    # iced-x86 1.21 exact64-bit Code IDs: Jcc rel8 161+3*cc,
    # Jcc rel32 1856+3*cc; JMP rel8=701 and rel32=696.
    if raw[0]==0xeb:
        form_length,disp_at,width,flow,condition,code=2,1,1,2,16,701
    elif raw[0]==0xe9:
        form_length,disp_at,width,flow,condition,code=5,1,4,2,16,696
    elif 0x70<=raw[0]<=0x7f:
        condition=raw[0]&15
        form_length,disp_at,width,flow,code=2,1,1,1,161+3*condition
    elif len(raw)>=2 and raw[0]==15 and 0x80<=raw[1]<=0x8f:
        condition=raw[1]&15
        form_length,disp_at,width,flow,code=6,2,4,1,1856+3*condition
    else:raise ValueError('canonical historical direct JMP/Jcc form')
    need(length==form_length and available>=form_length,'exact historical direct instruction length')
    next_pc=pc+length
    delta=int.from_bytes(raw[disp_at:disp_at+width],'little',signed=True)
    target=next_pc+delta
    # li2_dd_span's address() bounds next_pc at 2**47. Signed rel32 adds
    # at most 2**31-1, and its explicit underflow check forbids wrapping
    # below zero. Thus even its upper-canonical alternative is unreachable:
    # target < 2**47+2**31 < 0xffff800000000000. Its canonical-gap refusal
    # leaves exactly this lower-half interval, for every historical source.
    need(0<=target<LIMIT,'nonwrapping canonical historical direct target')
    targets=(target,next_pc if flow==1 else 0)
    arms=2 if flow==1 else 1
    need(successors==arms and arm<arms and (arms==2 or k1==0),
         'historical direct successor and arm dimensions')
    # Version11 reconstructs the cut from actual source bytes and source
    # membership. No current certificate or captured mask is its authority.
    membership=tuple(sum(p<=at<p+PAGE for p in pages)for at in targets[:arms])
    need(all(n<=1 for n in membership),'unambiguous historical PF targets')
    backward=bool(membership[0]and target<=pc)
    external=int(not backward)
    if arms==2 and(backward or not membership[1]):external|=2
    need(external in(1,2,3),'actual historical exit has at least one direction cut')
    tokens=(k0,k1)
    for ordinal,k in enumerate(tokens[:arms]):
        need(k<heads or 128<=k<128+exits,'bounded historical direct successor token')
        if external&(1<<ordinal):need(k>=128,'historical external arm has an exit token')
        elif k>=128:
            rebuilt=graph(pages,b''.join(data),entry);h=rebuilt['heads'][head]if head<len(rebuilt['heads'])else None
            need(len(rebuilt['heads'])==heads and len(rebuilt['exits'])==exits and
                 h is not None and h['kind']==5 and h['pc']==pc and h['flow']==flow and
                 h['external']==external and tuple(h['successors'])==tokens[:arms],
                 'ordinary frontier retains exact full graph dimensions and saved direct head')
            need(unsupported_frontier(rebuilt,head,ordinal)==targets[ordinal],
                 'saved nondirectional frontier is the independently reconstructed branch target')
        else:need(k<heads,'historical internal arm names a generated head')
    need(tokens[arm]==128+index,'historical chosen arm matches exact exit index')
    if external==3:
        # pgd_graph appends exits in one uninterrupted ordinal0/ordinal1
        # loop, including equal-target arms; no other head interleaves.
        need(k1==k0+1,'historical taken/fallthrough exit tokens retain planner order')
    # These bit predicates ignore RF/TF entirely; the saved bits themselves
    # remain checked above and are never rewritten or normalized.
    if flow==2:chosen=0
    else:
        of=(flags>>11)&1;cf=flags&1;zf=(flags>>6)&1;sf=(flags>>7)&1;pf=(flags>>2)&1
        predicates=(of,cf,zf,cf|zf,sf,pf,sf^of,zf|(sf^of))
        taken=predicates[condition//2]^(condition&1);chosen=0 if taken else 1
    need(arm==chosen,'historical direct arm follows restored original condition flags')
    # Fixed-register common adapter206; one external Jcc prepends a6-byte
    # conditional plus a5-byte internal jump; two external arms add21.
    expected_length=206 if flow==2 else 227 if external==3 else 217
    header=check.f(members[member],'pda_member_completion','header')
    need(check.i(header,'pe_header','version')==2 and check.i(header,'pe_header','plan_policy')==11,
         'separate LOOP-domain historical PF header')
    layout=struct.unpack('<6Q',check.f(header,'pe_header','layout'))
    need(all(type(x)is int and PAGE<=x<LIMIT and x%PAGE==0 for x in layout),
         'whole canonical saved LOOP-domain generated geometry')
    generated=layout[head//64]+512*(head%64)
    # The old expected extent is retained verbatim above. Only the source-
    # derived old final-E9 displacement selects the distinct LD2 encoding.
    miss=expected_length-53
    expected_length+=9*int(not -(1<<31)<=pc-generated-miss-5<(1<<31))
    need(generated_length==expected_length,'exact historical direct adapter byte extent')
    decoded=struct.pack('<2Q10I',pc,next_pc,1,0,code,0,16,0,0,available,length,0)+raw+bytes(16-available)
    original=bytearray(336);original[:72]=decoded
    struct.pack_into('<Q',original,72,target)
    struct.pack_into('<Q6I',original,80,target,4,0,64,1,width*8,0)
    struct.pack_into('<9I',original,256,1,1,0,flow,condition,1,0,0,0)
    struct.pack_into('<I',original,292,READ_FLAGS[condition//2]if flow==1 else 0)
    description=decoded+struct.pack('<2Q8I',*targets,1,1,0,available,flow,condition,external,0)
    need(len(decoded)==72 and len(description)==120 and e[72:408]==original,
         'whole independently reconstructed historical direct span descriptor')
    need(e[408:528]==description,'whole independently reconstructed historical typed direct descriptor')
    return dict(complete=1,member=member,heads=heads,head=head,exits=exits,index=index,arm=arm,
        pc=pc,target=targets[arm],targets=targets,tokens=tokens[:arms],external_mask=external,
        flags=flags,flow=flow,condition=condition,code=code,available=available,length=length,
        generated_length=generated_length,pages=pages,entry=entry,window=raw,source_key=key,
        row=row,decoded=decoded,original=bytes(original),description=description,raw=e)


def graph(pages,source,entry):
    """Independent exact policy11 BFS; no captured graph or table is read."""
    need(type(pages)is tuple and len(pages)==2 and pages[0]<pages[1]and
         all(type(p)is int and PAGE<=p<=LIMIT-PAGE and not p%PAGE for p in pages)and
         type(source)is bytes and len(source)==2*PAGE and type(entry)is int,
         'complete immutable historical PF source pair')
    def location(pc):
        rows=[(i,pc-p)for i,p in enumerate(pages)if p<=pc<p+PAGE]
        need(len(rows)<=1,'unique historical source byte owner')
        return rows[0]if rows else None
    def window(pc):
        result=bytearray()
        for at in range(pc,pc+15):
            row=location(at)
            if row is None:break
            i,off=row;result.append(source[i*PAGE+off])
        return bytes(result)
    queue=[];queued=set();heads=[];exits=[];tokens={};occupied=set()
    def enqueue(pc):
        need(location(pc)is not None,'PF ordinary internal successor stays in source pair')
        if pc not in queued:
            need(len(queue)<136,'original PF128-head plus8-frontier queue bound')
            queue.append(pc);queued.add(pc)
    enqueue(entry)
    for pc in queue:
        d=decoder.decode(pc,window(pc));original=d['old']
        need(len(original)==336 and struct.unpack_from('<I',original,256)[0]==1,
             'whole original version1 PF source descriptor')
        for at in range(pc,d['next_pc']):
            need(location(at)is not None and at not in occupied,
                 'historical PF decoded ownership has no hole or interior overlap')
            occupied.add(at)
        ready=struct.unpack_from('<I',original,260)[0]
        kind=1 if ready else 2 if struct.unpack_from('<I',d['mov'],84)[0]else 0
        need(ready in(0,1),'literal original PF readiness')
        if not kind:
            need(pc!=entry and len(exits)<8,'unsupported PF frontier is nonroot and bounded')
            tokens[pc]=128+len(exits);exits.append(dict(pc=pc,original=original,head=None,arm=None))
            continue
        need(len(heads)<128,'original PF128 admitted-head bound')
        flow=struct.unpack_from('<I',original,268)[0]if kind==1 else 0
        need(flow in(0,1,2),'only original PF NONE/MOV/direct source families')
        external=0
        if kind==1 and flow:
            backward=location(d['target'])is not None and d['target']<=pc
            external=int(not backward)
            if flow==1 and(backward or location(d['next_pc'])is None):external|=2
        h=dict(pc=pc,original=original,kind=5 if external else kind,flow=flow,
               external=external,targets=(d['next_pc'],)if not flow else
               (d['target'],d['next_pc'])if flow==1 else(d['target'],),successors=[])
        head=len(heads);tokens[pc]=head;heads.append(h)
        for arm,target in enumerate(h['targets']):
            if external&(1<<arm):
                need(len(exits)<8,'original PF external arm bound')
                h['successors'].append(128+len(exits))
                exits.append(dict(pc=pc,original=original,head=head,arm=arm))
            else:
                h['successors'].append(None);enqueue(target)
    need(heads and exits,'complete PF graph has admitted heads and a real exit')
    for head,h in enumerate(heads):
        if h['flow']:
            for target in h['targets']:
                if target in occupied:
                    matches=sum(row['pc']==target for row in heads)+sum(
                        row['pc']==target and not struct.unpack_from('<I',row['original'],260)[0]
                        for row in exits)
                    need(matches==1,'exact decoded branch target, never an interior byte')
        for arm,target in enumerate(h['targets']):
            if h['successors'][arm]is None:
                need(target in tokens,'all queued historical PF successors resolved')
                token=tokens[target];h['successors'][arm]=token
                if h['kind']==5 and arm==0 or h['kind']==1 and h['flow']==2:
                    need(token<len(heads),'unsupported backward target never becomes an admitted PF edge')
        need(all(k<len(heads)or 128<=k<128+len(exits)for k in h['successors']),
             'all historical PF head and frontier token ranges exact')
    links=[]
    for head,h in enumerate(heads):
        for arm,k in enumerate(h['successors']):
            if k<128 and head//64!=k//64:
                need(len(links)+len(exits)<8,'unchanged combined PF capacity-link and exit bound')
                links.append((head,arm,k))
    need(bool(links)==(len(heads)>64),'exact one/two-image PF partition')
    return dict(heads=heads,exits=exits,links=links)


def direct_history(check,completion):
    domain=dict(version=2,policies=[11,12,13],near_record=1,far_record=2,
        miss='source-derived-rel32-or-rip-indirect-u64',literal_bytes=8,literal_boundaries=0,old_pf_api=False)
    actual=check.image['persistent_binding'].get('encoding_domain')
    need(type(actual)is dict and all(type(actual.get(k))is int for k in
         ('version','near_record','far_record','literal_bytes','literal_boundaries'))and
         type(actual.get('policies'))is list and all(type(x)is int for x in actual['policies'])and
         actual.get('old_pf_api')is False and actual==domain,
         'saved PF far encoding belongs only to the separately authenticated LOOP domain')
    result=local_history(check,completion)
    if not result['complete']:return result
    members=check.r.items(completion,'pda_completion','member','pda_member_completion')
    member=members[result['member']];header=check.f(member,'pda_member_completion','header')
    key=check.f(member,'pda_member_completion','source')
    pages=result['pages'];source=b''.join(check.f(p,'li2_pg_source_page','bytes')for p in
        check.r.items(key,'li2_pg_source_key','page','li2_pg_source_page'))
    rebuilt=graph(pages,source,result['entry']);heads=rebuilt['heads'];exits=rebuilt['exits']
    need(len(heads)==result['heads']and len(exits)==result['exits'],
         'full historical PF BFS dimensions reconstructed from immutable source')
    head,arm,index=result['head'],result['arm'],result['index'];h=heads[head]
    need(h['kind']==5 and h['pc']==result['pc']and h['original']==result['original']and
         tuple(h['successors'])==result['tokens']and h['external']==result['external_mask']and
         h['successors'][arm]==128+index and exits[index]==dict(
             pc=h['pc'],original=h['original'],head=head,arm=arm),
         'exact saved original, true external cut ordinal and complete PF successor row')
    layout=struct.unpack('<6Q',check.f(header,'pe_header','layout'));a,b,stubs,slots,spill,directory=layout
    table=check.i(header,'pe_header','table')
    need(table>=64576+PAGE and table%8==0,'actual saved immutable table/original-row address')
    extents=((pages[0],PAGE),(pages[1],PAGE),(a,32768),(b,32768),
             (stubs,PAGE),(slots,PAGE),(spill,PAGE),(directory,12288),(table,4224))
    need(all(PAGE<=x and x+n<=LIMIT for x,n in extents)and
         all(x+n<=y or y+m<=x for i,(x,n)in enumerate(extents)for y,m in extents[:i]),
         'whole saved source/generated/private extents remain canonical and disjoint')
    internal=[0,0]
    for ordinal,k in enumerate(h['successors']):
        if h['external']&(1<<ordinal):continue
        if k>=128:
            internal[ordinal]=unsupported_frontier(rebuilt,head,ordinal);continue
        need(k<len(heads),'historical internal arm has a real generated head')
        if k//64==head//64:internal[ordinal]=(a,b)[k//64]+512*(k%64)
        else:
            matches=[j for j,row in enumerate(rebuilt['links'])if row==(head,ordinal,k)]
            need(len(matches)==1,'unique reconstructed historical capacity stub')
            internal[ordinal]=stubs+6*matches[0]
    generated=(a,b)[head//64]+512*(head%64)
    binding=struct.pack('<3Q2IQ',table-64576,a,b,len(heads),head,directory)
    model=direct.emit(h['original'],generated,spill,binding,h['external'],tuple(internal),
                      policy=11,encoding_domain=2)
    page=next(i for i,p in enumerate(pages)if p<=h['pc']<p+PAGE)
    row=struct.pack('<8I',5,page,h['pc']-pages[page],result['length'],len(h['successors']),
        h['successors'][0],h['successors'][1]if len(h['successors'])==2 else 0,len(model['image']))
    need(row==result['row']and model['description']==result['description']and
         len(model['image'])==result['generated_length'],
         'whole canonical LOOP-bound PF adapter and immutable saved row reconstructed')
    return result
