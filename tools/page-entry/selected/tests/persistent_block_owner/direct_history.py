"""Independent by-value historical direct-exit validation.

Only bytes in the supplied immutable completion are read. No current slot,
live sibling, production decoder/emitter, or finite-fixture plan is consulted.
"""
import struct

PAGE=4096
LIMIT=1<<47
TF=0x100
RF=0x10000
READ_FLAGS=(0x800,1,0x40,0x41,0x80,4,0x880,0x8c0)


def need(value,message):
    if not value:raise ValueError(message)


def direct_history(check,c):
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
    # This distinct version10 policy sends every arm through the directory;
    # logical in-pair membership grants no internal generated destination.
    for at in targets[:arms]:
        need(sum(p<=at<p+PAGE for p in pages)<=1,'unambiguous historical PB target')
    external=(1<<arms)-1
    need(head+1==heads and exits==arms and index==arm and
         k0==128 and (k1==129 if arms==2 else k1==0),
         'exact final-head all-arms PB exit order')
    tokens=(k0,k1)
    for ordinal,k in enumerate(tokens[:arms]):
        need(k<heads or 128<=k<128+exits,'bounded historical direct successor token')
        if external&(1<<ordinal):need(k>=128,'historical external arm has an exit token')
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
