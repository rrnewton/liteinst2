"""Independent same-pair A12/B11/C12 compact graphs and emitted bytes.

Literal fixture source/edges select the expected graphs. A complete independent
chooser rebuild must agree (including A's rejected B-prefix candidate and B's
NO_ENVELOPE); neither caller policy nor captured masks choose authority. This
value model grants no ownership, entry, lifetime or performance credit.
"""
import importlib.util
import struct
from pathlib import Path

def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
old=load('lifecycle_literal_scalar_primitives',HERE.parent/'persistent_direct_frontier_owner/plan.py')
chooser=load('lifecycle_independent_chooser',HERE.parent/'persistent_loop_owner/chooser.py')
direct=load('lifecycle_independent_direct',HERE.parent/'persistent_loop_owner/direct_model.py')
need,table,reg,imm,ins,descriptor=old.need,old.table,old.reg,old.imm,old.ins,old.descriptor
A,B,D,C,END=512,256,531,535,541
A_BODY=bytes.fromhex('4883e9014883f9020f84f2feffff4885c975ed66894f084983ea0175fa')
B_BODY=bytes.fromhex('4c890f4983e9014c89c9e9f1000000')


def source_image(page,endpoint):
    need(type(page)is int and page in(0x4000000,0x700000000000)and
         type(endpoint)is int and 4096<=endpoint<(1<<47),'literal low/high source and actual ELF endpoint')
    out=bytearray(b'\xcc'*8192)
    out[A:A+29]=A_BODY;out[B:B+15]=B_BODY
    for at in(A-5,B-5):out[at:at+5]=b'\xe9'+bytes(4)
    out[END:END+14]=b'\xff\x25'+bytes(4)+struct.pack('<Q',endpoint)
    return bytes(out)


def descriptions(page,offset):
    ar=(0,0x8d5,0,0,0);test=(0,0xc4,0,0x801,0x10)
    branch=lambda raw,code,condition,target:ins(raw,code,((page+target,4,0,64,1,32 if len(bytes.fromhex(raw))>2 else 8,0),),
        (0 if condition==16 else 0x40,0,0,0,0),flow=2 if condition==16 else 1,target=page+target,condition=condition)
    if offset==A:
        rows=(ins('4883e901',264,(reg(1,64,3),imm(1,64,8)),ar),
              ins('4883f902',270,(reg(1,64,1),imm(2,64,8)),ar),
              branch('0f84f2feffff',1868,4,B),
              ins('4885c9',274,(reg(1,64,1),reg(1,64,1)),test),
              branch('75ed',176,5,A))
        return (512,516,520,526,529),rows,((1,),(2,),(128,3),(4,),(0,129)),((2,0,B),(4,1,D)),None
    if offset==B:
        rows=(ins('4c890f',282),ins('4983e901',264,(reg(9,64,3),imm(1,64,8)),ar),
              ins('4c89c9',282,(reg(1,64,2),reg(9,64,1)),step=1),
              branch('e9f1000000',696,16,A))
        return (256,259,263,266),rows,((1,),(2,),(3,),(128,)),((3,0,A),),0
    need(offset==C,'only the genuine A/B/C source roots')
    rows=(ins('4983ea01',264,(reg(10,64,3),imm(1,64,8)),ar),branch('75fa',176,5,C))
    return (535,539),rows,((1,),(0,128)),((1,1,END),),None


def choice_check(source,page,entry,offsets,successors,cuts,originals,policy):
    w=chooser.choose((page,page+4096),source,entry);offset=entry-page
    expected_policy=11 if offset==B else 12
    need(type(policy)is int and policy==expected_policy,'policy follows complete source-root semantics, not caller selection')
    if offset==B:
        need(w['result']==1 and not w['ready']and not w['eligible']and not w['candidates']and
             w['selected']is None and w['stop']==3 and w['stop_pc']==page+266 and
             tuple(n['pc']-page for n in w['nodes'])==(256,259,263,266),
             'B forward-JMP spine has complete NO_ENVELOPE, never an incomplete or budget fallback')
    else:
        n=len(offsets);size=19 if offset==A else 6;end=D if offset==A else END;latch=529 if offset==A else 539
        expected=dict(first=entry,end=page+end,latch=page+latch,result=0,heads=n,
            exits=len(cuts),links=0,backwards=1,stores=0,source_bytes=size,reserved=0)
        candidates=[]
        if offset==A:
            candidates.append(dict(first=page+B,end=page+526,latch=page+520,result=1,
                heads=0,exits=0,links=0,backwards=0,stores=0,source_bytes=0,reserved=0))
        candidates.append(expected)
        wanted_nodes=(512,516,520,526,529,531,256,259,263,266)if offset==A else(535,539,541)
        need(w['result']==0 and w['ready']and w['eligible']==1 and w['stop']==1 and
             w['stop_pc']==page+end and w['candidates']==tuple(candidates)and
             tuple(n['pc']-page for n in w['nodes'])==wanted_nodes,
             'complete source-discovered candidate census including the rejected B-prefix and actual unsupported stop')
        s=w['selected'];need(s['choice']==expected and not s['link'],'literal selected interval and zero capacity links')
        wanted=[]
        for i,(off,succ)in enumerate(zip(offsets,successors,strict=True)):
            flow=1 if len(succ)==2 else 0;mask=sum(1<<arm for arm,k in enumerate(succ)if k>=128)
            decoded=next(j for j,d in enumerate(w['nodes'])if d['pc']==page+off)
            wanted.append([page+off,decoded,1,flow,len(succ),succ[0],succ[1]if len(succ)==2 else 0,mask,0])
        need(s['head']==wanted and tuple(s['exit'])==tuple((page+target,head,arm)for head,arm,target in cuts),
             'every genuine-entry BFS head, internal arm and typed external token independently literal')
    by_pc={d['pc']:d for d in w['nodes']}
    for off,original in zip(offsets,originals,strict=True):
        need(by_pc[page+off]['bridge']==original,'whole old-ready or old-refused bridge descriptor equals independent literal row')
    return w


def store_description(source,page,entry):
    need(entry-page==B and source[B:B+3]==bytes.fromhex('4c890f'),'exact R9 qword store before effect')
    return (struct.pack('<QQ6I',entry,entry+3,1,1,282,3,1,1)+source[B:B+15]+b'\0'+bytes(24)+
        struct.pack('<16I',1,1,0,15,8,1,9,7,16,1,0,0,0,2,1,0))


def guard(source,page,entry,generated,spill,successor,table_bytes):
    """All37 independently modeled MOV rows for the literal R9-to-[RDI] store."""
    need(entry-page==256,'only the actual policy11 B root owns this guard')
    scratch=(0,1,2,3);a,e,t=scratch[1:]
    raw=bytes.fromhex('4c890f');ea=bytes.fromhex('488d0f')
    root=struct.unpack_from('<Q',table_bytes,24)[0]
    save=lambda r:bytes((0x48,0x89,5|(r<<3)))+bytes(4)
    load=lambda r:bytes((0x48,0x8b,5|(r<<3)))+bytes(4)
    rr=lambda op,left,right:bytes((0x48,op,0xc0|(left<<3)|right))
    memory=lambda op,r,b,disp:bytes((0x48,op,0x40|(r<<3)|b,disp))
    branch=lambda cc:b'\xe9'+bytes(4)if cc==16 else bytes((15,128+cc))+bytes(4)
    restore=[b'\x04\x7f',b'\x9e',load(a),load(e),load(t),load(0)]
    pieces=([save(r)for r in scratch]+
        [ea,b'\x9f',b'\x0f\x90\xc0',bytes((0x48,0xb8+t))+struct.pack('<Q',root),
         memory(0x8d,e,a,8),rr(0x3b,e,a),branch(6),rr(0x85,t,t),branch(4),
         memory(0x3b,e,t,0),branch(6),memory(0x3b,a,t,8),branch(3),branch(16),
         memory(0x8b,t,t,16),branch(16),memory(0x8b,t,t,24),branch(16)]+
        restore+[raw,branch(16)]+restore+[b'\x0f\x0b'])
    states=(((0,0,0,0),(1,0,0,0),(3,0,0,0),(7,0,0,0),
        (15,0,0,0),(15,2,0,0),(15,3,1,0),(15,3,2,0),(15,11,2,0))+
        ((15,15,2,0),)*14+((15,15,1,0),(15,15,0,0),(15,13,0,0),
        (15,9,0,0),(15,1,0,0),(15,0,0,1),(15,0,0,2),(15,15,2,0),
        (15,15,1,0),(15,15,0,0),(15,13,0,0),(15,9,0,0),(15,1,0,0),(15,0,0,3)))
    need(len(pieces)==len(states)==37,'all original MOV boundaries')
    offsets=[];at=0
    for piece in pieces:offsets.append(at);at+=len(piece)
    code=bytearray(b''.join(pieces))
    def relative(i,target):
        end=offsets[i]+len(pieces[i]);code[end-4:end]=struct.pack('<i',target-generated-end)
    for i in range(4):relative(i,spill+8*i)
    for first in(24,32):
        for j,slot in enumerate((1,2,3,0)):relative(first+j,spill+8*slot)
    for i,target in((10,30),(12,22),(14,18),(16,20),(17,30),(19,11),(21,11)):
        relative(i,generated+offsets[target])
    relative(29,successor)
    rows=tuple((off,len(piece),*state)for off,piece,state in zip(offsets,pieces,states,strict=True))
    boundary=b''.join(struct.pack('<6I',*row)for row in rows)+bytes(27*24)
    need(len(code)==182 and rows[28][5]==1 and rows[29][5]==2 and rows[36][5]==3,
         'exact MOV store/after/reject phases and byte extent')
    header=struct.pack('<8I',1,1,0,len(code),37,offsets[28],offsets[36],0)
    record=header+struct.pack('<4I',*scratch)+boundary
    description=store_description(source,page,entry)
    whole=(header+struct.pack('<3Q',generated,spill,successor)+struct.pack('<4I',*scratch)+
           description+table_bytes+boundary+code+bytes(512-len(code)))
    need(len(description)==144 and len(record)==1584 and len(whole)==6488,
         'whole MOV description, compact record and typed materialization')
    return dict(image=bytes(code),description=description,record=record,whole=bytes(whole),
        rows=rows,scratch_regs=scratch,store_offset=offsets[28],reject_offset=offsets[36])



def graph(source,page,entry,layout,table_bytes,*,policy,endpoint):
    need(type(source)is bytes and source==source_image(page,endpoint)and
         type(entry)is int and entry-page in(A,B,C),'whole exact same-pair source, both predecessors, refusal and endpoint')
    need(type(layout)is tuple and len(layout)==6 and all(type(v)is int and 4096<=v<1<<47 and not v%4096 for v in layout),
         'six actual generated/stubs/slots/spill/directory extents')
    need(type(table_bytes)is bytes and len(table_bytes)==4224 and struct.unpack_from('<2I',table_bytes)==(1,1),
         'whole actual exclusion table')
    count=struct.unpack_from('<I',table_bytes,8)[0];at=struct.unpack_from('<Q',table_bytes,16)[0]
    need(0<count<=131 and at>=64576+4096 and at%8==0,'bounded actual table and original-row offset')
    ranges=tuple(struct.unpack_from('<2Q',table_bytes,32+32*i)for i in range(count))
    need(table(ranges,at)==table_bytes,'whole canonical merged-node tree and all zero tails')
    a,b,stubs,slots,spill,directory=layout
    extents=((page,8192),(a,32768),(b,32768),(stubs,4096),(slots,4096),(spill,4096),(directory,12288),(at,4224))
    need(all(any(lo<=x and x+n<=hi for lo,hi in ranges)for x,n in extents),
         'every whole source/generated/mutable/table extent independently excluded')
    need(all(x+n<=y or y+m<=x for i,(x,n)in enumerate(extents)for y,m in extents[:i]),
         'all actual source/generated/mutable/table extents disjoint')
    offsets,rows,successors,cuts,store=descriptions(page,entry-page);n=len(rows)
    originals=tuple(descriptor(row,page+off,source,off,refusal=5 if i==store else 0)
                    for i,(off,row)in enumerate(zip(offsets,rows,strict=True)))
    witness=choice_check(source,page,entry,offsets,successors,cuts,originals,policy)
    image=bytearray(b'\xcc'*65536);instructions=bytearray(128*144);guards=bytearray(128*1584)
    heads=[];guard_models={};direct_models={};direct_heads={h for h,_,_ in cuts}
    for i,(off,row,succ,original)in enumerate(zip(offsets,rows,successors,originals,strict=True)):
        generated=a+512*i;kind=2 if i==store else 5 if i in direct_heads else 1
        if kind==2:
            model=guard(source,page,entry,generated,spill,a+512*succ[0],table_bytes)
            body=model['image'];instructions[i*144:(i+1)*144]=model['description']
            guards[i*1584:(i+1)*1584]=model['record'];guard_models[i]=model
        elif kind==5:
            external=sum(1<<arm for arm,k in enumerate(succ)if k>=128)
            internal=tuple(0 if arm>=len(succ)or succ[arm]>=128 else a+512*succ[arm]for arm in range(2))
            model=direct.emit(original,generated,spill,struct.pack('<3Q2IQ',at-64576,a,b,n,i,directory),external,internal,policy=policy)
            model=dict(model,whole=model['whole']+bytes(6488-len(model['whole'])))
            body=model['image'];instructions[i*144:(i+1)*144]=model['description']+bytes(24)
            guards[i*1584:(i+1)*1584]=model['record'];direct_models[i]=model
        else:
            need(row['flow']==0 and len(succ)==1 and succ[0]<n,'only actual ordinary fallthrough heads')
            body=row['raw']+b'\xe9'+struct.pack('<i',a+512*succ[0]-generated-len(row['raw'])-5)
        image[512*i:512*i+len(body)]=body
        heads.append((kind,off//4096,off%4096,len(row['raw']),len(succ),succ[0],succ[1]if len(succ)==2 else 0,len(body)))
    source_bytes=sum(h[3]for h in heads);gpr=flags=0
    for h,d in zip(heads,originals,strict=True):
        if h[0]==1:
            gpr|=struct.unpack_from('<I',d,316)[0]
            for value in struct.unpack_from('<4I',d,296):flags|=value
    need((n,source_bytes,int(store is not None),len(cuts),gpr,flags)==
         ((5,19,0,2,2,0x8d5)if entry-page==A else(4,15,1,1,514,0x8d5)if entry-page==B else(2,6,0,1,1024,0x8d5)),
         'literal complete graph/source/effect populations')
    frontiers=tuple(originals[h]for h,_,_ in cuts);exitpcs=tuple(page+offsets[h]for h,_,_ in cuts)
    boundary=tuple(dict(index=j,head=h,arm=arm,kind='direct',token=128+j,target=page+target)
                   for j,(h,arm,target)in enumerate(cuts))
    last_none=max(i for i,h in enumerate(heads)if h[0]==1);last_direct=max(direct_models);last_proved=max(last_direct,store if store is not None else -1)
    # Cold rseq visits BFS heads in order: NONE and DIRECT write its footprint.
    # MOV proof checks do not update it; retain the separate NONE/proved keys.
    last_rseq=max(i for i,h in enumerate(heads)if h[0]in(1,5))
    return dict(head=b''.join(struct.pack('<8I',*h)for h in heads)+bytes((128-n)*32),
        original=b''.join(originals)+bytes((128-n)*336),frontier=b''.join(frontiers)+bytes((8-len(frontiers))*336),
        edge=bytes(8*48),instruction=bytes(instructions),guard=bytes(guards),image=bytes(image),stub_image=b'\xcc'*4096,
        exit_pc=exitpcs[0],exit_pc_bytes=struct.pack('<8Q',*exitpcs,*([0]*(8-len(exitpcs)))),
        initial_slots=bytes(4096),terminal_slots=bytes(4096),source=source,source_bytes=source_bytes,
        heads=n,stores=int(store is not None),exits=len(cuts),links=0,source_mask=1,member_heads=(n,0),offsets=offsets,
        head_rows=tuple(heads),original_rows=originals,frontier_rows=frontiers,boundary_rows=boundary,
        guard_models=guard_models,dispatch_models={},direct_models=direct_models,gpr_written=gpr,flags_written=flags,
        last_rseq_index=last_rseq,last_rseq_decoded=originals[last_rseq][:72],
        last_none_index=last_none,last_none_decoded=originals[last_none][:72],last_proved_index=last_proved,
        last_proved_decoded=originals[last_proved][:72],last_store_index=store,
        last_store_scratch=guard_models[store]['scratch_regs']if store is not None else None,
        direct_index=last_direct,terminal_decoded=originals[last_direct][:72],direct_terminal_decoded=originals[last_direct][:72],
        direct_terminal_exit_index=len(cuts)-1,direct_terminal_arm=cuts[-1][1],
        plan_policy=policy,chooser_result=witness['result'],chooser=witness,chooser_bytes=witness['raw'])
