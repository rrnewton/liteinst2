"""Independent paired-loop source, canonical descriptors, BFS and emitted bytes.

This finite model recognizes the actual immutable88-byte source only. It does
not import a production decoder/planner/emitter or grant generic history credit.
All input layout, table and source bytes remain independently checked.
"""
import importlib.util
import struct
from pathlib import Path
_spec=importlib.util.spec_from_file_location('loop_independent_scalar_primitives',
    Path(__file__).resolve().parents[1]/'persistent_direct_frontier_owner/plan.py')
old=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(old)
need,table,reg,imm,mem,address,ins=(old.need,old.table,old.reg,old.imm,old.mem,old.address,old.ins)
U64=(1<<64)-1
OFFSETS=(0,4,8,12,18,23,26,28,32,35,37,40,43,46,48,52,56,59,61,63,65,67,71,75,79,81,83,86)
ENTRY=(0,0,23,59,59,18,52)
FIRST=(1,2,3,-1,5,6,0,8,9,0,11,12,13,14,15,16,17,18,0,20,0,22,23,24,25,16,27,0)
SECOND=(-3,-3,-3,4,-3,-3,7,-3,-3,10,-3,-3,-3,-3,-3,-3,-3,-3,19,-3,21,-3,-3,-3,-3,26,-3,-2)
ADDED=(4,5,8,15,17,19,24,26)
BODY=bytes.fromhex('4983c1014983e8804983f9250f8472ffffff418078f8004d63d175e4410fb6384084ff74db4c89cd4c89c64889d889f948c1e5070f1f40000fb61084d274c138ca75bd0fb64e014883c6014883c00184c975e580383d75a8')


def source_image(page,base,entry,high):
    need(page in(0x4000000,0x700000000000)and base-page in(512,4022)and
         entry-base in ENTRY and 4096<=high<1<<47,'literal paired placement and genuine root')
    source=bytearray(b'\xcc'*8192);off=base-page
    source[off:off+88]=BODY
    source[off-5:off]=b'\xe9'+struct.pack('<i',entry-base)
    stub=b'\xff\x25'+bytes(4)+struct.pack('<Q',high)
    for at in(off-124,off+88):source[at:at+14]=stub
    return bytes(source)


def descriptions(base):
    arithmetic=(0,0x8d5,0,0,0);test=(0,0xc4,0,0x801,0x10);shift=(0,0xc5,0,0,0x810)
    def branch(index,condition,target):
        at=OFFSETS[index];end=OFFSETS[index+1]if index<27 else 88
        width=4 if end-at==6 else 1;code=(1856 if width==4 else 161)+3*condition
        return ins(BODY[at:end],code,((base+target,4,0,64,1,8*width,0),),
                   (0x40,0,0,0,0),flow=1,target=base+target,condition=condition)
    return (
        ins('4983c101',249,(reg(9,64,3),imm(1,64,8)),arithmetic),
        ins('4983e880',264,(reg(8,64,3),imm(-128,64,8)),arithmetic),
        ins('4983f925',270,(reg(9,64,1),imm(37,64,8)),arithmetic),branch(3,4,-124),
        ins('418078f800',214,(mem(8),imm(0,8,8)),arithmetic,address=address(8,-8,1)),
        ins('4d63d1',140,(reg(10,64,2),reg(9,32,1))),branch(6,5,0),
        ins('410fb638',2090,(reg(7,32,2),mem(8)),address=address(8,0,1)),
        ins('4084ff',271,(reg(7,8,1),reg(7,8,1)),test),branch(9,4,0),
        ins('4c89cd',282,(reg(5,64,2),reg(9,64,1)),step=1),
        ins('4c89c6',282,(reg(6,64,2),reg(8,64,1)),step=1),
        ins('4889d8',282,(reg(0,64,2),reg(3,64,1)),step=1),
        ins('89f9',281,(reg(1,32,2),reg(7,32,1)),step=1),
        ins('48c1e507',381,(reg(5,64,3),imm(7,8,8)),shift),ins('0f1f4000',1057),
        ins('0fb610',2090,(reg(2,32,2),mem(8)),address=address(0,0,1)),
        ins('84d2',271,(reg(2,8,1),reg(2,8,1)),test),branch(18,4,0),
        ins('38ca',107,(reg(2,8,1),reg(1,8,1)),arithmetic),branch(20,5,0),
        ins('0fb64e01',2090,(reg(1,32,2),mem(8)),address=address(6,1,1)),
        ins('4883c601',249,(reg(6,64,3),imm(1,64,8)),arithmetic),
        ins('4883c001',249,(reg(0,64,3),imm(1,64,8)),arithmetic),
        ins('84c9',271,(reg(1,8,1),reg(1,8,1)),test),branch(25,5,56),
        ins('80383d',214,(mem(8),imm(61,8,8)),arithmetic,address=address(0,0,1)),branch(27,5,0))


def descriptor(row,pc,source,offset,version):
    need(version in(1,2),'explicit canonical old/new descriptor route')
    value=bytearray(old.descriptor(row,pc,source,offset))
    struct.pack_into('<I',value,256,version)
    return bytes(value)


def bfs(entry_offset,first=0,end=88):
    need(entry_offset in OFFSETS and first in OFFSETS and end in tuple(x+len(r['raw'])for x,r in zip(OFFSETS,descriptions(0))),
         'exact literal interval endpoints and genuine original root')
    inside=tuple(i for i,x in enumerate(OFFSETS)if first<=x<end)
    root=OFFSETS.index(entry_offset);need(root in inside,'genuine entry belongs to selected interval')
    queue=[root];rank={root:0};edges={};cuts=[]
    for i in inside:
        targets=(FIRST[i],SECOND[i])if SECOND[i]!=-3 else(FIRST[i],)
        edges[i]=targets
    for i in queue:
        for target in edges[i]:
            if target in inside and target not in rank:rank[target]=len(queue);queue.append(target)
    need(len(queue)==len(inside),'every selected source head reachable from genuine entry')
    successors=[]
    for at,i in enumerate(queue):
        row=[]
        for arm,target in enumerate(edges[i]):
            if target in rank:row.append(rank[target])
            else:
                need(SECOND[i]!=-3,'only a real conditional arm may leave this interval')
                target_offset=-124 if target==-1 else 88 if target==-2 else OFFSETS[target]
                row.append(128+len(cuts));cuts.append((at,arm,target_offset))
        successors.append(tuple(row))
    need(1<=len(cuts)<=8 and len(queue)<=128,'unchanged explicit graph capacities')
    backwards=sum(1 for i in inside if SECOND[i]!=-3 and FIRST[i]in inside and OFFSETS[FIRST[i]]<=OFFSETS[i])
    return tuple(queue),tuple(successors),tuple(cuts),backwards


def direct(original,generated,spill,binding,external,internal):
    """Independent full adapter bytes, selected by the literal source graph.

    The unchanged typed model body retains every spill/flags/phase boundary.
    No direction heuristic determines the external arm for policy12.
    """
    pc,next_pc=struct.unpack_from('<2Q',original);target=struct.unpack_from('<Q',original,72)[0]
    available=struct.unpack_from('<I',original,44)[0]
    rows_address,a,b,heads,head,directory=struct.unpack('<3Q2IQ',binding)
    flow,condition=struct.unpack_from('<2I',original,268)
    conditional=flow==1
    need(heads==28 and 0<=head<28 and flow==1 and condition in(4,5) and
         external in(1,2) and generated==a+head*512 and rows_address>=4096 and b!=a,
         'literal paired-loop conditional cut binding')
    need((condition,external)in((4,1),(5,2)) and
         internal[0 if external==1 else 1]==0 and
         internal[1 if external==1 else 0]>=a and
         (internal[1 if external==1 else 0]-a)%512==0 and
         internal[1 if external==1 else 0]<a+28*512,
         'one exact generated internal successor; caller joins whole BFS')
    desc=original[:72]+struct.pack('<2Q8I',target,next_pc if conditional else 0,
        1,1,0,available,flow,condition,external,0)
    save=lambda r:bytes((0x48,0x89,5|(r<<3)))+bytes(4)
    load=lambda r:bytes((0x48,0x8b,5|(r<<3)))+bytes(4)
    branch=lambda c:b'\xe9'+bytes(4)if c==16 else bytes((15,128+c))+bytes(4)
    absolute=lambda reg,value:bytes((0x48,0xb8+reg))+struct.pack('<Q',value)
    restore=(b'\x04\x7f',b'\x9e',load(1),load(2),load(3),load(0))
    pieces=([branch(condition^(1 if external==2 else 0)),branch(16)]if conditional else[])+[save(r)for r in range(4)]
    states=([(0,0,0,0),(0,0,0,0)]if conditional else[])+[(0,0,0,0),(1,0,0,0),(3,0,0,0),(7,0,0,0)]
    pieces+=[absolute(3,next_pc if external==2 else target)];states+=[(15,0,0,0)]
    start=len(pieces)
    pieces += [b'\x9f',b'\x0f\x90\xc0',absolute(1,directory),bytes.fromhex('488b5108'),
        bytes.fromhex('4881fa01000000'),branch(2),bytes.fromhex('4881fa00010000'),branch(7),
        bytes.fromhex('4881c120000000'),bytes.fromhex('48c1e205'),bytes.fromhex('4803d1'),
        bytes.fromhex('483b5900'),branch(4),bytes.fromhex('4881c120000000'),bytes.fromhex('483bca'),branch(2)]
    states += [(15,8,0,0),(15,9,1,0),(15,9,2,0),(15,11,2,0)]+[(15,15,2,0)]*12
    rejected=len(pieces)
    pieces += list(restore)+[branch(16)]
    states += [(15,15,2,0),(15,15,1,0),(15,15,0,0),(15,13,0,0),(15,9,0,0),(15,1,0,0),(15,0,0,0)]
    hit=len(pieces)
    pieces += [bytes.fromhex('488b4908'),bytes.fromhex('48890d')+bytes(4)]+list(restore)+[bytes.fromhex('ff25')+bytes(4)]
    states += [(15,15,2,0),(15,15,2,0),(15,15,2,1),(15,15,1,1),(15,15,0,1),
        (15,13,0,1),(15,9,0,1),(15,1,0,1),(15,0,0,1)]
    # This literal graph is policy12. Only the old miss E9's signed32
    # failure selects version2; all other relative edges remain checked.
    miss_index=rejected+6;old_miss=sum(map(len,pieces[:miss_index]))
    far=not -(1<<31)<=pc-generated-old_miss-5<(1<<31)
    if far:pieces[miss_index]=b'\xff\x25'+bytes(4)+struct.pack('<Q',pc)
    offsets=[];at=0
    for piece in pieces:offsets.append(at);at+=len(piece)
    code=bytearray(b''.join(pieces))
    def rel(index,dest):
        end=offsets[index]+len(pieces[index]);code[end-4:end]=struct.pack('<i',dest-generated-end)
    for i in range(4):rel(i+(2 if conditional else 0),spill+8*i)
    if conditional:rel(0,generated+11);rel(1,internal[1 if external==1 else 0])
    for index,dest in((start+5,rejected),(start+7,rejected),(start+12,hit),(start+15,start+11)):
        rel(index,generated+offsets[dest])
    for begin in(rejected+2,hit+4):
        for i,slot in enumerate((1,2,3,0)):rel(begin+i,spill+8*slot)
    if not far:rel(rejected+6,pc)
    rel(hit+1,spill+32);rel(hit+8,spill+32)
    boundary=tuple((off,6 if far and i==miss_index else len(piece),*state)
        for i,(off,piece,state)in enumerate(zip(offsets,pieces,states,strict=True)))
    miss_offset=offsets[rejected+6];hit_offset=offsets[hit+8]
    if not far:
        need((len(code),len(boundary),miss_offset,hit_offset)==((217,39,164,211)if conditional else(206,37,153,200)),
             'literal full direct byte and recovery-boundary extents')
    else:
        need((len(code),len(boundary),miss_offset,hit_offset)==((226,39,164,220)if conditional else(215,37,153,209)),
             'literal far DIRECT byte and recovery-boundary extents')
        need(boundary[miss_index]==(miss_offset,6,15,0,0,0)and
             code[miss_offset:miss_offset+14]==b'\xff\x25'+bytes(4)+struct.pack('<Q',pc)and
             all(not miss_offset+6<=off<miss_offset+14 for off,*_ in boundary),
             'restored-state far jump and all eight target bytes excluded from boundaries')
    record=struct.pack('<12I',2 if far else 1,1,0,len(code),len(boundary),hit_offset,miss_offset,0,0,1,2,3)
    record+=b''.join(struct.pack('<6I',*row)for row in boundary)+bytes((64-len(boundary))*24)
    whole=record+desc+struct.pack('<2Q',generated,spill)+binding+struct.pack('<2Q',*internal)+code+bytes(512-len(code))
    need(len(desc)==120 and len(record)==1584 and len(whole)==2288,'whole DIRECT description/record/materialization')
    return dict(image=bytes(code),description=desc,record=record,whole=bytes(whole)+bytes(6488-len(whole)),
        rows=boundary,scratch_regs=(0,1,2,3),hit_offset=hit_offset,miss_offset=miss_offset,
        external_mask=external,targets=(target,next_pc if conditional else 0),internal=internal)


def graph(source,page,base,entry,high,layout,table_bytes):
    need(type(source)is bytes and source==source_image(page,base,entry,high),
         'whole independently reconstructed dynamic source pair and both actual cut stubs')
    need(len(layout)==6 and all(type(v)is int and 4096<=v<1<<47 and v%4096==0 for v in layout),
         'complete actual generated/spill/directory geometry')
    need(type(table_bytes)is bytes and len(table_bytes)==4224 and struct.unpack_from('<2I',table_bytes)==(1,1),
         'complete actual exclusion table')
    count=struct.unpack_from('<I',table_bytes,8)[0];at=struct.unpack_from('<Q',table_bytes,16)[0]
    need(0<count<=131 and at>=64576+4096 and at%8==0,'bounded immutable table and original-row binding')
    ranges=tuple(struct.unpack_from('<2Q',table_bytes,32+32*i)for i in range(count))
    need(table(ranges,at)==table_bytes,'all actual canonical merged exclusion nodes and unused bytes')
    a,b,stubs,slots,spill,directory=layout
    extents=((page,8192),(a,32768),(b,32768),(stubs,4096),(slots,4096),(spill,4096),(directory,12288),(at,4224))
    need(all(any(lo<=x and x+n<=hi for lo,hi in ranges)for x,n in extents),
         'every whole source/generated/mutable/proof-table range excluded')
    need(all(x+n<=y or y+m<=x for i,(x,n)in enumerate(extents)for y,m in extents[:i]),
         'actual source/generated/mutable/table storage pairwise disjoint')
    order,successors,cuts,backwards=bfs(entry-base);need((len(order),len(cuts),backwards)==(28,2,6),'whole literal selected28-head loop')
    rows=descriptions(base)
    originals=tuple(descriptor(rows[i],base+OFFSETS[i],source,base-page+OFFSETS[i],2 if i in ADDED else 1)for i in order)
    image=bytearray(b'\xcc'*65536);instructions=bytearray(128*144);guards=bytearray(128*1584)
    heads=[];direct_models={};boundary_rows=[]
    def jump(pc,target):return b'\xe9'+struct.pack('<i',target-pc-5)
    for n,(i,succ,d)in enumerate(zip(order,successors,originals,strict=True)):
        off=base-page+OFFSETS[i];generated=a+512*n;row=rows[i]
        external=sum(1<<arm for arm,k in enumerate(succ)if k>=128)
        if external:
            internal=tuple(0 if k>=128 else a+512*k for k in succ)
            model=direct(d,generated,spill,struct.pack('<3Q2IQ',at-64576,a,b,28,n,directory),external,internal)
            body=model['image'];instructions[144*n:144*(n+1)]=model['description']+bytes(24)
            guards[1584*n:1584*(n+1)]=model['record'];direct_models[n]=model;kind=5
        elif row['flow']==1:
            need(len(succ)==2 and all(k<28 for k in succ),'both internal arms name actual BFS heads')
            body=bytes((15,128+row['condition']))+struct.pack('<i',a+512*succ[0]-generated-6)+jump(generated+6,a+512*succ[1]);kind=1
        else:
            need(row['flow']==0 and len(succ)==1 and succ[0]<28,'actual copied NEXT successor')
            body=row['raw']+jump(generated+len(row['raw']),a+512*succ[0]);kind=1
        image[512*n:512*n+len(body)]=body
        heads.append((kind,off//4096,off%4096,len(row['raw']),len(succ),succ[0],succ[1]if len(succ)==2 else 0,len(body)))
    frontiers=[];exitpcs=[]
    for index,(head,arm,target_offset)in enumerate(cuts):
        frontiers.append(originals[head]);exitpcs.append(base+OFFSETS[order[head]])
        boundary_rows.append(dict(index=index,head=head,arm=arm,kind='direct',token=128+index,target=base+target_offset))
    gpr=flags=0
    for h,d in zip(heads,originals,strict=True):
        if h[0]==1:
            gpr|=struct.unpack_from('<I',d,316)[0]
            for f in struct.unpack_from('<4I',d,296):flags|=f
    last_none=max(i for i,h in enumerate(heads)if h[0]==1);last_direct=max(direct_models)
    # Cold rseq visits BFS heads in order: NONE and DIRECT write its footprint.
    # MOV proof checks do not update it; retain the separate NONE/proved keys.
    last_rseq=max(i for i,h in enumerate(heads)if h[0]in(1,5))
    return dict(head=b''.join(struct.pack('<8I',*h)for h in heads)+bytes(100*32),
        original=b''.join(originals)+bytes(100*336),frontier=b''.join(frontiers)+bytes(6*336),
        instruction=bytes(instructions),guard=bytes(guards),image=bytes(image),stub_image=b'\xcc'*4096,
        edge=bytes(8*48),exit_pc_bytes=struct.pack('<8Q',*exitpcs,*([0]*6)),
        initial_slots=bytes(4096),terminal_slots=bytes(4096),source=source,source_bytes=88,
        heads=28,stores=0,exits=2,links=0,source_mask=3 if base-page==4022 else 1,member_heads=(28,0),
        offsets=tuple(base-page+OFFSETS[i]for i in order),order=order,head_rows=tuple(heads),original_rows=originals,
        frontier_rows=tuple(frontiers),guard_models={},dispatch_models={},direct_models=direct_models,
        boundary_rows=tuple(boundary_rows),gpr_written=gpr,flags_written=flags,
        last_rseq_index=last_rseq,last_rseq_decoded=originals[last_rseq][:72],
        last_none_index=last_none,last_none_decoded=originals[last_none][:72],
        last_proved_index=last_direct,last_proved_decoded=originals[last_direct][:72])
