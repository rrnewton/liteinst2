"""Independent finite PF11 source, decoder, MOV and direct-arm reconstruction.

Only reviewed independent Python primitives are imported. No production
planner, decoder or emitter supplies expected bytes. Entry at A206 preserves
the two earlier source heads for the actual backward path, never initial entry.
"""
import importlib.util
import struct
from pathlib import Path

_spec=importlib.util.spec_from_file_location('pf_independent_frontier_plan',
    Path(__file__).resolve().parents[1]/'persistent_direct_frontier_owner/plan.py')
old=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(old)
need,table,reg,imm,mem,address,ins,descriptor=(old.need,old.table,old.reg,old.imm,
    old.mem,old.address,old.ins,old.descriptor)
U64=(1<<64)-1
A_OFFSETS=(0x206,0x20a,0x210,0x214,0x218,0x21b,0x21e,0x221,0x200,0x203)
B_OFFSETS=(0x400,0x403,0x406,0x409)


def source_image(entry_offset):
    need(entry_offset in(0x206,0x400),'one separate finite PF source root')
    source=bytearray(b'\xcc'*8192)
    if entry_offset==0x206:
        source[0x200:0x228]=(bytes.fromhex('488b104c01e2837808080f85')+
            struct.pack('<i',0x2400-0x210)+
            bytes.fromhex('488b48104883c0184c01e148890a4839d872dd668907ffe6'))
    else:
        source[0x400:0x40e]=(bytes.fromhex('4d891a4889f84c89eae9')+
            struct.pack('<i',0x206-0x240e))
    return bytes(source)


def descriptions(page,entry):
    need(entry-page in(0x206,0x400),'actual finite A/B entry only')
    arithmetic=(0,0x8d5,0,0,0)
    if entry-page==0x206:
        target=page+0x2400
        rows=(
            ins('83780808',269,(mem(32),imm(8,32,8)),arithmetic,address=address(0,8,4)),
            ins(b'\x0f\x85'+struct.pack('<i',0x2400-0x210),1871,
                ((target,4,0,64,1,32,0),),(0x40,0,0,0,0),flow=1,target=target,condition=5),
            ins('488b4810',286,(reg(1,64,2),mem(64)),address=address(0,16)),
            ins('4883c018',249,(reg(0,64,3),imm(24,64,8)),arithmetic),
            ins('4c01e1',8,(reg(1,64,3),reg(12,64,1)),arithmetic),
            ins('48890a',282),
            ins('4839d8',110,(reg(0,64,1),reg(3,64,1)),arithmetic),
            ins('72dd',167,((page+0x200,4,0,64,1,8,0),),(1,0,0,0,0),
                flow=1,target=page+0x200,condition=2),
            ins('488b10',286,(reg(2,64,2),mem(64)),address=address(0)),
            ins('4c01e2',8,(reg(2,64,3),reg(12,64,1)),arithmetic))
        return A_OFFSETS,rows,((1,),(128,2),(3,),(4,),(5,),(6,),(7,),(8,129),(9,),(0,))
    target=page-0x2000+0x206
    rows=(ins('4d891a',282),
          ins('4889f8',282,(reg(0,64,2),reg(7,64,1)),step=1),
          ins('4c89ea',282,(reg(2,64,2),reg(13,64,1)),step=1),
          ins(b'\xe9'+struct.pack('<i',0x206-0x240e),696,
              ((target,4,0,64,1,32,0),),flow=2,target=target))
    return B_OFFSETS,rows,((1,),(2,),(3,),(128,))


def store_description(source,page,entry):
    a=entry-page==0x206
    need(a or entry-page==0x400,'one finite canonical qword store')
    offset=0x21b if a else 0x400
    raw=bytes.fromhex('48890a'if a else'4d891a')
    need(source[offset:offset+3]==raw,'literal original store and full decoder window')
    pc=page+offset
    return (struct.pack('<QQ6I',pc,pc+3,1,1,282,3,1,1)+
        source[offset:offset+15]+b'\0'+bytes(24)+
        struct.pack('<16I',1,1,0,15,8,1,1 if a else 11,2 if a else 10,
                    16,1,0,0,0,2,1,0))


def guard(source,page,entry,generated,spill,successor,table_bytes):
    """All37 MOV rows, including exact operand-preserving scratch palettes.

    A preserves RCX/RDX and uses RAX/RBX/RBP/RSI. B preserves R10/R11
    and uses RAX/RCX/RDX/RBX. The original store bytes remain unchanged.
    """
    a_graph=entry-page==0x206
    need(a_graph or entry-page==0x400,'one actual guarded A/B store')
    scratch=(0,3,5,6)if a_graph else(0,1,2,3)
    a,e,t=scratch[1:]
    raw=bytes.fromhex('48890a'if a_graph else'4d891a')
    ea=bytes.fromhex('488d1a'if a_graph else'498d0a')
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


def direct(original,generated,spill,binding,external,internal):
    """Literal JNE taken-only, JB fallthrough-only and unconditional cuts.

    The internal conditional arm changes neither spills nor flags. Every
    directory row describes original branch-before state, not a retired edge.
    """
    pc,next_pc=struct.unpack_from('<2Q',original);target=struct.unpack_from('<Q',original,72)[0]
    available=struct.unpack_from('<I',original,44)[0]
    rows_address,a,b,heads,head,directory=struct.unpack('<3Q2IQ',binding)
    flow,condition=struct.unpack_from('<2I',original,268)
    conditional=flow==1
    need((heads,head,flow,condition,external)in((10,1,1,5,1),(10,7,1,2,2),(4,3,2,16,1))and
         generated==a+head*512 and rows_address>=4096 and b!=a,
         'exact finite DIRECT head and external-arm contract')
    expected_internal=(0,a+2*512)if head==1 else(a+8*512,0)if heads==10 else(0,0)
    need(internal==expected_internal,'exact generated internal successor, no original-PC substitution')
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
    rel(rejected+6,pc);rel(hit+1,spill+32);rel(hit+8,spill+32)
    boundary=tuple((off,len(piece),*state)for off,piece,state in zip(offsets,pieces,states,strict=True))
    miss_offset=offsets[rejected+6];hit_offset=offsets[hit+8]
    need((len(code),len(boundary),miss_offset,hit_offset)==((217,39,164,211)if conditional else(206,37,153,200)),
         'literal full direct byte and recovery-boundary extents')
    record=struct.pack('<12I',1,1,0,len(code),len(boundary),hit_offset,miss_offset,0,0,1,2,3)
    record+=b''.join(struct.pack('<6I',*row)for row in boundary)+bytes((64-len(boundary))*24)
    whole=record+desc+struct.pack('<2Q',generated,spill)+binding+struct.pack('<2Q',*internal)+code+bytes(512-len(code))
    need(len(desc)==120 and len(record)==1584 and len(whole)==2288,'whole DIRECT description/record/materialization')
    return dict(image=bytes(code),description=desc,record=record,whole=bytes(whole)+bytes(6488-len(whole)),
        rows=boundary,scratch_regs=(0,1,2,3),hit_offset=hit_offset,miss_offset=miss_offset,
        external_mask=external,targets=(target,next_pc if conditional else 0),internal=internal)


def graph(source,page,entry,layout,table_bytes):
    need(type(source)is bytes and len(source)==8192 and type(page)is int and
         page>=4096 and page%4096==0 and entry-page in(0x206,0x400)and
         source==source_image(entry-page),'whole exact independent PF source pair')
    need(len(layout)==6 and all(type(v)is int and 4096<=v<1<<47 and v%4096==0 for v in layout),
         'complete actual generated/spill/directory geometry')
    need(type(table_bytes)is bytes and len(table_bytes)==4224 and struct.unpack_from('<2I',table_bytes)==(1,1),
         'complete actual exclusion table')
    count=struct.unpack_from('<I',table_bytes,8)[0];at=struct.unpack_from('<Q',table_bytes,16)[0]
    need(0<count<=131 and at>=146632+4096 and at%8==0,'bounded immutable table and original-row binding')
    ranges=tuple(struct.unpack_from('<2Q',table_bytes,32+32*i)for i in range(count))
    need(table(ranges,at)==table_bytes,'all actual canonical exclusion nodes and unused bytes')
    a,b,stubs,slots,spill,directory=layout
    offsets,rows,successors=descriptions(page,entry);n=len(rows);store_index=5 if n==10 else 0
    originals=tuple(descriptor(row,page+off,source,off,refusal=5 if i==store_index else 0)
        for i,(off,row)in enumerate(zip(offsets,rows,strict=True)))
    images=bytearray(b'\xcc'*65536);instructions=bytearray(128*144);guards=bytearray(128*1584)
    heads=[];guard_models={};direct_models={}
    direct_heads=(1,7)if n==10 else(3,)
    for i,(off,row,succ)in enumerate(zip(offsets,rows,successors,strict=True)):
        generated=a+512*i;kind=2 if i==store_index else 5 if i in direct_heads else 1
        if kind==2:
            model=guard(source,page,entry,generated,spill,a+512*succ[0],table_bytes)
            body=model['image'];instructions[i*144:(i+1)*144]=model['description']
            guards[i*1584:(i+1)*1584]=model['record'];guard_models[i]=model
        elif kind==5:
            external=2 if n==10 and i==7 else 1
            internal=(0,a+512*2)if n==10 and i==1 else(a+512*8,0)if n==10 else(0,0)
            binding=struct.pack('<3Q2IQ',at-64576,a,b,n,i,directory)
            model=direct(originals[i],generated,spill,binding,external,internal);body=model['image']
            instructions[i*144:(i+1)*144]=model['description']+bytes(24)
            guards[i*1584:(i+1)*1584]=model['record'];direct_models[i]=model
        else:
            need(row['flow']==0 and len(succ)==1,'only exact ordinary fallthrough heads')
            body=row['raw']+b'\xe9'+struct.pack('<i',a+512*succ[0]-generated-len(row['raw'])-5)
        images[512*i:512*i+len(body)]=body
        heads.append((kind,off//4096,off%4096,len(row['raw']),len(succ),succ[0],succ[1]if len(succ)==2 else 0,len(body)))
    source_bytes=sum(h[3]for h in heads)
    need((n,source_bytes)==((10,35)if entry-page==0x206 else(4,14)),'exact finite head and source-byte populations')
    gpr_written=flags_written=0
    for i,d in enumerate(originals):
        if heads[i][0]==1:
            gpr_written|=struct.unpack_from('<I',d,316)[0]
            for value in struct.unpack_from('<4I',d,296):flags_written|=value
    need((gpr_written,flags_written)==((7,0x8d5)if n==10 else(5,0)),
         'all ordinary GPR/flag effects, including later backward-closure heads')
    arms=(0,1)if n==10 else(0,)
    frontiers=tuple(originals[i]for i in direct_heads);exitpcs=tuple(page+offsets[i]for i in direct_heads)
    boundaries=tuple(dict(index=j,head=i,arm=arm,kind='direct',token=128+j,
        target=direct_models[i]['targets'][arm])for j,(i,arm)in enumerate(zip(direct_heads,arms,strict=True)))
    last_none=9 if n==10 else 2;last_direct=direct_heads[-1];last_proved=max(store_index,last_direct)
    return dict(head=b''.join(struct.pack('<8I',*h)for h in heads)+bytes((128-n)*32),
        original=b''.join(originals)+bytes((128-n)*336),frontier=b''.join(frontiers)+bytes((8-len(frontiers))*336),
        instruction=bytes(instructions),guard=bytes(guards),image=bytes(images),stub_image=b'\xcc'*4096,
        edge=bytes(8*48),exit_pc=exitpcs[0],exit_pc_bytes=struct.pack('<8Q',*exitpcs,*([0]*(8-len(exitpcs)))),
        initial_slots=bytes(4096),terminal_slots=bytes(4096),source=source,source_bytes=source_bytes,
        heads=n,stores=1,exits=len(frontiers),links=0,source_mask=1,member_heads=(n,0),offsets=offsets,
        head_rows=tuple(heads),original_rows=originals,frontier_rows=frontiers,guard_models=guard_models,
        dispatch_models={},direct_models=direct_models,boundary_rows=boundaries,
        gpr_written=gpr_written,flags_written=flags_written,last_none_index=last_none,last_none_decoded=originals[last_none][:72],
        last_proved_index=last_proved,last_proved_decoded=originals[last_proved][:72],
        last_store_index=store_index,last_store_scratch=guard_models[store_index]['scratch_regs'],
        direct_index=last_direct,terminal_decoded=originals[last_direct][:72],
        direct_terminal_decoded=originals[last_direct][:72],direct_terminal_exit_index=len(frontiers)-1,
        direct_terminal_arm=arms[-1])
