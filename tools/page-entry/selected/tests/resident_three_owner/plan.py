"""Independent three-pair direct-only source, full images and recovery records.

No production decoder or emitter is imported. Source admission is not inferred
from this model; the actual held union and full guard table remain reader gates.
"""
import struct,importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
base=load('resident_three_independent_plan_donor',Path(__file__).resolve().parents[1]/'persistent_direct_frontier_owner/plan.py')
need,table,reg,imm,ins,descriptor=base.need,base.table,base.reg,base.imm,base.ins,base.descriptor
U64=(1<<64)-1

def direct(original,generated,spill,binding,conditional):
    """Literal E9 external and JNZ external/internal adapters;37/39 rows.

    The JNZ internal arm branches to the original memory-JMP frontier before
    any spill or flag change. Only the external arm scans the actual directory.
    """
    pc,next_pc=struct.unpack_from('<2Q',original)
    target=struct.unpack_from('<Q',original,72)[0]
    available=struct.unpack_from('<I',original,44)[0]
    rows_address,a,b,heads,head,directory=struct.unpack('<3Q2IQ',binding)
    need(conditional in(False,True)and heads==(3 if conditional else 2)and head==heads-1 and
         generated==a+head*512 and rows_address>=4096 and b!=a,
         'exact fixture direct adapter binding')
    desc=original[:72]+struct.pack('<2Q8I',target,next_pc if conditional else 0,
        1,1,0,available,1 if conditional else 2,5 if conditional else 16,1,0)
    save=lambda r:bytes((0x48,0x89,5|(r<<3)))+bytes(4)
    load=lambda r:bytes((0x48,0x8b,5|(r<<3)))+bytes(4)
    branch=lambda c:b'\xe9'+bytes(4)if c==16 else bytes((15,128+c))+bytes(4)
    absolute=lambda reg,value:bytes((0x48,0xb8+reg))+struct.pack('<Q',value)
    restore=(b'\x04\x7f',b'\x9e',load(1),load(2),load(3),load(0))
    pieces=([branch(5),branch(16)]if conditional else[])+[save(r)for r in range(4)]
    states=([(0,0,0,0),(0,0,0,0)]if conditional else[])+[(0,0,0,0),(1,0,0,0),(3,0,0,0),(7,0,0,0)]
    pieces += [absolute(3,target)];states += [(15,0,0,0)]
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
    for value in pieces:offsets.append(at);at+=len(value)
    code=bytearray(b''.join(pieces))
    def rel(index,dest):
        end=offsets[index]+len(pieces[index]);code[end-4:end]=struct.pack('<i',dest-generated-end)
    for i in range(4):rel(i+(2 if conditional else 0),spill+8*i)
    if conditional:
        rel(0,generated+11);rel(1,next_pc)
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
    whole=record+desc+struct.pack('<2Q',generated,spill)+binding+struct.pack('<2Q',0,next_pc if conditional else 0)+code+bytes(512-len(code))
    need(len(desc)==120 and len(record)==1584 and len(whole)==2288,'exact typed direct descriptor/record/adapter')
    return dict(image=bytes(code),description=desc,record=record,whole=bytes(whole)+bytes(6488-len(whole)),
        rows=boundary,scratch_regs=(0,1,2,3),hit_offset=hit_offset,miss_offset=miss_offset,
        external_mask=1,targets=(target,next_pc if conditional else 0),internal=(0,next_pc if conditional else 0))

def source_image():
    source=bytearray(b'\xcc'*24576)
    source[0x1fe:0x200]=bytes.fromhex('ffe3')
    source[0x200:0x209]=bytes.fromhex('4883c001e9f71f0000')
    source[0x2200:0x2209]=bytes.fromhex('4883c002e9f71f0000')
    source[0x4200:0x4211]=bytes.fromhex('4883c0044883e9010f85f2bfffff41ff23')
    return bytes(source)


def graph(source,page,entry,layout,table_bytes,index):
    need(type(index)is int and 0<=index<3 and type(source)is bytes and len(source)==8192 and
         source==source_image()[8192*index:8192*(index+1)]and
         page==0x410000+8192*index and entry==page+0x200,
         'whole fixed source pair and three real independent roots')
    need(len(layout)==6 and all(type(v)is int and 4096<=v<1<<47 and v%4096==0 for v in layout),
         'all actual image/spill/directory coordinates')
    need(type(table_bytes)is bytes and len(table_bytes)==4224 and struct.unpack_from('<2I',table_bytes)==(1,1),
         'whole guard table')
    count=struct.unpack_from('<I',table_bytes,8)[0];at=struct.unpack_from('<Q',table_bytes,16)[0]
    need(0<count<=131 and at>=4096+146632 and at%8==0,'bounded immutable table/row address')
    ranges=tuple(struct.unpack_from('<2Q',table_bytes,32+32*i)for i in range(count))
    need(table(ranges,at)==table_bytes,'complete canonical exclusion tree and unused nodes')
    a,b,stubs,slots,spill,directory=layout
    need((b,stubs,slots,spill)==(a+32768,a+65536,a+69632,a+73728),
         'exact current separate resident code/data placement')
    arithmetic=(0,0x8d5,0,0,0)
    offsets=(0x200,0x204,0x208)if index==2 else(0x200,0x204)
    rows=[ins(bytes((0x48,0x83,0xc0,1<<index)),249,(reg(0,64,3),imm(1<<index,64,8)),arithmetic)]
    if index==2:rows.append(ins('4883e901',264,(reg(1,64,3),imm(1,64,8)),arithmetic))
    target=0x410200 if index==2 else page+0x2200
    branch_raw=source[offsets[-1]:offsets[-1]+(6 if index==2 else 5)]
    rows.append(ins(branch_raw,1871 if index==2 else 696,((target,4,0,64,1,32,0),),
        (0x40 if index==2 else 0,0,0,0,0),flow=1 if index==2 else 2,
        target=target,condition=5 if index==2 else 16))
    originals=tuple(descriptor(row,page+off,source,off)for row,off in zip(rows,offsets,strict=True));n=len(rows)
    frontiers=[originals[-1]];exits=[page+offsets[-1]]
    if index==2:
        frontiers.append(descriptor(ins('41ff23',765),page+0x20e,source,0x20e,refusal=1));exits.append(page+0x20e)
    image=bytearray(b'\xcc'*65536);heads=[];instructions=bytearray(128*144);guards=bytearray(128*1584)
    direct_model=None
    for i,(off,row)in enumerate(zip(offsets,rows,strict=True)):
        generated=a+512*i
        if i==n-1:
            successors=(128,129)if index==2 else(128,)
            binding=struct.pack('<3Q2IQ',at-64576,a,b,n,i,directory)
            direct_model=direct(originals[i],generated,spill,binding,index==2);body=direct_model['image']
            instructions[i*144:(i+1)*144]=direct_model['description']+bytes(24)
            guards[i*1584:(i+1)*1584]=direct_model['record'];kind=5
        else:
            successors=(i+1,);body=row['raw']+b'\xe9'+struct.pack('<i',a+512*(i+1)-generated-len(row['raw'])-5);kind=1
        image[512*i:512*i+len(body)]=body
        heads.append((kind,0,off,len(row['raw']),len(successors),successors[0],successors[1]if len(successors)==2 else 0,len(body)))
    need(n==(3 if index==2 else 2)and len(frontiers)==(2 if index==2 else 1)and
         sum(r[3]for r in heads)==(14 if index==2 else 9),'exact accepted heads, original bytes and before-effect frontiers')
    return dict(head=b''.join(struct.pack('<8I',*r)for r in heads)+bytes((128-n)*32),
        original=b''.join(originals)+bytes((128-n)*336),
        frontier=b''.join(frontiers)+bytes((8-len(frontiers))*336),instruction=bytes(instructions),guard=bytes(guards),
        image=bytes(image),stub_image=b'\xcc'*4096,edge=bytes(384),
        exit_pc_bytes=struct.pack('<8Q',*exits,*([0]*(8-len(exits)))),source=source,
        heads=n,exits=len(frontiers),stores=0,source_bytes=sum(h[3]for h in heads),source_mask=1,member_heads=(n,0),links=0,
        head_rows=tuple(heads),original_rows=originals,frontier_rows=tuple(frontiers),direct_index=n-1,
        direct_model=direct_model,gpr_written=3 if index==2 else 1,flags_written=0x8d5,
        initial_slots=bytes(4096),terminal_slots=bytes(4096))


def directory(layouts):
    need(len(layouts)==3,'three distinct actual published resident layouts')
    rows=[]
    for i,layout in enumerate(layouts):
        page=0x410000+8192*i
        for h,off in enumerate((0x200,0x204,0x208)if i==2 else(0x200,0x204)):
            rows.append(struct.pack('<3Q2I',page+off,layout[0]+512*h,i+1,i,h))
    need(len(rows)==7,'all seven actual accepted heads, no artificial terminal head')
    return struct.pack('<4Q',1,7,1,0)+b''.join(rows)+bytes(12288-32-7*32)


def terminal_spill(index,seed,layouts):
    need(type(index)is int and 0<=index<3 and len(seed)==16 and seed[0]==1 and seed[1]==4,
         'exact four-cycle original register seed')
    # C takes its external path only three times. The last internal branch has
    # no spill/flag effect, so its retained scratch words belong to cycle3.
    value=(23,25,22)[index]
    target=layouts[(index+1)%3][0]
    return struct.pack('<5Q',value,1,seed[2],seed[3],target)+bytes(4096-40)
