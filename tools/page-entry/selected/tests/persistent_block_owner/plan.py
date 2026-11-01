"""Independent literal PB A2/B2 source, decoder, image and compact model."""
import struct,importlib.util
from pathlib import Path
_spec=importlib.util.spec_from_file_location('pb_donor_plan',Path(__file__).resolve().parents[1]/'persistent_direct_frontier_owner/plan.py')
old=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(old)
need,table,reg,imm,ins,descriptor=old.need,old.table,old.reg,old.imm,old.ins,old.descriptor
U64=(1<<64)-1

def source_image(entry_offset):
    need(entry_offset in(0x200,0x400),'one separate PB graph root')
    out=bytearray(b'\xcc'*8192)
    if entry_offset==0x200:
        out[0x1fe:0x200]=bytes.fromhex('6690')
        out[0x200:0x209]=bytes.fromhex('4883c001e9')+struct.pack('<i',0x2400-0x209)
    else:
        out[0x400:0x40f]=(bytes.fromhex('4883e9010f85')+
            struct.pack('<i',0x200-0x240a)+bytes.fromhex('488907ffe6'))
    return bytes(out)

def descriptions(page,entry):
    a=entry==page+0x200
    need(a or entry==page+0x400,'one actual A or B root')
    arithmetic=(0,0x8d5,0,0,0)
    pc=entry+4;target=page+0x2400 if a else page-0x1e00
    raw=(b'\xe9' if a else b'\x0f\x85')+struct.pack('<i',target-pc-(5 if a else 6))
    rows=(ins('4883c001'if a else'4883e901',249 if a else 264,
              (reg(0 if a else 1,64,3),imm(1,64,8)),arithmetic),
          ins(raw,696 if a else 1871,((target,4,0,64,1,32,0),),
              (0 if a else 0x40,0,0,0,0),flow=2 if a else 1,target=target,condition=16 if a else 5))
    return (entry-page,entry-page+4),rows,((1,),(128,)if a else(128,129))

def graph(source,page,entry,layout,table_bytes):
    need(type(source)is bytes and len(source)==8192 and page>=4096 and page%4096==0 and
         entry-page in(0x200,0x400)and source==source_image(entry-page),'whole exact separate PB source pair')
    need(len(layout)==6 and all(type(v)is int and 4096<=v<1<<47 and v%4096==0 for v in layout),'whole actual generated geometry')
    need(type(table_bytes)is bytes and len(table_bytes)==4224 and struct.unpack_from('<2I',table_bytes)==(1,1),'whole guard table')
    count=struct.unpack_from('<I',table_bytes,8)[0];address=struct.unpack_from('<Q',table_bytes,16)[0]
    need(0<count<=131 and address>=146632+4096 and address%8==0,'actual bounded immutable guard address')
    ranges=tuple(struct.unpack_from('<2Q',table_bytes,32+32*i)for i in range(count))
    need(table(ranges,address)==table_bytes,'whole canonical exclusion tree')
    a,b,stubs,slots,spill,directory=layout;offsets,rows,successors=descriptions(page,entry)
    originals=tuple(descriptor(row,page+off,source,off)for off,row in zip(offsets,rows,strict=True))
    binding=struct.pack('<3Q2IQ',address-64576,a,b,2,1,directory)
    model=direct(originals[1],a+512,spill,binding,entry-page==0x400)
    first=rows[0]['raw']+b'\xe9'+struct.pack('<i',512-len(rows[0]['raw'])-5)
    images=bytearray(b'\xcc'*65536);images[:len(first)]=first;images[512:512+len(model['image'])]=model['image']
    instructions=bytearray(128*144);instructions[144:288]=model['description']+bytes(24)
    guards=bytearray(128*1584);guards[1584:3168]=model['record']
    arms=1 if entry-page==0x200 else 2;frontiers=(originals[1],)*arms;exitpcs=(entry+4,)*arms
    heads=((1,0,offsets[0],4,1,1,0,len(first)),
           (5,0,offsets[1],len(rows[1]['raw']),arms,128,129 if arms==2 else 0,len(model['image'])))
    return dict(head=b''.join(struct.pack('<8I',*h)for h in heads)+bytes(126*32),
        original=b''.join(originals)+bytes(126*336),frontier=b''.join(frontiers)+bytes((8-arms)*336),
        instruction=bytes(instructions),guard=bytes(guards),image=bytes(images),stub_image=b'\xcc'*4096,
        edge=bytes(8*48),exit_pc=entry+4,exit_pc_bytes=struct.pack('<8Q',*exitpcs,*([0]*(8-arms))),
        initial_slots=bytes(4096),terminal_slots=bytes(4096),source=source,source_bytes=9 if arms==1 else 10,
        heads=2,stores=0,exits=arms,links=0,source_mask=1,member_heads=(2,0),offsets=offsets,
        head_rows=heads,original_rows=originals,frontier_rows=frontiers,guard_models={},dispatch_models={},
        direct_models={1:model},boundary_rows=tuple(dict(index=i,head=1,arm=i,kind='direct',token=128+i,target=model['targets'][i])for i in range(arms)),
        gpr_written=1 if arms==1 else 2,flags_written=0x8d5,last_none_index=0,last_none_decoded=originals[0][:72],
        last_proved_index=1,last_proved_decoded=originals[1][:72],direct_index=1,
        terminal_decoded=originals[1][:72],direct_terminal_decoded=originals[1][:72],
        direct_terminal_exit_index=0 if arms==1 else 1,direct_terminal_arm=0 if arms==1 else 1)

def direct(original,generated,spill,binding,conditional):
    """Literal JMP-external/JNZ-two-external adapters; all37/40 rows.

    The two Jcc target MOVs are selected while original flags remain physical.
    The common directory scan begins only after that selection. Every row
    recovers the original branch-before; CELL_READY is private state only.
    """
    pc,next_pc=struct.unpack_from('<2Q',original)
    target=struct.unpack_from('<Q',original,72)[0]
    available=struct.unpack_from('<I',original,44)[0]
    rows_address,a,b,heads,head,directory=struct.unpack('<3Q2IQ',binding)
    need(conditional in(False,True)and heads==2 and head==1 and
         generated==a+head*512 and rows_address>=4096 and b!=a,
         'exact fixture direct adapter binding')
    desc=original[:72]+struct.pack('<2Q8I',target,next_pc if conditional else 0,
        1,1,0,available,1 if conditional else 2,5 if conditional else 16,3 if conditional else 1,0)
    save=lambda r:bytes((0x48,0x89,5|(r<<3)))+bytes(4)
    load=lambda r:bytes((0x48,0x8b,5|(r<<3)))+bytes(4)
    branch=lambda c:b'\xe9'+bytes(4)if c==16 else bytes((15,128+c))+bytes(4)
    absolute=lambda reg,value:bytes((0x48,0xb8+reg))+struct.pack('<Q',value)
    restore=(b'\x04\x7f',b'\x9e',load(1),load(2),load(3),load(0))
    pieces=[save(r)for r in range(4)]
    states=[(0,0,0,0),(1,0,0,0),(3,0,0,0),(7,0,0,0)]
    if conditional:
        pieces += [branch(5),absolute(3,next_pc),branch(16),absolute(3,target)]
        states += [(15,0,0,0),(15,0,0,0),(15,8,0,0),(15,0,0,0)]
    else:
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
    for i in range(4):rel(i,spill+8*i)
    if conditional:
        rel(4,generated+offsets[7]);rel(6,generated+offsets[start])
    for index,dest in((start+5,rejected),(start+7,rejected),(start+12,hit),(start+15,start+11)):
        rel(index,generated+offsets[dest])
    for begin in(rejected+2,hit+4):
        for i,slot in enumerate((1,2,3,0)):rel(begin+i,spill+8*slot)
    rel(rejected+6,pc);rel(hit+1,spill+32);rel(hit+8,spill+32)
    boundary=tuple((off,len(piece),*state)for off,piece,state in zip(offsets,pieces,states,strict=True))
    miss_offset=offsets[rejected+6];hit_offset=offsets[hit+8]
    need((len(code),len(boundary),miss_offset,hit_offset)==((227,40,174,221)if conditional else(206,37,153,200)),
        'literal full direct byte and recovery-boundary extents')
    record=struct.pack('<12I',1,1,0,len(code),len(boundary),hit_offset,miss_offset,0,0,1,2,3)
    record+=b''.join(struct.pack('<6I',*row)for row in boundary)+bytes((64-len(boundary))*24)
    whole=record+desc+struct.pack('<2Q',generated,spill)+binding+bytes(16)+code+bytes(512-len(code))
    need(len(desc)==120 and len(record)==1584 and len(whole)==2288,'exact typed direct descriptor/record/adapter')
    return dict(image=bytes(code),description=desc,record=record,whole=bytes(whole)+bytes(6488-len(whole)),
        rows=boundary,scratch_regs=(0,1,2,3),hit_offset=hit_offset,miss_offset=miss_offset,
        external_mask=3 if conditional else 1,targets=(target,next_pc if conditional else 0),internal=(0,0))
