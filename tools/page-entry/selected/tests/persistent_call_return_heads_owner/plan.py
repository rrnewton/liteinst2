"""Independent version-8 eight-head return-head graph and full CALL/RET models.

The unchanged donor supplies only general finite descriptor/table encoders.
Both emitted models reconstruct literal x86 without a production emitter import.
The unchanged B-JZ admits only A's return continuation. The explicit CALL
return-head rule additionally admits A-prime+13, without borrowing a callee
or another page. CALL/RET retain their original before-effect frontiers.
"""
import importlib.util
from pathlib import Path
import struct

_path=Path(__file__).resolve().parent.parent/'persistent_direct_frontier_owner'/'plan.py'
_spec=importlib.util.spec_from_file_location('ret_puzzle_plan_primitives',_path)
base=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
need,table,reg,imm,ins,descriptor=(base.need,base.table,base.reg,base.imm,base.ins,base.descriptor)
def source_image():
    out=bytearray(b'\xcc'*8192)
    out[0x1fe:0x214]=bytes.fromhex('ffe34883c0010f84f600000041ffd44883c00941ff23')
    out[0x5fe:0x614]=bytes.fromhex('ffe34883c0010f84f6fcffff41ffd44883c00941ff23')
    out[0x300:0x30b]=bytes.fromhex('4883c0050f8403ffffffc3')
    return bytes(out)


def descriptions(page,root,source):
    arithmetic=(0,0x8d5,0,0,0)
    jz=lambda pc,target:ins(source[pc-page:pc-page+6].hex(),1868,
        ((target,4,0,64,1,32,0),),(0x40,0,0,0,0),flow=1,target=target,condition=4)
    rows=(ins('4883c001',249,(reg(0,64,3),imm(1,64,8)),arithmetic),
          jz(root+4,page+0x300),
          ins('4883c005',249,(reg(0,64,3),imm(5,64,8)),arithmetic),
          ins('41ffd4',759),jz(page+0x304,page+0x20d),
          ins('4883c009',249,(reg(0,64,3),imm(9,64,8)),arithmetic),
          ins('4883c009',249,(reg(0,64,3),imm(9,64,8)),arithmetic),ins('c3',396))
    return rows,((1,),(2,3),(4,),(),(6,7),(130,),(131,),())


def call(original, generated, spill, binding):
    """Literal x86 instruction/row material, independent of the C helper calls."""
    pc, next_pc = struct.unpack_from('<2Q', original)
    rows_address, image_a, image_b, heads, head, directory, window = struct.unpack('<3Q2I2Q', binding)
    reg = 12
    need(len(original) == 336 and heads == 8 and head == 3 and generated == image_a+512*head,
         'exact CALL head and complete typed domain/window binding')
    scratch = [0]+[r for r in range(1, 16) if r not in (4, 12, reg)][:3]
    a, e, t = scratch[1:]
    image, rows = bytearray(), []
    state = [0, 0, 0, 0]
    patches = []
    def emit(raw):
        at = len(image)
        rows.append((at, len(raw), *state))
        image.extend(raw)
        return at
    def displacement(at, length, target):
        return struct.pack('<i', target-(generated+at+length))
    def slot(i, load=False):
        r = scratch[i]
        at = len(image)
        emit(bytes((0x48 | ((r >> 3) << 2), 0x8B if load else 0x89,
                    5 | ((r & 7) << 3)))+displacement(at, 7, spill+8*i))
        if load:
            state[1] &= ~(1 << i)
        else:
            state[0] |= 1 << i
    def rr(op, r, m):
        emit(bytes((0x48 | ((r >> 3) << 2) | (m >> 3), op,
                    0xC0 | ((r & 7) << 3) | (m & 7))))
    def imm(r, op, value):
        emit(bytes((0x48 | (r >> 3), 0x81, 0xC0 | (op << 3) | (r & 7)))+struct.pack('<I', value))
    def absolute(r, value):
        emit(bytes((0x48 | (r >> 3), 0xB8+(r & 7)))+struct.pack('<Q', value))
    def load(r, base, offset):
        emit(bytes((0x48 | ((r >> 3) << 2) | (base >> 3), 0x8B,
                    0x40 | ((r & 7) << 3) | (base & 7), offset)))
    def branch(cc, label):
        at = emit(bytes((0x0F, 0x80+cc))+bytes(4))
        patches.append((at, label))
        return at
    def restore():
        emit(b'\x04\x7f'); state[2] = 1
        emit(b'\x9e'); state[2] = 0
        for i in (1, 2, 3, 0):
            slot(i, True)
    for i in range(4):
        slot(i)
    rr(0x89, reg, t); state[1] |= 8
    emit(b'\x9f'); state[1] |= 1; state[2] = 1
    emit(b'\x0f\x90\xc0'); state[2] = 2
    absolute(a, window); state[1] |= 2
    load(e, a, 24); state[1] |= 4
    imm(e, 0, 8); rr(0x3B, 4, e); branch(2, 'reject')
    load(e, a, 32); rr(0x3B, 4, e); branch(7, 'reject')
    absolute(a, directory); load(e, a, 8)
    imm(e, 7, 1); branch(2, 'reject')
    imm(e, 7, 256); branch(7, 'reject')
    imm(a, 0, 32)
    emit(bytes((0x48 | (e >> 3), 0xC1, 0xE0 | (e & 7), 5)))
    rr(0x03, e, a)
    loop = len(image)
    emit(bytes((0x48 | ((t >> 3) << 2) | (a >> 3), 0x3B,
                0x40 | ((t & 7) << 3) | (a & 7), 0)))
    found = branch(4, 'hit')
    imm(a, 0, 32); rr(0x3B, a, e); branch(2, 'loop')
    reject = len(image); restore()
    miss = len(image)
    emit(b'\xe9'+displacement(miss, 5, pc))
    hit = len(image); state[:] = [15, 15, 2, 0]
    load(a, a, 8)
    at = len(image)
    emit(bytes((0x48 | ((a >> 3) << 2), 0x89, 5 | ((a & 7) << 3)))+displacement(at, 7, spill+32))
    state[3] = 1; restore(); state[3] = 2
    push = len(image); emit(b'\xff\x35'+displacement(push, 6, generated+504))
    state[3] = 3
    transfer = len(image); emit(b'\xff\x25'+displacement(transfer, 6, spill+32))
    for at, label in patches:
        image[at+2:at+6] = displacement(at, 6, generated+{'reject': reject, 'hit': hit, 'loop': loop}[label])
    need((len(image), len(rows), miss, push, transfer) == (248, 46, 189, 236, 242),
         'exact fixed emitted scalar geometry')
    length = 3 if reg >= 8 else 2
    instruction = (b'\x41' if reg >= 8 else b'')+bytes((0xFF, 0xD0+(reg & 7)))
    need(original[56:56+length] == instruction and next_pc == pc+length and
         struct.unpack_from('<I', original,44)[0] == 15,
         'whole source-owned canonical CALL and complete fifteen-byte window')
    source15 = original[56:71]
    image += bytes(504-len(image))+struct.pack('<Q', pc+length)
    record = struct.pack('<16I', 1, 1, 0, 248, 46, 236, 242, 189, 504, 0, 0, 0, *scratch)
    record += b''.join(struct.pack('<6I', *row) for row in rows)+bytes(24*(64-len(rows)))
    decoded = struct.pack('<QQ10I', pc, pc+length, 1, 0, 759, 0, 16, 0, 0, 15, length, 0)+source15+b'\0'
    need(decoded == original[:72], 'whole independent CALL decode equals original graph row')
    tf = struct.pack('<QQ6I', pc, pc+length, 1, 1, 759, length, 2, 4)
    descriptor = decoded+tf+struct.pack('<8I', 1, 1, 0, 15, reg, 0, 0, 0)
    complete = record+descriptor+struct.pack('<QQ', generated, spill)+binding+image
    need(len(complete) == 2320, 'whole typed plan ABI')
    compact = record[:32]+record[48:]
    need(len(record) == 1600 and len(compact) == 1584 and
         compact[:32]+struct.pack('<4I',504,0,0,0)+compact[32:] == record,
         'exact compact CALL record reconstructs fixed literal and reserved bytes')
    return dict(image=bytes(image),description=descriptor,record=compact,full_record=record,
                whole=complete+bytes(6488-len(complete)),rows=tuple(rows),scratch_regs=tuple(scratch),
                push_offset=push,hit_offset=transfer,transfer_offset=transfer,miss_offset=miss,
                literal_offset=504,image_bytes=248,binding=binding)


def ret(original,generated,spill,binding):
    """Independent literal machine bytes, typed rows and exact full2328-byte image."""
    pc,next_pc=struct.unpack_from('<2Q',original)
    rows_address,image_a,image_b,heads,head,directory,window,landing=struct.unpack('<3Q2I3Q',binding)
    need(len(original)==336 and heads==8 and head==7 and generated==image_a+512*head and
         landing in(window+64+8*head,window+64+1024+8*head),'whole actual RET binding and distinct loaded-miss landing')
    image,rows=bytearray(),[];state=[0,0,0,0];patches=[]
    def emit(raw):
        at=len(image);rows.append((at,len(raw),*state));image.extend(raw);return at
    def disp(at,n,target):return struct.pack('<i',target-(generated+at+n))
    def slot(i,load=False):
        at=len(image);emit(bytes((0x48,0x8b if load else 0x89,5|(i<<3)))+disp(at,7,spill+8*i))
        if load:state[1]&=~(1<<i)
        else:state[0]|=1<<i
    def rr(op,r,m):emit(bytes((0x48,op,0xc0|(r<<3)|m)))
    def imm(r,op,n):emit(bytes((0x48,0x81,0xc0|(op<<3)|r))+struct.pack('<I',n))
    def absolute(r,n):emit(bytes((0x48,0xb8+r))+struct.pack('<Q',n))
    def load(r,base,offset):emit(bytes((0x48,0x8b,0x40|(r<<3)|base,offset)))
    def branch(cc,label):
        at=emit(bytes((0x0f,0x80+cc))+bytes(4));patches.append((at,label));return at
    def cell(r,offset):
        at=len(image);emit(bytes((0x48,0x89,5|(r<<3)))+disp(at,7,spill+offset))
    def restore():
        emit(b'\x04\x7f');state[2]=1;emit(b'\x9e');state[2]=0
        for i in (1,2,3,0):slot(i,True)
    for i in range(4):slot(i)
    emit(b'\x9f');state[1]|=1;state[2]=1
    emit(b'\x0f\x90\xc0');state[2]=2
    absolute(1,window);state[1]|=2
    load(2,1,24);state[1]|=4;rr(0x3b,4,2);branch(2,'before')
    load(2,1,32);rr(0x3b,4,2);branch(7,'before')
    state[3]=1;guest_load=len(image);emit(b'\x48\x8b\x1c\x24');state[1]|=8;state[3]=2
    save=len(image);cell(3,40);state[3]=3
    absolute(1,directory);load(2,1,8);imm(2,7,1);branch(2,'loaded');imm(2,7,256);branch(7,'loaded')
    imm(1,0,32);emit(b'\x48\xc1\xe2\x05');rr(0x03,2,1)
    loop=len(image);emit(b'\x48\x3b\x59\0');found=branch(4,'hit')
    imm(1,0,32);rr(0x3b,1,2);again=branch(2,'loop')
    loaded=len(image);restore();loaded_miss=len(image);emit(b'\xff\x25'+disp(loaded_miss,6,generated+504))
    before=len(image);state[:]=[15,7,2,0];restore();miss=len(image);emit(b'\xe9'+disp(miss,5,pc))
    hit=len(image);state[:]=[15,15,2,3];load(1,1,8);cell(1,32);state[3]=4;restore()
    state[3]=5;commit=len(image);emit(b'\x48\x8d\x64\x24\x08')
    state[3]=6;transfer=len(image);emit(b'\xff\x25'+disp(transfer,6,spill+32))
    labels=dict(before=before,loaded=loaded,hit=hit,loop=loop)
    for at,label in patches:image[at+2:at+6]=disp(at,6,generated+labels[label])
    need((len(image),len(rows),guest_load,save,commit,transfer,miss,loaded_miss)==(285,53,68,72,274,279,227,190),
         'exact independent full emitted geometry and all53 recovery rows')
    image+=bytes(504-len(image))+struct.pack('<Q',landing)
    record=struct.pack('<16I',1,1,0,285,53,68,72,274,279,227,190,0,0,1,2,3)
    record+=b''.join(struct.pack('<6I',*r) for r in rows)+bytes(24*(64-len(rows)))
    decoded=struct.pack('<QQ10I',pc,pc+1,1,0,396,0,16,0,0,15,1,0)+original[56:71]+b'\0'
    tf=struct.pack('<QQ6I',pc,pc+1,1,1,396,1,2,5)
    descriptor=decoded+tf+struct.pack('<8I',1,1,0,15,0,0,0,0)
    need(next_pc==pc+1 and original[56:71]==b'\xc3'+b'\xcc'*14 and decoded==original[:72],
         'whole canonical C3 descriptor and full original fifteen-byte source window')
    plan=record+descriptor+struct.pack('<QQ',generated,spill)+binding+image
    need(len(plan)==2328,'whole typed RET plan and zero padding')
    compact=record[12:44]+record[48:]
    need(len(record)==1600 and len(compact)==1584 and
         struct.pack('<3I',1,1,0)+compact[:32]+bytes(4)+compact[32:]==record,
         'entire RET compact record reconstructs fixed version/ready/result/reserved')
    return dict(image=bytes(image),description=descriptor,record=compact,full_record=record,
                whole=plan+bytes(6488-len(plan)),rows=tuple(rows),scratch_regs=(0,1,2,3),
                load_offset=guest_load,save_offset=save,commit_offset=commit,transfer_offset=transfer,
                miss_offset=miss,loaded_miss_offset=loaded_miss,image_bytes=285,binding=binding)




def graph(source,page,entry,layout,table_bytes):
    need(type(source)is bytes and len(source)==8192 and source==source_image() and
         type(page)is int and 4096<=page<(1<<47)-8192 and page%4096==0 and entry==page+0x600,
         'whole exact RET puzzle source pair including every padding byte')
    need(len(layout)==8 and all(type(v)is int and 4096<=v<1<<47 and v%4096==0 for v in layout[:7]) and layout[7] in(layout[6]+64,layout[6]+64+1024),
         'complete actual image/spill/directory/window geometry')
    extents=(32768,32768,4096,4096,4096,12288,4096)
    for i,(first,size) in enumerate(zip(layout[:7],extents,strict=True)):
        need(first+size<=1<<47 and (first+size<=page or page+8192<=first),
             'bounded private storage disjoint from both original source pages')
        for other,other_size in zip(layout[:i],extents[:i],strict=True):
            need(first+size<=other or other+other_size<=first,'complete private layout disjointness')
    need(type(table_bytes)is bytes and len(table_bytes)==4224 and struct.unpack_from('<2I',table_bytes)==(1,1),
         'complete independently modeled guard table')
    count=struct.unpack_from('<I',table_bytes,8)[0]
    table_address=struct.unpack_from('<Q',table_bytes,16)[0]
    need(0<count<=131 and table_address>=146648+4096 and table_address%8==0,
         'actual immutable table and full CALL-profile original-row binding')
    ranges=tuple(struct.unpack_from('<2Q',table_bytes,32+32*i)for i in range(count))
    need(table(ranges,table_address)==table_bytes,'entire canonical exclusion tree including unused nodes')
    a,b,stubs,slots,spill,directory,window,ret_miss=layout
    offsets=(0x600,0x604,0x300,0x60a,0x304,0x60d,0x20d,0x30a)
    rows,successors=descriptions(page,entry,source)
    originals=tuple(descriptor(row,page+off,source,off,1 if i in(3,7) else 0)
                    for i,(off,row)in enumerate(zip(offsets,rows,strict=True)))
    memory_exit=descriptor(ins('41ff23',765),page+0x611,source,0x611,1)
    old_memory_exit=descriptor(ins('41ff23',765),page+0x211,source,0x211,1)
    frontiers=(originals[3],originals[7],memory_exit,old_memory_exit)
    exit_pcs=(entry+10,page+0x30a,page+0x611,page+0x211)
    images=[bytearray(b'\xcc'*32768),bytearray(b'\xcc'*32768)]
    instructions=bytearray(128*144);guards=bytearray(128*1584)
    heads=[];call_models={};ret_models={}
    def destination(token):
        return a+512*token if token<128 else exit_pcs[token-128]
    def jump(at,target):return b'\xe9'+struct.pack('<i',target-at-5)
    for i,(off,row,succ)in enumerate(zip(offsets,rows,successors,strict=True)):
        generated=a+512*i;kind=6 if i==3 else 7 if i==7 else 1
        if kind==6:
            binding=struct.pack('<3Q2I2Q',table_address-64576,a,b,8,i,directory,window)
            model=call(originals[i],generated,spill,binding)
            body=model['image'];generated_length=model['image_bytes']
            instructions[i*144:(i+1)*144]=model['description']
            guards[i*1584:(i+1)*1584]=model['record'];call_models[i]=model
        elif kind==7:
            binding=struct.pack('<3Q2I3Q',table_address-64576,a,b,8,i,directory,window,ret_miss+8*i)
            model=ret(originals[i],generated,spill,binding)
            body=model['image'];generated_length=model['image_bytes']
            instructions[i*144:(i+1)*144]=model['description']
            guards[i*1584:(i+1)*1584]=model['record'];ret_models[i]=model
        elif row['flow']==1:
            body=bytes((15,128+row['condition']))+struct.pack('<i',destination(succ[0])-generated-6)
            body+=jump(generated+6,destination(succ[1]));generated_length=len(body)
        else:
            body=row['raw']+jump(generated+len(row['raw']),destination(succ[0]));generated_length=len(body)
        images[0][512*i:512*i+len(body)]=body
        heads.append((kind,off//4096,off%4096,len(row['raw']),len(succ),
                      succ[0]if succ else 0,succ[1]if len(succ)==2 else 0,generated_length))
    source_bytes=sum(h[3]for h in heads)
    gpr_written=flags_written=0
    for i,d in enumerate(originals):
        if heads[i][0]==1:
            gpr_written|=struct.unpack_from('<I',d,316)[0]
            for value in struct.unpack_from('<4I',d,296):flags_written|=value
    need((len(heads),source_bytes,gpr_written,flags_written)==(8,32,1,0x8d5),
         'complete BFS graph and ordinary effects before separate CALL RSP contribution')
    boundaries=(dict(index=0,head=3,arm=None,kind='call',token=128,target=None),
                dict(index=1,head=7,arm=None,kind='ret-before-load',token=129,target=None),
                dict(index=2,head=None,arm=None,kind='unsupported-memory-jump',token=130,target=None),
                dict(index=3,head=None,arm=None,kind='unsupported-memory-jump',token=131,target=None))
    # The last successful decoded_footprint is A+20d ADD. RET uses the actual
    # stack-window check without adding a guest store or fake NONE footprint.
    return dict(head=b''.join(struct.pack('<8I',*h)for h in heads)+bytes(120*32),
        original=b''.join(originals)+bytes(120*336),
        frontier=b''.join(frontiers)+bytes(4*336),instruction=bytes(instructions),guard=bytes(guards),
        image=bytes(images[0]+images[1]),stub_image=b'\xcc'*4096,edge=bytes(8*48),
        exit_pc=exit_pcs[0],exit_pc_bytes=struct.pack('<8Q',*exit_pcs,0,0,0,0),
        initial_slots=bytes(4096),terminal_slots=bytes(4096),source=source,source_bytes=source_bytes,
        heads=8,stores=1,exits=4,links=0,source_mask=1,member_heads=(8,0),offsets=offsets,
        head_rows=tuple(heads),original_rows=originals,frontier_rows=frontiers,
        guard_models={},dispatch_models={},direct_models={},call_models=call_models,ret_models=ret_models,boundary_rows=boundaries,
        gpr_written=gpr_written,call_gpr_written=16,ret_gpr_written=16,entry_gpr_written=gpr_written|16,flags_written=flags_written,
        last_none_index=6,last_none_decoded=originals[6][:72],
        last_proved_index=6,last_proved_decoded=originals[6][:72],
        last_store_index=3,last_store_scratch=call_models[3]['scratch_regs'],
        dispatch_index=None,dispatch_scratch=None,terminal_decoded=memory_exit[:72],direct_index=None,
        direct_terminal_decoded=None,direct_terminal_exit_index=None,direct_terminal_arm=None,
        call_index=3,call_scratch=call_models[3]['scratch_regs'],call_terminal_decoded=originals[3][:72],
        call_terminal_exit_index=0,ret_terminal_exit_index=1,memory_terminal_exit_index=2,ret_index=7,return_head_index=5)
