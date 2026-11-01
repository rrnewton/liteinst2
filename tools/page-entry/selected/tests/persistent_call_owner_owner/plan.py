"""Independent four-head CALL puzzle graph and complete emitted-byte model.

The unchanged donor supplies only general finite descriptor/table encoders.
The CALL model is literal x86 reconstruction, not a production emitter import.
No target register value is used to fabricate a graph edge or borrow a return
continuation: the JZ alternative independently admits B; CALL has one original
before-effect frontier. Full generated padding, literal and recovery rows remain.
"""
import importlib.util
from pathlib import Path
import struct

_path=Path(__file__).resolve().parent.parent/'persistent_direct_frontier_owner'/'plan.py'
_spec=importlib.util.spec_from_file_location('call_puzzle_plan_primitives',_path)
base=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
need,table,reg,imm,ins,descriptor=(base.need,base.table,base.reg,base.imm,base.ins,base.descriptor)
OFFSETS=(0x200,0x204,0x300,0x20a)


def source_image():
    out=bytearray(b'\xcc'*8192)
    out[0x1fe:0x20d]=bytes.fromhex('ffe34883c0010f84f600000041ffd4')
    out[0x300:0x307]=bytes.fromhex('4883c00541ff23')
    return bytes(out)


def descriptions(page):
    arithmetic=(0,0x8d5,0,0,0)
    rows=(ins('4883c001',249,(reg(0,64,3),imm(1,64,8)),arithmetic),
          ins('0f84f6000000',1868,((page+0x300,4,0,64,1,32,0),),
              (0x40,0,0,0,0),flow=1,target=page+0x300,condition=4),
          ins('4883c005',249,(reg(0,64,3),imm(5,64,8)),arithmetic),
          ins('41ffd4',759))
    return rows,((1,),(2,3),(129,),())


def call(original, generated, spill, binding):
    """Literal x86 instruction/row material, independent of the C helper calls."""
    pc, next_pc = struct.unpack_from('<2Q', original)
    rows_address, image_a, image_b, heads, head, directory, window = struct.unpack('<3Q2I2Q', binding)
    reg = 12
    need(len(original) == 336 and heads == 4 and head == 3 and generated == image_a+512*head,
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


def graph(source,page,entry,layout,table_bytes):
    need(type(source)is bytes and len(source)==8192 and source==source_image() and
         type(page)is int and 4096<=page<(1<<47)-8192 and page%4096==0 and entry==page+0x200,
         'whole exact CALL puzzle source pair including every padding byte')
    need(len(layout)==7 and all(type(v)is int and 4096<=v<1<<47 and v%4096==0 for v in layout),
         'complete actual image/spill/directory/window geometry')
    extents=(32768,32768,4096,4096,4096,12288,4096)
    for i,(first,size) in enumerate(zip(layout,extents,strict=True)):
        need(first+size<=1<<47 and (first+size<=page or page+8192<=first),
             'bounded private storage disjoint from both original source pages')
        for other,other_size in zip(layout[:i],extents[:i],strict=True):
            need(first+size<=other or other+other_size<=first,'complete private layout disjointness')
    need(type(table_bytes)is bytes and len(table_bytes)==4224 and struct.unpack_from('<2I',table_bytes)==(1,1),
         'complete independently modeled guard table')
    count=struct.unpack_from('<I',table_bytes,8)[0]
    table_address=struct.unpack_from('<Q',table_bytes,16)[0]
    need(0<count<=131 and table_address>=146640+4096 and table_address%8==0,
         'actual immutable table and full CALL-profile original-row binding')
    ranges=tuple(struct.unpack_from('<2Q',table_bytes,32+32*i)for i in range(count))
    need(table(ranges,table_address)==table_bytes,'entire canonical exclusion tree including unused nodes')
    a,b,stubs,slots,spill,directory,window=layout
    rows,successors=descriptions(page)
    originals=tuple(descriptor(row,page+off,source,off,1 if i==3 else 0)
                    for i,(off,row)in enumerate(zip(OFFSETS,rows,strict=True)))
    memory_exit=descriptor(ins('41ff23',765),page+0x304,source,0x304,1)
    frontiers=(originals[3],memory_exit)
    exit_pcs=(page+0x20a,page+0x304)
    images=[bytearray(b'\xcc'*32768),bytearray(b'\xcc'*32768)]
    instructions=bytearray(128*144);guards=bytearray(128*1584)
    heads=[];call_models={}
    def destination(token):
        return a+512*token if token<128 else exit_pcs[token-128]
    def jump(at,target):return b'\xe9'+struct.pack('<i',target-at-5)
    for i,(off,row,succ)in enumerate(zip(OFFSETS,rows,successors,strict=True)):
        generated=a+512*i;kind=6 if i==3 else 1
        if kind==6:
            binding=struct.pack('<3Q2I2Q',table_address-64576,a,b,4,i,directory,window)
            model=call(originals[i],generated,spill,binding)
            body=model['image'];generated_length=model['image_bytes']
            instructions[i*144:(i+1)*144]=model['description']
            guards[i*1584:(i+1)*1584]=model['record'];call_models[i]=model
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
    need((len(heads),source_bytes,gpr_written,flags_written)==(4,17,1,0x8d5),
         'complete BFS graph and ordinary effects before separate CALL RSP contribution')
    boundaries=(dict(index=0,head=3,arm=None,kind='call',token=128,target=None),
                dict(index=1,head=None,arm=None,kind='unsupported-memory-jump',token=129,target=None))
    # The last successful decoded_footprint is B ADD. The later CALL head uses
    # li2_pg_call_window_check; it must never be modeled as a guest NONE write.
    return dict(head=b''.join(struct.pack('<8I',*h)for h in heads)+bytes(124*32),
        original=b''.join(originals)+bytes(124*336),
        frontier=b''.join(frontiers)+bytes(6*336),instruction=bytes(instructions),guard=bytes(guards),
        image=bytes(images[0]+images[1]),stub_image=b'\xcc'*4096,edge=bytes(8*48),
        exit_pc=exit_pcs[0],exit_pc_bytes=struct.pack('<8Q',*exit_pcs,0,0,0,0,0,0),
        initial_slots=bytes(4096),terminal_slots=bytes(4096),source=source,source_bytes=source_bytes,
        heads=4,stores=1,exits=2,links=0,source_mask=1,member_heads=(4,0),offsets=OFFSETS,
        head_rows=tuple(heads),original_rows=originals,frontier_rows=frontiers,
        guard_models={},dispatch_models={},direct_models={},call_models=call_models,boundary_rows=boundaries,
        gpr_written=gpr_written,call_gpr_written=16,entry_gpr_written=gpr_written|16,flags_written=flags_written,
        last_none_index=2,last_none_decoded=originals[2][:72],
        last_proved_index=2,last_proved_decoded=originals[2][:72],
        last_store_index=3,last_store_scratch=call_models[3]['scratch_regs'],
        dispatch_index=None,dispatch_scratch=None,terminal_decoded=memory_exit[:72],direct_index=None,
        direct_terminal_decoded=None,direct_terminal_exit_index=None,direct_terminal_arm=None,
        call_index=3,call_scratch=call_models[3]['scratch_regs'],call_terminal_decoded=originals[3][:72],
        call_terminal_exit_index=0,memory_terminal_exit_index=1)
