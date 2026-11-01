"""Independent full DIRECT bytes for source-rebuilt historical policy12 arms.

The fixed common body and boundary rows derive from the existing independent
37/39/40-row models. The caller reconstructs source, graph, binding and target
identities first; this module does not use a captured mask as authority.
"""
import struct

def need(ok,why):
    if not ok:raise ValueError(why)

def emit(original,generated,spill,binding,external,internal):
    pc,next_pc=struct.unpack_from('<2Q',original)
    target=struct.unpack_from('<Q',original,72)[0]
    available=struct.unpack_from('<I',original,44)[0]
    rows_address,a,b,heads,head,directory=struct.unpack('<3Q2IQ',binding)
    flow,condition=struct.unpack_from('<2I',original,268)
    conditional=flow==1;single=conditional and external in(1,2)
    need(type(original)is bytes and len(original)==336 and type(binding)is bytes and len(binding)==40 and
         1<=heads<=128 and 0<=head<heads and flow in(1,2)and
         ((condition<16 and external in(1,2,3))if conditional else(condition==16 and external==1))and
         generated==(a,b)[head//64]+512*(head%64)and rows_address>=4096 and a!=b and
         all(type(x)is int and 4096<=x<1<<47 for x in(rows_address,a,b,spill,directory))and
         type(internal)is tuple and len(internal)==2,'complete independently joined DIRECT binding')
    for arm in range(2):
        need((internal[arm]==0)if arm>=(2 if conditional else 1)or external&(1<<arm)
             else 4096<=internal[arm]<1<<47,'internal target only for an actual internal arm')
    desc=original[:72]+struct.pack('<2Q8I',target,next_pc if conditional else 0,
        1,1,0,available,flow,condition,external,0)
    save=lambda r:bytes((0x48,0x89,5|(r<<3)))+bytes(4)
    load=lambda r:bytes((0x48,0x8b,5|(r<<3)))+bytes(4)
    branch=lambda c:b'\xe9'+bytes(4)if c==16 else bytes((15,128+c))+bytes(4)
    absolute=lambda reg,value:bytes((0x48,0xb8+reg))+struct.pack('<Q',value)
    restore=(b'\x04\x7f',b'\x9e',load(1),load(2),load(3),load(0))
    pieces=([branch(condition^(1 if external==2 else 0)),branch(16)]if single else[])+[save(r)for r in range(4)]
    states=([(0,0,0,0),(0,0,0,0)]if single else[])+[(0,0,0,0),(1,0,0,0),(3,0,0,0),(7,0,0,0)]
    if conditional and not single:
        pieces += [branch(condition),absolute(3,next_pc),branch(16),absolute(3,target)]
        states += [(15,0,0,0),(15,0,0,0),(15,8,0,0),(15,0,0,0)]
    else:
        pieces += [absolute(3,next_pc if external==2 else target)];states += [(15,0,0,0)]
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
    for i in range(4):rel(i+(2 if single else 0),spill+8*i)
    if single:rel(0,generated+11);rel(1,internal[1 if external==1 else 0])
    elif conditional:
        rel(4,generated+offsets[7]);rel(6,generated+offsets[start])
    for index,dest in((start+5,rejected),(start+7,rejected),(start+12,hit),(start+15,start+11)):
        rel(index,generated+offsets[dest])
    for begin in(rejected+2,hit+4):
        for i,slot in enumerate((1,2,3,0)):rel(begin+i,spill+8*slot)
    rel(rejected+6,pc);rel(hit+1,spill+32);rel(hit+8,spill+32)
    boundary=tuple((off,len(piece),*state)for off,piece,state in zip(offsets,pieces,states,strict=True))
    miss_offset=offsets[rejected+6];hit_offset=offsets[hit+8]
    need((len(code),len(boundary),miss_offset,hit_offset)==((217,39,164,211)if single else(227,40,174,221)if conditional else(206,37,153,200)),
        'literal full direct byte and recovery-boundary extents')
    record=struct.pack('<12I',1,1,0,len(code),len(boundary),hit_offset,miss_offset,0,0,1,2,3)
    record+=b''.join(struct.pack('<6I',*row)for row in boundary)+bytes((64-len(boundary))*24)
    whole=record+desc+struct.pack('<2Q',generated,spill)+binding+struct.pack('<2Q',*internal)+code+bytes(512-len(code))
    need(len(desc)==120 and len(record)==1584 and len(whole)==2288,'exact typed direct descriptor/record/adapter')
    return dict(image=bytes(code),description=desc,record=record,whole=bytes(whole),
        rows=boundary,scratch_regs=(0,1,2,3),hit_offset=hit_offset,miss_offset=miss_offset,
        external_mask=external,targets=(target,next_pc if conditional else 0),internal=internal)
