"""Independent finite two-page semantics and complete actual frame checks.

Source candidate: real qualification awaits composed review and execution.
Existing registered-native and boundary readers are unchanged.
"""
import hashlib
import importlib.util
import json
import re
import struct
from pathlib import Path
from page_selected import need

_SPEC = importlib.util.spec_from_file_location(
    'native_pair_old_frame', Path(__file__).resolve().parent.parent/'rseq_native/check.py')
old = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(old)
q, word, put = old.q, old.word, old.put
GREG, VECTORS, MASKS = old.GREG, old.VECTORS, old.MASKS
MAIN = 0x200401000
HELPER, BODY, TAIL, GUARD, REFERENCE, DATA = (MAIN+n*4096 for n in (1,2,3,4,5,7))
ARENA, PAGE, AREA, WORD = old.ARENA, old.PAGE, old.AREA, old.WORD
LEDGER, START, CLOSE = DATA+12288, MAIN+3072, MAIN+3104
MAGIC = 0x31524941504e534c
SOURCE_BYTES, DATA_BYTES, FRAME_BYTES = 28672, 16384, 117248
ROWS, STAGES = 12, 24
U64 = (1 << 64)-1
# This composed release reserves SIGILL for its reusable patch landing.
PAIR_MASK = U64 & ~sum(1 << (s-1) for s in (4,5,11,31,9,19))


def exact_shape(types, name, fields, alignment=8):
    """Authenticate minimal source-required alignment; retain every padding byte."""
    shape = types[name]
    need(set(shape['fields']) == set(fields) and shape['alignment'] == alignment,
         'exact field inventory and aggregate alignment '+name)
    at = 0
    gaps = []
    for key, spec in fields.items():
        size, align = spec if type(spec) is tuple else (spec,8)
        need(type(size) is int and size > 0 and align in (1,2,4,8,64),
             'source-defined extent and alignment '+name+'.'+key)
        offset = (at+align-1)&~(align-1)
        field = shape['fields'][key]
        need(set(field) == {'offset','bytes','alignment','type'} and
             (field['offset'],field['bytes'],field['alignment']) == (offset,size,align) and
             type(field['type']) is str and bool(field['type']),
             'actual minimally aligned field '+name+'.'+key)
        if offset != at:gaps.append((at,offset))
        at = offset+size
    extent = (at+alignment-1)&~(alignment-1)
    if extent != at:gaps.append((at,extent))
    need(shape['bytes'] == extent, 'complete record extent '+name)
    return gaps


class Reader(old.Reader):
    def __init__(self, data, layout, record):
        self.data, self.types, self.layout = data, layout['types'], layout
        self.rt = self.types[record]
        self.ft = self.types['rn_frame']
        self.padding = {}
        self.ucn = layout['uc_bytes']
        self.go = layout['offsets']['greg']
        self.fo = layout['offsets']['fp_pointer']
        need(record in ('npf_native_record','npf_record') and
             layout['record'] == record and len(data) == self.rt['bytes'] < 16 << 20 and
             0 < self.ucn <= 2048 and self.go+23*8 <= self.ucn and self.fo+8 <= self.ucn,
             'complete actual two-page record and DWARF extent')
        need(layout['siginfo'] == dict(bytes=128,
             offsets=dict(si_signo=0, si_errno=4, si_code=8, si_addr=16, si_pid=16, si_uid=20),
             widths=dict(si_signo=4, si_errno=4, si_code=4, si_addr=8, si_pid=4, si_uid=4)),
             'complete native x86-64 signal-info ABI')
        def shape(name,fields,align=8):
            self.padding[id(self.types[name])] = exact_shape(self.types,name,fields,align)
        self.shape = shape
        shape('rn_frame', dict(h=512, uc=(2048,1), fp=(65536,1),
                    source=(SOURCE_BYTES,1), data=(DATA_BYTES,1), rseq=(4096,1)))
        need(self.ft['bytes'] == FRAME_BYTES, 'exact full frame bytes')
        if record == 'npf_native_record':
            need(layout['member_witnesses'] == {}, 'native observer has no invented product alignment witness')
            shape('npf_native_row', dict(h=256, permissions=128,
                signal_before=(128,1), signal_after=(128,1), before=FRAME_BYTES, after=FRAME_BYTES))
            shape(record, dict(h=512,xstate=128,
                rows=ROWS*self.types['npf_native_row']['bytes']))
            need(len(data) == 2822272, 'exact native observer record extent')
        else:
            need(layout['member_witnesses'] == {'li2_step_frame.fp': dict(
                 symbol='npf_step_frame_fp_alignment',bytes=8,alignment=64)},
                 'actual emitted compiler member-alignment witness')
            shape('li2_step_frame',dict(greg=23*8,mask=8,fp_address=8,fp_bytes=8,
                  initialized=8,fp=(65536,64)),64)
            size = lambda name:self.types[name]['bytes']
            pair, life, rseq = map(size, ('li2_native_pair_progress',
                'li2_native_pair_lifecycle','li2_rseq_pair_progress'))
            state, close = map(size, ('li2_rseq_state','li2_native_close'))
            shape('npf_row', dict(h=256,permits=384,
                signal_before=(128,1),signal_after=(128,1),before=FRAME_BYTES,after=FRAME_BYTES,
                guard_before=FRAME_BYTES,guard_after=FRAME_BYTES,pair_before=(pair,64),pair_after=(pair,64),
                life_before=life,life_after=life,rseq_before=rseq,rseq_after=rseq,
                guard_state=state,close=close),64)
            shape('npf_stage', dict(h=128,life=life,rseq=rseq,close=close))
            shape(record, dict(h=512,xstate=128,hardware=(size('li2_selected_hardware'),4),
                rows=(ROWS*size('npf_row'),64),stages=STAGES*size('npf_stage'),control=512,
                publication_frame=FRAME_BYTES,terminal_frame=FRAME_BYTES,
                nested_outer_frame=FRAME_BYTES,nested_outer_signal=(128,1),
                terminal_pair=(pair,64),terminal_life=life,terminal_rseq_pair=rseq,
                terminal_rseq=state,terminal_close=close,terminal_source=(SOURCE_BYTES,1),
                terminal_data=(DATA_BYTES,1),terminal_page=(4096,1)),64)

    def field(self,data,shape,name):
        shape = self.types[shape] if isinstance(shape,str) else shape
        need(len(data) == shape['bytes'], 'whole typed captured object extent')
        for first,end in self.padding.get(id(shape),()):
            need(not any(data[first:end]), 'all source-required alignment padding is zero')
        return super().field(data,shape,name)

    def envelope(self,f,lo,cap,native):
        need(type(lo)is int and lo>0 and cap==(131072 if native else 512*1024) and lo<=f['h'][3]<=lo+cap-self.ucn and
          lo<=word(f['uc'],self.fo)<=lo+cap-f['h'][2],'actual UC/FP pointers in the observed installed altstack')
        o=self.layout['offsets'];mask=PAIR_MASK
        need(word(f['uc'],o['stack_sp'])==lo and word(f['uc'],o['stack_size'])==cap and struct.unpack_from('<I',f['uc'],o['stack_flags'])[0]==0 and
          word(f['uc'],o['mask'])==mask and f['greg'][21]==mask,'actual altstack and exact pre-delivery application mask')

    def frame(self, data, image):
        h = q(self.field(data,self.ft,'h'))
        uc, fp = (self.field(data,self.ft,n) for n in ('uc','fp'))
        need(h[:2] == (1,self.ucn) and 512 <= h[2] <= 65536 and h[3] > 0 and
             h[4:8] == (11,11,2,0) and h[11] == 0 and not any(h[12:]),
             'genuine complete SEGV prefix and actual zero word')
        need(not any(uc[self.ucn:]) and not any(fp[h[2]:]) and word(uc,self.fo) > 0,
             'full UC/initialized FP and exact unused payload tails')
        if h[2] > 512:
            need(struct.unpack_from('<I',fp,464)[0] == 0x46505853 and
                 struct.unpack_from('<I',fp,468)[0] == h[2] and
                 struct.unpack_from('<I',fp,h[2]-4)[0] == 0x46505845 and word(fp,520) == 0,
                 'actual standard signal XSAVE envelope')
        source, memory, page = (self.field(data,self.ft,n) for n in ('source','data','rseq'))
        need(source == bytes.fromhex(image['source_hex']), 'entire unchanged source including both observer pages')
        ids = page_ids(page, image['case'] >= 2)
        need(memory[512:2624] == VECTORS+MASKS, 'independent complete vector/mask seed')
        g = q(uc[self.go:self.go+23*8])
        need(g[20] == 14 and g[22] == h[8] and g[18] == 0x002b000000000033 and
             g[17]&0x10000 and not g[17]&0x100,
             'actual saved fault registers, selectors, RF and no TF')
        return dict(h=h,uc=uc,fp=fp,data=memory,page=page,greg=g,raw=data,kernel_ids=ids)

    def signal(self, row, row_type, frame):
        v = q(self.field(row,row_type,'h'))
        before, after = (self.field(row,row_type,n) for n in ('signal_before','signal_after'))
        need(v[24] == v[25] > 0 and v[26:28] == (128,16),
             'actual signal-info pointer and complete ABI observations')
        expected = bytearray(128)
        struct.pack_into('<iii',expected,0,frame['h'][5],frame['h'][7],frame['h'][6])
        put(expected,16,frame['h'][8])
        need(before == after == expected, 'entire signal-info unchanged including padding/union')
        offset = v[24]-frame['h'][3]
        need(offset == self.layout['offsets']['mask']+8 and 0 <= offset <= self.ucn-128 and
             frame['uc'][offset:offset+128] == expected,
             'actual full signal-info alias following kernel ucontext mask')
        return offset+16

    def seeded_vectors(self, frame, components):
        fp = frame['fp']
        need(frame['h'][9:11] == (0,0) and word(fp,512)&0xe7 == 0xe7 and
             all(o+n <= frame['h'][2]-4 for o,n in components.values()),
             'real zero TLS selectors and complete seeded XSTATE components')
        for reg in range(32):
            if reg < 16:
                z = fp[160+reg*16:176+reg*16]
                offset = components[2][0]+reg*16
                z += fp[offset:offset+16]
                offset = components[6][0]+reg*32
                z += fp[offset:offset+32]
            else:
                offset = components[7][0]+(reg-16)*64
                z = fp[offset:offset+64]
            need(z == VECTORS[reg*64:reg*64+64], 'every original ZMM byte')
        offset, count = components[5]
        need(fp[offset:offset+count] == MASKS, 'every original mask-register byte')


def page_ids(page, registered):
    need(type(registered) is bool and len(page) == 4096, 'exact page/registration profile')
    if registered:
        return old.page_ids(page)
    need(not any(page), 'whole unregistered anonymous page remains zero')
    return None


def iterations(case):
    need(type(case) is int and 0 <= case <= 20, 'fixed finite case')
    return 1 if case in (3,19) else 32


def initial_registers(case):
    r = [0x1122334455667700+i for i in range(16)]
    r[1],r[4],r[7],r[8] = iterations(case),DATA+16320,AREA,LEDGER
    if case == 10:r[15] = ARENA
    return r


def arithmetic_flags(a,b,result,operation,bits=64,carry=0):
    """x86 arithmetic flags; IF/DF and reserved bit retain the original seed."""
    mask = (1 << bits)-1
    a,b,result = a&mask,b&mask,result&mask
    sign = 1 << (bits-1)
    need(operation in ('add','sub','xor','dec'), 'independent finite arithmetic operation')
    if operation == 'add':
        cf = int(a+b > mask)
        of = int(bool((~(a^b)&(a^result))&sign))
        af = int(bool((a^b^result)&16))
    elif operation in ('sub','dec'):
        cf = carry if operation == 'dec' else int(a < b)
        of = int(bool(((a^b)&(a^result))&sign))
        af = int(bool((a^b^result)&16))
    else:
        # XOR's AF is architecturally undefined and is not used as an
        # independently predicted endpoint; the following ADD overwrites it.
        need(False, 'XOR alone requires actual full native/gated flag equality')
    return 0x602|cf|((int((result&255).bit_count()%2 == 0))<<2)|(af<<4)|\
           (int(result == 0)<<6)|(int(bool(result&sign))<<7)|(of<<11)


def ledger(case, calls, decs=None):
    """Expected registers/ledger after complete CALL/RET iterations only."""
    need(type(calls) is int and 0 <= calls <= iterations(case)+(case == 9),
         'bounded actual source-defined call count')
    decs = min(calls,iterations(case)) if decs is None else decs
    need(type(decs) is int and 0 <= decs <= min(calls,iterations(case)) and calls-decs <= 1,
         'exact completed leaf calls versus executed loop decrements')
    r = initial_registers(case)
    values = []
    flags = 0xed7
    for index in range(calls):
        r[0] = ((r[0]<<1)|(r[0]>>63))&U64
        r[0] = ((r[0]^r[14])+r[3])&U64
        r[3] ^= 0x5a5a
        values.append(r[0])
        before = r[8]
        r[8] += 8
        flags = arithmetic_flags(before,8,r[8],'add')
        if index < decs:
            before = r[1]
            r[1] = (before-1)&0xffffffff
            flags = arithmetic_flags(before,1,r[1],'dec',32,flags&1)
    return r,flags,values


def elf(data, interpreter, case, control, native_policy):
    """Bind actual complete source/data and literal puzzle geometry."""
    iterations(case)
    need(type(control) is int and control in (0,1) and (case == 16 or control == 0),
         'fixed explicit finite subcontrol')
    need(type(data) is bytes and len(data) >= 64, 'complete actual fixture ELF')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (2,62,1) and
         h[4] == MAIN and h[8:10] == (64,56) and h[11] == 64, 'actual fixed high ET_EXEC')
    def extent(first,count):
        need(type(first) is int and type(count) is int and
             0 <= first <= len(data) and 0 <= count <= len(data)-first, 'actual file extent')
        return data[first:first+count]
    ph = [struct.unpack('<IIQQQQQQ',extent(h[5]+56*i,56)) for i in range(h[10])]
    loads = [p for p in ph if p[0] == 1]
    need(len(loads) == 3 and [p[1] for p in loads] == [4,5,6] and
         loads[0][2:4] == (0,MAIN-4096) and loads[0][5] <= 4096 and
         loads[1][2:4] == (4096,MAIN) and loads[1][5:7] == (SOURCE_BYTES,SOURCE_BYTES) and
         loads[2][3] == DATA and loads[2][5] >= DATA_BYTES and
         all(p[7] == 4096 and p[5] <= p[6] for p in loads) and not any(p[0] == 7 for p in ph),
         'three actual disjoint domains and no TLS image')
    ip = [p for p in ph if p[0] == 3]
    need(len(ip) == 1 and extent(ip[0][2],ip[0][5]) == str(interpreter).encode()+b'\0',
         'exact actual interpreter path')
    ss = [struct.unpack('<IIQQQQIIQQ',extent(h[6]+64*i,64)) for i in range(h[12])]
    need(not any(s[1] in (4,9) and s[5] for s in ss), 'no source relocations or per-lane code fixups')
    tables = [s for s in ss if s[1] == 2]
    need(len(tables) == 1 and tables[0][9] == 24, 'one complete actual symbol table')
    table = tables[0]
    strings = ss[table[6]]
    names = extent(strings[4],strings[5])
    symbols, symbol_sizes = {}, {}
    for at in range(table[4],table[4]+table[5],24):
        n,info,other,index,value,size = struct.unpack('<IBBHQQ',extent(at,24))
        if n and info&15 != 4:
            need(n < len(names) and b'\0' in names[n:], 'bounded symbol string')
            name = names[n:names.index(b'\0',n)].decode()
            need(name not in symbols, 'unique actual named symbol')
            symbols[name] = value
            symbol_sizes[name] = size
    need(symbol_sizes.get('npf_altstack') == 131072 and
         symbols['npf_altstack'] % 64 == 0 and
         loads[2][3]+DATA_BYTES <= symbols['npf_altstack'] and
         symbols['npf_altstack']+131072 <= loads[2][3]+loads[2][6],
         'actual fixed native altstack symbol and entire separate writable extent')
    def read(address,count):
        matches = [p for p in loads if p[3] <= address and address+count <= p[3]+p[5]]
        need(len(matches) == 1, 'one actual file-backed source extent')
        p = matches[0]
        return extent(p[2]+address-p[3],count)
    expected = dict(_start=MAIN,rn_seed=HELPER,rn_body=BODY,rn_tail=TAIL,rn_guard=GUARD,
        rn_data=DATA,rn_data_end=DATA+DATA_BYTES,rn_case=DATA+8,rn_mode=DATA+16,
        rn_active=DATA+24,rn_registration_result=DATA+32,rn_rounds=DATA+40,
        rn_commit=DATA+48,rn_abort_seen=DATA+56,rn_final_fs=DATA+64,rn_final_gs=DATA+72,
        rn_call_return=DATA+80,rn_call_rsp=DATA+88,npf_control=DATA+96,rn_store=DATA+128,
        rn_descriptor=DATA+256,rn_vectors=DATA+512,rn_masks=DATA+2560,
        rn_live_vectors=DATA+4096,rn_live_masks=DATA+6144,rn_live_gpr=DATA+6208,
        rn_live_flags=DATA+6336,rn_live_selectors=DATA+6344,rn_rseq_initial=DATA+8192,
        npf_ledger=LEDGER,rn_stack_top=DATA+16320,npf_start_gate=START,npf_close_gate=CLOSE,
        rn_after_call=BODY+6,rn_b=BODY+128 if case == 0 else TAIL if case == 3 else GUARD+(case == 19),
        npf_c=TAIL+32 if case in (4,5,6) else TAIL+(3 if case == 9 else 1 if case in (7,8) else 0))
    need(all(symbols.get(k) == v for k,v in expected.items()), 'exact full source/data/stack/ledger geometry')
    source, initial = read(MAIN,SOURCE_BYTES),read(DATA,DATA_BYTES)
    need(q(initial[:104]) == (MAGIC,case,0,0,U64,0,0,0,0,0,0,0,control) and
         initial[512:2624] == VECTORS+MASKS and not any(initial[12288:12288+264]),
         'literal independent scalar/vector/mask/ledger initial state')
    need(read(symbols['rn_setup_syscall'],2 if case >= 2 else 1) ==
         (bytes.fromhex('0f05') if case >= 2 else b'\x90'), 'actual registered or unregistered setup')
    need(read(BODY,2) == bytes.fromhex('90e8') and read(BODY+6,4) == bytes.fromhex('ffc975f7') and
         BODY+6+struct.unpack('<i',read(BODY+2,4))[0] == symbols['rn_b'],
         'real first-A NOP fallback and fixed original CALL/DEC/JNE loop')
    leaf = bytes.fromhex('48d1c04c31f04801d84881f35a5a00004989004983c008c3')
    b = symbols['rn_b']
    if case == 9:
        need(read(b,1) == b'\x90', 'real split-CALL callee entry NOP');b += 1
    need(read(b,len(leaf)) == leaf, 'complete source-defined noncommutative leaf and real RET')
    def direct_jump(pc,target):
        need(read(pc,1) == b'\xe9' and pc+5+struct.unpack('<i',read(pc+1,4))[0] == target,
             'exact unmodified original direct continuation')
    need(read(START,1) == read(CLOSE,1) == b'\x90', 'real dirty-page baseline/close NOPs')
    direct_jump(START+1,BODY);direct_jump(CLOSE+1,symbols['rn_capture'])
    need(native_policy(read(HELPER-14,4124)) == 0 and native_policy(read(BODY-14,4124)) == 0 and
         native_policy(read(MAIN,4096)) != 0, 'unchanged actual source and halo policy')
    if case != 0:
        page = symbols['rn_b']&~4095
        need((native_policy(read(page-14,4124)) != 0) == (case == 19),
             'full B page/halos; actual cross-edge selected core remains blocked')
    if case == 19:
        need(read(GUARD-1,2) == bytes.fromhex('0fa2'), 'actual CPUID straddles the B admission halo')
    if case in (7,8,9):
        fault = TAIL-2
        start = TAIL-6 if case == 7 else fault
        after = TAIL+(3 if case == 9 else 1)
        abort = TAIL-14 if case == 7 else BODY+256
        need(symbols['rn_fault'] == fault and symbols['rn_cs_start'] == start and
             symbols['rn_cs_end'] == after and symbols['rn_return'] == after and
             symbols['rn_abort'] == abort and read(abort-4,4) == bytes.fromhex('53300553') and
             struct.unpack_from('<IIQQQ',initial,256) == (0,0,start,after-start,abort) and
             not start <= abort < after, 'exact current-PC, descriptor and abort boundary geometry')
        need(read(fault,5 if case == 9 else 3) == bytes.fromhex('e8fd0f0000' if case == 9 else '4889c3'),
             'exact real split CALL or MOV bytes')
        direct_jump(abort,CLOSE)
        if case == 7:need(read(start,4) == bytes.fromhex('48894708'), 'real publication in the registered interval')
    need(read(symbols['rn_restorer'],9) == bytes.fromhex('b80f0000000f050f0b'), 'actual kernel rt_sigreturn restorer')
    interp = interpreter.read_bytes()
    ih = struct.unpack_from('<16sHHIQQQIHHHHHH',interp)
    entry = bytes.fromhex('0fa248b8')+struct.pack('<Q',MAIN)+bytes.fromhex('ffe0')
    need(len(interp) == 8192 and ih[1:4] == (3,62,1) and ih[4] == 4096 and
         interp[4096:4096+len(entry)] == entry and not any(interp[4096+len(entry):]),
         'actual first-interpreter CPUID and original handoff')
    policies = {page:native_policy(read(page-(14 if page > MAIN else 0),
        4096+(14 if page > MAIN else 0)+(14 if page+4096 < MAIN+SOURCE_BYTES else 0)))
        for page in range(MAIN,MAIN+SOURCE_BYTES,4096)}
    return dict(case=case,control=control,spec=profile(case,control),entry=MAIN,symbols=symbols,
        original_bytes=len(data),page_policy=policies,
        source_hex=source.hex(),data_hex=initial.hex(),
        source_sha256=hashlib.sha256(source).hexdigest(),data_sha256=hashlib.sha256(initial).hexdigest())


def modeled_application(image, pc, calls, decs, pushed, pid, leaf0, af):
    """Independent complete scalar effects at a declared application boundary.

    Only XOR's architecturally undefined AF is supplied from the separately
    retained native observation; the full native/gated flags still must match.
    No other register or flag is exempted from this model.
    """
    c = image['case'];sy = image['symbols']
    need(type(pushed) is bool and type(pid) is int and pid > 0 and
         type(af) is int and af in (0,16) and len(leaf0) == 4 and
         all(type(v) is int and 0 <= v < 1 << 32 for v in leaf0),
         'typed actual process/CPUID identity and native AF observation')
    r,flags,values = ledger(c,calls,decs)
    if pushed:r[4] -= 8
    if calls == iterations(c) and decs == iterations(c):
        if c == 4 and pc == CLOSE:
            r[2] = (r[2]^0x10203040)&0xffffffff
            flags = 0x602|af|(int((r[2]&255).bit_count()%2 == 0)<<2)|\
                    (int(r[2] == 0)<<6)|(int(bool(r[2]&(1 << 31)))<<7)
        elif c in (5,6):
            r[0],r[1] = (0 if c == 5 else 39),0
            if pc in (sy['npf_c']+2,CLOSE):
                if c == 5:r[0],r[3],r[1],r[2] = leaf0
                else:r[0],r[1],r[11] = pid,sy['npf_c']+2,flags
        elif c == 7:
            r[0] = DATA+256
        elif c == 8 and pc in (sy['rn_return'],CLOSE):
            r[3] = r[0]
    need(af == (flags&16) if c != 4 or pc != CLOSE else True,
         'only the actual XOR endpoint has undefined independently predicted AF')
    return r,flags,values


def modeled_memory(image, native, page, pc, calls, decs, pushed, pid, leaf0, af,
                   terminal=False):
    """Every original data/stack byte, including retained CALL return words."""
    c = image['case'];sy = image['symbols']
    need(type(native) is bool and type(terminal) is bool, 'literal lane and terminal kinds')
    page_ids(page,c >= 2)
    r,flags,values = modeled_application(image,pc,calls,decs,pushed,pid,leaf0,af)
    b = bytearray.fromhex(image['data_hex'])
    for offset,value in ((16,int(native)),(24,1),(32,0 if c >= 2 else U64),
                         (40,int(terminal))):put(b,offset,value)
    b[8192:12288] = page
    for i,value in enumerate(values):put(b,12288+8*i,value)
    # PUSHFQ/POPFQ in the literal seed writes one word below the stack top.
    # Every real CALL overwrites that exact slot; RET never erases it.
    stack_word = 0xed7
    if calls or pushed:stack_word = sy['rn_after_call']
    if c == 9 and (calls == 33 or pushed and calls == 32):stack_word = sy['rn_return']
    if terminal:
        need(not pushed and calls == iterations(c)+(c == 9) and
             decs == iterations(c) and pc == CLOSE, 'complete final original control flow')
        b[4096:6208] = VECTORS+MASKS
        b[6208:6336] = struct.pack('<16Q',*r)
        put(b,6336,flags)
        b[6344:6356] = struct.pack('<6H',0x33,0x2b,0,0,0,0)
        put(b,64,DATA+2048);put(b,72,DATA+2304)
        # The original capture's PUSHFQ writes the actual post-loop flags.
        stack_word = flags
    put(b,16312,stack_word)
    return bytes(b),r,flags


EXPECTED_SHA256 = '034f0d5890f7d0c317c8270902b6966bcbfe4db688ae05850ae060a529be9124'


def profile(case,control):
    raw = Path(__file__).with_name('expected.json').read_bytes()
    need(hashlib.sha256(raw).hexdigest() == EXPECTED_SHA256,
         'entire fixed source-reviewed finite event catalogue')
    table = json.loads(raw)
    rows = table['cases']
    need([(r['case'],r['control']) for r in rows] ==
         [(c,k) for c in range(21) for k in (range(2) if c == 16 else range(1))],
         'all twenty-two literal finite profiles')
    found = [r for r in rows if (r['case'],r['control']) == (case,control)]
    need(len(found) == 1, 'one exact finite profile')
    row = found[0]
    return dict(case=row,native_flow=table['flows'][row['native_flow']],
                gated_flow=table['flows'][row['gated_flow']])


def address(expression,image):
    """Resolve only the reviewed symbolic address grammar, never evaluate code."""
    constants = dict(RN_MAIN=MAIN,RN_HELPER=HELPER,RN_BODY=BODY,RN_TAIL=TAIL,
        RN_GUARD=GUARD,RN_REFERENCE=REFERENCE,RN_DATA=DATA,RN_ARENA=ARENA,
        RN_PAGE=PAGE,RN_AREA=AREA,RN_WORD=WORD)
    if type(expression) is int:return expression
    need(type(expression) is str, 'fixed literal address expression')
    if expression.startswith('page(') and expression.endswith(')'):
        return address(expression[5:-1],image)&~4095
    match = re.fullmatch(r'([A-Za-z_][A-Za-z_0-9]*)(?:\+(\d+))?',expression)
    need(match is not None, 'bounded literal symbol plus offset')
    name,delta = match.groups()
    need(name in constants or name in image['symbols'], 'actual ELF symbol or fixed image constant')
    return (constants[name] if name in constants else image['symbols'][name])+int(delta or 0)


def application_frame(reader, raw, image, event, native, pid, leaf0, components, lo,cap):
    f = reader.frame(raw,image)
    pc,a = address(event['pc'],image),address(event['address'],image)
    s = event['state']
    need(s['context'] == 'application' and f['greg'][16] == pc and
         f['h'][8] == a and f['greg'][19] == (4 if event['event'] == 'actual-read-fault' else 21),
         'actual fault geometry and exact original application state stage')
    reader.envelope(f,lo,cap,native)
    reader.seeded_vectors(f,components)
    expected,registers,flags = modeled_memory(image,native,f['page'],pc,
        s['completed_calls'],s['executed_decs'],s['call_push_outstanding'],pid,leaf0,f['greg'][17]&16)
    need(f['data'] == expected and tuple(f['greg'][i] for i in GREG) == tuple(registers) and
         f['greg'][17] == flags|0x10000,
         'every original data/stack byte, all GPR and exact flags at actual instruction boundary')
    if s['call_push_outstanding']:
        need(word(f['data'],16312) == address(s['return_pc'],image) and
             registers[4] == DATA+16312, 'one actual CALL push and exact return address')
    else:need(s['return_pc'] is None and registers[4] == DATA+16320,
              'no outstanding original CALL frame')
    return f


def fp_platform(h,xcr0,components,native,case):
    """Actual pre-arm CPUID/PKRU, plus a separate live nested-handler value."""
    need(all(v < 1 << 32 for v in h[36:47]) and h[44]&0x40010000 == 0x40010000,
         'complete actual native/gated CPUID7 and typed optional PKRU observations')
    active = bool(xcr0 & (1 << 9))
    layout = None
    if active:
        size,offset,flags,reserved = h[36:40]
        need(h[45]&0x18 == 0x18 and size == 8 and 576 <= offset <= 65536-8 and
             not flags&1 and reserved == 0 and h[41:43] == (0,1) and
             all(offset+size <= first or first+count <= offset
                 for first,count in components.values()),
             'actual enabled user PKRU component, disjoint standard layout and completed RDPKRU')
        layout = (offset,size)
    else:need(not any(h[36:43]), 'absent PKRU has no descriptor, value or invented execution')
    live = active and not native and case == 11
    if live:
        need(h[47] < 1 << 32 and h[48:50] == (0,1),
             'actual live outer-handler RDPKRU immediately before nested tgkill')
    else:need(not any(h[47:50]), 'no fabricated nested-handler PKRU observation')
    return dict(layout=layout,initial=h[40] if active else None,
                handler=h[47] if live else None)


def initialized_handler_fp(outer,platform,components):
    """Linux saves the app frame before initializing live handler FP state.

    The full standard XSAVE buffer is modeled, including all unused bytes.
    Dynamic or otherwise unmodeled software features are refused. MXCSR_MASK
    is a same-CPU capability; live PKRU comes from the separate actual read
    immediately before tgkill, never from a guessed kernel default.
    """
    saved = outer['fp'];size = outer['h'][2];layout = platform['layout']
    features = 0xe7 | (0x200 if layout is not None else 0)
    ends = [first+count for first,count in components.values()]
    if layout is not None:
        offset,count = layout;ends.append(offset+count)
        need(platform['handler'] is not None and
             struct.unpack_from('<II',saved,offset) == (platform['initial'],0),
             'suspended application PKRU still equals its independently observed initial value')
    need(size == max(ends)+4 and 580 <= size <= 65536 and
         struct.unpack_from('<IIQI',saved,464) == (0x46505853,size,features,size-4) and
         not any(saved[484:512]) and word(saved,512) == features and
         not any(saved[520:576]) and
         struct.unpack_from('<I',saved,size-4)[0] == 0x46505845,
         'complete closed FP/SSE/AVX512/optional-PKRU signal ABI; no dynamic or unknown component')
    mask = struct.unpack_from('<I',saved,28)[0]
    need(mask&0x1f80 == 0x1f80, 'same-hardware MXCSR mask admits the architectural initial control')
    expected = bytearray(65536)
    struct.pack_into('<H',expected,0,0x037f)
    struct.pack_into('<II',expected,24,0x1f80,mask)
    struct.pack_into('<IIQI',expected,464,0x46505853,size,features,size-4)
    put(expected,512,3 | (0x200 if layout is not None else 0))
    if layout is not None:struct.pack_into('<I',expected,layout[0],platform['handler'])
    struct.pack_into('<I',expected,size-4,0x46505845)
    return bytes(expected)


def native(data,layout,image,pid,exit_status):
    spec = image['spec']['case'];events = image['spec']['native_flow']
    need(type(pid) is int and pid > 0 and type(exit_status) is int and
         exit_status == spec['native_exit'], 'exact independent native process result')
    r = Reader(data,layout,'npf_native_record')
    h = q(r.field(data,r.rt,'h'))
    want = [0]*64
    want[:6] = [MAGIC,1,len(data),image['case'],len(events),1]
    want[7:13] = [125 if image['case'] == 10 else 0,pid,pid,h[10],h[11],131072]
    want[21] = image['control'];want[32:47] = h[32:47]
    need(tuple(want) == h and h[10]&0xe7 == 0xe7 and h[11] == image['symbols']['npf_altstack'] and
         all(v < 1 << 32 for v in h[32:36]) and h[32] >= 13,
         'whole native header, actual process/stack/XSTATE/CPUID and every unused word')
    components = r.components(r.field(data,r.rt,'xstate'))
    platform = fp_platform(h,h[10],components,True,image['case'])
    rows = r.field(data,r.rt,'rows');shape = r.types['npf_native_row'];size = shape['bytes']
    need(len(events) <= ROWS and not any(rows[len(events)*size:]),
         'native exact event population and entire unused capture tail')
    frames = []
    for i,event in enumerate(events):
        row = rows[i*size:(i+1)*size];v = q(r.field(row,shape,'h'))
        before,after = (r.field(row,shape,n) for n in ('before','after'))
        need(before == after, 'entire actual native frame unchanged across real permission calls')
        f = application_frame(r,before,image,event,True,pid,h[32:36],components,h[11],h[12])
        want = [0]*32;want[:7] = [1,i,f['greg'][16],f['h'][8],1,
            {'nx':0,'split-fetch':1,'first-byte-refault':2,'actual-read-fault':3}[event['event']],len(event['permissions'])]
        want[24:28] = v[24:28]
        need(tuple(want) == v, 'entire native row header and literal event classification')
        r.signal(row,shape,f)
        actual = q(r.field(row,shape,'permissions'))
        permissions = [value for permission in event['permissions']
                       for value in [address(permission[0],image),*permission[1:]]]
        need(actual == tuple(permissions+[0]*(16-len(permissions))),
             'all actual native mprotect arguments/results and unused operation slots')
        if frames:need(f['fp'] == frames[0]['fp'],
                       'complete native initialized FP/x87/MXCSR/XSTATE preserved through every leaf')
        frames.append(f)
    return dict(reader=r,frames=frames,header=h,leaf0=h[32:36],components=components,fp_platform=platform,
                summary=dict(native_exit=exit_status,native_events=len(events)))


def output(data,image,native,pid,leaf0):
    need(type(data) is bytes and type(native) is bool, 'actual complete lane stdout')
    spec = image['spec']['case']
    count = spec['native_stdout_bytes' if native else 'gated_stdout_bytes']
    need(len(data) == count, 'exact completed stdout or required empty failure output')
    if not count:
        return dict(summary=dict(bytes=0,completed_output=0),data=None,page=None)
    need(count == DATA_BYTES+4096, 'complete actual data and rseq page output')
    actual,page = data[:DATA_BYTES],data[DATA_BYTES:]
    ids = page_ids(page,image['case'] >= 2)
    need(actual[8192:12288] == page, 'complete initial and final rseq page on the reserved CPU')
    expected,regs,flags = modeled_memory(image,native,page,CLOSE,
        iterations(image['case'])+(image['case'] == 9),iterations(image['case']),False,
        pid,leaf0,word(actual,6336)&16,True)
    need(actual == expected, 'complete independent final GPR/flags/vectors/masks/selectors/ledger/stack image')
    return dict(data=actual,page=page,kernel_ids=ids,summary=dict(bytes=len(data),
        completed_output=1,sha256=hashlib.sha256(data).hexdigest(),
        completed_calls=iterations(image['case'])+(image['case'] == 9),
        live_gprs=16,live_vectors=32,live_masks=8,flags=flags))


def bridge(data):
    """Bind runtime symbol offsets to the actual retained observed bridge ELF."""
    need(type(data) is bytes and len(data) >= 64, 'actual complete observed runtime ELF')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (3,62,1) and
         h[8:10] == (64,56) and h[11] == 64, 'actual x86-64 runtime ET_DYN')
    def span(at,n):
        need(0 <= at <= len(data) and 0 <= n <= len(data)-at, 'bounded actual runtime ELF extent')
        return data[at:at+n]
    ph = [struct.unpack('<IIQQQQQQ',span(h[5]+56*i,56)) for i in range(h[10])]
    sh = [struct.unpack('<IIQQQQIIQQ',span(h[6]+64*i,64)) for i in range(h[12])]
    tables = [s for s in sh if s[1] == 2]
    need(len(tables) == 1 and tables[0][9] == 24, 'one complete observed runtime symbol table')
    t = tables[0];names = span(sh[t[6]][4],sh[t[6]][5]);symbols = {}
    required = {'selected_session','np_owner','li2_raw6'}
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,index,value,size = struct.unpack('<IBBHQQ',span(at,24))
        if n and info&15 != 4:
            need(n < len(names) and b'\0' in names[n:], 'bounded runtime symbol name')
            name = names[n:names.index(b'\0',n)].decode()
            if name in required:
                need(name not in symbols and size > 0 and 0 < index < len(sh),
                     'unique actual complete runtime symbol')
                flags = 5 if name == 'li2_raw6' else 6
                loads = [p for p in ph if p[0] == 1 and p[1] == flags and
                         p[3] <= value and value+size <= p[3]+p[6]]
                need(len(loads) == 1, 'complete runtime symbol in exact RX or RW-NX segment')
                symbols[name] = dict(address=value,bytes=size)
                if name == 'li2_raw6':
                    p = loads[0]
                    raw = bytes.fromhex('4889f84889f74889d64889ca4d89c24d89c84c8b4c24080f05c3')
                    need(size == len(raw) and value+size <= p[3]+p[5] and
                         span(p[2]+value-p[3],size) == raw,
                         'actual whole unchanged raw syscall register shuffle and RET')
                    symbols[name]['return_pc'] = value+len(raw)-1
    need(set(symbols) == required, 'all independent runtime owner and raw-call symbols')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),symbols=symbols)


def signal_record(reader,row,shape,frame,returned):
    """Complete actual SI; an unreturned call has no fabricated after capture."""
    v = q(reader.field(row,shape,'h'))
    before,after = (reader.field(row,shape,n) for n in ('signal_before','signal_after'))
    need(type(returned) is bool and v[24] > 0 and v[26:28] == (128,16) and
         v[25] == (v[24] if returned else 0), 'actual signal-info observation markers')
    expected = bytearray(128)
    struct.pack_into('<III',expected,0,frame['h'][5],frame['h'][7],frame['h'][6])
    put(expected,16,frame['h'][8])
    need(before == expected and (after == before if returned else not any(after)),
         'whole actual signal-info prefix and exact returned/unreturned after state')
    offset = v[24]-frame['h'][3]
    need(offset == reader.layout['offsets']['mask']+8 and
         0 <= offset <= reader.ucn-128 and frame['uc'][offset:offset+128] == expected,
         'full actual kernel signal-info alias in saved ucontext')
    return offset+16


def inner_frame(reader,raw,image,outer,pid,uid,lo,cap,base,platform,components):
    """Actual nested tgkill context: preservation only, never application semantics."""
    h = q(reader.field(raw,reader.ft,'h'))
    uc,fp,source,memory,page = (reader.field(raw,reader.ft,n)
                              for n in ('uc','fp','source','data','rseq'))
    need(h[:2] == (1,reader.ucn) and h[2] == outer['h'][2] and
         h[4:12] == (5,5,(1 << 32)-6,0,pid|(uid << 32),0,0,0) and not any(h[12:]),
         'actual nested SI_TKILL, pid/uid union and safe zero-word prefix')
    need(not any(uc[reader.ucn:]) and fp == initialized_handler_fp(outer,platform,components) and
         source == bytes.fromhex(image['source_hex']) and memory == outer['data'] and page == outer['page'],
         'complete initialized handler FP plus unchanged nested source/application memory and rseq page')
    f = dict(h=h,uc=uc,fp=fp,data=memory,page=page,
             greg=q(uc[reader.go:reader.go+23*8]),raw=raw,kernel_ids=page_ids(page,True))
    g = f['greg'];o = reader.layout['offsets'];raw_pc = base+image['bridge']['symbols']['li2_raw6']['return_pc']
    need(cap == 512*1024 and lo <= h[3] < outer['h'][3] and
         h[3]+reader.ucn <= lo+cap and lo <= word(uc,reader.fo) <= lo+cap-h[2] and
         word(uc,reader.fo)%16 == 0 and word(uc,o['stack_sp']) == lo and
         word(uc,o['stack_size']) == cap and struct.unpack_from('<I',uc,o['stack_flags'])[0] == 1 and
         word(uc,o['mask']) == PAIR_MASK and g[21] == PAIR_MASK,
         'actual deeper on-altstack nested context with exact installed reserved-signal mask')
    need(g[16] == g[14] == raw_pc and g[13] == 0 and
         (g[8],g[9],g[12],g[2],g[0],g[1]) == (pid,pid,5,0,0,0) and
         lo <= g[15] < outer['h'][3] and g[18] == 0x002b000000000033 and
         not g[17]&0x10500,
         'actual successful tgkill kernel-return PC/arguments, runtime stack, selectors and no TF/RF/DF')
    # All other runtime GPR/flags/UC bytes are actual observations, conserved
    # byte-for-byte by the terminal capture. They are not application outputs.
    return f


def gated(data,layout,image,pid,exit_status):
    spec = image['spec']['case'];events = image['spec']['gated_flow']
    need(type(pid) is int and pid > 0 and type(exit_status) is int and exit_status == spec['gated_exit'],
         'exact independent gated process outcome')
    r = Reader(data,layout,'npf_record')
    owner_module = load_leaf('owners')
    owner_summary = owner_module.validate(r,data,image,pid)
    need(type(owner_summary) is dict and all(type(x) is int for x in owner_summary.values()),
         'numeric independent owner/custody summary')
    h = q(r.field(data,r.rt,'h'));unsafe = spec['safe_prefix']
    want = [0]*64
    want[:8] = [MAGIC,1,len(data),image['case'],r.ucn,r.types['npf_row']['bytes'],h[6],1]
    code,detail = (0,0) if unsafe else spec['gated_terminal']
    want[9:17] = [int(not unsafe),0 if unsafe else exit_status,code,detail&U64,
                  len(events),1,h[15],512*1024]
    want[17:22] = [h[17],h[18],int(unsafe),spec['stages'],image['control']]
    want[32:47] = h[32:47]
    if image['case'] == 11:want[47:50] = h[47:50]
    need(tuple(want) == h and h[6]&0xe7 == 0xe7 and h[15] > 0 and h[15]%4096 == 0 and
         h[32] >= 13 and all(v < 1 << 32 for v in h[32:36]),
         'entire gated terminal/safe-prefix header and every unused word')
    r.shape('li2_selected_hardware',dict(abi_version=(4,4),reserved=(4,4),
        leaf0=(16,4),leaf1=(16,4),leaf7=(16,4)),4)
    hw = struct.unpack('<14I',r.field(data,r.rt,'hardware'))
    need(hw[:2] == (1,0) and hw[2:6] == h[32:36] and hw[10:14] == h[43:47] and hw[8]&0x18000000 == 0x18000000 and
         hw[11]&0x40010000 == 0x40010000, 'actual complete hardware capability and leaf0 observations')
    components = r.components(r.field(data,r.rt,'xstate'))
    platform = fp_platform(h,h[6],components,False,image['case'])
    rows = r.field(data,r.rt,'rows');shape = r.types['npf_row'];size = shape['bytes']
    need(len(events) <= ROWS and not any(rows[len(events)*size:]),
         'exact gated event population and whole unused row tail')
    stages = r.field(data,r.rt,'stages')
    need(h[20] <= STAGES and not any(stages[h[20]*r.types['npf_stage']['bytes']:]),
         'exact gated stage capacity and complete unused operation-capture tail')
    # Two independently retained static addresses bind the actual bridge bias;
    # the nested syscall PC uses this same bias, never one inferred from its PC.
    terminal_pair = r.field(data,r.rt,'terminal_pair')
    session = r.integer(terminal_pair,'li2_native_pair_progress','session')
    base = session-image['bridge']['symbols']['selected_session']['address']
    owner = r.integer(r.field(data,r.rt,'terminal_life'),'li2_native_pair_lifecycle','owner')
    need(base > 0 and base%4096 == 0 and
         owner == base+image['bridge']['symbols']['np_owner']['address'],
         'actual independent static session/owner identity and observed runtime ELF bias')
    control = q(r.field(data,r.rt,'control'));frames = [];signals = []
    for i,event in enumerate(events):
        row = rows[i*size:(i+1)*size];v = q(r.field(row,shape,'h'))
        before,after = (r.field(row,shape,n) for n in ('before','after'))
        returned = event['pair_result'] is not None
        if event['state']['context'] == 'application':
            f = application_frame(r,before,image,event,False,pid,h[32:36],components,h[15],h[16])
            if frames:need(f['fp'] == frames[0]['fp'], 'full gated application FP state unchanged across all original leaves')
        else:
            need(image['case'] == 11 and i == 2 and len(frames) == 2 and
                 event['event'] == 'delivered-SIGTRAP' and control[16:18] == (1,1) and control[18] < 1 << 32,
                 'one actual nested signal with independently captured getuid result')
            f = inner_frame(r,before,image,frames[1],pid,control[18],h[15],h[16],base,platform,components)
        need(v[:4] == (1,i,f['greg'][16],f['h'][8]) and not any(v[15:24]) and not any(v[28:]),
             'whole gated event identity and all unused row header words')
        signals.append(signal_record(r,row,shape,f,returned))
        if returned:
            need(after == before, 'complete actual returned pair frame/SI/FP/source/data/rseq unchanged')
        else:
            need(not any(after) and all(not any(r.field(row,shape,n)) for n in
                 ('pair_after','life_after','rseq_after')), 'no fabricated after state for an unreturned owner call')
        guard_before,guard_after = (r.field(row,shape,n) for n in ('guard_before','guard_after'))
        if v[8]:
            need(returned and guard_before == guard_after == after,
                 'actual old instruction guard preserves the full closed-entry frame')
        else:need(not any(guard_before+guard_after+r.field(row,shape,'guard_state')),
                  'no invented instruction-guard captures')
        frames.append(f)
    publication,terminal_frame,nested_outer = (r.field(data,r.rt,n) for n in
        ('publication_frame','terminal_frame','nested_outer_frame'))
    if unsafe:
        need(len(frames) == 1 and publication == frames[0]['raw'] and not any(terminal_frame),
             'only complete safe actual A publication prefix; no post-mutation terminal capture')
    else:
        need(not any(publication), 'ordinary run has no fabricated unsafe-prefix publication')
        if exit_status:
            need(terminal_frame == frames[-1]['raw'],
                 'entire still-live actual failed/inner frame conserved through cleanup before exit')
        else:need(not any(terminal_frame), 'successful termination has no claimed live focal signal frame')
    nested_signal = r.field(data,r.rt,'nested_outer_signal')
    if image['case'] == 11:
        outer_row = rows[size:2*size]
        need(nested_outer == frames[1]['raw'] and
             nested_signal == r.field(outer_row,shape,'signal_before'),
             'complete suspended original outer UC/SI/FP/data/rseq survives genuine nested cleanup')
    else:need(not any(nested_outer+nested_signal), 'no fabricated nested outer observation')
    need(r.field(data,r.rt,'terminal_source') == bytes.fromhex(image['source_hex']),
         'entire original terminal source including both observer pages unchanged')
    page = r.field(data,r.rt,'terminal_page');ids = page_ids(page,image['case'] >= 2)
    memory = r.field(data,r.rt,'terminal_data')
    if exit_status:
        app = frames[1] if image['case'] == 11 else frames[-1]
        need(memory == app['data'] and page == app['page'],
             'complete terminal or safe-prefix data/stack/page equals actual last application observation')
    return dict(reader=r,frames=frames,header=h,leaf0=h[32:36],components=components,fp_platform=platform,
        terminal_data=memory,terminal_page=page,kernel_ids=ids,
        summary=dict(gated_exit=exit_status,gated_events=len(events),**owner_summary))


def load_leaf(name):
    need(name in ('owners','terminal'), 'fixed independent reader leaf')
    spec = importlib.util.spec_from_file_location('native_pair_'+name,Path(__file__).with_name(name+'.py'))
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def normalized_memory(data,page,image,native,pc=None,terminal=False):
    """Only independently typed mode, kernel mm_cid and getpid identities."""
    d,p = bytearray(data),bytearray(page)
    need(word(d,16) == int(native), 'actual independently modeled lane marker')
    put(d,16,0)
    ids = page_ids(page,image['case'] >= 2)
    if ids is not None:
        struct.pack_into('<I',d,8192+88,0);struct.pack_into('<I',p,88,0)
    if image['case'] == 6 and terminal:
        # RAX's final captured value was independently checked against this
        # subject's actual PID before the cross-process semantic comparison.
        put(d,6208,0)
    return bytes(d),bytes(p)


def compare_frames(n,g,nr,gr,image,n_event,g_event,relocated=False):
    need(nr.ucn == gr.ucn and nr.layout['offsets'] == gr.layout['offsets'] and
         nr.layout['widths'] == gr.layout['widths'] and n['fp'] == g['fp'],
         'same actual ABI and complete native/gated initialized FP including x87/MXCSR')
    nu,gu = bytearray(n['uc']),bytearray(g['uc']);o = nr.layout['offsets']
    for offset in (o['stack_sp'],o['stack_size'],o['fp_pointer']):
        put(nu,offset,0);put(gu,offset,0)
    n_pc,g_pc = n['greg'][16],g['greg'][16]
    if image['case'] == 6 and n_pc in (image['symbols']['npf_c']+2,CLOSE):
        need(g_pc in (image['symbols']['npf_c']+2,CLOSE), 'both actual post-getpid boundaries')
        put(nu,nr.go+13*8,0);put(gu,gr.go+13*8,0)
    if relocated:
        need(image['case'] in (5,6,8) and n_pc == CLOSE and
             g_pc == (image['symbols']['rn_return'] if image['case'] == 8 else image['symbols']['npf_c']+2) and
             n_event['state']['completed_calls'] == g_event['state']['completed_calls'] and
             n_event['state']['executed_decs'] == g_event['state']['executed_decs'] and
             not n_event['state']['call_push_outstanding'] and not g_event['state']['call_push_outstanding'],
             'exact source-defined extra old-owner continuation and equal completed scalar stage')
        # The direct continuation executes no state-changing instruction.
        # Both complete frames already matched their independent literal model.
        for offset in (nr.go+16*8,nr.go+22*8,o['mask']+8+16):
            put(nu,offset,0);put(gu,offset,0)
    need(nu == gu, 'entire actual native/gated ucontext after explicit separately validated identities')
    ni,gi = n['kernel_ids'],g['kernel_ids']
    if ni is not None:
        need(gi is not None and (ni['cpu'],ni['node']) == (gi['cpu'],gi['node']),
             'actual native/gated kernel CPU and node equality')
    else:need(gi is None, 'both complete pages genuinely unregistered')
    need(normalized_memory(n['data'],n['page'],image,True,n_pc) ==
         normalized_memory(g['data'],g['page'],image,False,g_pc),
         'every original data/stack/page byte equal with only actual mode/mm_cid identities')


def pair(native_record,gated_record,native_output,gated_output,layout,image,
         native_pid,gated_pid,cpu,native_exit,gated_exit):
    need(type(cpu) is int and cpu >= 0 and type(native_pid) is int and type(gated_pid) is int and
         native_pid > 0 and gated_pid > 0 and native_pid != gated_pid,
         'independent actual process identities on one reserved CPU')
    n = native(native_record,layout['native'],image,native_pid,native_exit)
    g = gated(gated_record,layout['gated'],image,gated_pid,gated_exit)
    need(n['leaf0'] == g['leaf0'] and n['components'] == g['components'] and
         n['header'][10] == g['header'][6] and n['header'][36:47] == g['header'][36:47],
         'same actual independent CPU, enabled XSTATE and complete pre-arm PKRU/CPUID7 observations')
    no = output(native_output,image,True,native_pid,n['leaf0'])
    go = output(gated_output,image,False,gated_pid,g['leaf0'])
    nr,gr = n['reader'],g['reader']
    n_events,g_events = image['spec']['native_flow'],image['spec']['gated_flow']
    def key(event):
        s = event['state']
        return (address(event['pc'],image),address(event['address'],image),
                s['completed_calls'],s['executed_decs'],s['call_push_outstanding'])
    nk = [key(event) for event in n_events]
    need(len(set(nk)) == len(nk), 'unambiguous literal independent native boundaries')
    pairs,continuations = 0,0
    for event,f in zip(g_events,g['frames'],strict=True):
        if event['state']['context'] != 'application':continue
        k = key(event)
        relocated = k not in nk
        if relocated:
            need(image['case'] in (5,6,8), 'only three explicitly modeled extra old-owner continuations')
            choices = [i for i,e in enumerate(n_events) if address(e['pc'],image) == CLOSE]
            need(len(choices) == 1, 'one actual native completed-boundary comparison')
            i = choices[0];continuations += 1
        else:i = nk.index(k)
        compare_frames(n['frames'][i],f,nr,gr,image,n_events[i],event,relocated)
        pairs += 1
    expected_extra = int(image['case'] in (5,6,8))
    need(continuations == expected_extra and pairs == len(g_events)-(image['case'] == 11),
         'every actual gated application frame compared to an exact native semantic boundary')
    for lane,events,result,out in ((n,n_events,native_exit,no),(g,g_events,gated_exit,go)):
        for frame in lane['frames']:
            ids = frame['kernel_ids']
            if ids is not None:need(ids['cpu'] == cpu, 'every actual saved registered CPU equals reserved CPU')
        if not result:
            close = [f for e,f in zip(events,lane['frames'],strict=True)
                     if e['state']['context'] == 'application' and address(e['pc'],image) == CLOSE]
            need(len(close) == 1 and out['data'] is not None and
                 word(out['data'],6336) == (close[0]['greg'][17]&~0x10000),
                 'actual complete CLOSE flags equal original captured output flags, including undefined XOR AF')
            need(out['page'] == close[0]['page'], 'whole registered or unregistered page unchanged through original capture')
            if out['kernel_ids'] is not None:need(out['kernel_ids']['cpu'] == cpu, 'actual output CPU equals reserved CPU')
    if no['data'] is not None and go['data'] is not None:
        need(normalized_memory(no['data'],no['page'],image,True,terminal=True) ==
             normalized_memory(go['data'],go['page'],image,False,terminal=True),
             'entire actual completed native/gated data/page output with only typed process identities')
    if g['kernel_ids'] is not None:need(g['kernel_ids']['cpu'] == cpu, 'actual terminal prefix CPU equals reserved CPU')
    if gated_exit == 0:
        need(g['terminal_data'] == go['data'] and g['terminal_page'] == go['page'],
             'complete actual gated final stdout equals terminal data/page capture')
    return dict(qualified_case=1,completed_pair=int(gated_exit == 0),required_refusal=int(gated_exit != 0),
        native_events=len(n_events),gated_events=len(g_events),native_exit=native_exit,gated_exit=gated_exit,
        application_frame_comparisons=pairs,source_defined_extra_continuations=continuations,
        complete_output_pairs=int(no['data'] is not None and go['data'] is not None))


def terminal(parsed,gated_record,layout,image,pid,exit_status):
    g = gated(gated_record,layout,image,pid,exit_status)
    return load_leaf('terminal').validate(parsed,g['reader'],gated_record,image,pid,exit_status)
