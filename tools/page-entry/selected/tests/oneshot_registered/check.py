"""Strict file-only source, output and genuine registered-fallback record reader."""
import hashlib,struct
from page_selected import need

MARKER=b'LI2-RSEQ-FBACK!\n'
SITES=('li2_registered_clock','li2_registered_getpid','li2_registered_writev','li2_registered_exit')
RECORD_BYTES=26176

def elf(data, interpreter):
    need(type(data) is bytes and len(data) >= 64, 'complete actual ELF')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (3,62,1) and
         h[4] == 4096 and h[8:10] == (64,56) and h[11] == 64, 'actual PIE x86-64 entry and metadata')
    def extent(off, size):
        need(0 <= off <= len(data) and 0 <= size <= len(data)-off, 'actual ELF extent')
        return data[off:off+size]
    ph = [struct.unpack('<IIQQQQQQ',extent(h[5]+56*i,56)) for i in range(h[10])]
    loads = [p for p in ph if p[0] == 1]
    need(len(loads) == 3 and [p[1] for p in loads] == [4,5,6] and loads[0][2:4] == (0,0) and
         loads[0][5] <= 4096 and loads[1][2:4] == (4096,4096) and loads[1][5:7] == (8192,8192) and
         loads[2][2:4] == (12288,12288), 'separate R metadata, two full RX pages, RW data')
    need(all(p[7] == 4096 and p[5] <= p[6] for p in loads) and not any(p[0] == 7 for p in ph), 'page load geometry; no TLS')
    ips = [p for p in ph if p[0] == 3]
    need(len(ips) == 1 and extent(ips[0][2],ips[0][5]) == interpreter.encode()+b'\0', 'actual system interpreter')
    ss = [struct.unpack('<IIQQQQIIQQ',extent(h[6]+64*i,64)) for i in range(h[12])]
    need(not any(s[1] in (4,9) and s[5] for s in ss), 'no source relocations or source fixups')
    symbols = {}
    tables = [s for s in ss if s[1] == 2]
    need(len(tables) == 1 and tables[0][9] == 24, 'one complete actual symbol table')
    t = tables[0]; strings = ss[t[6]]; names = extent(strings[4],strings[5])
    for off in range(t[4],t[4]+t[5],24):
        n,info,other,index,value,size = struct.unpack('<IBBHQQ',extent(off,24))
        if n:
            name = names[n:names.index(b'\0',n)].decode()
            need(name not in symbols, 'unique emitted symbol')
            symbols[name] = (value,size,info,index)
    def read(address,size):
        out = bytearray()
        while size:
            p = next((p for p in loads if p[3] <= address < p[3]+p[5]), None)
            need(p is not None, 'symbol/halo outside complete file-backed LOAD')
            take = min(size,p[3]+p[5]-address)
            out.extend(extent(p[2]+address-p[3],take));address += take;size -= take
        return bytes(out)
    offsets={name:symbols[name][0]for name in SITES}
    need(symbols['_start'][0]==4096 and symbols['li2_registered_tail'][0]==8190 and
         read(8190,2)==b'\x0f\x05' and len(set(offsets.values()))==4,'real two-byte mmap/rseq tail and four distinct registered sites')
    for i,name in enumerate(SITES):
        pc=offsets[name]
        need(8192<=pc<=12288-5 and read(pc,5)==bytes.fromhex('0f31'if i==0 else'0f05')+b'\x90'*3,
             'actual full five-byte eligible source window')
    need(symbols['li2_registered_output'][0]==12288 and symbols['li2_registered_iov'][0]==12352 and
         read(12288,96)==MARKER+bytes(48)+struct.pack('<4Q',0,5,0,48),'independent initial output/iov bytes')
    return dict(elf_sha256=hashlib.sha256(data).hexdigest(),entry=4096,source_pages=2,
                sites=offsets,source_hex=read(4096,8192).hex(),stdout_bytes=53)


def output(data,pid):
    need(type(pid)is int and pid>0 and type(data)is bytes and len(data)==53 and
         data[:21]==bytes.fromhex('0f05909090')+MARKER,'kernel-read original five source bytes and independent marker')
    low,high,actual_pid,result=struct.unpack_from('<4Q',data,21)
    need(low<=0xffffffff and high<=0xffffffff and low|(high<<32),'actual nonzero zero-extended RDTSC words')
    need(actual_pid==pid and result==0,'actual kernel getpid and successful registration result')
    return dict(clock_words=[low,high],clock=low|(high<<32),pid=actual_pid,registration_result=result,
                stdout_sha256=hashlib.sha256(data).hexdigest(),source_bytes=data[:5].hex())


def record(data,image,pid,stdout,registration):
    need(type(data)is bytes and len(data)==RECORD_BYTES,'complete actual fallback record')
    h=list(struct.unpack_from('<64Q',data));rows=[list(struct.unpack_from('<32Q',data,512+i*256))for i in range(4)]
    need(h[:9]==[0x31514553524f464f,1,RECORD_BYTES,1,4,1,0,0,0] and h[9]==h[10]+4096 and
         h[9]%4096==0 and h[11:17]==[pid,pid,1,1,3,1],'complete actual terminal ACTIVE fallback prefix')
    need(h[17]==h[18]>0 and h[17]%4096==0 and h[19:27]==[1,1,0,0,0,0,0,0] and
         h[27:33]==[8192,1,1,0x53053053,32,1] and h[33:]==[0]*31,'one held registration, zero owners/publications, no unused header writes')
    owner=registration['owner']
    need(owner[1:4]==h[13:16] and owner[7:11]==[pid,pid,h[17],h[18]] and owner[11:14]==[32,0x53053053,1] and
         registration['counts'][:4]==h[19:23],'independent report and actual branch-record state join')
    for i,row in enumerate(rows):
        pc=h[10]+image['sites'][SITES[i]]
        need(row[:15]==[i,pc,pc+2,5 if i==0 else 7,2,1,1,3,1,h[17],h[18],pid,pid,0,0] and
             row[15]==0 and row[16]==301 and 5<=row[17]<=15 and row[18:23]==[11,2,pc,14,21] and
             row[23]==row[24]|0x10000 and not row[24]&0x10100 and row[25]==0x33 and row[26:]==[0]*6,
             'each genuine authenticated NX branch is registered/held, original PC+2 and not a publication')
    at=1536;before=data[at:at+8192];after=data[at+8192:at+16384];at+=16384
    need(before==after==bytes.fromhex(image['source_hex']),'both complete source pages retain every original byte')
    first,last=data[at:at+4096],data[at+4096:at+8192];at+=8192
    need(first[8:]==last[8:]==bytes(4088),'full anonymous rseq page except actual kernel CPU fields remains zero; no descriptor publication')
    need(data[at:]==stdout[5:]+bytes(16),'complete terminal application output including unused bytes')
    return dict(registered_fallbacks=4,rdtsc_fallbacks=1,syscall_fallbacks=3,owners=0,published=0,
                actual_nx_frames=4,source_bytes_equal=8192,rseq_page_bytes_observed=8192,
                terminal_registered=1,terminal_held=1,terminal_phase=3,epoch=1,
                raw_rseq_cpu_words=[list(struct.unpack_from('<2I',v))for v in(first,last)],
                record_bytes=len(data),record_sha256=hashlib.sha256(data).hexdigest())
