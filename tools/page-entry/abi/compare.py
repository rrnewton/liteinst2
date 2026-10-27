"""Independent reader of the two assembly endpoints, with no runtime imports."""
import struct

SIZE=2429312
XSAVE=384
PHDR=XSAVE+65536
MAPS=PHDR+4096
STACK=MAPS+262144
KNOWN=0x2e7
MAGIC=0x3149424132494c

class Refusal(ValueError):
    pass

def check(ok, reason):
    if not ok:
        raise Refusal(reason)

def q(data, offset):
    check(0<=offset<=len(data)-8,"word extent")
    return struct.unpack_from("<Q",data,offset)[0]

def capability(cap):
    check(set(cap)=={"xcr0","supported","xsave_size","xgetbv1","components"},"capability shape")
    check(cap["xgetbv1"] is True and 576<=cap["xsave_size"]<=65536,"XSAVE capability")
    check(cap["xcr0"]&3==3 and cap["xcr0"]&~cap["supported"]==0,"XCR0 capability")
    bits=[];ranges=[]
    for row in cap["components"]:
        check(set(row)=={"bit","offset","bytes","flags"},"component shape")
        b,s,n=row["bit"],row["offset"],row["bytes"]
        check(2<=b<64 and b not in bits and n>0 and s>=576 and s+n<=cap["xsave_size"] and row["flags"]&1==0,"component bounds")
        check(all(s+n<=a or s>=z for a,z in ranges),"overlapping components")
        bits.append(b);ranges.append((s,s+n))
    check(sum(1<<b for b in bits)==cap["xcr0"]&~3,"complete XCR0 layout")

def elf(data):
    check(len(data)>=64 and data[:7]==b"\x7fELF\x02\x01\x01","ELF")
    h=struct.unpack_from("<16sHHIQQQIHHHHHH",data)
    check(h[2]==62 and h[8]==64 and h[9]==56 and 0<h[10]<=32,"ELF header")
    check(h[5]+56*h[10]<=len(data),"ELF PHDR bound")
    return {"entry":h[4],"phoff":h[5],"phdr":data[h[5]:h[5]+56*h[10]],"headers":[struct.unpack_from("<IIQQQQQQ",data,h[5]+56*i) for i in range(h[10])]}

def symbols(data):
    h=struct.unpack_from("<16sHHIQQQIHHHHHH",data)
    check(h[11]==64 and h[6]+h[12]*64<=len(data),"ELF sections")
    sections=[struct.unpack_from("<IIQQQQIIQQ",data,h[6]+64*i) for i in range(h[12])]
    result={}
    for s in sections:
        if s[1]!=2:continue
        check(s[9]==24 and s[6]<len(sections) and s[4]+s[5]<=len(data),"symbol table")
        names=sections[s[6]];strings=data[names[4]:names[4]+names[5]]
        for at in range(s[4],s[4]+s[5],24):
            name,info,other,section,value,size=struct.unpack_from("<IBBHQQ",data,at)
            check(name<len(strings),"symbol name")
            end=strings.find(b"\0",name);check(end>=0,"symbol NUL")
            text=strings[name:end].decode("ascii")
            if section and text in ("_abi_capture","_abi_kernel_entry","_abi_interpreter_entry","_start"):
                check(text not in result,"duplicate ABI symbol");result[text]=value
    return result

def record(data, cap):
    check(len(data)==SIZE,"record length")
    check(q(data,0)==MAGIC and q(data,8)==1 and q(data,24)==SIZE and q(data,16) in (0,1),"record header")
    check(data[336:384]==bytes(48),"record reserved")
    check(q(data,176)==q(data,328)==cap["xcr0"] and q(data,320)==cap["xsave_size"],"actual XCR0/size")
    first,end,n,maps_n,phaddr,phn,base_at,count=struct.unpack_from("<8Q",data,256)
    regs=struct.unpack_from("<16Q",data,32)
    check(end>first and end-first==n and n<=2097152 and first<=regs[7]<end and regs[7]%16==0,"stack range")
    check(0<maps_n<262144 and 0<phn<=4096 and phn%56==0,"record payload bounds")
    stack=data[STACK:STACK+n];maps=data[MAPS:MAPS+maps_n]
    rows=[]
    for line in maps.splitlines(keepends=True):
        check(line.endswith(b"\n"),"maps incomplete")
        words=line.split(maxsplit=5);check(len(words)>=5,"maps row")
        span=words[0].split(b"-");check(len(span)==2,"maps range")
        a,z=(int(x,16) for x in span);check(a<z and (not rows or rows[-1][1]<=a),"ordered maps")
        perms=words[1];check(len(perms)==4,"maps permissions")
        rows.append((a,z,perms,int(words[2],16)))
    owner=[x for x in rows if x[0]<=regs[7]<x[1]]
    check(len(owner)==1 and owner[0][:3]==(first,end,b"rw-p"),"actual stack VMA")
    argc=q(stack,regs[7]-first);check(argc<=4096,"argc")
    at=regs[7]-first+8
    for _ in range(argc):
        p=q(stack,at);check(first<=p<end and stack.find(b"\0",p-first)>=0,"argv extent");at+=8
    check(q(stack,at)==0,"argv terminator");at+=8
    for i in range(8192):
        p=q(stack,at);at+=8
        if not p:break
        check(first<=p<end and stack.find(b"\0",p-first)>=0,"environment extent")
    else:raise Refusal("environment terminator")
    aux={};slots={}
    for i in range(128):
        key,value=q(stack,at),q(stack,at+8)
        if not key:break
        check(key not in aux,"duplicate auxiliary key")
        aux[key]=value;slots[key]=at+8;at+=16
    else:raise Refusal("auxiliary terminator")
    check(all(k in aux for k in (3,4,5,6,7,9,23)),"required auxiliary keys")
    check(count==i+1 and slots.get(7)==base_at and aux.get(3)==phaddr and aux.get(4)==56 and aux[5]*56==phn,"observed auxiliary headers")
    check(aux.get(6)==4096 and aux.get(23)==0 and aux.get(7)>0 and aux.get(9)>0,"kernel auxiliary shape")
    x=data[XSAVE:XSAVE+65536];bv=q(x,512)
    check(q(x,520)==0 and x[528:576]==bytes(48),"standard XSAVE header")
    check(bv&~cap["xcr0"]==0 and q(data,184)&~cap["xcr0"]==0,"XSTATE mask")
    check((bv|q(data,184))&~KNOWN==0,"unqualified active XSTATE")
    return {"raw":data,"endpoint":q(data,16),"regs":regs,"flags":q(data,160),"pc":q(data,168),"first":first,"end":end,"stack":stack,"maps":rows,"aux":aux,"slots":slots,"phdr":data[PHDR:PHDR+phn],"xsave":x}

def architectural_state(rec,cap):
    x=rec["xsave"];bv=q(x,512);parts=[]
    # Same explicit architectural byte envelope as the existing native oracle.
    x87=x[:24] if bv&1 else b"\x7f\x03"+bytes(22)
    parts.append(("x87",x87[:5]+x87[6:]+b"".join(x[32+16*i:42+16*i] if bv&1 else bytes(10) for i in range(8))))
    parts.append(("mxcsr",x[24:28]))
    parts.append(("sse",x[160:416] if bv&2 else bytes(256)))
    for c in cap["components"]:
        if not (KNOWN&(1<<c["bit"])):continue
        value=x[c["offset"]:c["offset"]+c["bytes"]] if bv&(1<<c["bit"]) else bytes(c["bytes"])
        parts.append((str(c["bit"]),value))
    return parts

def entry(rec,image,negative_prefix=False):
    layout=elf(image);syms=symbols(image);capture=syms["_abi_capture"]
    name="_abi_kernel_entry" if rec["endpoint"] else "_abi_interpreter_entry"
    check(name in syms and layout["entry"]==syms[name],"ELF entry differs from actual entry symbol")
    check(capture==layout["entry"] if not negative_prefix else capture>layout["entry"],"capture prefix scope")
    bias=rec["pc"]-capture
    check(bias==rec["aux"][7] and bias>=0 and bias%4096==0,"actual entry load bias")
    check(any(a<=rec["pc"]<z and perms==b"r-xp" for a,z,perms,_ in rec["maps"]),"executed capture mapping")
    return bias

def pair(pre,post,cap,bridge,interpreter,carrier,original,negative_prefix=False):
    check(pre["endpoint"]==1 and post["endpoint"]==0,"endpoint order")
    check(pre["regs"]==post["regs"],"GPR mismatch")
    check(pre["flags"]==post["flags"],"RFLAGS mismatch")
    check(pre["raw"][192:256]==post["raw"][192:256],"FS/GS or selector mismatch")
    check((pre["first"],pre["end"])==(post["first"],post["end"]),"stack mapping changed")
    entry(pre,bridge);entry(post,interpreter,negative_prefix)
    check(pre["slots"]==post["slots"],"auxiliary locations changed")
    slot=pre["slots"][7];left=bytearray(pre["stack"]);right=post["stack"]
    left[slot:slot+8]=right[slot:slot+8]
    check(left==right,"stack bytes changed outside authenticated AT_BASE")
    check(pre["phdr"]==elf(carrier)["phdr"] and post["phdr"]==elf(original)["phdr"],"actual logical PHDR transfer")
    check(architectural_state(pre,cap)==architectural_state(post,cap),"architectural XSTATE changed")

def kernel_state(rec):
    check(all(v==0 for i,v in enumerate(rec["regs"]) if i not in (0,7)),"kernel-defined GPR initialization")
    check(rec["raw"][192:208]==bytes(16) and rec["raw"][224:256]==bytes(32),"kernel-defined FS/GS/DS/ES initialization")

def native(rec,cap,image,original):
    check(rec["endpoint"]==0,"native endpoint")
    entry(rec,image);kernel_state(rec)
    check(rec["phdr"]==elf(original)["phdr"],"native PHDR")
    architectural_state(rec,cap)
