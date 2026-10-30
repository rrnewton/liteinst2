"""Bounded actual linked-DSO facts. No final package or execution authority."""
import hashlib
import struct
import types

MIB=1048576
PACKAGE='evaluation/offline-router-native/package.py'
PACKAGE_SHA='13a5e8655f23c933a016908e3a875a089368a7a4be8a1891d4409f36b0d99bd2'
# Standard tags for this finite GNU-linked bootstrap profile. Loader injection,
# RELR, Android packed relocation and unknown dynamic protocols are unsupported.
TAGS=set(range(0,31))|{32,33,34}|{0x6ffffef5,0x6ffffff0,0x6ffffff9,0x6ffffffa,0x6ffffffb,
                     0x6ffffffc,0x6ffffffd,0x6ffffffe,0x6fffffff}


def need(ok,detail):
    if not ok:
        raise ValueError(detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def resolver(ctx):
    raw=ctx.read(ctx.ROOT/PACKAGE,cap=MIB)
    need(sha(raw)==PACKAGE_SHA,'reviewed package resolver v2')
    module=types.ModuleType('_startup_dso_package');module.__file__=str(ctx.ROOT/PACKAGE)
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module


def dynamic(elf):
    segments=[p for p in elf.ph if p[0]==2]
    need(len(segments)==1,'one actual PT_DYNAMIC')
    p=segments[0]
    need(0<p[5]<=MIB and p[5]%16==0,'bounded PT_DYNAMIC')
    raw=elf.mapped_bytes(p[3],p[2],p[5])
    tags={};needed=[];ended=False
    for at in range(0,len(raw),16):
        tag,value=struct.unpack_from('<qQ',raw,at)
        if ended:
            need(tag==value==0,'canonical dynamic NULL tail')
        elif tag==0:
            need(value==0,'canonical dynamic terminator');ended=True
        elif tag==1:
            need(len(needed)<16,'finite DT_NEEDED population');needed.append(value)
        else:
            need(tag in TAGS and tag not in tags,'supported unique dynamic tag')
            tags[tag]=value
    need(ended,'dynamic terminator')
    return tags,needed


def string(strings,index):
    need(0<=index<len(strings),'dynamic string offset')
    end=strings.find(b'\0',index)
    need(index<=end and end-index<=4095,'bounded terminated dynamic string')
    value=strings[index:end]
    need(value and all(33<=c<=126 for c in value),'nonempty printable dynamic string')
    return value.decode('ascii')


def relocations(elf,tags):
    ranges=[]
    for a,n,e,width in ((7,8,9,24),(17,18,19,16)):
        if any(k in tags for k in (a,n,e)):
            need(all(k in tags for k in (a,n,e)) and tags[e]==width,'complete relocation tags')
            ranges.append((tags[a],tags[n],width))
    if any(k in tags for k in (2,20,23)):
        need(all(k in tags for k in (2,20,23)) and tags[20] in (7,17),'complete PLT relocation tags')
        ranges.append((tags[23],tags[2],24 if tags[20]==7 else 16))
    # glibc's counted initial prefix uses the relative fast path. Its effective
    # semantics must agree with the records we resolve below; a claimed R_64
    # inside that prefix cannot be analysed as an ordinary symbol relocation.
    for count_tag,a,n,e,width in ((0x6ffffff9,7,8,9,24),(0x6ffffffa,17,18,19,16)):
        if count_tag not in tags:
            continue
        need(all(k in tags for k in (a,n,e)) and tags[e]==width,
             'relative fast-path count requires complete table')
        need(tags[n]<=MIB and tags[n]%width==0 and tags[count_tag]<=tags[n]//width,
             'relative fast-path count within actual table')
        prefix=elf.at(tags[a],tags[count_tag]*width)
        need(all(struct.unpack_from('<Q',prefix,at+8)[0]==8 for at in range(0,len(prefix),width)),
             'relative fast-path prefix contains only symbol-zero RELATIVE records')
    records={}
    for address,length,width in ranges:
        need(length<=MIB and length%width==0,'bounded dynamic relocation records')
        raw=elf.at(address,length)
        for at in range(0,len(raw),width):
            target,info=struct.unpack_from('<QQ',raw,at)
            record=dict(target=target,symbol=info>>32,kind=info&0xffffffff,
                        addend=struct.unpack_from('<q',raw,at+16)[0] if width==24 else None)
            # This finite GNU x86-64 DSO profile supports ordinary 64-bit
            # stores and the 16-byte TLSDESC pair, never a size-dependent COPY.
            widths={0:0,1:8,6:8,7:8,8:8,16:8,17:8,18:8,36:16,37:8}
            need(record['kind'] in widths,'supported bounded DSO relocation store')
            record['write_bytes']=widths[record['kind']]
            if record['write_bytes']:
                owners=[p for p in elf.loads if p[3]<=target and target+record['write_bytes']<=p[3]+p[6]]
                need(len(owners)==1 and owners[0][1]==6,'dynamic relocation target must be writable non-executable LOAD')
            # RELA and JMPREL may name the same actual records; exact duplicate
            # bytes are one loader record, but conflicting aliases must refuse.
            slot=address+at
            need(slot not in records or records[slot]==record,'conflicting relocation table alias')
            records[slot]=record
    return [dict(table_address=at,**row) for at,row in sorted(records.items())]


def notes(elf):
    result=[];seen=set()
    for p in elf.ph:
        if p[0] not in (4,0x6474e553):
            continue
        raw=elf.mapped_bytes(p[3],p[2],p[5]);at=0
        need(len(raw)<=MIB,'bounded ELF notes')
        while at<len(raw):
            need(at+12<=len(raw),'ELF note header')
            namesz,descsz,kind=struct.unpack_from('<III',raw,at);at+=12
            need(namesz<=256 and descsz<=65536 and at+namesz<=len(raw),'ELF note name/description bound')
            name=raw[at:at+namesz];at=(at+namesz+3)&~3
            need(at+descsz<=len(raw),'ELF note extent')
            desc=raw[at:at+descsz];at=(at+descsz+3)&~3
            need(at<=len(raw),'ELF note aligned extent')
            identity=(name,kind,desc)
            if identity in seen:
                continue
            seen.add(identity)
            properties=[]
            if name==b'GNU\0' and kind==5:
                pos=0
                while pos<len(desc):
                    need(pos+8<=len(desc),'GNU property header')
                    tag,size=struct.unpack_from('<II',desc,pos);pos+=8
                    need(size<=256 and pos+size<=len(desc),'GNU property size')
                    data=desc[pos:pos+size];pos=(pos+size+7)&~7
                    need(pos<=len(desc),'GNU property alignment')
                    properties.append(dict(kind=tag,bytes=data.hex()))
            result.append(dict(name=name.hex(),kind=kind,bytes=len(desc),sha256=sha(desc),properties=properties))
    need(len(result)<=64,'finite note population')
    return result


def load_pages(elf):
    """Prove one owner per mapped page for this finite ET_DYN profile.

    Byte-disjoint LOADs can remap the same page with different permissions or
    backing. This profile refuses *all* rounded-page overlap, including equal
    permissions, instead of guessing the loader's final remap/zero-fill order.
    No page-sized allocation or virtual-span widening is needed for the proof.
    """
    page=4096
    align=lambda n:(n+page-1)&~(page-1)
    result=[]
    for index,p in enumerate(elf.loads):
        _,flags,offset,address,_,filesz,memsz,_=p
        if not memsz:
            continue
        start=address&~(page-1);end=align(address+memsz)
        need(0<=start<end<1<<64,'bounded page-rounded LOAD extent')
        need(not result or result[-1]['end']<=start,'page-rounded LOAD ownership overlap/order')
        # A zero-file unaligned LOAD would still map an initial file page in
        # glibc's mapend calculation. It is outside this explicit simple profile.
        need(filesz or address==start,'zero-file LOAD requires page-aligned start')
        file_end=align(address+filesz) if filesz else start
        file_start=offset&~(page-1)
        need(file_end<=end and file_start+(file_end-start)<=align(len(elf.raw)),
             'LOAD page backing file extent')
        zero_start=address+filesz
        result.append(dict(load_index=index,start=start,end=end,flags=flags,
            file_end=file_end,file_offset=file_start,
            file_zero_tail=[zero_start,min(align(zero_start),address+memsz)] if memsz>filesz else None,
            anonymous=[file_end,end] if file_end<end else None))
    need(result,'nonempty page ownership proof')
    return result


def relative_constructor(elf,record,symbols):
    """Return A or S+A only when the loader really produces load_bias+value.

    Array entries are called as already-relocated absolute pointers. A raw
    unrelocated integer is not relative merely because it resembles an ELF VA.
    The supported symbol case deliberately excludes interposition, IFUNC/TLS,
    SHN_ABS/COMMON/XINDEX and every other reserved section-index interpretation.
    """
    need(record['addend'] is not None,'constructor requires explicit RELA addend')
    if record['kind']==8:
        need(record['symbol']==0,'RELATIVE constructor requires symbol zero')
        resolved=record['addend']
    elif record['kind']==1:
        need(record['symbol']<len(symbols),'constructor symbol index')
        sym=symbols[record['symbol']][1]
        binding,kind=sym[1]>>4,sym[1]&15
        visibility=sym[2]&3
        need(binding in (0,1) and sym[2]&~3==0 and (binding==0 or visibility==2),
             'constructor symbol must be local or hidden without preemption')
        need(kind in (0,2,3),'constructor symbol is ordinary code, not IFUNC/TLS')
        need(0<sym[3]<min(len(elf.sh),0xff00),'constructor symbol requires ordinary defined section index')
        section=elf.sh[sym[3]]
        need(section[1]==1 and section[2]&6==6 and not section[2]&1,
             'constructor symbol owns allocated nonwritable code section')
        elf.mapped_bytes(section[3],section[4],section[5])
        resolved=sym[4]+record['addend']
        need(section[3]<=sym[4]<section[3]+section[5]
             and sym[5]<=section[3]+section[5]-sym[4]
             and section[3]<=resolved<section[3]+section[5],
             'constructor symbol and addend remain in their owned code section')
    else:
        raise ValueError('constructor requires supported load-bias-producing relocation')
    need(0<resolved<1<<64,'constructor relative address bound')
    executable(elf,resolved)
    return resolved


def executable(elf,address):
    owner,_=elf.file_owner(address,1,'completion-relocation')
    need(owner[1]&1 and not owner[1]&2,'constructor target executable/nonwritable LOAD')


def constructors(elf,tags,records,symbols):
    result={}
    for tag,name in ((12,'init'),(13,'fini')):
        value=tags.get(tag,0)
        if value:
            executable(elf,value)
        result[name]=value
    for addr_tag,size_tag,name in ((25,27,'init_array'),(26,28,'fini_array'),(32,33,'preinit_array')):
        present=any(t in tags for t in (addr_tag,size_tag))
        if not present:
            result[name]=[];continue
        need(all(t in tags for t in (addr_tag,size_tag)) and tags[size_tag]<=512
             and tags[size_tag]%8==0,'bounded constructor array')
        raw=elf.at(tags[addr_tag],tags[size_tag]);entries=[]
        for offset in range(0,len(raw),8):
            slot=tags[addr_tag]+offset
            pointer=struct.unpack_from('<Q',raw,offset)[0]
            references=[r for r in records if r['write_bytes'] and r['target']<slot+8 and slot<r['target']+r['write_bytes']]
            need(len(references)<=1 and (not references or (references[0]['target']==slot and references[0]['write_bytes']==8)),
                 'unique whole constructor relocation')
            need(references,'constructor slot requires load-bias-producing relocation')
            resolved=relative_constructor(elf,references[0],symbols)
            entries.append(dict(slot=slot,file_pointer=pointer,relocations=references,resolved_relative=resolved))
        result[name]=entries
    need(not result['preinit_array'],'bootstrap DSO cannot own main preinit')
    return result


def _relro_file_zero_tail(elf, relro, page_owners):
    """One whole RW LOAD: actual file prefix followed by its loader-zeroed tail.

    Called only after load_pages has proved disjoint rounded LOAD ownership.
    This named class does not infer storage from section names or zero-looking
    file bytes: the exact LOAD filesz/memsz boundary determines the zero fill.
    """
    need(relro[1]==4 and 0<relro[5]<relro[6],
         'RELRO file-zero-tail requires a nonempty file prefix and zero suffix')
    owners=[(index,p) for index,p in enumerate(elf.loads)
            if p[3]<=relro[3] and relro[3]+relro[6]<=p[3]+p[6]]
    need(len(owners)==1,'RELRO file-zero-tail requires one whole memory owner')
    index,owner=owners[0]
    need(owner[1]==6,'RELRO file-zero-tail requires actual RW/non-executable LOAD')
    need((relro[2],relro[3],relro[5],relro[6])==(owner[2],owner[3],owner[5],owner[6]),
         'RELRO file-zero-tail must exactly match whole LOAD offset/file/memory extent')
    prefix=elf.mapped_bytes(relro[3],relro[2],relro[5])
    protected_start=relro[3]&~4095
    protected_end=(relro[3]+relro[6])&~4095
    pages=[p for p in page_owners if p['load_index']==index]
    need(len(pages)==1 and pages[0]['flags']==6 and
         pages[0]['start']<=protected_start<protected_end<=pages[0]['end'],
         'RELRO file-zero-tail requires nonempty protected pages in that LOAD owner')
    return dict(schema='LI2STARTUP-RELRO-LOAD-FILE-ZERO-TAIL-1',load_index=index,
        load=list(owner),relro=list(relro),
        file_prefix=dict(address=relro[3],file_offset=relro[2],bytes=len(prefix),sha256=sha(prefix)),
        zero_fill=[owner[3]+owner[5],owner[3]+owner[6]],
        protected=[protected_start,protected_end],page_owner=dict(pages[0]))


def inspect(raw,catalog,package):
    """Inspect a concrete linked file; facts are inputs to later platform review."""
    need(type(catalog) is bytes and 0<len(catalog)<=16*MIB,'bounded frozen embedded catalog')
    elf=package.Elf(raw)
    need(elf.kind==3 and elf.entry==0 and all(p[0]!=3 for p in elf.ph),'bootstrap ET_DYN/non-entry/no interpreter')
    page_owners=load_pages(elf)
    stack=[p for p in elf.ph if p[0]==0x6474e551]
    need(len(stack)==1 and stack[0][1]==6,'explicit RW/non-executable GNU stack')
    relro=[p for p in elf.ph if p[0]==0x6474e552]
    need(len(relro)==1 and relro[0][6]>0,'explicit nonempty GNU RELRO')
    relro_storage=None
    full_file_owners=[p for p in elf.loads if p[3]<=relro[0][3]
                      and relro[0][3]+relro[0][6]<=p[3]+p[5]]
    if full_file_owners:
        # Preserve the original all-file-backed class and its exact refusal.
        relro_owner,relro_offset=elf.file_owner(relro[0][3],relro[0][6],'completion-relocation')
        need(relro_owner[1]==6 and relro_offset==relro[0][2],'actual writable file-backed RELRO owner')
    else:
        relro_storage=_relro_file_zero_tail(elf,relro[0],page_owners)
    protected_start=relro[0][3]&~4095
    protected_end=(relro[0][3]+relro[0][6])&~4095
    need(protected_end>protected_start,'actual nonempty page-protected RELRO')
    completion=elf.completion()
    need(not (completion['address']<protected_end and protected_start<completion['address']+8),
         'completion store remains writable after RELRO')
    tags,needed_offsets=dynamic(elf)
    need(all(t in tags for t in (5,6,10,11)) and tags[11]==24,'actual dynamic strings/symbols')
    tables={i:elf.symbols(i) for i,s in enumerate(elf.sh) if s[1] in (2,11)}
    symbol_index=elf.dynamic_symbols(tags,tables)
    strings=elf.at(tags[5],tags[10]);symbols=tables[symbol_index]
    needed=[string(strings,n) for n in needed_offsets]
    need(needed and len(set(needed))==len(needed),'nonempty unique actual dependencies')
    need(22 not in tags and not tags.get(30,0)&4,'no dynamic text relocations')
    flags1=tags.get(0x6ffffffb,0)
    need((24 in tags or tags.get(30,0)&8 or flags1&1) and flags1&8 and flags1&0x40,
         'linked NOW/NODELETE/NODLOPEN flags')
    records=relocations(elf,tags)
    need(all(r['symbol']<len(symbols) for r in records),'actual relocation symbol index')
    at=raw.find(catalog)
    need(at>=0 and raw.find(catalog,at+1)<0,'exactly one complete catalog byte image')
    owners=[p for p in elf.loads if p[2]<=at and at+len(catalog)<=p[2]+p[5]]
    need(len(owners)==1 and owners[0][1]==4,'catalog is wholly in one read-only non-executable LOAD')
    address=owners[0][3]+at-owners[0][2]
    need(elf.at(address,len(catalog))==catalog,'actual mapped catalog bytes')
    need(all(not(r['write_bytes'] and r['target']<address+len(catalog) and address<r['target']+16) for r in records),
         'no dynamic relocation writes embedded catalog')
    for address_tag,size_tag in ((25,27),(26,28)):
        if tags.get(size_tag,0):
            need(protected_start<=tags[address_tag] and tags[address_tag]+tags[size_tag]<=protected_end,
                 'constructor array is actually page-protected by RELRO')
    constructor_facts=constructors(elf,tags,records,symbols)
    need(constructor_facts['init_array'] and all(row['resolved_relative'] not in (None,0)
         for row in constructor_facts['init_array']),'actual resolved nonempty bootstrap init array')
    symbol_facts=[]
    for index,(name,sym) in enumerate(symbols):
        symbol_facts.append(dict(index=index,name=name.hex(),info=sym[1],visibility=sym[2],section=sym[3],value=sym[4],bytes=sym[5]))
    result=dict(schema='LI2STARTUP-LINKED-DSO-FACTS-1',bytes=len(raw),sha256=sha(raw),
        completion=completion,catalog=dict(file_offset=at,address=address,bytes=len(catalog),sha256=sha(catalog)),
        loads=[list(p) for p in elf.loads],page_owners=page_owners,relro=[list(p) for p in relro],
        relro_protected=[protected_start,protected_end],stack=list(stack[0]),
        tls=[list(p) for p in elf.ph if p[0]==7],notes=notes(elf),
        needed=needed,soname=string(strings,tags[14]) if 14 in tags else None,
        rpath=string(strings,tags[15]) if 15 in tags else None,runpath=string(strings,tags[29]) if 29 in tags else None,
        dynamic_tags={str(k):v for k,v in sorted(tags.items())},symbols=symbol_facts,relocations=records,
        constructors=constructor_facts,artifact_inspected=True,
        platform_contract_accepted=False,execution_authorized=False,qualification_complete=False)
    if relro_storage is not None:
        result['relro_storage']=relro_storage
    return result
