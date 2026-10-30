"""A finite, separately named GNU dependency constructor resolution profile.

Not the bootstrap constructor resolver. GLOBAL DEFAULT is accepted only for a
versioned, unique ordinary defined function in the complete fixed namespace.
All competing same-basename definitions refuse, even if an ELF lookup might
prefer one by order, visibility, binding or version. No inventory-only grant.
"""
import hashlib
import struct

PROFILE = 'gnu-five-object-unique-versioned-constructor-v1'
ROLES = ('main', 'bootstrap', 'loader', 'libc', 'libgcc')
MIB = 1048576


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def elf_hash(name):
    h = 0
    for byte in name:
        h = ((h << 4) + byte) & 0xffffffff
        top = h & 0xf0000000
        if top: h ^= top >> 24
        h &= ~top
    return h


def gnu_hash(name):
    h = 5381
    for byte in name: h = ((h << 5) + h + byte) & 0xffffffff
    return h


def section_bytes(elf, address, kind, link, name):
    matches = [s for s in elf.sh if s[1] == kind and s[3] == address]
    need(len(matches) == 1, name+' unique actual dynamic section')
    section = matches[0]
    need(section[2] & 2 and not section[2] & 1 and section[6] == link and 0 < section[5] <= MIB,
         name+' allocated immutable bounded linked section')
    owner, _ = elf.file_owner(section[3], section[5], 'dependency-lookup')
    need(owner[1] & 4 and not owner[1] & 2, name+' immutable actual LOAD owner')
    return elf.mapped_bytes(section[3], section[4], section[5]), section


def versions(obj, dso):
    """Parse actual version chains, not readelf labels or numeric coincidence."""
    elf, tags, symbols, index = obj['elf'], obj['tags'], obj['symbols'], obj['symbol_index']
    need(0x6ffffff0 in tags, 'versioned constructor requires actual DT_VERSYM')
    raw, section = section_bytes(elf, tags[0x6ffffff0], 0x6fffffff, index, 'VERSYM')
    need(len(raw) == 2*len(symbols) and section[9] == 2, 'whole actual VERSYM population')
    versym = list(struct.unpack('<'+'H'*len(symbols), raw))
    definitions, requirements = {}, {}
    strings = elf.at(tags[5], tags[10])
    str_index = elf.sh[index][6]
    def name(at): return dso.string(strings, at)
    if any(t in tags for t in (0x6ffffffc,0x6ffffffd)):
        need(all(t in tags for t in (0x6ffffffc,0x6ffffffd)) and 1 <= tags[0x6ffffffd] <= 4096,
             'complete bounded version definitions')
        raw, section = section_bytes(elf, tags[0x6ffffffc], 0x6ffffffd, str_index, 'VERDEF')
        need(section[7] == tags[0x6ffffffd], 'VERDEF section and dynamic count agree')
        at = 0; owned_until = 0
        for n in range(tags[0x6ffffffd]):
            need(owned_until <= at and at+20 <= len(raw), 'VERDEF header extent/ownership')
            version, flags, ndx, count, hash_value, aux, nxt = struct.unpack_from('<HHHHIII', raw, at)
            need(version == 1 and flags in (0,1,2) and 1 <= ndx < 0x7f00 and ndx not in definitions and
                 1 <= count <= 128 and aux >= 20, 'canonical bounded VERDEF header')
            limit = at+nxt if nxt else len(raw)
            need((nxt > 0) == (n+1 < tags[0x6ffffffd]) and at+20 <= limit <= len(raw), 'VERDEF forward exact count')
            owned_until=at+20; cursor=at+aux; names=[]
            for j in range(count):
                need(owned_until <= cursor and cursor+8 <= limit,
                     'unique bounded VERDEF auxiliary ownership')
                name_index, onward = struct.unpack_from('<II',raw,cursor)
                names.append(name(name_index));owned_until=cursor+8
                need((onward > 0) == (j+1 < count) and (not onward or onward >= 8), 'VERDEF auxiliary chain')
                cursor += onward
            need(elf_hash(names[0].encode('ascii')) == hash_value, 'actual version-name ELF hash')
            need((ndx == 1) == (flags == 1), 'base version index/flag')
            definitions[ndx] = dict(name=names[0],hash=hash_value,flags=flags,parents=names[1:])
            at = limit
    if any(t in tags for t in (0x6ffffffe,0x6fffffff)):
        need(all(t in tags for t in (0x6ffffffe,0x6fffffff)) and 1 <= tags[0x6fffffff] <= 4096,
             'complete bounded version requirements')
        raw, section = section_bytes(elf,tags[0x6ffffffe],0x6ffffffe,str_index,'VERNEED')
        need(section[7] == tags[0x6fffffff], 'VERNEED section and dynamic count agree')
        at=0;owned_until=0
        for n in range(tags[0x6fffffff]):
            need(owned_until <= at and at+16 <= len(raw), 'VERNEED header extent/ownership')
            version,count,file_index,aux,nxt = struct.unpack_from('<HHIII',raw,at)
            needed_file=name(file_index)
            need(version == 1 and 1 <= count <= 128 and aux >= 16 and needed_file in obj['needed'],
                 'VERNEED actual dependency and bounds')
            limit=at+nxt if nxt else len(raw)
            need((nxt > 0) == (n+1 < tags[0x6fffffff]) and at+16 <= limit <= len(raw), 'VERNEED forward exact count')
            owned_until=at+16;cursor=at+aux
            for j in range(count):
                need(owned_until <= cursor and cursor+16 <= limit,
                     'unique bounded VERNEED auxiliary ownership')
                hash_value,flags,other,name_index,onward=struct.unpack_from('<IHHII',raw,cursor)
                label=name(name_index)
                need(flags in (0,2) and 2 <= other < 0x7f00 and other not in requirements and other not in definitions and
                     elf_hash(label.encode('ascii')) == hash_value, 'unique actual version requirement identity')
                requirements[other]=dict(name=label,hash=hash_value,flags=flags,file=needed_file)
                owned_until=cursor+16
                need((onward > 0) == (j+1 < count) and (not onward or onward >= 16), 'VERNEED auxiliary chain')
                cursor += onward
            at=limit
    need(all((v & 0x7fff) <= 1 or (v & 0x7fff) in definitions or (v & 0x7fff) in requirements for v in versym),
         'every symbol version has an actual definition or requirement')
    return versym, definitions, requirements


def hash_lookup(obj, name, wanted):
    """Prove the loader's actual selected hash table reaches this dynsym slot."""
    elf, tags, symbols, index = obj['elf'], obj['tags'], obj['symbols'], obj['symbol_index']
    if 0x6ffffef5 in tags:
        raw, _ = section_bytes(elf,tags[0x6ffffef5],0x6ffffff6,index,'GNU hash')
        need(len(raw)>=16,'GNU hash header')
        buckets, first, blooms, shift = struct.unpack_from('<IIII',raw)
        need(1<=buckets<=65536 and 1<=blooms<=16384 and blooms & (blooms-1)==0 and
             shift<32 and first<=wanted<len(symbols) and
             len(raw)==16+8*blooms+4*buckets+4*(len(symbols)-first), 'complete bounded GNU hash layout')
        h=gnu_hash(name)
        bloom=struct.unpack_from('<Q',raw,16+8*((h//64)&(blooms-1)))[0]
        mask=(1 << (h%64)) | (1 << ((h>>shift)%64))
        need(bloom & mask == mask,'GNU hash bloom actually permits selected name')
        bucket_at=16+8*blooms
        all_buckets=struct.unpack_from('<'+'I'*buckets,raw,bucket_at)
        need(all(value==0 or first<=value<len(symbols) for value in all_buckets),'GNU hash bucket ownership')
        slot=all_buckets[h%buckets]
        need(slot!=0,'GNU hash actual selected bucket is nonempty')
        chain_at=bucket_at+4*buckets;found=[]
        while True:
            need(first<=slot<len(symbols),'GNU hash terminated in actual dynsym bounds')
            chain=struct.unpack_from('<I',raw,chain_at+4*(slot-first))[0]
            if (chain|1)==(h|1) and symbols[slot][0]==name and symbols[slot][1][3]!=0:
                found.append(slot)
            if chain&1:break
            slot+=1
        need(found==[wanted],'GNU hash resolves the exact unique defined symbol')
        return dict(kind='gnu',hash=h,symbol=wanted)
    need(4 in tags,'actual symbol lookup hash table required')
    raw, _ = section_bytes(elf,tags[4],5,index,'SysV hash')
    need(len(raw)>=8,'SysV hash header')
    buckets,chains=struct.unpack_from('<II',raw)
    need(1<=buckets<=65536 and chains==len(symbols) and len(raw)==8+4*(buckets+chains),'whole bounded SysV hash layout')
    bucket=struct.unpack_from('<'+'I'*buckets,raw,8)
    chain=struct.unpack_from('<'+'I'*chains,raw,8+4*buckets)
    need(all(n<chains for n in (*bucket,*chain)),'SysV hash indices')
    h=elf_hash(name);slot=bucket[h%buckets];seen=set();found=[]
    while slot:
        need(slot not in seen,'acyclic SysV hash chain');seen.add(slot)
        if symbols[slot][0]==name and symbols[slot][1][3]!=0:found.append(slot)
        slot=chain[slot]
    need(found==[wanted],'SysV hash resolves the exact unique defined symbol')
    return dict(kind='sysv',hash=h,symbol=wanted)


def complete_population(obj, dso):
    """Prove each loader-visible table population before namespace uniqueness.

    SHT_DYNSYM size is only one claim. Join it to every actual hash table and
    walk all GNU buckets/chains; a section-header truncation cannot omit an
    index still reachable by the loader. Both hash forms must agree if present.
    All actual version tables are independently checked for every object.
    """
    elf,tags,symbols,index=obj['elf'],obj['tags'],obj['symbols'],obj['symbol_index']
    counts={}
    if 0x6ffffef5 in tags:
        raw,_=section_bytes(elf,tags[0x6ffffef5],0x6ffffff6,index,'GNU hash')
        need(len(raw)>=16,'GNU hash header')
        buckets,first,blooms,shift=struct.unpack_from('<IIII',raw)
        need(1<=buckets<=65536 and 1<=blooms<=16384 and blooms&(blooms-1)==0 and
             shift<32 and 1<=first<=65536,'complete bounded GNU hash layout')
        bucket_at=16+8*blooms;chain_at=bucket_at+4*buckets
        need(chain_at<=len(raw) and (len(raw)-chain_at)%4==0,'complete bounded GNU hash layout')
        count=first+(len(raw)-chain_at)//4
        need(count<=65536 and count==len(symbols),
             'complete loader-visible symbol population: GNU hash/dynsym count')
        roots=struct.unpack_from('<'+'I'*buckets,raw,bucket_at)
        seen=set()
        for bucket,root in enumerate(roots):
            if root==0:continue
            slot=root
            while True:
                need(first<=slot<count,
                     'GNU hash terminated in actual dynsym bounds: complete loader-visible symbol population')
                need(slot not in seen,'complete loader-visible symbol population: disjoint GNU bucket chains')
                seen.add(slot)
                chain=struct.unpack_from('<I',raw,chain_at+4*(slot-first))[0]
                h=gnu_hash(symbols[slot][0])
                need(h%buckets==bucket and (chain|1)==(h|1),
                     'GNU hash resolves the exact unique defined symbol population')
                bloom=struct.unpack_from('<Q',raw,16+8*((h//64)&(blooms-1)))[0]
                mask=(1<<(h%64))|(1<<((h>>shift)%64))
                need(bloom&mask==mask,'GNU hash bloom actually permits selected name')
                if chain&1:break
                slot+=1
        need(len(seen)==count-first,
             'GNU hash actual selected bucket coverage: complete loader-visible symbol population')
        counts['gnu']=count
    if 4 in tags:
        raw,_=section_bytes(elf,tags[4],5,index,'SysV hash')
        need(len(raw)>=8,'SysV hash header')
        buckets,count=struct.unpack_from('<II',raw)
        need(1<=buckets<=65536 and 1<=count<=65536 and len(raw)==8+4*(buckets+count) and
             count==len(symbols),'whole bounded SysV hash layout: complete loader-visible symbol population')
        roots=struct.unpack_from('<'+'I'*buckets,raw,8)
        chains=struct.unpack_from('<'+'I'*count,raw,8+4*buckets)
        need(chains[0]==0 and all(slot<count for slot in (*roots,*chains)),
             'SysV hash indices: complete loader-visible symbol population')
        # Check every chain, including unreachable entries, in linear time.
        # A later bucket cannot introduce an out-of-range or cyclic suffix.
        finished={0}
        for start in range(1,count):
            cursor=start;path=set()
            while cursor not in finished:
                need(cursor not in path,'acyclic SysV hash chain')
                path.add(cursor);cursor=chains[cursor]
            finished.update(path)
        reached=set()
        for bucket,root in enumerate(roots):
            cursor=root
            while cursor:
                need(cursor not in reached and elf_hash(symbols[cursor][0])%buckets==bucket,
                     'complete loader-visible symbol population: consistent SysV bucket ownership')
                reached.add(cursor);cursor=chains[cursor]
        counts['sysv']=count
    need(counts,'actual symbol lookup hash table required for complete loader-visible symbol population')
    # GNU is loader-selected when both forms exist; the preceding guards still
    # require both declarations to agree, rather than ignoring a contradictory
    # secondary population. Absence of versioning means truly unversioned.
    version_tags=(0x6ffffff0,0x6ffffffc,0x6ffffffd,0x6ffffffe,0x6fffffff)
    if any(tag in tags for tag in version_tags):
        numbers,definitions,requirements=versions(obj,dso)
        versioning=dict(present=True,entries=len(numbers),definitions=len(definitions),requirements=len(requirements))
    else:
        versioning=dict(present=False,entries=len(symbols),definitions=0,requirements=0)
    return dict(symbols=len(symbols),hash_counts=counts,
                selected_hash='gnu' if 'gnu' in counts else 'sysv',versioning=versioning)


def main_namespace(elf, tags, needed, dso):
    """Two explicit nonexporting main classes; never a permissive tag union.

    The new class is the byte grammar emitted by carrier/startup.rs. It has no
    dynamic section headers: the actual DT pointers and canonical SysV count
    establish the entire null-only population, independently of section size.
    """
    need(elf.kind==2, 'main has no exported dynamic symbol namespace')
    if set(tags)=={5,10}:
        # Preserve the original no-symbol-table class and all of its checks.
        need(len(needed)==1 and tags[10]<=MIB, 'one actual bounded main dependency')
        names=[dso.string(elf.at(tags[5],tags[10]),needed[0])]
        need(names[0].startswith('/'), 'main dependency is the actual absolute bootstrap')
        return dict(profile='main-no-symbol-table-v1',needed=names,symbols=0)
    need(set(tags)=={5,10,6,11,4}, 'main has no exported dynamic symbol namespace')
    need(tags[11]==24 and needed==[1] and 3<=tags[10]<=4097,
         'canonical empty main symbol width/needed/string bound')
    pages=dso.load_pages(elf)
    dyn=[p for p in elf.ph if p[0]==2];interp=[p for p in elf.ph if p[0]==3]
    need(len(dyn)==len(interp)==1, 'canonical empty main dynamic/interpreter population')
    dyn,interp=dyn[0],interp[0]
    need(dyn[1]==4 and dyn[5]==dyn[6]==112 and dyn[7]==8 and
         interp[1]==4 and 2<=interp[5]==interp[6]<=4096 and interp[7]==1,
         'canonical empty main metadata segment grammar')
    ranges=[(interp[3],interp[5]),(tags[5],tags[10]),(tags[6],24),(tags[4],16),(dyn[3],112)]
    owners=[elf.file_owner(address,size,'empty-main') for address,size in ranges]
    owner=owners[0][0]
    need(owner[1]==4 and owner[5]==owner[6] and all(row[0]==owner for row in owners),
         'canonical empty main metadata has one readonly LOAD owner')
    raw=[elf.mapped_bytes(address,offset,size) for (address,size),(_,offset) in zip(ranges,owners)]
    need(owners[0][1]==interp[2] and owners[-1][1]==dyn[2],
         'canonical empty main segment file offsets match actual owner')
    name=dso.string(raw[1],1)
    need(name.startswith('/') and len(name)>=2 and raw[1]==b'\0'+name.encode('ascii')+b'\0',
         'canonical empty main whole string table')
    need(raw[0].endswith(b'\0') and raw[0].count(b'\0')==1 and
         raw[0].startswith(b'/'), 'canonical empty main interpreter string')
    need(raw[2]==bytes(24), 'canonical empty main entire null symbol')
    need(raw[3]==struct.pack('<IIII',1,1,0,0), 'canonical empty main entire SysV table')
    align=lambda n,a:(n+a-1)&~(a-1)
    need(tags[5]==interp[3]+interp[5] and tags[6]==align(tags[5]+tags[10],8) and
         tags[4]==align(tags[6]+24,4) and dyn[3]==align(tags[4]+16,8),
         'canonical empty main ordered disjoint metadata layout')
    records=[(1,1),(5,tags[5]),(10,tags[10]),(6,tags[6]),(11,24),(4,tags[4]),(0,0)]
    need(raw[4]==b''.join(struct.pack('<QQ',*row) for row in records),
         'canonical empty main exact ordered dynamic records')
    for (address,size),(following,_) in zip(ranges[1:],ranges[2:]):
        need(elf.at(address+size,following-address-size)==bytes(following-address-size),
             'canonical empty main zero alignment padding')
    start,end=owners[0][1],owners[-1][1]+112
    vstart,vend=interp[3],dyn[3]+112
    need(end==owner[2]+owner[5] and vend==owner[3]+owner[6],
         'canonical empty main metadata ends its readonly carrier')
    overlaps=lambda a,n,b,m:n>0 and m>0 and a<b+m and b<a+n
    owner_index=elf.loads.index(owner)
    need(all(p['load_index']==owner_index or not overlaps(start,end-start,
             p['file_offset'],p['file_end']-p['start']) for p in pages),
         'canonical empty main metadata has no other LOAD file alias')
    need(elf.sh[0]==(0,)*10 and all(s[1] in (0,1,2,3,7,8) and not s[2]&0x400 for s in elf.sh),
         'canonical empty main preserves only static section classes')
    for section in elf.sh:
        need((section[1]==8 or not overlaps(start,end-start,section[4],section[5])) and
             (not section[2]&2 or not overlaps(vstart,vend-vstart,section[3],section[5])),
             'canonical empty main metadata has no section alias')
    for offset,size in ((0,64),(elf.unpack('<Q',32)[0],56*len(elf.ph)),
                        (elf.unpack('<Q',40)[0],64*len(elf.sh))):
        need(not overlaps(start,end-start,offset,size), 'canonical empty main metadata has no ELF-table alias')
    need(all(p[0] in (1,2,3) or not overlaps(start,end-start,p[2],p[5]) for p in elf.ph),
         'canonical empty main metadata has no other segment alias')
    return dict(profile='canonical-null-sysv-main-v1',needed=[name],symbols=1,
        null_symbol_sha256=sha(raw[2]),sysv_sha256=sha(raw[3]),
        metadata=dict(file_offset=start,address=vstart,bytes=end-start,sha256=sha(elf.slice(start,end-start))))


class Namespace:
    def __init__(self, raw_objects, package, dso):
        need(type(raw_objects) is dict and set(raw_objects)==set(ROLES),'complete fixed five-object namespace')
        self.dso=dso;self.objects={};self.identities={}
        for role in ROLES:
            raw=raw_objects[role]
            need(type(raw) is bytes and 64<=len(raw)<=16*MIB,'bounded actual namespace object')
            elf=package.Elf(raw);dso.load_pages(elf);tags,needed=dso.dynamic(elf)
            need(22 not in tags, 'no namespace text relocation protocol')
            need(16 not in tags and tags.get(30,0)&~0x18==0 and tags.get(0x6ffffffb,0)&~0x49==0,
                 'no symbolic/direct/group/interpose/audit/filter lookup mode')
            if role=='main':
                self.main_namespace=main_namespace(elf,tags,needed,dso)
                needed_names=self.main_namespace['needed']
                symbols=[];index=None  # Both classes prove no possible export.
            else:
                need(elf.kind==3 and all(t in tags for t in (5,6,10,11)) and tags[11]==24 and tags[10]<=MIB,
                     'actual DSO dynamic namespace')
                tables={i:elf.symbols(i) for i,s in enumerate(elf.sh) if s[1] in (2,11)}
                index=elf.dynamic_symbols(tags,tables);symbols=tables[index]
                for table in (elf.sh[index], elf.sh[elf.sh[index][6]]):
                    owner, _ = elf.file_owner(table[3], table[5], 'dependency-lookup')
                    need(table[2] & 2 and not table[2] & 1 and owner[1] & 4 and not owner[1] & 2,
                         'dynamic lookup symbol/string metadata has immutable actual LOAD owner')
                strings=elf.at(tags[5],tags[10]);needed_names=[dso.string(strings,n) for n in needed]
                need(len(symbols)<=65536,'bounded complete dynamic symbol population')
                need(15 not in tags and 29 not in tags,'no namespace RPATH/RUNPATH injection')
                if role=='bootstrap':
                    need({'libgcc_s.so.1','libc.so.6'}<=set(needed_names) and
                         set(needed_names)<={'libgcc_s.so.1','libc.so.6','ld-linux-x86-64.so.2'} and
                         len(set(needed_names))==len(needed_names),'complete finite bootstrap lookup graph')
                else:
                    required={'loader':[],'libc':['ld-linux-x86-64.so.2'],'libgcc':['libc.so.6']}[role]
                    expected_name={'loader':'ld-linux-x86-64.so.2','libc':'libc.so.6','libgcc':'libgcc_s.so.1'}[role]
                    need(needed_names==required and 14 in tags and dso.string(strings,tags[14])==expected_name,
                         'exact actual platform dependency namespace edge/SONAME')
            self.objects[role]=dict(elf=elf,tags=tags,symbols=symbols,symbol_index=index,needed=needed_names)
            self.identities[role]=dict(bytes=len(raw),sha256=sha(raw))
        self.populations={role:complete_population(self.objects[role],dso) for role in ROLES if role!='main'}

    def global_target(self, role, record):
        need(role in ('loader','libc','libgcc'),'new resolver is only for dependencies')
        obj=self.objects[role];elf=obj['elf'];symbols=obj['symbols']
        need(record['kind']==1 and record['write_bytes']==8 and record['addend']==0 and
             0<record['symbol']<len(symbols),'finite zero-addend R_X86_64_64 constructor')
        name,sym=symbols[record['symbol']]
        need(name and sym[1]==0x12 and sym[2]==0 and 0<sym[3]<min(len(elf.sh),0xff00),
             'ordinary GLOBAL DEFAULT defined FUNC, never weak/unique/IFUNC/TLS/special index')
        need(0 < sym[4] < 1 << 64, 'positive bounded ordinary constructor address')
        section=elf.sh[sym[3]]
        need(section[1]==1 and section[2]&6==6 and not section[2]&1 and sym[5]>0 and
             section[3]<=sym[4] and sym[4]+sym[5]<=section[3]+section[5], 'whole actual ordinary code symbol ownership')
        elf.mapped_bytes(section[3],section[4],section[5]);self.dso.executable(elf,sym[4])
        definitions=[(other,index) for other,entry in self.objects.items()
            for index,(candidate,definition) in enumerate(entry['symbols']) if candidate==name and definition[3]!=0]
        need(definitions==[(role,record['symbol'])], 'unique same-basename definition across the complete namespace')
        numbers,versions_by_index,requirements=versions(obj,self.dso)
        number=numbers[record['symbol']];index=number&0x7fff
        need(index>=2 and index in versions_by_index and index not in requirements and
             versions_by_index[index]['flags']==0 and versions_by_index[index]['hash'] != 0,
             'exact strong defined explicit symbol version')
        version=versions_by_index[index]
        lookup=hash_lookup(obj,name,record['symbol'])
        # A relocation supplies this explicit version (VERSYM masked by0x7fff).
        # The high bit marks a non-default export; it does not invalidate an
        # exact versioned reference. No unversioned/default-version fallback is
        # accepted, and ANY other definition was rejected regardless of version.
        proof=dict(profile=PROFILE,namespace=self.identities,populations=self.populations,
            name=name.decode('ascii'),symbol=record['symbol'],
            version=dict(index=index,nondefault=bool(number&0x8000),**version),lookup=lookup,
            target_object=role,target_relative=sym[4])
        if self.main_namespace['profile']=='canonical-null-sysv-main-v1':
            proof['main_namespace']=self.main_namespace
        return sym[4],proof

    def constructors(self, role, records):
        need(role in ('loader','libc','libgcc'),'finite dependency constructor role')
        obj=self.objects[role];elf,tags,symbols=obj['elf'],obj['tags'],obj['symbols'];dso=self.dso
        result={}
        for tag,name in ((12,'init'),(13,'fini')):
            value=tags.get(tag,0)
            if value:dso.executable(elf,value)
            result[name]=value
        for address_tag,size_tag,name in ((25,27,'init_array'),(26,28,'fini_array'),(32,33,'preinit_array')):
            if not any(t in tags for t in (address_tag,size_tag)):
                result[name]=[];continue
            need(all(t in tags for t in (address_tag,size_tag)) and tags[size_tag]<=512 and tags[size_tag]%8==0,
                 'unchanged bounded dependency constructor array')
            raw=elf.at(tags[address_tag],tags[size_tag]);entries=[]
            for offset in range(0,len(raw),8):
                slot=tags[address_tag]+offset
                refs=[r for r in records if r['write_bytes'] and r['target']<slot+8 and slot<r['target']+r['write_bytes']]
                need(len(refs)==1 and refs[0]['target']==slot and refs[0]['write_bytes']==8,'unique whole actual constructor relocation')
                record=refs[0];proof=None
                # Original strict rules are still the only path for RELATIVE or
                # local/hidden R64. The explicit new class has independent proof.
                if record['kind']==1 and record['symbol']<len(symbols) and symbols[record['symbol']][1][1:3]==(0x12,0):
                    resolved,proof=self.global_target(role,record)
                else:
                    resolved=dso.relative_constructor(elf,record,symbols)
                entry=dict(slot=slot,file_pointer=struct.unpack_from('<Q',raw,offset)[0],relocations=refs,resolved_relative=resolved)
                if proof is not None:entry['binding_proof']=proof
                entries.append(entry)
            result[name]=entries
        need(not result['preinit_array'],'no dependency-owned main preinit')
        return result
