#!/usr/bin/env python3
"""One unchanged bounded gated launch with attributable read-only progress samples.

One diagnostic attempt only. No qualification, aggregate, or timing comparison
is inferred from either completion or asynchronous observations.
"""
import argparse,csv,ctypes,hashlib,importlib.util,json,os,shutil,stat,struct,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
SAMPLER_FILES=('persistent_dynamic_sample.py','persistent_dynamic_sample_dwarf.py','persistent_dynamic_sample_process.py')
ENV={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC','PYTHONDONTWRITEBYTECODE':'1'}
PROGRAM=[30,512<<20,16<<20,60]
INSPECT=[10,256<<20,4<<20,20]

def need(ok,message):
    if not ok:raise ValueError(message)

def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def fact(path):
    h=hashlib.sha256();size=0
    with Path(path).open('rb')as f:
        while b:=f.read(1<<20):size+=len(b);h.update(b)
    return dict(bytes=size,sha256=h.hexdigest())
def save(path,value):Path(path).write_bytes(encoded(value)+b'\n')
def git(root,*args):return subprocess.check_output(['git',*args],cwd=root)

def elf_symbols(data):
    """Independent whole-file ELF symbol binding, separate from DWARF."""
    eh=struct.Struct('<16sHHIQQQIHHHHHH');sh=struct.Struct('<IIQQQQIIQQ');sym=struct.Struct('<IBBHQQ')
    need(len(data)>=eh.size,'complete ELF symbol input')
    h=eh.unpack_from(data)
    need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[2]==62 and h[11]==sh.size and
         0<h[12]<=512 and h[6]+h[12]*sh.size<=len(data),'bounded actual ELF section table')
    sections=[sh.unpack_from(data,h[6]+i*sh.size)for i in range(h[12])]
    result={};tables=0
    for section in sections:
        if section[1]!=2:continue # SHT_SYMTAB, not duplicate dynamic aliases
        tables+=1
        need(section[9]==sym.size and section[5]%sym.size==0 and
             section[4]+section[5]<=len(data)and section[6]<len(sections),'whole actual symbol table')
        strings=sections[section[6]]
        need(strings[1]==3 and strings[4]+strings[5]<=len(data),'whole actual symbol strings')
        names=data[strings[4]:strings[4]+strings[5]]
        for off in range(section[4],section[4]+section[5],sym.size):
            name,info,other,index,address,size=sym.unpack_from(data,off)
            if not 0<index<len(sections)or info&15 not in (1,2):continue
            end=names.find(b'\0',name)
            need(0<=name<len(names)and end>=name,'complete symbol name')
            text=names[name:end].decode('utf-8');target=sections[index]
            if not text or not target[2]&2:continue # actual allocated object/function
            # Zero-sized linker labels have no readable extent (for example
            # __TMC_END__ can follow its empty table). Named owner bindings
            # still require their exact positive size; PC intervals stay empty.
            if size:
                need(target[3]<=address and address+size<=target[3]+target[5],
                     'complete symbol within its actual allocated section')
            result.setdefault(text,[]).append(dict(address=address,bytes=size,kind=info&15))
    need(tables==1,'one complete independent static symbol table')
    return result

def one_symbol(symbols,name,kind):
    values=symbols.get(name,[])
    need(len(values)==1 and values[0]['kind']==kind,'unique exact emitted ELF symbol '+name)
    return values[0]

def pin_inputs(receipt,extra):
    """Every original source/tool input plus exact reused artifacts, whole bytes."""
    observed={}
    for name,expected in sorted({**receipt['inputs'],**extra}.items()):
        p=Path(name);actual=fact(p)
        need(actual=={k:expected[k]for k in ('bytes','sha256')},'retained input changed: '+name)
        observed[name]=dict(actual,mode=stat.S_IMODE(p.stat().st_mode),resolved=str(p.resolve(strict=True)))
    for name,resolved in receipt['aliases'].items():
        need(str(Path(name).resolve(strict=True))==resolved,'original input alias changed: '+name)
    return dict(count=len(observed),sha256=digest(observed))

def bounded(path,cap):
    with Path(path).open('rb')as f:b=f.read(cap+1)
    need(len(b)<=cap,'bounded proc file: '+str(path))
    return b

class Sampler:
    """No ptrace, process stop, signal, write, or guessed load bias."""
    def __init__(self,bridge,layout,outer,out,cpu):
        self.bridge=bridge;self.layout=layout;self.outer=outer;self.out=out
        self.cpu=cpu
        self.samples=[];self.starttime=None;self.attribution=None
        self.image=bridge.read_bytes();s=bridge.stat()
        self.stat_identity=(os.major(s.st_dev),os.minor(s.st_dev),s.st_ino)
        self.eh=struct.Struct('<16sHHIQQQIHHHHHH');self.ph=struct.Struct('<IIQQQQQQ')
        h=self.eh.unpack_from(self.image)
        need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[1:4]==(3,62,1)and h[8]==64 and
             h[9]==56 and 1<=h[10]<=32,'actual bounded ELF64 x86-64 ET_DYN bridge')
        off,n=h[5],h[10];need(off+n*56<=len(self.image),'whole actual program headers')
        self.header=(off,off+n*56)
        self.loads=[]
        for i in range(n):
            typ,flags,fileoff,va,pa,filesz,memsz,align=self.ph.unpack_from(self.image,off+i*56)
            if typ!=1:continue
            need(filesz<=memsz and fileoff+filesz<=len(self.image)and
                 fileoff%4096==va%4096 and flags&4,'bounded readable actual PT_LOAD')
            self.loads.append(dict(flags=flags,offset=fileoff,vaddr=va,filesz=filesz,memsz=memsz))
        need(self.loads and any(p['offset']==0 and p['vaddr']==0 and p['filesz']>=self.header[1]
                                  for p in self.loads),'actual bridge header mapping')
        self.symbols=elf_symbols(self.image)
        self.fields=self.field_table()
        self.project_identity()

    def project_identity(self):
        # As in lifecycle_loader.c, fstat identity and kernel maps identity
        # are separate observations. Derive the latter from this exact file.
        libc=ctypes.CDLL(None,use_errno=True)
        libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
        libc.mmap.restype=ctypes.c_void_p
        libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];libc.munmap.restype=ctypes.c_int
        fd=os.open(self.bridge,os.O_RDONLY|os.O_CLOEXEC);address=None;errors=[]
        proof=dict(bytes=4096,stat_identity=list(self.stat_identity),unmapped=False,fd_closed=False)
        try:
            s=os.fstat(fd)
            need((os.major(s.st_dev),os.minor(s.st_dev),s.st_ino)==self.stat_identity and
                 s.st_size==len(self.image),'same actual retained bridge descriptor')
            address=libc.mmap(None,4096,1,2,fd,0) # PROT_READ, MAP_PRIVATE, file offset0
            need(address not in (None,ctypes.c_void_p(-1).value)and address%4096==0,
                 'actual read-only private bridge projection')
            raw,maps=self.maps(os.getpid())
            with(self.out/'projection.maps').open('xb')as f:f.write(raw)
            rows=[m for m in maps if m['lo']<=address and address+4096<=m['hi']]
            need(len(rows)==1,'unique complete parent projection mapping')
            row=rows[0]
            need(row['perms']=='r--p'and row['offset']+(address-row['lo'])==0 and row['inode']>0,
                 'actual readable private file-offset-zero mapping identity')
            actual=ctypes.string_at(address,4096)
            need(actual==self.image[:4096],'whole actual projection bytes equal retained bridge')
            self.identity=(*row['device'],row['inode'])
            proof.update(address=address,mapping=row,map_identity=list(self.identity),
                         maps_sha256=hashlib.sha256(raw).hexdigest(),page_sha256=hashlib.sha256(actual).hexdigest())
        finally:
            if address not in (None,ctypes.c_void_p(-1).value):
                if libc.munmap(address,4096)==0:proof['unmapped']=True
                else:errors.append('parent projection munmap failed')
            try:os.close(fd);proof['fd_closed']=True
            except OSError as exc:errors.append('parent projection close: '+repr(exc))
            proof['cleanup_errors']=errors
            save(self.out/'projection.json',proof)
            need(not errors,'parent read-only projection cleanup')
        need(proof['unmapped']and proof['fd_closed'],'complete parent projection cleanup')
        self.projection=proof

    def field_table(self):
        l=self.layout;o=self.outer['pe'];reg=l['registrations']['pe']
        need(self.outer['schema']==1 and all(o[k]==reg[k]for k in ('address','bytes','tag','source')),
             'new file-only query joins retained actual owner registration')
        fields=[]
        def add(name,address,size):
            need(size in (4,8)and address>=0,'bounded scalar diagnostic field')
            fields.append((name,address,size))
        def scalars(prefix,address,tag,names=None):
            t=l['types'][tag]
            for name,f in t['fields'].items():
                if names is not None and name not in names:continue
                if f['bytes']in(4,8):add(prefix+'.'+name,address+f['offset'],f['bytes'])
        pe=o['address']
        tags={'p':'li2_pe_progress','last_terminal':'li2_pe_progress','permit':'ped_permit',
              'generation':'li2_pe_generation','ingress':'le_frame','before':'le_frame','after':'le_frame'}
        for name,f in o['fields'].items():
            need(f['offset']>=0 and f['offset']+f['bytes']<=o['bytes'],'field within actual owner')
            a=pe+f['offset']
            if name in tags:
                tag=tags[name];need(f['bytes']==l['types'][tag]['bytes']and f['type']=='struct '+tag,
                                    'retained actual child type and extent')
                if tag=='le_frame':
                    scalars('pe.'+name,a,tag,{'started','complete','sig','uc_saved'})
                    uc=l['types'][tag]['fields']['uc']
                    need(l['uc']['widths']['greg']==23*8,'actual23 x86-64 saved GREGs')
                    add('pe.'+name+'.saved_rip',a+uc['offset']+l['uc']['offsets']['greg']+16*8,8)
                else:
                    scalars('pe.'+name,a,tag)
                    if tag=='li2_pe_progress':
                        source=l['types'][tag]['fields']['source']
                        need(source['bytes']==16,'actual two-page source progress')
                        for i in range(2):add('pe.'+name+'.source.'+str(i),a+source['offset']+8*i,8)
            elif name=='misses':
                need(f['bytes']==15*8,'actual15 classified miss counters')
                for i in range(15):add('pe.misses.'+str(i),a+8*i,8)
            else:add('pe.'+name,a,f['bytes'])
        # DWARF names the declaration location, which can precede an include.
        # Independent ELF object symbols bind each actual DWARF address/width;
        # both exact declaration files are already whole-input pinned.
        flag_bindings={
            'pe_busy':'runtime_loader.c',
            'pe_active':'runtime_loader.c',
            'pe_failing':'persistent_dynamic_controller.inc',
            'pe_closing':'persistent_dynamic_controller.inc',
            'pe_decoding':'persistent_dynamic_controller.inc',
            'pe_terminal_ingress':'persistent_dynamic_controller.inc'}
        need(set(self.outer['flags'])==set(flag_bindings),'exact six emitted controller flags')
        actual_owner=one_symbol(self.symbols,'pe',1)
        need((actual_owner['address'],actual_owner['bytes'])==(reg['address'],reg['bytes']),
             'independent actual ELF owner object agrees with retained DWARF')
        for name,f in self.outer['flags'].items():
            declaration=flag_bindings[name];emitted=one_symbol(self.symbols,name,1)
            need(emitted['bytes']==4 and f==dict(source=str(Path(reg['source']).with_name(declaration)),
                 address=emitted['address'],bytes=4),
                 'exact named declaration/ELF-object-address/sig_atomic_t width: '+name)
            add(name,f['address'],f['bytes'])
        chain=l['symbols']['selected_chain'];scalars('chain',chain,'li2_tf_chain')
        slot=l['types']['li2_tf_chain']['fields']['slots'];st=l['types']['li2_tf_chain_slot']
        need(slot['bytes']==2*st['bytes'],'actual two ordinary chain slots')
        for i in range(2):
            scalars('chain.slot'+str(i),chain+slot['offset']+i*st['bytes'],'li2_tf_chain_slot')
        wire=l['symbols']['pdo_wire'];wt=l['types']['pdo_wire'];h=wt['fields']['h']
        need(h['bytes']==64*8,'actual64-word observation header')
        for i in range(64):add('capture.h.'+str(i),wire+h['offset']+i*8,8)
        epochs=wt['fields']['epochs'];et=l['types']['pdo_epoch'];eh=et['fields']['h']
        need(epochs['bytes']==3*et['bytes']and eh['bytes']==24*8,'actual three focal epoch headers')
        for i in range(3):
            for j in range(24):add('capture.epoch'+str(i)+'.h.'+str(j),wire+epochs['offset']+i*et['bytes']+eh['offset']+8*j,8)
        miss=wt['fields']['miss'];mh=l['types']['pdo_miss']['fields']['h']
        need(mh['bytes']==24*8,'actual focal miss header')
        for j in range(24):add('capture.miss.h.'+str(j),wire+miss['offset']+mh['offset']+8*j,8)
        need(len(fields)<400 and len({n for n,_,_ in fields})==len(fields),'small unique diagnostic scalar table')
        return fields

    def proc_stat(self,pid):
        b=bounded('/proc/'+str(pid)+'/stat',8192);end=b.rfind(b')')
        need(end>0 and int(b[:b.index(b' ')])==pid,'actual child proc identity')
        cols=b[end+2:].split();need(len(cols)>=37,'complete bounded proc stat')
        return dict(starttime=int(cols[19]),utime=int(cols[11]),stime=int(cols[12]),state=cols[0].decode(),
                    cpu=int(cols[36]))

    def maps(self,pid):
        raw=bounded('/proc/'+str(pid)+'/maps',1<<20);maps=[]
        for line in raw.splitlines():
            v=line.split(maxsplit=5);need(len(v)>=5,'whole proc maps row')
            lo,hi=(int(x,16)for x in v[0].split(b'-'));major,minor=(int(x,16)for x in v[3].split(b':'))
            maps.append(dict(lo=lo,hi=hi,perms=v[1].decode(),offset=int(v[2],16),
                             device=(major,minor),inode=int(v[4])))
        return raw,maps

    @staticmethod
    def read(fd,address,size):
        need(0<=address<1<<63 and 0<size<=1<<20,'bounded user-space read')
        b=os.pread(fd,size,address);need(len(b)==size,'complete read-only child memory')
        return b

    def locate(self,maps):
        own=[m for m in maps if (*m['device'],m['inode'])==self.identity]
        candidates=set()
        for m in own:
            for p in self.loads:
                po=p['offset']&~4095;pv=p['vaddr']&~4095
                if po<=m['offset']<((p['offset']+p['filesz']+4095)&~4095):
                    candidates.add(m['lo']-pv-(m['offset']-po))
        valid=[]
        for base in candidates:
            if base<=0 or base%4096:continue
            ok=True
            for p in self.loads:
                current=base+(p['vaddr']&~4095);end=base+((p['vaddr']+p['filesz']+4095)&~4095)
                while current<end:
                    matches=[m for m in own if m['lo']<=current<m['hi']and 'r'in m['perms']and
                        m['offset']+(current-m['lo'])==(p['offset']&~4095)+(current-(base+(p['vaddr']&~4095)))]
                    if len(matches)!=1:ok=False;break
                    current=min(end,matches[0]['hi'])
                if not ok:break
            if ok:valid.append(base)
        need(len(valid)==1,'unique bridge dev/inode and complete PT_LOAD file-offset correspondence')
        return valid[0],own

    def values(self,fd,base,maps):
        result={}
        for name,offset,size in self.fields:
            a=base+offset
            need(any(m['lo']<=a and a+size<=m['hi']and 'r'in m['perms']for m in maps),
                 'sample scalar in actual readable mapping')
            result[name]=int.from_bytes(self.read(fd,a,size),'little')
        return result

    def sample(self,pid,row,elapsed):
        began=time.monotonic_ns();sample=dict(index=len(self.samples),elapsed_seconds=elapsed,attributed=False)
        try:
            need(len(self.samples)<60,'at most60 one-second observations')
            before=self.proc_stat(pid)
            need(os.sched_getaffinity(pid)=={self.cpu},'actual child retains the one reserved CPU')
            if self.starttime is None:self.starttime=before['starttime']
            need(before['starttime']==self.starttime,'same unreaped child starttime')
            raw,maps=self.maps(pid)
            maps_path=self.out/('sample-%02d.maps'%sample['index'])
            with maps_path.open('xb')as f:f.write(raw)
            sample['maps_artifact']=dict(file=maps_path.name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
            base,own=self.locate(maps)
            fd=os.open('/proc/'+str(pid)+'/mem',os.O_RDONLY|os.O_CLOEXEC)
            try:
                need(self.read(fd,base,64)==self.image[:64]and
                     self.read(fd,base+self.header[0],self.header[1]-self.header[0])==self.image[self.header[0]:self.header[1]],
                     'live bridge ELF and complete program headers equal retained ELF')
                if self.attribution is None:
                    rx=[]
                    for p in self.loads:
                        if not p['flags']&1:continue
                        b=self.read(fd,base+p['vaddr'],p['filesz'])
                        need(b==self.image[p['offset']:p['offset']+p['filesz']],
                             'entire actual live RX load equals retained immutable bridge bytes')
                        rx.append(dict(vaddr=p['vaddr'],bytes=len(b),sha256=hashlib.sha256(b).hexdigest()))
                    need(rx,'at least one complete actual RX identity')
                    self.attribution=dict(base=base,identity=list(self.identity),stat_identity=list(self.stat_identity),
                                          projection=self.projection,maps=own,rx=rx,starttime=self.starttime)
                    save(self.out/'attribution.json',self.attribution)
                need(base==self.attribution['base'],'same attributed bridge base')
                a=self.values(fd,base,maps);b=self.values(fd,base,maps)
            finally:os.close(fd)
            after=self.proc_stat(pid)
            need(after['starttime']==self.starttime,'same child after asynchronous reads')
            sample.update(attributed=True,base=base,proc_before=before,proc_after=after,
                          maps_sha256=hashlib.sha256(raw).hexdigest(),values=b,
                          changed_between_reads=[name for name in a if a[name]!=b[name]])
        except Exception as exc:sample['unavailable']=type(exc).__name__+': '+str(exc)
        sample['sampling_ns']=time.monotonic_ns()-began
        self.samples.append(sample)
        # Durable bounded output even if the target later hits its unchanged cap.
        data=encoded(sample)+b'\n'
        need(len(data)<=32768,'bounded scalar sample output')
        with(self.out/'samples.jsonl').open('ab')as f:f.write(data)

def inner(root,receipt_path,out,manifest):
    r=dict(schema=1,scope='one-read-only-progress-diagnostic',status='failed',qualification=False,
           error=None,final_errors=[],commands=[],source_unchanged=False,inputs_unchanged=False,
           cleanup_complete=False,receipt=fact(receipt_path),sampler=manifest,
           reproduction=manifest['reproduction'],
           argv=sys.argv,started_utc=datetime.now(timezone.utc).isoformat())
    source=None;before=None;extra={};sampler=None;command=None
    try:
        receipt=json.loads(receipt_path.read_bytes());old=next(c for c in receipt['commands']if c['name']=='subject-gated-0-0')
        need(receipt['source']['revision']==manifest['revision']and receipt['source_unchanged']is True and
             receipt['cleanup_complete']is True and receipt['final_errors']==[] and receipt['status']=='failed',
             'exact original closed failed cohort remains failed')
        need(old['bounds']==PROGRAM and old['capture_limit']==16<<20 and old['expected_exit']==0 and
             old['exit']==-9 and old['reaped']is True and old['cleanup_errors']==[] and
             old['environment']==ENV,'actual original failed success-mode command and bounds')
        need(len(os.sched_getaffinity(0))==1,'one hard reserved CPU')
        cpu=next(iter(os.sched_getaffinity(0)));r['cpu']=cpu
        base=receipt_path.parent;bridge=base/'persistent-dynamic-capture/bridge-persistent-dynamic-capture.so'
        layout_path=base/'owner-dwarf-layout.json';layout=json.loads(layout_path.read_bytes())
        extra={str(receipt_path):manifest['receipt'],str(layout_path):receipt['owner_layout']['artifact'],
               str(bridge):receipt['subject_artifacts']['bridge']}
        for flag,key in (('--original','original'),('--carrier','carrier')):
            extra[old['argv'][old['argv'].index(flag)+1]]=receipt['subject_artifacts'][key]
        for value in receipt['runtime_libraries'].values():extra[value['path']]=value
        for c in receipt['commands']:
            if c['name']=='owner-layout':original_gdb=c;break
        else:raise ValueError('retained actual file-only GDB command')
        before=pin_inputs(receipt,extra);r['inputs_before']=before
        sys.path.insert(0,str(root/'evaluation/inprocess'))
        from checks import source
        from run import hardware
        spec=importlib.util.spec_from_file_location('persistent_dynamic_sample_process',HERE/SAMPLER_FILES[2])
        process=importlib.util.module_from_spec(spec);spec.loader.exec_module(process)
        r['source']=source();need(r['source']==receipt['source'],'exact clean original committed source')
        r['hardware']=hardware(cpu)
        need(r['hardware']['probe_cpu']==cpu and r['hardware']['affinity_cpu_count']==1,
             'fresh actual diagnostic hardware on the reserved CPU')
        need(process.ENV==ENV,'exact original invocation environment')
        argv=list(original_gdb['argv']);need(argv[-2]=='-x'and original_gdb['bounds']==INSPECT and
             argv.count('--se='+str(bridge))==1,'exact original bounded file-only DWARF inspection')
        argv[-1]=str(HERE/'persistent_dynamic_sample_dwarf.py')
        gdb=dict(name='owner-counter-layout',argv=argv,bounds=INSPECT,capture_limit=4<<20,
                 expected_exit=0,environment=original_gdb['environment'])
        need(gdb['environment'].get('MALLOC_ARENA_MAX')=='1'and
             'maintenance set worker-threads 1'in argv and 'set index-cache enabled off'in argv,
             'existing bounded GDB memory configuration')
        r['commands'].append(gdb);save(out/'receipt.json',r)
        stdout,stderr=process.program_invoke(gdb,out,cpu)
        need(gdb['exit']==0 and stdout and not stderr,'exact complete file-only GDB result')
        outer=json.loads(stdout);sampler=Sampler(bridge,layout,outer,out,cpu)
        save(out/'sample-fields.json',sampler.fields)
        child=out/'subject-gated-0-0';child.mkdir()
        argv=list(old['argv']);changes={}
        for flag,value in (('--preparation',str(child/'preparation.json')),
                           ('--namespace',str(child/'namespace')),('--record-fd','{record_fd}')):
            need(argv.count(flag)==1,'unique actual launch argument '+flag)
            i=argv.index(flag)+1;changes[flag]=dict(before=argv[i],after=value);argv[i]=value
        need(argv[argv.index('--root')+1]==str(root)and argv[argv.index('--role')+1]=='gated'and
             argv[argv.index('--mode')+1]=='0'and argv[argv.index('--control')+1]=='0',
             'exact original source/role/mode/control')
        r['argument_replacements']=changes
        command=dict(name=old['name'],argv=argv,bounds=PROGRAM,capture_limit=16<<20,
                     expected_exit=0,environment=ENV,profile='program')
        r['commands'].append(command);save(out/'receipt.json',r)
        process.OBSERVER=sampler
        try:process.program_invoke(command,out,cpu,record=True)
        finally:process.OBSERVER=None
        r['status']='completed_unqualified'if command['exit']==0 else 'failed_subject'
        if command['exit']!=0:r['error']='actual subject exit '+str(command['exit'])
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        if sampler is not None:
            r['observations']=dict(samples=len(sampler.samples),attributed=sum(s['attributed']for s in sampler.samples),
                                   asynchronous=True,coherent_snapshot_claim=False,qualification=False)
            if(out/'samples.jsonl').exists():r['samples']=fact(out/'samples.jsonl')
        for name,action in (
            ('source',lambda:source()if source else None),
            ('inputs',lambda:pin_inputs(receipt,extra)if before else None),
            ('private_driver',lambda:private_inputs(root,manifest))):
            try:
                value=action();r[name+'_after']=value
                if name=='source':r['source_unchanged']=value is not None and value==r.get('source')
                if name=='inputs':r['inputs_unchanged']=value is not None and value==before
            except BaseException as exc:r['final_errors'].append(name+': '+repr(exc))
        r['cleanup_complete']=all(c.get('reaped')is True and not c.get('cleanup_errors')for c in r['commands'])
        r['preparation_artifacts']={}
        for name in ('subject-gated-0-0/preparation.json','subject-gated-0-0/namespace/namespace.json',
                     'subject-gated-0-0/namespace/launch.json'):
            path=out/name
            if path.exists():r['preparation_artifacts'][name]=fact(path)
        prep=out/'subject-gated-0-0/preparation.json'
        if command is not None and prep.exists():
            try:
                prepared=json.loads(bounded(prep,65536))
                need(prepared['pid']==command.get('pid')and prepared['cpu']==[r['cpu']]and
                     prepared['mode']==0 and prepared['control']==0 and prepared['role']=='gated'and
                     prepared['reset_mask']==0 and prepared['observer']['fd']==3,
                     'fresh actual same-pid/CPU launch preparation')
                r['preparation_join']=True
            except Exception as exc:r['final_errors'].append('preparation: '+repr(exc))
        if any(c.get('observer_errors')for c in r['commands']):
            r['final_errors'].append('read-only diagnostic sample persistence failed; subject bounds unchanged')
        if not r['source_unchanged']or not r['inputs_unchanged']or not r['cleanup_complete']or r['final_errors']:
            r['status']='failed_diagnostic_closure'
        r['finished_utc']=datetime.now(timezone.utc).isoformat();save(out/'receipt.json',r)
        try:publish_projection(out,r,sampler)
        except BaseException as exc:
            r['final_errors'].append('compact projection: '+repr(exc));r['status']='failed_diagnostic_closure'
            save(out/'receipt.json',r)
    print(json.dumps(dict(receipt=str(out/'receipt.json'),status=r['status'],error=r['error'],
                         observations=r.get('observations')),sort_keys=True),flush=True)
    return 0 if r['status']=='completed_unqualified'else 1

def publish_projection(out,r,sampler):
    """Small source-bound numbers; all maps, PID details and raw values stay private."""
    command=next((c for c in r['commands']if c['name']=='subject-gated-0-0'),None)
    symbols={}
    if command is not None:
        original=Path(command['argv'][command['argv'].index('--original')+1])
        symbols=elf_symbols(original.read_bytes())
    samples=[]if sampler is None else sampler.samples
    header=['sample','elapsed_seconds','attributed','saved_rip','symbol','symbol_offset',
            'offers','entries','completed','cancelled','hits','fallthrough_reach_misses',
            'permit_claims','retirements','epoch_serial','phase','all_three_focal_terminal_headers',
            'changed_between_reads','child_user_ticks','child_system_ticks','unavailable']
    with(out/'summary.csv').open('x',newline='')as stream:
        writer=csv.DictWriter(stream,fieldnames=header);writer.writeheader()
        for sample in samples:
            row=dict(sample=sample['index'],elapsed_seconds=format(sample['elapsed_seconds'],'.9f'),
                     attributed=int(sample['attributed']),unavailable='')
            if not sample['attributed']:
                # Error category only; private raw text can contain host details.
                row['unavailable']='read_or_attribution_unavailable';writer.writerow(row);continue
            v=sample['values'];pc=v['pe.ingress.saved_rip'];matches=[]
            for name,entries in symbols.items():
                for item in entries:
                    if item['kind']==2 and item['address']<=pc<item['address']+item['bytes']:
                        matches.append((name,item))
            row.update(saved_rip=hex(pc),symbol='',symbol_offset='',
                       offers=v['pe.offers'],entries=v['pe.entries'],completed=v['pe.completed'],
                       cancelled=v['pe.cancelled'],hits=v['pe.hits'],fallthrough_reach_misses=v['pe.misses.12'],
                       permit_claims=v['pe.permit_claims'],retirements=v['pe.retirements'],
                       epoch_serial=v['pe.p.serial'],phase=v['pe.p.phase'],
                       changed_between_reads=len(sample['changed_between_reads']),
                       child_user_ticks=sample['proc_after']['utime'],child_system_ticks=sample['proc_after']['stime'],
                       all_three_focal_terminal_headers=int(all(v['capture.epoch'+str(i)+'.h.14']==1 and
                           v['capture.epoch'+str(i)+'.h.9']==1 and v['capture.epoch'+str(i)+'.h.10']==0 for i in range(3))))
            if len(matches)==1:
                row['symbol']=matches[0][0];row['symbol_offset']=hex(pc-matches[0][1]['address'])
            writer.writerow(row)
    summary=dict(schema=1,scope='single-read-only-progress-diagnostic',status=r['status'],
        source_revision=r.get('source',{}).get('revision'),sampler_revision=r['sampler']['sampler_revision'],
        sampler_files=r['sampler']['files'],hardware=r.get('hardware'),reproduction=r['reproduction'],
        allocator={k:r['sampler']['allocator'][k]for k in ('name','bytes','sha256')},
        receipt_input=r['receipt'],receipt=fact(out/'receipt.json'),
        subject_exit=None if command is None else command.get('exit'),
        subject_duration_ns=None if command is None else command.get('duration_ns'),
        program_bounds=PROGRAM,inspect_bounds=INSPECT,source_unchanged=r['source_unchanged'],
        inputs_unchanged=r['inputs_unchanged'],cleanup_complete=r['cleanup_complete'],
        final_error_count=len(r['final_errors']),sample_count=len(samples),
        attributed_sample_count=sum(s['attributed']for s in samples),csv=fact(out/'summary.csv'),
        qualification=False,performance_credit=False,
        limits=['saved_rip is a historical signal-frame PC, not the live instruction pointer',
                'asynchronous reads are not coherent transactional snapshots',
                'scalar focal headers do not replace complete native/owner qualification',
                'sampled progress does not attribute all elapsed time or unsampled execution'])
    need(len(encoded(summary))<=32768 and fact(out/'summary.csv')['bytes']<=65536,
         'small sanitized public diagnostic projection')
    save(out/'summary.json',summary)

def private_inputs(root,manifest):
    revision=manifest['sampler_revision']
    need(len(revision)==40 and all(c in '0123456789abcdef'for c in revision),'exact sampler Git revision')
    actual={}
    for name in SAMPLER_FILES:
        path='evaluation/inprocess/'+name
        expected=git(root,'show',revision+':'+path)
        observed=fact(HERE/name)
        need(observed==dict(bytes=len(expected),sha256=hashlib.sha256(expected).hexdigest()),
             'published sampler source matches exact Git object: '+name)
        actual[name]=observed
    need(actual==manifest['files'],'same complete published sampler inputs')
    allocator=manifest['allocator']
    need(fact(allocator['path'])=={k:allocator[k]for k in ('bytes','sha256')} and
         Path(allocator['path']).name==allocator['name'],'same complete CPU allocator executable')
    return digest(dict(files=actual,allocator={k:allocator[k]for k in ('name','bytes','sha256')}))


def main():
    global HERE
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--receipt',type=Path,required=True)
    p.add_argument('--receipt-sha256',required=True)
    p.add_argument('--sampler-revision',required=True)
    p.add_argument('--sampler-dir',type=Path,default=HERE)
    p.add_argument('--output',type=Path)
    p.add_argument('--child',action='store_true')
    p.add_argument('--allocator',help='cpuset-alloc executable; otherwise resolved from PATH')
    a=p.parse_args();root=Path(git(Path.cwd(),'rev-parse','--show-toplevel').decode().strip()).resolve()
    HERE=a.sampler_dir.resolve(strict=True)
    need(Path(__file__).resolve()==HERE/SAMPLER_FILES[0],'exact explicit sampler directory')
    receipt_path=a.receipt.resolve(strict=True);receipt_fact=fact(receipt_path)
    need(receipt_path.is_relative_to(root),'retained receipt within the repository slot')
    need(len(a.receipt_sha256)==64 and receipt_fact['sha256']==a.receipt_sha256,
         'caller-pinned exact retained collector receipt')
    prior=json.loads(receipt_path.read_bytes())
    allocator=shutil.which(a.allocator or 'cpuset-alloc')
    need(allocator is not None,'explicit or PATH-resolved cpuset-alloc required')
    # Dispatch wrappers can select their tool from argv[0]; keep that symlink.
    allocator=str(Path(allocator).absolute())
    sampler_dir='evaluation/inprocess'if HERE==root/'evaluation/inprocess'else '<SAMPLER_DIR>'
    reproduction=dict(cwd='repository root at source_revision',
        argv=['python3','-B',sampler_dir+'/'+SAMPLER_FILES[0],
              '--receipt',receipt_path.relative_to(root).as_posix(),
              '--receipt-sha256',a.receipt_sha256,'--sampler-revision',a.sampler_revision,
              '--sampler-dir',sampler_dir,'--allocator',Path(allocator).name],
        extracted_sampler_directory=None if sampler_dir=='evaluation/inprocess'else
            'replace <SAMPLER_DIR> with a directory containing exactly the three sampler Git blobs',
        output='fresh private directory under target/evaluation/inprocess')
    manifest=dict(schema=1,revision=prior['source']['revision'],receipt=receipt_fact,
                  sampler_revision=a.sampler_revision,files={n:fact(HERE/n)for n in SAMPLER_FILES},
                  allocator=dict(path=allocator,name=Path(allocator).name,**fact(allocator)),
                  reproduction=reproduction)
    private_inputs(root,manifest)
    need(git(root,'rev-parse','HEAD').decode().strip()==manifest['revision']and
         not git(root,'status','--porcelain','-uno'),'same clean committed collector source')
    if a.child:
        need(a.output is not None and a.output.is_dir(),'parent owns fresh private output')
        return inner(root,receipt_path,a.output.resolve(),manifest)
    need(int(subprocess.check_output(['du','-sx','-B1',str(root)]).split()[0])<20_000_000_000,
         'original slot below20GB')
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    out=(a.output or root/'target/evaluation/inprocess'/('persistent-dynamic-sample-'+stamp)).resolve()
    need(out.is_relative_to(root/'target')and not out.exists(),'fresh output in the same target slot')
    out.mkdir(parents=True)
    env=dict(os.environ,AGENT_UTILS_ENGINE='python',CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='1')
    argv=[allocator,'run','--cores','1','--tag','li2adm-dynamic-stall','--',sys.executable,'-B',
          str(HERE/SAMPLER_FILES[0]),'--child','--receipt',str(receipt_path),
          '--receipt-sha256',a.receipt_sha256,'--sampler-revision',a.sampler_revision,
          '--sampler-dir',str(HERE),'--allocator',allocator,'--output',str(out)]
    r=dict(schema=1,scope='one-bounded-diagnostic-reservation',argv=argv,revision=manifest['revision'],
           started_utc=stamp,exit=None,qualification=False,allocator=fact(allocator),sampler=manifest)
    save(out/'outer.json',r);start=time.monotonic_ns()
    try:
        with(out/'outer.stdout').open('xb')as stdout,(out/'outer.stderr').open('xb')as stderr:
            child=subprocess.run(argv,cwd=root,env=env,stdout=stdout,stderr=stderr)
        r['exit']=child.returncode
    except BaseException as exc:r['error']=repr(exc)
    finally:
        r['duration_ns']=time.monotonic_ns()-start
        r['captures']={n:fact(out/n)for n in ('outer.stdout','outer.stderr')if(out/n).exists()}
        save(out/'outer.json',r)
    print(json.dumps(dict(output=str(out),exit=r['exit']),sort_keys=True),flush=True)
    return r['exit']if type(r['exit'])is int else 1

if __name__=='__main__':raise SystemExit(main())
