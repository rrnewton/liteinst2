#!/usr/bin/env python3
"""Current release: five real-ls pairs and fixed same-process strrchr batches."""
import argparse,ctypes,csv,hashlib,importlib.util,io,json,os,platform,re,resource,select,shlex,shutil,signal,statistics,struct,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from page_selected import ENV,fact,need,save,elf,interpreter
from checks import source
from run import hardware
from page_selected_generic_build import Build,PROFILES as BUILD_PROFILES
from page_selected_process import invoke,Action
import page_default_ls_release_provenance as provenance
import page_selected_repeat_lease_ls_reports as ls_reports
import page_late_dso_reports as hot_reports
from page_selected_effect_ls import finalize
from page_selected_repeat_lease_ls import build_bridge,PROGRAM_ENV,BOUNDS,SELECTED
from page_selected_register_real import resolved_libraries
from page_selected_oneshot_build import before_default
from page_selected_register_time_build import recipe,expand
from page_selected_register_time_compare import decode
FIXTURE=SELECTED/'tests/release_workload'
ORDER=tuple((workload,pair,lane)for workload in('ls','hot')for pair in range(5)
    for lane in (('native','gated')if pair%2==0 else('gated','native')))
NAMES=tuple(f'{workload}-{pair}-{lane}'for workload,pair,lane in ORDER)
H=lambda b:hashlib.sha256(b).hexdigest()
def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode())

def program_invoke(row, directory, cpu, record=False, step=False):
    process = None
    pidfd = None
    descriptors = []
    start = time.monotonic_ns()
    row.update(exit=None, timed_out=False, reaped=False, error=None, cleanup_errors=[], descriptors=[])
    bounds = row['bounds']
    paths = {name: directory/(row['name']+'.'+name) for name in ('stdout', 'stderr')}
    record_fd = prep_fd = None
    libc = None

    def reset_signals():
        previous = ctypes.c_uint64(0)
        empty = ctypes.c_uint64(0)
        actual = ctypes.c_uint64(1)
        zero, before, after = Action(), Action(), Action()
        if libc.syscall(14, 2, ctypes.byref(empty), ctypes.byref(previous), 8) != 0:
            os._exit(120)
        observations = []
        for number in range(1, 65):
            if number in (9, 19):
                continue
            if libc.syscall(13, number, None, ctypes.byref(before), 8) != 0:
                os._exit(121)
            if libc.syscall(13, number, ctypes.byref(zero), None, 8) != 0:
                os._exit(122)
            if libc.syscall(13, number, None, ctypes.byref(after), 8) != 0 or after.handler:
                os._exit(123)
            observations.append({'signal': number, 'before': int(before.handler or 0),
                                 'after': int(after.handler or 0)})
        if libc.syscall(14, 2, None, ctypes.byref(actual), 8) != 0 or actual.value != 0:
            os._exit(123)
        data = json.dumps({'previous_mask': previous.value, 'mask': actual.value,
                           'dispositions': observations}, separators=(',', ':')).encode()
        if os.write(prep_fd, data) != len(data):
            os._exit(124)
        os.close(prep_fd)

    def prepare():
        os.sched_setaffinity(0, {cpu})
        if step:
            reset_signals()
        for key, value in ((resource.RLIMIT_CPU, bounds[0]), (resource.RLIMIT_AS, bounds[1]),
                           (resource.RLIMIT_FSIZE, bounds[2]), (resource.RLIMIT_CORE, 0)):
            resource.setrlimit(key, (value, value))
        if row.get('nproc') is not None:
            resource.setrlimit(resource.RLIMIT_NPROC, (row['nproc'], row['nproc']))

    def own(name):
        path = directory/(row['name']+'.'+name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        state = {'name': name, 'fd': fd, 'closed': False}
        descriptors.append((fd, state))
        row['descriptors'].append(state)
        paths[name] = path
        return fd

    def close_group():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as exc:
            row['cleanup_errors'].append('kill: '+repr(exc))

    try:
        # Resolve libc before fork inside the retained attempt. Only this
        # diagnostic child's preparation uses it; target handlers do not.
        if step:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.syscall.restype = ctypes.c_long
        if record:
            record_fd = own('record')
            if step:
                need(record_fd == 3, 'standalone step requires actual fixed fd 3')
                prep_fd = own('preparation')
        row['argv'] = [str(record_fd) if value == '{record_fd}' else str(value) for value in row['argv']]
        with paths['stdout'].open('xb') as stdout, paths['stderr'].open('xb') as stderr:
            row['stdout_provenance_before']=provenance.observe(stdout.fileno())
            try:
                row['process_start_ns'] = time.monotonic_ns()
                process = subprocess.Popen(row['argv'], cwd=directory, env=row.get('environment', ENV),
                                           stdout=stdout, stderr=stderr, start_new_session=True,
                                           pass_fds=tuple(fd for fd, _ in descriptors), preexec_fn=prepare)
                row['pid'] = process.pid
                pidfd = os.pidfd_open(process.pid)
                if not select.select([pidfd], [], [], bounds[3])[0]:
                    row['timed_out'] = True
                    raise TimeoutError('component wall bound')
                # The unreaped leader pins the process-group number until cleanup.
                close_group()
                row['exit'] = process.wait(timeout=3)
                row['reaped'] = True
                row.setdefault('process_reaped_ns', time.monotonic_ns())
            finally:
                try:
                    row['stdout_provenance_after']=provenance.observe(stdout.fileno())
                    provenance.same(row['stdout_provenance_before'],row['stdout_provenance_after'])
                except BaseException as exc:
                    row['cleanup_errors'].append('parent descriptor identity: '+repr(exc))
    except BaseException as exc:
        row['error'] = type(exc).__name__+': '+str(exc)
    finally:
        if process is not None and process.returncode is None:
            close_group()
            try:
                row['exit'] = process.wait(timeout=3)
                row['reaped'] = True
                row.setdefault('process_reaped_ns', time.monotonic_ns())
            except BaseException as exc:
                row['cleanup_errors'].append('wait: '+repr(exc))
        elif process is not None:
            row['exit'] = process.returncode
            row['reaped'] = True
            row.setdefault('process_reaped_ns', time.monotonic_ns())
        if pidfd is not None:
            try:
                os.close(pidfd)
            except BaseException as exc:
                row['cleanup_errors'].append('pidfd_close: '+repr(exc))
        # Each descriptor leaves the close list before its close is attempted;
        # a failure cannot trigger a later close of a reused numeric descriptor.
        while descriptors:
            fd, state = descriptors.pop()
            try:
                os.close(fd)
                state['closed'] = True
            except BaseException as exc:
                state['error'] = repr(exc)
                row['cleanup_errors'].append(state['name']+'_close: '+repr(exc))
        if 'process_reaped_ns' in row:
            row['process_ns'] = row['process_reaped_ns']-row['process_start_ns']
        row['duration_ns'] = time.monotonic_ns()-start
        row['captures'] = {}
        for name, path in paths.items():
            try:
                row['captures'][name] = dict(fact(path), file=path.name)
            except BaseException as exc:
                row['cleanup_errors'].append(name+'_capture: '+repr(exc))
        try:
            save(directory/(row['name']+'.json'), row)
        except BaseException as exc:
            row['cleanup_errors'].append('command_record: '+repr(exc))
    need(row['reaped'] and not row['timed_out'] and not row['error'] and not row['cleanup_errors'],
         'component process/cleanup failed: '+row['name'])
    cap = row['capture_limit']
    need(all(row['captures'][name]['bytes'] <= cap for name in ('stdout', 'stderr')), 'capture limit')
    if record:
        need(row['captures']['record']['bytes'] <= bounds[2], 'private record limit')
    if step:
        data = json.loads(paths['preparation'].read_bytes())
        need(data['mask'] == 0 and [x['signal'] for x in data['dispositions']] ==
             [n for n in range(1, 65) if n not in (9, 19)] and
             all(x['after'] == 0 for x in data['dispositions']), 'actual standalone signal preparation')
    return paths['stdout'].read_bytes(), paths['stderr'].read_bytes()


def subject_record(data):
    need(type(data)is bytes and 0<len(data)<4096 and data.endswith(b'\n'), 'complete bounded workload record')
    lines=data.splitlines();need(len(lines)==10,'one header and all nine actual timed batches')
    prefix=b'LI2_WORKLOAD 1 64 4096 1024 8 8192 '
    need(lines[0].startswith(prefix),'exact workload population/version')
    resolution=lines[0][len(prefix):]
    need(re.fullmatch(rb'[1-9][0-9]*',resolution)is not None and 0<int(resolution)<1<<64,'positive actual RAW resolution')
    rows=[]
    for index,line in enumerate(lines[1:]):
        need(re.fullmatch(rb'[0-9]+(?: [0-9]+){5}',line)is not None,'exact six numeric workload fields')
        row=list(map(int,line.split()))
        need(b' '.join(str(x).encode()for x in row)==line and all(0<=x<1<<64 for x in row),'canonical uint64 workload row')
        i,count,start,end,ns,checksum=row;expected_count=1024 if index==0 else 8192
        expected_sum=sum(63+37*((k*17)&63)for k in range(expected_count))
        need(i==index and count==expected_count and checksum==expected_sum,'independent exact result for every real call')
        need(start>0 and start<end and end-start==ns and ns<60_000_000_000 and
             (index==0 or rows[-1][3]<=start),'same RAW domain, complete ordered timestamps and exact interval')
        rows.append(row)
    return dict(resolution_ns=int(resolution),rows=rows,semantic=[[x[0],x[1],x[5]]for x in rows])


def subject_controls(data):
    accepted=subject_record(data);lines=data.splitlines();changed=[]
    for name,index,field,value in (('checksum',1,5,accepted['rows'][0][5]+1),
        ('calls',2,1,8191),('index',2,0,0),('elapsed',2,4,accepted['rows'][1][4]+1),
        ('clock_order',2,2,accepted['rows'][0][2]),('empty_interval',1,3,accepted['rows'][0][2])):
        copy=list(lines);row=copy[index].split();row[field]=str(value).encode();copy[index]=b' '.join(row)
        changed.append((name,b'\n'.join(copy)+b'\n'))
    changed.extend((('missing_row',b'\n'.join(lines[:-1])+b'\n'),
        ('duplicate_row',data+lines[-1]+b'\n'),('zero_resolution',lines[0].rsplit(b' ',1)[0]+b' 0\n'+b'\n'.join(lines[1:])+b'\n')))
    for name,value in changed:
        need(value!=data,'supplied workload input actually changes')
        refused=False
        try:subject_record(value)
        except ValueError:refused=True
        need(refused,'complete workload reader refuses supplied '+name)
    need(subject_record(data)==accepted,'actual workload record unchanged')
    return dict(scope='supplied record mutations; no native credit',refusals=[x[0]for x in changed],actual_sha256=H(data))


def subject_elf(path,assembly):
    data,h,ph=elf(path)
    need(h[1]==3 and len([p for p in ph if p[0]==2])==1 and len([p for p in ph if p[0]==3])==1 and
         not any(p[0]==1 and p[1]&3==3 for p in ph),'actual dynamic PIE, PT_INTERP and no RWX load')
    need(h[11]==64 and h[12]>0 and h[6]+64*h[12]<=len(data),'complete actual ELF section table')
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,h[6]+64*i)for i in range(h[12])]
    def contents(section):
        need(section[4]<=len(data) and section[5]<=len(data)-section[4],'complete file section')
        return data[section[4]:section[4]+section[5]]
    def symbols(section):
        need(section[9]==24 and section[5]%24==0 and section[6]<len(sections),'actual ELF symbol table')
        raw=contents(section);strings=contents(sections[section[6]]);values=[]
        for at in range(0,len(raw),24):
            row=struct.unpack_from('<IBBHQQ',raw,at);off=row[0]
            need(off<len(strings)and b'\0'in strings[off:],'complete symbol name')
            values.append((strings[off:strings.index(0,off)].decode('ascii'),row))
        return values
    full=[s for s in sections if s[1]==2];need(len(full)==1,'retained exact full symbols')
    found={name:[r for n,r in symbols(full[0])if n==name]for name in('workload_scan','workload_batch')}
    need(all(len(v)==1 for v in found.values()),'one actual volatile pointer and batch symbol')
    pointer=found['workload_scan'][0];batch=found['workload_batch'][0]
    need(pointer[1]&15==1 and pointer[5]==8 and batch[1]&15==2 and batch[5]>0,'actual pointer/function extents')
    need(sum(p[0]==1 and p[1]==6 and p[3]<=pointer[4] and pointer[4]+8<=p[3]+p[5] for p in ph)==1 and
         sum(p[0]==1 and p[1]==5 and p[3]<=batch[4] and batch[4]+batch[5]<=p[3]+p[5]for p in ph)==1,
         'complete source pointer in writable data and batch in RX')
    # Tie the relocation to the dynamic loader's actual tables, rather than
    # accepting a same-name relocation in unrelated/debug sections.
    dynamic=next(p for p in ph if p[0]==2)
    need(dynamic[5]%16==0 and dynamic[2]+dynamic[5]<=len(data),'actual complete dynamic table')
    tags=[]
    for at in range(dynamic[2],dynamic[2]+dynamic[5],16):
        tag,value=struct.unpack_from('<qQ',data,at)
        if tag==0:break
        tags.append((tag,value))
    else:need(False,'terminated dynamic table')
    def tag_value(tag):
        values=[v for k,v in tags if k==tag];need(len(values)==1,'unique required dynamic tag')
        return values[0]
    rela_address,rela_size=tag_value(7),tag_value(8)
    need(tag_value(9)==24 and tag_value(11)==24,'actual dynamic RELA/symbol entry sizes')
    relas=[s for s in sections if s[1]==4 and s[3]==rela_address and s[5]==rela_size]
    need(len(relas)==1,'dynamic RELA is one complete real section')
    rel=relas[0]
    need(rel[9]==24 and rel[5]%24==0 and rel[6]<len(sections),'complete actual dynamic RELA')
    dynsym=sections[rel[6]]
    need(dynsym[1]==11 and dynsym[3]==tag_value(6) and dynsym[6]<len(sections),
         'loader-selected dynamic symbol table')
    strings=sections[dynsym[6]]
    need(strings[1]==3 and strings[3]==tag_value(5) and strings[5]==tag_value(10),
         'loader-selected complete symbol string table')
    for section in(rel,dynsym,strings):
        need(sum(p[0]==1 and p[3]<=section[3] and section[3]+section[5]<=p[3]+p[5] and
             p[2]+section[3]-p[3]==section[4]for p in ph)==1,'actual file-backed loaded dynamic section')
    syms=symbols(dynsym);raw=contents(rel);targets=[]
    for at in range(0,len(raw),24):
        offset,info,addend=struct.unpack_from('<QQq',raw,at)
        if offset!=pointer[4]:continue
        need(info>>32<len(syms),'relocation symbol index')
        name,symbol=syms[info>>32]
        need(symbol[1]&15==2 and symbol[3]==0 and symbol[4]==0,'actual undefined imported function')
        targets.append((info&0xffffffff,name,addend))
    need(targets==[(1,'strrchr',0)],'actual volatile pointer initialized by exactly one loader strrchr relocation')
    text=assembly.decode('ascii');body=[]
    for line in text.splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(\S+)\s*(.*)$',line)
        if m:body.append((int(m[1],16),bytes.fromhex(m[2]),m[3],m[4]))
    need(body and body[0][0]==batch[4] and body[-1][0]+len(body[-1][1])==batch[4]+batch[5] and
         all(a[0]+len(a[1])==b[0]for a,b in zip(body,body[1:])),
         'complete contiguous bytes of the named emitted batch function')
    load=next(p for p in ph if p[0]==1 and p[1]==5 and p[3]<=batch[4]<p[3]+p[5])
    for pc,encoded,op,operands in body:
        offset=load[2]+pc-load[3]
        need(data[offset:offset+len(encoded)]==encoded,'every disassembled instruction matches actual ELF bytes')
    calls=[i for i,x in enumerate(body)if x[2].startswith('call')]
    indirect=[i for i in calls if '*'in body[i][3]]
    need(len(indirect)==1 and all(i in indirect or '<_exit@plt>'in body[i][3]for i in calls),
         'one actual indirect dispatch; only terminal assertion failure may call another function')
    names=('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15')
    loads=[]
    for i,(pc,code,op,operands)in enumerate(body):
        if len(code)!=7 or code[0]not in(0x48,0x4c)or code[1]!=0x8b or code[2]&0xc7!=5:continue
        address=pc+7+int.from_bytes(code[3:],'little',signed=True)
        if address!=pointer[4]:continue
        reg=((code[2]>>3)&7)+(8 if code[0]&4 else 0)
        need(op in('mov','movq')and re.search(r',%'+names[reg]+r'\s+#\s*'+format(pointer[4],'x')+r' <workload_scan>$',operands),
             'actual RIP-relative eight-byte volatile pointer load')
        loads.append((i,reg))
    need(len(loads)==1,'one exact actual volatile pointer load')
    li,reg=loads[0];ci=indirect[0];call=body[ci]
    encoding=(bytes([0x41])if reg>=8 else b'')+bytes([0xff,0xd0+(reg&7)])
    need(li<ci and call[1]==encoding and call[3]=='*%'+names[reg],
         'loaded pointer is exactly the indirect-call register')
    aliases=(('rax','eax','ax','al','ah'),('rcx','ecx','cx','cl','ch'),('rdx','edx','dx','dl','dh'),
        ('rbx','ebx','bx','bl','bh'),('rsp','esp','sp','spl'),('rbp','ebp','bp','bpl'),
        ('rsi','esi','si','sil'),('rdi','edi','di','dil'))
    register_names=aliases[reg]if reg<8 else tuple(names[reg]+x for x in('','d','w','b'))
    need(not any(re.search(r'%(?:'+'|'.join(register_names)+r')\b',x[3])or
         x[2].startswith(('call','j','loop'))for x in body[li+1:ci]),
         'pointer register and straight-line load-to-call provenance remain intact')
    back=[]
    for i,x in enumerate(body):
        m=re.match(r'([0-9a-f]+) <',x[3])
        if x[2].startswith('j')and m and batch[4]<=int(m[1],16)<x[0]:back.append((i,int(m[1],16)))
    need(len(back)==1 and back[0][1]<=body[li][0]<call[0]<body[back[0][0]][0]and
         not any(x[2].startswith(('call','j','loop','ret'))for x in body if back[0][1]<=x[0]<call[0]),
         'actual loop backedge encloses the mandatory pointer reload and indirect call')
    return dict(type='PIE',pointer_bytes=8,batch_bytes=batch[5],strrchr_dynamic_relocations=1,
                indirect_calls=1,disassembly_sha256=H(assembly),elf=fact(path))


def build_subject(builder,private,pin,binary,run,r):
    output=private/'workload';output.mkdir();script=pin(FIXTURE/'build.sh')
    rows=recipe(script,'"$cc_bin"');need(len(rows)==1,'one explicit normal PIE workload recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$source_dir':FIXTURE,'$output':output})
    unit=str(pin(FIXTURE/'subject.c'));path=output/'strrchr-workload'
    expected=[str(builder.tools['cc']),'-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-fPIE','-pie',
        '-fno-builtin-strrchr','-fno-lto','-Wl,-z,relro,-z,now,-z,noexecstack',unit,'-o',str(path)]
    need(argv==expected,'exact ordinary release subject recipe; no ISA suppression')
    state=r['subject_build']=dict(status='failed',recipe=fact(script),argv=argv)
    flags=[x for x in argv[1:-2]if x!=unit and not x.startswith('-Wl,')]
    _,out,err=run('workload-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_workload',unit],env=builder.environment)
    rules=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(rules)==1 and rules[0].startswith('li2_workload: '),'one complete actual subject include rule')
    includes={str(pin(x)):fact(pin(x))for x in shlex.split(rules[0].split(':',1)[1])}
    need(unit in includes,'real subject included');state['headers']=includes
    run('workload-link',argv,profile='release_build',env=builder.environment);binary(path)
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('workload-body',[objdump,'-d','-w','-M','att','--disassemble=workload_batch',path],profile='inspect',env=builder.environment)
    need(not err,'actual emitted workload inspection stderr');state['elf']=subject_elf(path,out)
    state['status']='passed';return path


def prepare_workload(kind,original,args,bridge,builder,private,pin,binary,run,r,namespace):
    original=pin(original);interp=pin(interpreter(original));carrier=private/(kind+'-carrier')
    carrier_tool=pin(SELECTED.parent/'carrier.py')
    objects,description=namespace.plan(original,[Path('/usr/lib64')],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    if kind=='hot':need(namespace.parse(original.read_bytes())['needed']==['libc.so.6'],'actual normal libc dynamic workload')
    expected={interp:set()}
    for item in objects:
        p=pin(item['path']);need(fact(p)['sha256']==H(item['bytes']),'every actual namespace dependency pinned')
        expected.setdefault(p,set()).update(item['names'])
    system=dict(original=fact(original),interpreter=fact(interp),dependencies=[dict(names=x['names'],**fact(x['path']))for x in objects])
    r.setdefault('system_inputs',{})[kind]=system;r.setdefault('namespace_plans',{})[kind]=description
    images=[];image_bytes=[];by_hash={}
    for role,path in [('original',original),('interpreter',interp)]+[('dependency-'+str(i),x['path'])for i,x in enumerate(objects)]:
        path=pin(path);data=path.read_bytes();identity=fact(path)
        need(identity==dict(bytes=len(data),sha256=H(data)),'complete stable independent external ELF')
        if identity['sha256']in by_hash:
            index=by_hash[identity['sha256']];need(data==image_bytes[index],'complete duplicate external content identity')
            images[index]['roles'].append(role);continue
        index=len(images);copy=private/'external-inputs'/(identity['sha256']+'.elf')
        if not copy.exists():
            with copy.open('xb')as f:f.write(data)
        need(fact(binary(copy))==identity,'retained complete external ELF bytes')
        images.append(dict(identity,roles=[role]));image_bytes.append(data);by_hash[identity['sha256']]=index
    r.setdefault('external_inputs',{})[kind]=images
    _,out,err=run(kind+'-native-libraries',[interp,'--list',original],env=PROGRAM_ENV)
    need(not err,'actual native loader listing stderr');resolved_libraries(out,expected,interp,pin)
    _,out,err=run(kind+'-carrier',[builder.tools['python'],'-B',carrier_tool,'make',original,bridge,carrier],profile='program',env=PROGRAM_ENV)
    need(not err,'actual carrier construction stderr');binary(carrier);identities=decode(out)
    need(all(identities[k+'_sha256']==fact(p)['sha256']for k,p in
        (('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier)))and interpreter(carrier)==bridge,
        'actual original/interpreter/release bridge/carrier identities')
    r.setdefault('carriers',{})[kind]=fact(carrier)
    return dict(original=original,argv=[str(original),*args],carrier=carrier,carrier_bytes=carrier.read_bytes(),
        objects=objects,description=description,images=images,image_bytes=image_bytes,carrier_tool=carrier_tool)


def namespace_join(state,ns,binary,r,namespace):
    observed=decode(binary(ns/'namespace.json').read_bytes());launch=decode(binary(ns/'launch.json').read_bytes())
    objects=state['objects'];description=state['description']
    need(all(observed[k]==v for k,v in description.items())and observed['directory']==str(ns)and
         observed['schema_version']==1 and observed['status']=='prepared_not_executed'and len(observed['objects'])==len(objects),
         'actual complete sealed namespace matches independent plan')
    fds=[]
    for obj,item in zip(observed['objects'],objects,strict=True):
        need(type(obj['fd'])is int and obj['fd']>2 and obj['fd']not in fds and
             obj['source']==str(item['path'])and obj['names']==item['names']and obj['needed']==item['info']['needed']and
             obj['descriptive_pt_interp']==(str(item['info']['interpreter'])if item['info']['interpreter']else None)and
             obj['sha256']==H(item['bytes'])and obj['size']==len(item['bytes'])and obj['seals']==namespace.SEALS and
             type(obj['device'])is int and obj['device']>0 and type(obj['inode'])is int and obj['inode']>0,
             'actual complete sealed dependency identity')
        fds.append(obj['fd'])
        for alias in obj['names']:
            path=ns/alias;value='/proc/self/fd/'+str(obj['fd'])
            need(path.is_symlink()and os.readlink(path)==value,'actual sealed dependency alias')
            r['namespace_aliases'][str(path)]=value
    expected_env={k:v for k,v in PROGRAM_ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
    expected_env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)))
    need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',
        carrier_sha256=fact(state['carrier'])['sha256'],carrier_size=fact(state['carrier'])['bytes'],argv=state['argv'],
        environment=expected_env,dependency_fds=fds),'exact default-rseq launch/argv/environment/carrier/FD join')


def cohort(builder,products,private,pin,binary,aliases,run,r):
    bridge=build_bridge(builder,products,private,pin,binary,aliases,run,r)
    hot=build_subject(builder,private,pin,binary,run,r)
    spec=importlib.util.spec_from_file_location('performance_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    (private/'external-inputs').mkdir();r['namespace_aliases']={}
    states={kind:prepare_workload(kind,path,args,bridge,builder,private,pin,binary,run,r,namespace)
            for kind,path,args in(('ls','/bin/ls',['-d','.']),('hot',hot,[]))}
    semantic={};r['reader_controls']={};r['terminal_reports']={}
    for ordinal,(kind,pair,lane)in enumerate(ORDER):
        name=NAMES[ordinal];s=states[kind];case=dict(workload=kind,pair=pair,lane=lane,ordinal=ordinal,status='failed')
        r['cases'].append(case)
        if lane=='native':argv=s['argv']
        else:
            ns=private/(name+'-namespace')
            argv=[builder.tools['python'],'-B',s['carrier_tool'],'exec-loader','--library-root','/usr/lib64',
                  '--namespace',ns,s['carrier'],s['original'],'--',*s['argv']]
        try:
            row,out,err=run(name,argv,profile='program',env=PROGRAM_ENV)
        finally:
            # The real owner records failure/cleanup before run() may raise.
            # Retain that outcome without parsing it as successful work or
            # inventing an interval when no actual reap was observed.
            attempts=[c for c in r['commands']if c['name']==name]
            if attempts:
                actual=attempts[-1]
                for target,key in(('exit','exit'),('process_ns','process_ns'),('whole_capture_ns','duration_ns')):
                    if key in actual:case[target]=actual[key]
                captured=actual.get('captures',{}).get('stdout')
                if captured is not None:case['stdout']={k:captured[k]for k in('bytes','sha256')}
        need(0<row['process_ns']<=row['duration_ns'],'actual Popen-to-reap interval within complete capture window')
        if kind=='ls':
            need(out==b'.\n','complete exact real ls output');result=out
        else:
            observed=subject_record(out);case['workload_record']=observed
            result=(observed['resolution_ns'],observed['semantic'])
            if kind not in r['reader_controls']:r['reader_controls'][kind]=subject_controls(out)
        if kind in semantic:need(result==semantic[kind],'complete exact semantic result across every native/gated repetition')
        else:semantic[kind]=result
        if lane=='native':need(err==b'','native stderr exactly empty')
        else:
            namespace_join(s,ns,binary,r,namespace)
            reader=ls_reports if kind=='ls'else hot_reports
            parsed,summary=reader.check(err,row['pid'],row['exit'],row['stdout_provenance_before'],
                s['images'],s['image_bytes'],fact(s['carrier']),s['carrier_bytes'])
            r['terminal_reports'][name]=parsed;case['comparison']=summary
            # Preserve every original supplied terminal control after each
            # actual successful subject, independently of timing acceptance.
            r['reader_controls'][name]=reader.supplied_controls(err,row['pid'],row['exit'],row['stdout_provenance_before'],
                s['images'],s['image_bytes'],fact(s['carrier']),s['carrier_bytes'])
        case['status']='passed'
    need([(c['workload'],c['pair'],c['lane'])for c in r['cases']]==list(ORDER)and
         all(c['status']=='passed'for c in r['cases']),'all twenty fixed subjects, no skipped pair or workload')


def measurement_rows(r):
    process=[];hot=[];admission=[];terminal=[]
    for c in r['cases']:
        i=c['ordinal'];process.append([i,int(c['workload']=='hot'),c['pair'],int(c['lane']=='gated'),
            int(c['status']=='passed'),c.get('exit'),c.get('process_ns'),c.get('whole_capture_ns')])
        if 'workload_record'in c:
            w=c['workload_record'];hot.append([i,w['resolution_ns'],w['rows']])
        if 'comparison'in c:
            s=c['comparison'];a=s['admission_timing'];admission.append([i,a['first_source_offset'],a['first_admission_ns'],a['revisit_count'],a['revisit_ns']])
            q=s['cache_reuse'];p=r['terminal_reports'][NAMES[i]]
            terminal.append([i,q['completed_runs'],q['generations'],q['retirements'],q['hits'],p['trace_run']['completed'],
                p['repeat_lease']['completed'],p['repeat_lease']['traces'],s['selected']['completed'],s['native']['admissions'],s['native']['closed']])
    return process,hot,admission,terminal


def publish(path,r,private):
    process,hot,admission,terminal=measurement_rows(r)
    table=io.StringIO(newline='');writer=csv.writer(table,lineterminator='\n')
    writer.writerow(['workload','pair','lane','pid_sample','phase','index','calls','ns','checksum'])
    for c in r['cases']:
        common=[c['workload'],c['pair'],c['lane'],c['ordinal']]
        if type(c.get('process_ns'))is int:writer.writerow(common+['launch',0,0,c['process_ns'],0])
        if 'workload_record'in c:
            for index,count,start,end,ns,checksum in c['workload_record']['rows']:
                writer.writerow(common+['warmup'if index==0 else'batch',index,count,ns,checksum])
    csv_data=table.getvalue().encode();csv_path=path.with_suffix('.csv')
    hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    captures=[(c['name'],k,v)for c in r['commands']for k,v in c.get('captures',{}).items()]
    value={k:r.get(k)for k in('schema','profile','scope','status','expected_revision','started_utc','source','source_unchanged',
        'cpu','bounds','reproduce','cleanup_complete','system_inputs','archive')}
    value.update(hardware=hw,private_receipt=fact(private/'receipt.json'),commands=len(r['commands']),captures=len(captures),
        command_rows_sha256=digest(r['commands']),capture_manifest_sha256=digest(captures),
        inputs_sha256=digest(r['inputs_before']),artifacts_sha256=digest(r['artifacts_before']),
        build_status=r.get('build',{}).get('status'),configuration_unchanged=r.get('build',{}).get('configuration_unchanged',False),
        tool_versions=r.get('build',{}).get('numeric_versions'),tool_bindings_sha256=digest(r.get('build',{}).get('tools',{})),
        release_build_status=r.get('release_build',{}).get('status'),bridge=r.get('release_build',{}).get('bridge'),
        subject=r.get('subject_build',{}).get('elf'),carriers=r.get('carriers'),planned_subjects=20,
        actual_subjects=sum(c['name']in NAMES and type(c.get('pid'))is int for c in r['commands']),
        completed_subjects=sum(c['status']=='passed'for c in r['cases']),
        process_columns=['sample','workload_hot','pair','gated','passed','exit','popen_to_reap_ns','whole_capture_ns'],process=process,
        hot_columns=['sample','clock_resolution_ns','rows[index,calls,start_raw_ns,end_raw_ns,elapsed_ns,checksum]'],hot=hot,
        admission_columns=['sample','first_file_offset','first_admission_work_ns','revisit_count','all_revisit_work_ns'],admission=admission,
        terminal_columns=['sample','runs','generations','retirements','hits','trace_completed','rep_completed','rep_traces','selected_completed','native_admissions','native_closed'],terminal=terminal,
        supplied_control_counts=[[name,len(c['refusals'])]for name,c in r.get('reader_controls',{}).items()],
        supplied_controls_sha256=digest(r.get('reader_controls',{})),csv=dict(file=csv_path.name,bytes=len(csv_data),sha256=H(csv_data)),
        error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
        failed_commands=[{k:c.get(k)for k in('name','profile','expected_exit','exit','timed_out','reaped')}for c in r['commands']
            if c.get('error')or c.get('cleanup_errors')or c.get('timed_out')or not c.get('reaped')or c.get('exit')!=c['expected_exit']],
        timing_credit=r['status']=='passed',first_touch_latency_credit=False,continuous_native_epoch_credit=False,
        full_state_oracle_credit=False,application_stress_qualification=False,
        timing_scope='Fresh ls launch is not steady throughput. RAW hot batches are fixed same-process post-warmup workload intervals, including dispatch, loop and timing boundaries. Admission work excludes fault ingress, execution and close. No cross-domain subtraction, cache-cold claim or per-batch route attribution.',
        command_recipe=dict(release=['sh','tools/page-entry/selected/build-repeat-lease.sh','${FRESH_ARCHIVE}','${OUTPUT}'],
            workload=['sh','tools/page-entry/selected/tests/release_workload/build.sh','${OUTPUT}'],
            native_ls=['/bin/ls','-d','.'],native_hot=['${CURRENT_PIE_SUBJECT}'],
            gated=['python3','-B','tools/page-entry/carrier.py','exec-loader','--library-root','/usr/lib64','--namespace','${UNIQUE_NAMESPACE}',
                '${CURRENT_RELEASE_CARRIER}','${ORIGINAL}','--','${ORIGINAL}','${LS_ARGS_OR_EMPTY}'],
            environment='PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC LD_BIND_NOW=1; default rseq'))
    if r['status']=='passed':
        value['launch_statistics']={}
        for kind in('ls','hot'):
            rows=[c for c in r['cases']if c['workload']==kind]
            native=[c['process_ns']for c in rows if c['lane']=='native'];gated=[c['process_ns']for c in rows if c['lane']=='gated']
            value['launch_statistics'][kind]=dict(native_median_ns=statistics.median(native),gated_median_ns=statistics.median(gated),
                gated_native_ratios=[g/n for n,g in zip(native,gated,strict=True)])
        value['hot_throughput_columns']=['sample','measured_calls','sum_batch_ns','calls_per_second']
        value['hot_throughput']=[[i,65536,sum(row[4]for row in rows[1:]),65536*1e9/sum(row[4]for row in rows[1:])]for i,_,rows in hot]
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<16<<10 and len(csv_data)<16<<10 and not any(x and len(x)>1 and (x in text or x in table.getvalue())for x in
        (str(ROOT),str(Path.home()),platform.node(),'/home/')),'bounded public JSON/CSV without raw/private paths')
    path.parent.mkdir(parents=True,exist_ok=True)
    with csv_path.open('xb')as f:f.write(csv_data)
    with path.open('x')as f:f.write(text)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),
         'exact committed revision, assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-release-workload-performance-'+a.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem
    private.mkdir(parents=True,mode=0o700);public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    bounds=dict(BUILD_PROFILES,**BOUNDS)
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='page-release-workload-performance-v1',scope='Five alternating native/gated real-ls pairs plus five fixed warm strrchr pairs under the current unobserved release. Exact semantic results, full terminal closure and unchanged limits precede timing credit; full-state and stress qualifications remain separate.',
        status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
        cpu=cpu,hardware=hardware(cpu),bounds=bounds,commands=commands,cases=[],error=None,final_errors=[],
        reproduce=['python3','evaluation/inprocess/page_release_workload_performance.py','--expect-revision',a.expect_revision])
    def pin(path,want=None):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);f=fact(p)
        need(want is None or f=={k:want[k]for k in('bytes','sha256')},'exact requested input bytes')
        need(str(alias)not in aliases or aliases[str(alias)]==str(p),'input alias changed')
        need(str(p)not in pins or pins[str(p)]==f,'input bytes changed')
        aliases[str(alias)]=str(p);pins[str(p)]=f;return p
    def binary(path):
        p=Path(path).resolve(strict=True);f=dict(fact(p),mode=p.stat().st_mode&0o777)
        need(str(p)not in artifacts or artifacts[str(p)]==f,'retained artifact changed');artifacts[str(p)]=f;return p
    def stable():
        need(all(Path(p).resolve(strict=True)==Path(v)for p,v in aliases.items()),'all lexical input aliases unchanged')
        need(all(fact(p)==v for p,v in pins.items()),'all input bytes unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'all artifact bytes/modes unchanged')
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence unchanged')
        finalize(r)
    def run(name,argv,profile='metadata',expected=0,env=None,record=False,step=False):
        stable();need(not any(x['name']==name for x in commands),'unique command/capture names')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=bounds[profile],capture_limit=16<<20,
                 environment=dict(ENV if env is None else env),expected_exit=expected);commands.append(row)
        try:
            out,err=(program_invoke if name in NAMES else invoke)(row,private,cpu,record=record,step=step)
            need(type(row['exit'])is int and(expected is None or row['exit']==expected),'actual command exit '+name)
            return row,out,err
        finally:
            for stream in('stdout','stderr','record','preparation'):
                path=private/(name+'.'+stream)
                try:
                    observed=row.get('captures',{}).get(stream)
                    if path.exists()or path.is_symlink():
                        actual=fact(binary(path))
                        if observed is not None:need(observed['file']==path.name and actual=={k:observed[k]for k in('bytes','sha256')},'actual command capture binding')
                    else:need(observed is None,'retained command capture missing')
                except BaseException as error:r['final_errors'].append('capture '+name+'.'+stream+': '+type(error).__name__+': '+str(error))
            path=private/(name+'.json')
            try:
                if path.exists()or path.is_symlink():binary(path);need(digest(json.loads(path.read_bytes()))==digest(row),'actual retained command row')
            except BaseException as error:r['final_errors'].append('command row '+name+': '+type(error).__name__+': '+str(error))
    def build_run(name,argv,profile='metadata',env=None,expected=0):
        before_default(name,argv,builder,pin,aliases,run,r)
        return run(name,argv,profile=profile,env=env,expected=expected)
    builder=Build(r,private,pin,binary,build_run)
    try:
        r['source']=source();need(r['source']['revision']==a.expect_revision,'exact clean committed source')
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'])
        need(not err,'source enumeration stderr')
        for name in out.split(b'\0'):
            if name and not name.startswith(b'evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(name))
        for module in tuple(sys.modules.values()):
            p=getattr(module,'__file__',None)
            if p and Path(p).resolve().is_relative_to(ROOT)and Path(p).suffix=='.py':pin(p)
        for name in('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload');r['configuration_presence']=presence
        products=builder.prepare();r['archive']=fact(products['archive'])
        cohort(builder,products,private,pin,binary,aliases,run,r)
        need(len(r['cases'])==20 and all(c['status']=='passed'for c in r['cases'])and
             all(c['comparison']['application_completed']is True for c in r['cases']if c['lane']=='gated')and
             not r['final_errors'],'all twenty actual subjects and ten unchanged terminal readers; no skipped lane')
        r['status']='passed'
    except BaseException as error:r['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            for m in tuple(sys.modules.values()):
                path=getattr(m,'__file__',None)
                if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
        except BaseException as error:r['final_errors'].append('final imported source closure: '+repr(error))
        try:r['final_errors'].extend(builder.finish())
        except BaseException as error:r['final_errors'].append('build finalization: '+type(error).__name__+': '+str(error))
        for p in sorted(private.rglob('*')):
            if p.is_file()and not p.is_symlink():
                try:binary(p)
                except BaseException as error:r['final_errors'].append('retain '+str(p)+': '+type(error).__name__+': '+str(error))
        r['inputs_before']=dict(pins);r['aliases_before']=dict(aliases);r['artifacts_before']=dict(artifacts)
        for label,fn in(('closure',stable),('namespace',lambda:finalize(r))):
            try:fn()
            except BaseException as error:r['final_errors'].append(label+': '+type(error).__name__+': '+str(error))
        try:r['source_after']=source();need(r['source_after']==r['source'],'exact committed source unchanged')
        except BaseException as error:r['final_errors'].append('source: '+type(error).__name__+': '+str(error))
        r['inputs_after']={};r['artifacts_after']={};r['aliases_after']={}
        for table,observed,fn in(('inputs_after',pins,fact),('artifacts_after',artifacts,lambda p:dict(fact(p),mode=Path(p).stat().st_mode&0o777)),
                                  ('aliases_after',aliases,lambda p:str(Path(p).resolve(strict=True)))):
            for p in observed:
                try:r[table][p]=fn(p)
                except BaseException as error:r['final_errors'].append(table+' '+p+': '+type(error).__name__)
        r['source_unchanged']=r['source']is not None and r.get('source_after')==r['source']and r['inputs_before']==r['inputs_after']and r['aliases_before']==r['aliases_after']
        r['cleanup_complete']=all(type(c.get('exit'))is int and c.get('reaped')is True and
            c.get('timed_out')is False and not c.get('error')and c.get('cleanup_errors')==[] and
            all(d['closed']for d in c.get('descriptors',[]))for c in commands)
        if r['error']or r['final_errors']or not r['source_unchanged']or r['artifacts_before']!=r['artifacts_after']or not r['cleanup_complete']:r['status']='failed'
        save(private/'receipt.json',r);publish(public,r,private)
        print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)),commands=len(commands),
                             failure_type=r['error'].split(':',1)[0]if r['error']else None)))
    return 0 if r['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
