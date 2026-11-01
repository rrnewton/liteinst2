"""Complete same-ELF native/gated D3 audit; no processes or imports of historical packets."""
import hashlib,importlib.util,json,os,re,shlex,stat,struct,sys
from pathlib import Path
H=lambda b:hashlib.sha256(b).hexdigest()
BUILD=[30,512<<20,16<<20,60]
NATIVE=[5,512<<20,16<<20,15]
INSPECT=[10,256<<20,4<<20,20]
ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',PYTHONDONTWRITEBYTECODE='1')

def need(ok,why):
    if not ok:raise ValueError(why)

def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':')).encode())

def fact(path):
    p=Path(path);h=hashlib.sha256();n=0
    with p.open('rb')as f:
        for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk);n+=len(chunk)
    return dict(bytes=n,sha256=h.hexdigest())

def whole(path):return dict(fact(path),mode=format(stat.S_IMODE(Path(path).stat().st_mode),'04o'))

def unique(pairs):
    value=dict(pairs);need(len(value)==len(pairs),'duplicate semantic-input JSON key');return value

def load(path):
    return json.loads(Path(path).read_bytes(),object_pairs_hook=unique,
        parse_constant=lambda _:(_ for _ in()).throw(ValueError('nonfinite JSON')))

def module(name,path):
    spec=importlib.util.spec_from_file_location('r3_semantic_'+name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

def image_inventory(original,interp,carrier,objects,manifest):
    n=len(objects);rows={}
    for i,(item,observed)in enumerate(zip(objects,manifest['objects'],strict=True)):
        rows[i]=dict(data=item['bytes'],carrier_bytes=len(item['bytes']),kind=0,
            backing=dict(launch_fd=observed['fd'],dev=observed['device'],ino=observed['inode'],size=observed['size'],seals=observed['seals']))
    rows[n]=dict(data=original.read_bytes(),carrier_bytes=carrier.stat().st_size,kind=1)
    rows[n+1]=dict(data=interp.read_bytes(),carrier_bytes=interp.stat().st_size,kind=2)
    return dict(objects=rows,main_object=n,interpreter_object=n+1,uid=os.getuid())

def loaded_application_relation(left,right,left_interpreter,right_interpreter):
    """Complete load images; the only constructed delta is the actual PT_INTERP.

    Both whole ELFs are independently pinned. Nonloaded DWARF/section metadata
    remain bound by those identities; no code/data range is ignored.
    """
    def parse(data):
        need(64<=len(data)<=16<<20,'whole bounded fixture ELF')
        h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
        need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[1:4]==(2,62,1)and
             h[8:10]==(64,56)and 0<h[10]<=32 and h[5]+56*h[10]<=len(data)and
             h[11]==64 and 0<h[12]<=256 and h[6]+64*h[12]<=len(data),'exact complete ELF tables')
        ph=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)for i in range(h[10])]
        need(all(p[2]<=len(data)and p[5]<=len(data)-p[2]and p[5]<=p[6]for p in ph),
             'whole file-backed program segments')
        sections=[struct.unpack_from('<IIQQQQIIQQ',data,h[6]+64*i)for i in range(h[12])]
        need(h[13]<len(sections),'section-name table index')
        names=sections[h[13]];need(names[1]==3 and names[4]+names[5]<=len(data),'whole section-name table')
        strings=data[names[4]:names[4]+names[5]];allocated={}
        for s in sections:
            if not s[2]&2:continue
            end=strings.find(b'\0',s[0]);need(0<=s[0]<end<len(strings),'whole allocated-section name')
            name=strings[s[0]:end].decode('ascii');need(name not in allocated,'unique allocated section')
            need(s[5]<=16<<20 and (s[1]==8 or s[4]+s[5]<=len(data)),'whole allocated file/zero extent')
            allocated[name]=(s,bytes(s[5])if s[1]==8 else data[s[4]:s[4]+s[5]])
        return h,ph,allocated
    a,ap,asec=parse(left);b,bp,bsec=parse(right)
    need(a[:6]+a[7:]==b[:6]+b[7:]and set(asec)==set(bsec),'same ELF header except actual section-table offset; all allocated sections')
    ii=[i for i,p in enumerate(ap)if p[0]==3];need(len(ii)==1 and [i for i,p in enumerate(bp)if p[0]==3]==ii,'one corresponding PT_INTERP')
    i=ii[0];x,y=ap[i],bp[i]
    lp=str(left_interpreter).encode()+b'\0';rp=str(right_interpreter).encode()+b'\0'
    need(x[:5]+x[7:]==y[:5]+y[7:]and x[5:7]==(len(lp),len(lp))and y[5:7]==(len(rp),len(rp))and
         left[x[2]:x[2]+x[5]]==lp and right[y[2]:y[2]+y[5]]==rp,'only exact actual interpreter path extent changes')
    need(all(p==q for j,(p,q)in enumerate(zip(ap,bp,strict=True))if j!=i),'every other program header is whole-exact')
    for name,(s,data)in asec.items():
        t,other=bsec[name]
        if name=='.interp':
            need(s[:5]+s[6:]==t[:5]+t[6:]and s[5]==len(lp)and t[5]==len(rp)and
                 data==lp and other==rp,'the sole allocated-section delta is the proven interpreter string')
        else:need(s==t and data==other,'entire initialized/zero allocated section unchanged: '+name)
    reconstructed=bytearray(left)
    struct.pack_into('<Q',reconstructed,40,b[6])
    struct.pack_into('<QQ',reconstructed,a[5]+56*i+32,len(rp),len(rp))
    n=max(len(lp),len(rp));at=x[2]
    need(left[at+len(lp):at+n]==bytes(n-len(lp))and right[at+len(rp):at+n]==bytes(n-len(rp)),
         'interpreter strings occupy only their old/new zero-padded metadata extent')
    reconstructed[at:at+n]=rp+bytes(n-len(rp))
    loads=[]
    for p,q in zip(ap,bp,strict=True):
        if p[0]!=1:continue
        need(p==q and not(p[1]&2 and p[1]&1)and
             reconstructed[p[2]:p[2]+p[5]]==right[q[2]:q[2]+q[5]],
             'every complete PT_LOAD byte and zero-fill extent matches the exact metadata construction')
        loads.append(dict(address=p[3],file_bytes=p[5],memory_bytes=p[6],flags=p[1],
                          native_sha256=H(left[p[2]:p[2]+p[5]]),gated_sha256=H(right[p[2]:p[2]+p[5]])))
    need(len(loads)==7,'complete original seven-load fixture')
    return dict(native=dict(bytes=len(left),sha256=H(left)),gated=dict(bytes=len(right),sha256=H(right)),
        relation='all_allocated_sections_and_PT_LOAD_bytes_exact_except_constructed_PT_INTERP_and_ELF_metadata',
        native_interpreter=str(left_interpreter),gated_interpreter=str(right_interpreter),loads=loads)

def gated_controls(reader,data,native,exit_status,image,pid,cpu,seed_reference):
    """40 common fields plus40 absent-native-frame bytes; zero guest events."""
    PREFIX,FRAME,GREG,APP_CONTROL_COUNT=reader.PREFIX,reader.FRAME,reader.GREG,reader.APP_CONTROL_COUNT
    need(native is False,'distinct gated data and absent-native-frame controls')
    reader.read(data,native,exit_status,image,pid,cpu,seed_reference)
    tests=[('version',8),('prefix_extent',16),('suffix_extent',24),('cycles',32),
           ('role',40),('PID',48),('TID',56),('CPU',64),('root',80),('source_page',88),
           ('source_extent',96),('stack_base',104),('XCR0',112),('xstate_extent',120),
           ('signal_ABI',19*8),('whole_hardware',384+8),('seed_RAX',1992),('seed_RCX',2000),
           ('seed_RSP',2024),('seed_R11',2080),('seed_flags',2120),('seed_selectors',2128),
           ('machine_mask',2144),('machine_FS',2152),('stack_first',2208),('stack_middle',2464),
           ('stack_last',2727),('cleanup',PREFIX+40),('collection_complete',PREFIX+48),
           ('frame_count',PREFIX+56),('TRACE_count',PREFIX+64),('after_RAX',PREFIX+280),
           ('after_RCX',PREFIX+288),('after_RSP',PREFIX+312),('after_flags',PREFIX+408),
           ('after_TLS',PREFIX+504),('before_live',PREFIX+560),('after_live',PREFIX+2676),
           ('after_stack_first',PREFIX+4792),('after_stack_last',PREFIX+5311)]
    for index in range(5):
        frame=PREFIX+5312+index*FRAME
        for name,offset in(('kind',8),('steps',16),('PC',224+40+16*8),
                          ('RSP',224+40+GREG[4]*8),('flags',224+40+17*8),
                          ('CR2',224+40+22*8),('whole_FP',1248+64),('embedded_siginfo',224+304)):
            tests.append(('absent_native_frame'+str(index)+'_'+name,frame+offset))
    need(len(tests)==len({name for name,offset in tests})==APP_CONTROL_COUNT and
         len({offset for name,offset in tests})==APP_CONTROL_COUNT and
         all(type(offset)is int and 0<=offset<len(data)for name,offset in tests),
         'all80 distinct bounded causal D3 application stimuli')
    refused=[]
    for name,offset in tests:
        mutant=bytearray(data);mutant[offset]^=1
        try:reader.read(bytes(mutant),native,exit_status,image,pid,cpu,seed_reference)
        except ValueError:refused.append(name)
        else:raise ValueError('supplied actual app corruption accepted '+name)
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,
                scope='40_common_fields_and_40_absent_native_frame_bytes')

def check(root,here,r,path,old,pin,capture,closed):
    from page_selected_register_time_build import recipe,expand
    from page_selected import bridge_check
    from scalar_span_trace_build import fast_bytes_completed
    from resident_three import native_prerequisites,terminal_reports
    contract=load(pin(here/'CONTRACT.json'));selected=root/'tools/page-entry/selected'
    cpu=old['cpu'];commands={v['name']:v for v in old['commands']}
    need([v['name']for v in old['commands']]==contract['commands'] and len(commands)==22,
         'entire fixed fresh build/seed/native/gated schedule')
    releases={'app-0-link','app-1-link','bridge-link','span-bytes-link','seed-link'}
    finite={'span-bytes-oracle','native-fixture'}
    for name,row in commands.items():
        bounds=NATIVE if name in finite|{'seed-prerequisite'}else INSPECT if name in ('seed-headers','seed-libraries')else BUILD
        profile='release_build'if name in releases else'finite'if name in finite else'seed'if name=='seed-prerequisite'else'inspect'if name=='seed-libraries'else'program'if name in ('carrier','gated-fixture')else'metadata'
        env=dict(ENV)
        if name=='dwarf':env.update(MALLOC_ARENA_MAX='1',XDG_CACHE_HOME=str(path.parent/'gdb-cache'))
        if name in ('span-bytes-native-libraries','span-bytes-oracle'):env['LD_BIND_NOW']='1'
        closed(row,0,bounds)
        need(row['profile']==profile and row['environment']==env,'exact actual command profile and closed environment')
        need(set(row['captures'])==({'stdout','stderr','record'}if name=='gated-fixture'else{'stdout','stderr'}),
             'complete actual command capture population')
    for name in ('run.py','build.py','native_prerequisites.py','terminal_reports.py','native_launch.py','launch.py','audit.py','audit_semantics.py','CONTRACT.json'):
        q=pin(here/name);need(old['inputs'][str(q)]==whole(q),'actual entire installed reproduction source: '+name)
    for relative in contract['reader_paths']:
        q=pin(root/relative);need(old['inputs'][str(q)]==whole(q),'actual installed full semantic reader dependency')
    app=pin(old['application']['path'],old['application']);interp=pin(old['interpreter']['path'],old['interpreter'])
    bridge=pin(old['builds']['bridge']['output']['path'],old['builds']['bridge']['output'])
    need(old['elf']==bridge_check(bridge),'whole unchanged bridge ELF validation')
    need(old['application']==old['builds']['app-1']['output']and old['interpreter']==old['builds']['app-0']['output'],
         'same complete newly built app/interpreter for both subjects')
    source_dir=selected/'tests/resident_three_app';application=path.parent/'application';output=path.parent/'resident'
    application_rows=recipe(pin(source_dir/'build.sh'),'"$cc"');need(len(application_rows)==2,'two complete app compiler recipes')
    bridge_rows=recipe(pin(selected/'build-resident-three-flags.sh'),'"$cc_bin"');need(len(bridge_rows)==1,'one full bridge recipe')
    archive_path=old['flags_native_prerequisite']['receipt']['path']
    flags_receipt=load(pin(archive_path));archive=pin(flags_receipt['archive']['path'])
    for key,script in [('app-0',application_rows[0]),('app-1',application_rows[1]),('bridge',bridge_rows[0])]:
        build=old['builds'][key];cc=pin(build['argv'][0])
        expected=expand(script,{'$cc':cc,'$source_dir':source_dir,'$output':application} if key!='bridge'else
            {'$cc_bin':cc,'$selected_dir':selected,'$parent_dir':selected.parent,'$archive':archive,'$output':output})
        need(build['argv']==commands[key+'-link']['argv']==expected,'whole exact installed compiler recipe: '+key)
        if key=='bridge':
            need([x for x in expected if x.startswith('-D')]==contract['macros']and
                 [x for x in expected if x.endswith(('.c','.S'))]==[str(root/p)for p in contract['translation_units']],
                 'complete source-owned28-TU sequence and exact feature definitions')
        units=[x for x in expected if x.endswith(('.c','.S'))]
        flags=[x for x in expected[1:-2]if x not in units and not x.endswith(('.a','.o'))and not x.startswith('-Wl,')]
        row=commands[key+'-headers']
        need(row['argv']==[expected[0],*flags,'-M','-MT','li2_resident',*units],
             'complete actual compiler-M invocation agrees with exact effective recipe')
        lines=capture(path.parent,row,'stdout').decode().replace('\\\n',' ').splitlines()
        need(len(lines)==len(units)and not capture(path.parent,row,'stderr'),'one full actual dependency rule per TU')
        observed=set()
        for line,unit in zip(lines,units,strict=True):
            need(line.startswith('li2_resident: '),'literal compiler-M target')
            names=shlex.split(line.split(':',1)[1]);need(names and names[0]==unit,'actual TU heads its rule');observed.update(names)
        need(observed==set(build['headers']),'all and only actual compiler-M inputs')
        for p,v in build['headers'].items():pin(p,v)
        need(not capture(path.parent,commands[key+'-link'],'stdout')and not capture(path.parent,commands[key+'-link'],'stderr'),
             'strict original compiler diagnostics')
    headers={p:{k:v[k]for k in ('bytes','sha256')}for p,v in old['builds']['bridge']['headers'].items()}
    binding_path=pin(output/'resident_three_binding.json');binding=load(binding_path)
    need(old['artifacts'][str(binding_path)]==whole(binding_path)and
         [v['path']for v in binding['sources']]==contract['policy']and
         binding['original']['image']==fact(app)and binding['archive']==fact(archive),
         'actual generated binding source policy and app/archive identities')
    for member in binding['sources']:
        q=Path(member['path']);need(not q.is_absolute()and ('..'not in q.parts or member['path']=='../bridge.c'),
             'bounded declared policy source with exact parent bridge exception')
        actual=pin(selected/q,member)
        if member['path']=='../bridge.c':need(actual==pin(selected.parent/'bridge.c')and headers[str(actual)]==fact(actual),
             'sole parent policy member is the whole actual bridge compiler source')
    for name,value in binding['headers'].items():
        need(Path(name).name==name,'literal generated header basename');q=pin(output/name,value)
        need(headers[str(q)]==value,'actual generated header appears in full compiler-M closure')
    macros=old['builds']['bridge']['argv'];maps_mode='differential'if '-DLI2_MAPS_DIFFERENTIAL=1'in macros else'maintained'
    need('-DLI2_MAPS_MAINTAINED=1'in macros,'actual compiled maintained maps policy')
    undefined=commands['undefined'];need(undefined['argv'][1:]==['-u',str(bridge)]and
        not capture(path.parent,undefined,'stdout')and not capture(path.parent,undefined,'stderr'),'no unresolved bridge symbols')
    symbols=commands['symbols'];need(symbols['argv'][1:]==['-S','--defined-only',str(bridge)]and
        not capture(path.parent,symbols,'stderr'),'complete actual provider symbol observation')
    names={line.split()[-1]for line in capture(path.parent,symbols,'stdout').decode().splitlines()if len(line.split())==4 and line.split()[2]in ('t','T')}
    need(set(contract['providers'])<=names,'all original complete provider entries are defined code')
    dwarf=commands['dwarf'];script=pin(selected/'tests/resident_three_owner/layout.py')
    need(dwarf['argv'][1:]==['-nx','-nh','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
        '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','-ex','file '+str(bridge),'-ex','source '+str(script)],
        'whole actual source-owned DWARF observation without inferior execution')
    layout_bytes=capture(path.parent,dwarf,'stdout')
    need(not capture(path.parent,dwarf,'stderr')and layout_bytes.endswith(b'\n')and layout_bytes.count(b'\n')==1,
         'one complete actual DWARF JSON line')
    layout=json.loads(layout_bytes,object_pairs_hook=unique)
    need(old['layout']==dict(bytes=len(layout_bytes),sha256=H(layout_bytes),types=110,fields=1229,raw_bytes=2063040,footer_bytes=64)and
         len(layout['types'])==110 and sum(len(v['fields'])for v in layout['types'].values())==1229 and
         layout['types']['r3o_wire']['bytes']==2063040,'complete actual110-type/1229-field layout')
    fast_bytes_completed(old['byte_oracle'],old['commands'],pin)
    for key,checker in [('flags_native_prerequisite',native_prerequisites.flags),('helper_native_prerequisite',native_prerequisites.helper)]:
        prior=old[key]['receipt'];checked=checker(prior['path'],prior['sha256'],old,old,pin,whole)
        need(checked==old[key],'whole original finite native prerequisite and actual source/build joins')
    seed=old['seed_prerequisite'];seed_rows=[commands[n]for n in ('seed-headers','seed-link','seed-libraries','seed-prerequisite')]
    need(seed['status']=='passed'and seed['planned']==1 and seed['launched']is True and seed['exit']==seed['expected_exit']==0 and
         seed['timed_out']is False and seed['bounds']==NATIVE and seed['completed_applications']==seed['owner_subjects']==0 and
         seed['performance_credit']is False,'one separately mandatory unchanged independent seed')
    directory=selected/'tests/provider_app/seed_probe';unit=pin(directory/'probe.c');exe=pin(seed['argv'][-1],seed['elf'])
    flags=['-std=gnu11','-O2','-g','-mgeneral-regs-only','-fno-tree-vectorize','-fno-tree-loop-distribute-patterns','-fno-builtin','-fno-pie','-no-pie','-Wall','-Wextra','-Werror']
    need(seed['argv']==[seed['argv'][0],*flags,'-Wl,-z,noexecstack,--build-id=none',str(unit),'-o',str(exe)]and
         seed_rows[0]['argv']==[seed['argv'][0],*flags,'-M','-MT','li2_seed',str(unit)]and seed_rows[1]['argv']==seed['argv']and
         seed_rows[3]['argv']==[str(exe)]and seed_rows[3]['environment']==ENV,'whole unchanged independent seed compiler/native recipe')
    pin(seed['argv'][0]);pin(directory/'build.sh',seed['recipe'])
    lines=capture(path.parent,seed_rows[0],'stdout').decode().replace('\\\n',' ').splitlines()
    need(len(lines)==1 and lines[0].startswith('li2_seed: ')and not capture(path.parent,seed_rows[0],'stderr'),'complete seed compiler-M rule')
    header_paths={str(pin(x))for x in shlex.split(lines[0].split(':',1)[1])}
    need(header_paths==set(seed['headers'])and {str(unit),str(directory/'record.h')}<=header_paths,'complete actual seed includes')
    for p,v in seed['headers'].items():pin(p,v)
    libraries={}
    for line in capture(path.parent,seed_rows[2],'stdout').decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line);need(match is not None,'complete actual seed library row')
        q=pin(match[1]);need(q.name not in libraries,'unique actual seed library');libraries[q.name]=dict(path=str(q),**fact(q))
    need(libraries==seed['runtime_libraries']and seed_rows[2]['argv']==[next(v['path']for v in libraries.values()if Path(v['path']).name=='ld-linux-x86-64.so.2'),'--list',str(exe)]and
         not capture(path.parent,seed_rows[2],'stderr'),'entire actual seed interpreter/runtime library closure')
    seed_raw=capture(path.parent,seed_rows[3],'stdout');need(not capture(path.parent,seed_rows[3],'stderr')and len(seed_raw)==5792 and
         seed['pid']==seed_rows[3]['pid']and seed['whole_process_ns']==seed_rows[3]['duration_ns']and
         seed['captures']=={k:{j:v[j]for j in ('bytes','sha256')}for k,v in seed_rows[3]['captures'].items()},'whole actual independent seed process/capture joins')
    app_reader=module('app',pin(selected/'tests/resident_three_app/read.py'))
    policy=module('native_policy',pin(selected/'tests/oneshot_integrated/check.py'))
    seed_reader=module('seed',pin(directory/'read.py'));xstate=module('xstate',pin(selected/'tests/b2_reference/xstate.py'))
    h=struct.unpack_from('<16Q',seed_raw,128);cpuid=[struct.unpack_from('<6I',seed_raw,256+24*i)for i in range(67)]
    facts=xstate.profile(cpuid,h[8],h[10],h[12],h[5],h[6]);profile=seed_reader.read(seed_raw,exe.read_bytes(),facts,xstate,cpu=cpu,pid=seed_rows[3]['pid'])
    need(digest(facts)==digest(seed['format'])and profile==seed['profile']and seed_reader.require(profile,facts,cpu=cpu)==bytes(16),
         'complete unchanged seed/raw/format validators and exact independently observed profile')
    reference=(seed_reader,xstate,profile,facts)
    nr=commands['native-fixture'];np=pin(path.parent/'native-preparation.json');prep=load(np)
    need(nr['argv']==[str(pin(sys.executable)),'-I','-S','-B',str(pin(here/'native_launch.py')),'--root',str(root),
         '--original',str(app),'--preparation',str(np)]and nr['environment']==ENV,'whole native launcher/ELF invocation')
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']=='native'and prep['pid']==nr['pid']and
         prep['cpu']==[cpu]and prep['reset_mask']==0 and prep['launch_mask']==0xffffffffbffbfae7 and prep['observer']is None and
         prep['argv']==[str(app),'native']and prep['default_rseq']is False and prep['environment']==dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',GLIBC_TUNABLES='glibc.pthread.rseq=0',LD_LIBRARY_PATH='/usr/lib64')and
         [v['signal']for v in prep['dispositions']]==[n for n in range(1,65)if n not in (9,19)]and all(v['after']==0 for v in prep['dispositions']),
         'whole actual native preparation and signal policy')
    native_raw=capture(path.parent,nr,'stdout');need(not capture(path.parent,nr,'stderr'),'empty actual native stderr')
    app_image=app_reader.elf(app.read_bytes(),policy.native_policy);need(app_image['interpreter']==str(interp),'actual app PT_INTERP')
    native_args=(native_raw,True,nr['exit'],app_image,nr['pid'],cpu,reference)
    native_result=app_reader.read(*native_args);native_controls=app_reader.controls(*native_args)
    need(app_reader.APP_CONTROL_COUNT==80 and len(native_controls['refusals'])==len(set(native_controls['refusals']))==80 and
         native_controls['original_sha256']==H(native_raw)and native_controls['native_operations']==0,'all80 unchanged native data controls')
    relation=loaded_application_relation(app.read_bytes(),app.read_bytes(),interp,interp)
    need(relation['native']==relation['gated'],'the native and gated lanes use one entire identical built ELF')
    gp=path;gated=old;compiled=old;carrier_row=commands['carrier'];grow=commands['gated-fixture'];carrier=pin(gp.parent/'carrier')
    python=str(pin(sys.executable));carrier_tool=pin(root/'tools/page-entry/carrier.py')
    need(carrier_row['argv']==[python,'-B',str(carrier_tool),'make',str(app),str(bridge),str(carrier)]and
         set(carrier_row['captures'])=={'stdout','stderr'}and not capture(gp.parent,carrier_row,'stderr'),
         'exact actual carrier construction command')
    identity=json.loads(capture(gp.parent,carrier_row,'stdout'),object_pairs_hook=unique)
    need(all(identity[k+'_sha256']==fact(p)['sha256']for k,p in(('original',app),('interpreter',interp),('bridge',bridge),('carrier',carrier)))and
         gated['subject_artifacts']=={k:fact(p)for k,p in(('original',app),('interpreter',interp),('bridge',bridge),('carrier',carrier))},
         'whole real carrier/original/interpreter/bridge artifact identity')
    namespace=module('namespace',pin(root/'tools/page-entry/namespace.py'))
    need(namespace.parse(app.read_bytes())==dict(elf_type=2,needed=[],soname=None,interpreter=interp)and
         namespace.parse(interp.read_bytes())==dict(elf_type=3,needed=[],soname=None,interpreter=None)and
         namespace.parse(carrier.read_bytes())['interpreter']==bridge,'actual empty dependency pair and carrier PT_INTERP')
    objects,description=namespace.plan(app,[app.parent],bytes.fromhex(fact(app)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    need(objects==[]and gated['namespace_plan']==description and
         gated['runtime_libraries']=={interp.name:dict(path=str(interp),**fact(interp))}and
         gated['runtime_library_scope']=='source_owned_no_needed_fixture; no dynamic-loader list command',
         'exact source-owned no-needed namespace/interpreter contract')
    need(gated['external_inputs']==[dict(fact(p),roles=[role])for role,p in(('original',app),('interpreter',interp))]and
         all(fact(pin(gp.parent/'external-inputs'/(str(i)+'.elf')))==fact(p)for i,p in enumerate((app,interp))),
         'both independently retained full original input copies')
    ns=gp.parent/'namespace';observed=load(pin(ns/'namespace.json'));launch=load(pin(ns/'launch.json'));prep=load(pin(gp.parent/'preparation.json'))
    need(observed==dict(description,schema_version=1,scope='explicit_sealed_dependency_namespace',status='prepared_not_executed',
         directory=str(ns),objects=[],search_policy='explicit roots; no RPATH/RUNPATH/cache emulation',
         identity_policy='sealed copies and private paths; not filesystem transparency'),'complete actual empty namespace manifest')
    launcher=pin(here/'launch.py')
    need(grow['argv']==[python,'-B',str(launcher),'--root',str(root),'--role','gated','--mode','0','--control','0',
         '--original',str(app),'--preparation',str(gp.parent/'preparation.json'),'--library-root',str(app.parent),
         '--carrier',str(carrier),'--namespace',str(ns),'--record-fd',str(grow['descriptors'][0]['fd'])]and
         len(grow['descriptors'])==1 and grow['descriptors'][0]['name']=='record'and
         type(grow['descriptors'][0]['fd'])is int and grow['descriptors'][0]['fd']>=3 and
         set(grow['captures'])=={'stdout','stderr','record'},'exact one-subject launcher/record argument and complete streams')
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']=='gated'and
         prep['pid']==grow['pid']and prep['cpu']==[cpu]and prep['reset_mask']==prep['launch_mask']==0 and
         prep['argv']==[str(app),'gated']and prep['default_rseq']is False and prep['mode']==prep['control']==0 and
         type(prep['previous_mask'])is int and 0<=prep['previous_mask']<1<<64 and
         [v['signal']for v in prep['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and
         all(set(v)=={'signal','before','after'}and type(v['before'])is int and 0<=v['before']<1<<64 and v['after']==0 for v in prep['dispositions']),
         'whole actual PID/CPU/mask/disposition/mode preparation')
    env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',LD_LIBRARY_PATH=str(ns),
             LI2_DEPENDENCY_FDS='',GLIBC_TUNABLES='glibc.pthread.rseq=0',LI2_PERSISTENT_RETAINED_TWO_APP_MODE='0')
    need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',argv=prep['argv'],
         dependency_fds=[],carrier_sha256=fact(carrier)['sha256'],carrier_size=fact(carrier)['bytes'],environment=env)and
         prep['late_sonames']==[]and prep['environment_source']==str(ns/'launch.json'),'complete actual gated exec/carrier/environment join')
    record_path=pin(gp.parent/grow['captures']['record']['file']);st=record_path.stat()
    need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
         prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino),'same actual exclusive inherited owner record descriptor')
    raw=capture(gp.parent,grow,'stdout');stderr=capture(gp.parent,grow,'stderr');record=capture(gp.parent,grow,'record')
    output_stat=(gp.parent/grow['captures']['stdout']['file']).stat()
    before=grow['stdout_provenance_before'];after=grow['stdout_provenance_after']
    need(before['parent_fd']==after['parent_fd']and before['identity']==after['identity']and
         before['open_route']==after['open_route']=='exclusive-normal-open/Popen-stdout-dup2-exec'and
         type(before['parent_fd'])is int and before['parent_fd']>2,'same actual ordinary stdout descriptor through execution')
    for observation,size in((before,0),(after,len(raw))):
        identity=observation['identity'];data=bytes.fromhex(observation['statx_hex'])
        need(len(identity)==7 and len(data)==256 and identity[:2]==[output_stat.st_dev,output_stat.st_ino]and
             identity[3:6]==[os.major(output_stat.st_dev),os.minor(output_stat.st_dev),output_stat.st_mode]and
             identity[2]>0 and identity[6]&os.O_ACCMODE==os.O_WRONLY and not identity[6]&os.O_PATH and
             struct.unpack_from('<I',data)[0]&0x1103==0x1103 and not struct.unpack_from('<I',data)[0]&0x4000 and
             struct.unpack_from('<H',data,28)[0]==output_stat.st_mode and
             struct.unpack_from('<Q',data,32)[0]==output_stat.st_ino and struct.unpack_from('<Q',data,40)[0]==size and
             struct.unpack_from('<IIQ',data,136)==tuple(identity[3:5]+[identity[2]]),
             'complete actual stdout statx/fstat identity and before/after extent')
    terminal=terminal_reports.check(stderr);terminal_controls=terminal_reports.controls(stderr)
    need(terminal==gated['terminal_reports']and terminal_controls==gated['terminal_controls'],
         'whole strict successful terminal schema and every original report mutation')
    app_image=app_reader.elf(app.read_bytes(),policy.native_policy)
    app_args=(raw,False,grow['exit'],app_image,grow['pid'],cpu,reference)
    application=app_reader.read(*app_args);app_controls=gated_controls(app_reader,*app_args)
    need(app_reader.APP_CONTROL_COUNT==80 and len(app_controls['refusals'])==len(set(app_controls['refusals']))==80 and
         app_controls['original_sha256']==H(raw)and app_controls['native_operations']==0,'all80 exact gated app controls, independent complete seed/FP/native model')
    owner=module('owner',pin(selected/'tests/resident_three_owner/read.py'))
    image=image_inventory(app,interp,carrier,objects,observed)
    image.update(bridge=bridge.read_bytes(),persistent_binding=binding,headers=headers,maps_mode=maps_mode)
    owner_args=(record,layout,image,application,grow['pid'],cpu,grow['exit'])
    actual=owner.read(*owner_args);owner_controls=owner.controls(*owner_args)
    for key in('sink_initial','sink_terminal'):
        offset=layout['types']['r3o_wire']['fields'][key]['offset']
        for name,value in(('st_dev',st.st_dev),('st_ino',st.st_ino)):
            field=layout['types']['stat']['fields'][name]
            need(field['bytes']==8 and struct.unpack_from('<Q',record,offset+field['offset'])[0]==value,
                 'whole typed owner sink is the actual inherited descriptor: '+key+'/'+name)
    need(owner_controls['count']==231 and len(owner_controls['refusals'])==len(set(owner_controls['refusals']))==231 and
         owner_controls['source_sha256']==H(record)and owner_controls['native_operations']==0,'all231 exact owner data-mutation refusals')
    pair=owner.pair(native_result,application,actual);pair_controls=owner.pair_controls(native_result,application,actual)
    need(pair_controls['count']==44 and len(pair_controls['refusals'])==len(set(pair_controls['refusals']))==44 and
         pair_controls['native_operations']==0,'all44 exact cross-lane whole-state data mutations')
    expected=dict(observed_resident_three=1,cycles=4,native_trace_events=30,native_full_frames=5,protected_full_frames=3,
        fp_storage_per_frame=65536,ucontext_bytes_per_frame=968,stack_bytes=520,cold_publications=3,entries=1,completed=1,
        resident_certificates=3,old_active_domain_limit=2,closed_pages=51,interior_signals=0,terminal_ingresses=1,
        source_cost=actual['source_cost'],qualification_credit=False,performance_credit=False)
    need(pair==expected and actual['status']==actual['code']==actual['detail']==0,'complete fixed four-cycle finite observed pair')
    # Complete source/state inventories remain external evidence; zero new processes.
    r['semantic']=dict(status='observed_unqualified',pair=pair,application_relation=relation,
        native_app_controls=native_controls,gated_app_controls=app_controls,owner_controls=owner_controls,pair_controls=pair_controls,
        terminal=terminal,terminal_controls=terminal_controls,source_cost=actual['source_cost'],
        source_before=actual['source_before'],source_epoch=actual['source_epoch'],source_pages=actual['source_pages'],
        app_raw=fact(gp.parent/grow['captures']['stdout']['file']),owner_raw=fact(record_path),
        layout=dict(bytes=len(layout_bytes),sha256=H(layout_bytes)),maps_mode=maps_mode,
        frames=[dict(kind=name,greg=actual[name]['greg'],fp_sha256=H(actual[name]['fp']),
                     uc_sha256=H(actual[name]['uc']),si_sha256=H(actual[name]['si']))for name in('before','terminal','next')],
        qualification_credit=False,performance_credit=False,warm_reuse_credit=False,post_raw_reuse_credit=False)
