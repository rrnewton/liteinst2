"""One genuine same-child FP envelope measurement; no format equivalence claim.

The enclosing committed evaluator supplies its one Build/invoke/custody owner.
No compiler or child is started merely by importing this module.
"""
import hashlib,importlib.util,json,os,re,shlex,struct
from pathlib import Path
from page_selected import fact,need,elf

BOUNDS={'format_program':[5,512<<20,16<<20,15],
        'format_build':[30,512<<20,16<<20,60],
        'format_metadata':[5,512<<20,16<<20,15]}
SOURCES={
 'probe.c':(12093,'bb481631b9784ba9a5fd30bd103cd5bd57bbf200096454b6ea6a0ce7f950c350'),
 'probe.S':(250,'ac8eaf801b8c3d280e338c2c9472c3e24d621bcff9e5857f5d87319739a0d3a5'),
 'build.sh':(413,'0d7347da3551caea4c612ca260eccb636cd8e19a3bdc084266b279f509f0f524'),
 'check.py':(6380,'451fb32160db0fd1c3dae480bf589d0f9527fd10133b138698b57f1f653e5a6d')}
LINK_NAMES=('crt1.o','Scrt1.o','crti.o','crtn.o','crtbegin.o','crtbeginS.o','crtend.o','crtendS.o',
            'libgcc.a','libgcc_s.so','libc.so','libc_nonshared.a','libgcc_s.so.1','libc.so.6')
H=lambda b:hashlib.sha256(b).hexdigest()

def _load(name,path,pin):
    spec=importlib.util.spec_from_file_location(name,pin(path));module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module

def _recipe(script,cc,fixture,output):
    lines=[x for x in script.read_text().replace('\\\n',' ').splitlines()if x.startswith('exec "$probe_cc" ')]
    need(len(lines)==1,'one exact frozen compiler recipe')
    values={'$probe_cc':str(cc),'$probe_src':str(fixture),'$probe_out':str(output)}
    argv=[]
    for word in shlex.split(lines[0])[1:]:
        for key,value in values.items():word=word.replace(key,value)
        need('$'not in word and '`'not in word,'closed measurement recipe');argv.append(word)
    need(argv[0]==str(cc)and argv[-4:]==[str(fixture/'probe.c'),str(fixture/'probe.S'),'-o',str(output)],'exact two probe sources/output')
    need(argv[1:-4]==['-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-Wstrict-prototypes',
         '-mgeneral-regs-only','-fno-builtin','-fno-omit-frame-pointer','-fPIE','-pie','-Wl,-z,now,-z,relro,-z,noexecstack'],
         'unchanged optimized PIE recipe')
    return argv

def measure(builder,root,private,pin,binary,run,receipt):
    """Return (capture Path, accepted inspect result); shared finally owns closure.

    run(name,argv,profile,expected,env,record,step) returns(row,stdout,stderr).
    It must append commands before invocation, retain actual PID/captures even on
    error, enforce BOUNDS, and keep primary exceptions separate from final errors.
    """
    root,private=Path(root).resolve(),Path(private).resolve()
    state=receipt['format_measurement']=dict(status='failed',planned_processes=1,invocation_attempted=False,
        command=None,source={},units=[],link_inputs={},artifacts={},error=None)
    pending=[];presence={};capture=None;primary=None
    def retain(path):
        try:
            if path.exists()or path.is_symlink():
                value=binary(path);state['artifacts'][str(path)]=dict(fact(value),mode=Path(value).stat().st_mode&0o777)
        except BaseException as error:receipt['final_errors'].append('format partial artifact: '+type(error).__name__+': '+str(error))
    def configuration():
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'unchanged loader configuration presence')
    def command(name,argv,profile='format_metadata',record=False,step=False):
        configuration()
        row,out,err=run('format-'+name,argv,profile=profile,expected=0,env=builder.environment,record=record,step=step)
        need(row['bounds']==BOUNDS[profile]and row.get('exit')==0 and type(row.get('pid'))is int and row['pid']>0 and
             row.get('reaped')is True and not row.get('timed_out')and not row.get('error')and not row.get('cleanup_errors'),
             'actual bounded command/process closure')
        return row,out,err
    try:
        need(not receipt['final_errors'],'no prior unclosed evaluator error')
        need(receipt.get('bounds')is not None and all(receipt['bounds'].get(k)==v for k,v in BOUNDS.items()),'exact measurement resource profiles')
        need(len(os.sched_getaffinity(0))==1,'one reserved measurement CPU')
        pin(__file__)
        for name in ('page_selected.py','page_selected_process.py','page_selected_generic_build.py'):
            pin(root/'evaluation/inprocess'/name)
        need({'cc','cc1','collect2','as','ld','readelf'}<=set(builder.tools),'actual prepared compiler/subtool set')
        for path in builder.tools.values():pin(path)
        fixture=root/'tools/page-entry/selected/tests/b2_xstate'
        for name,(size,sha)in SOURCES.items():
            path=pin(fixture/name);need(fact(path)==dict(bytes=size,sha256=sha),'exact frozen probe '+name)
            state['source'][name]=fact(path)
        checker=_load('b2_format_measurement_check',fixture/'check.py',pin)
        namespace=_load('b2_format_measurement_namespace',root/'tools/page-entry/namespace.py',pin)
        output=private/'format-measurement';need(not output.exists(),'unique private measurement output');output.mkdir()
        executable=output/'probe';objects=[output/'probe.c.o',output/'probe.S.o'];capture=output/'capture/record.bin'
        pending=[*objects,executable,capture]
        for path in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[path]=os.path.lexists(path)
            if presence[path]:pin(path)
        state['configuration_presence']=presence.copy();need(not presence['/etc/ld.so.preload'],'no unclosed global preload')
        for name in LINK_NAMES:
            _,out,err=command('link-input-'+name,[builder.tools['cc'],'-print-file-name='+name])
            value=out.decode().strip();need(not err and Path(value).is_absolute(),'compiler-selected runtime input')
            path=pin(value);state['link_inputs'][name]=dict(path=str(path),**fact(path))
        _,_,err=command('compiler-specs',[builder.tools['cc'],'-dumpspecs']);need(not err,'actual compiler specifications')
        argv=_recipe(fixture/'build.sh',builder.tools['cc'],fixture,executable);state['original_recipe_argv']=argv
        flags=argv[1:-4];compile_flags=[x for x in flags if not x.startswith('-Wl,')]
        for name,obj in zip(('probe.c','probe.S'),objects):
            unit=pin(fixture/name);actual=[builder.tools['cc'],*compile_flags,'-c',unit,'-o',obj]
            item=dict(argv=list(map(str,actual)),source=str(unit));state['units'].append(item)
            row,out,err=command('headers-'+name,[builder.tools['cc'],*compile_flags,'-M','-MT','b2_format',unit])
            rules=out.decode().replace('\\\n',' ').splitlines()
            need(not err and len(rules)==1 and rules[0].startswith('b2_format: '),'one complete actual header rule')
            deps=shlex.split(rules[0].split(':',1)[1]);need(str(unit)in deps and len(deps)==len(set(deps))and all(Path(x).is_absolute()for x in deps),'all actual header paths')
            item['headers']={str(pin(x)):fact(x)for x in deps};item['header_command']=row['name']
            try:_,out,err=command('compile-'+name,actual,'format_build');need(out==err==b'','quiet exact object compile')
            finally:retain(obj)
            binary(obj)
        actual=[builder.tools['cc'],*flags,'-Wl,-t',*objects,'-o',executable]
        state['link_argv']=list(map(str,actual))
        try:_,trace,err=command('link',actual,'format_build');need(not err,'actual final link stderr')
        finally:retain(executable)
        binary(executable);image,h,segments=elf(executable)
        need(h[1:4]==(3,62,1)and any(p[0]==1 and p[1]&1 and p[3]<=h[4]<p[3]+p[6]for p in segments)and
             all(p[0]!=1 or p[1]&3!=3 for p in segments)and
             sum(p[0]==0x6474e551 and p[1]==6 for p in segments)==1,'actual executable PIE entry, no RWX, NX stack')
        info=namespace.parse(image);need(info['elf_type']==3 and info['interpreter']is not None and info['soname']is None,'actual PIE PT_INTERP')
        interpreter=pin(info['interpreter']);known={str(pin(x))for x in objects}|{v['path']for v in state['link_inputs'].values()}|{str(interpreter)}
        state['link_trace']=[]
        for line in trace.decode().splitlines():
            need(Path(line).is_absolute(),'literal actual linker trace path');path=pin(line)
            need(str(path)in known,'every actual linker input belongs to closed compiler/object/interpreter set')
            state['link_trace'].append(dict(alias=line,path=str(path),**fact(path)))
        required={str(pin(x))for x in objects}|{state['link_inputs'][n]['path']for n in ('Scrt1.o','crti.o','crtbeginS.o','crtendS.o','crtn.o','libc.so','libc.so.6')}
        need(required<={x['path']for x in state['link_trace']},'both objects and mandatory PIE runtime inputs linked')
        _,_,err=command('elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',executable]);need(not err,'retained actual ELF inspection')
        _,out,err=command('libraries',[interpreter,'--list',executable]);need(not err,'actual runtime loader list')
        state['libraries']=_libraries(root,executable,interpreter,out,state['link_inputs'],pin)
        state['invocation_attempted']=True;state['command']='format-program'
        row,out,err=command('program',[executable,output/'capture'],'format_program',record=True,step=True)
        need(out==err==b'' and row['captures']['record']['bytes']==0,'quiet probe and unused inherited fd3 capture')
        data=binary(capture).read_bytes();observed=checker.inspect(data)
        need(observed['capture_complete']is True and observed['cross_mode_semantic_agreement']is False and
             struct.unpack_from('<Q',data,24)[0]==row['pid'],'complete same-subject capture joined to actual invocation PID')
        state.update(status='passed',capture=dict(path=str(capture),**fact(capture)),observation=observed)
        return capture,observed
    except BaseException as error:
        primary=error;state['error']=type(error).__name__+': '+str(error);raise
    finally:
        for path in pending:retain(path)
        try:configuration()
        except BaseException as error:receipt['final_errors'].append('format configuration: '+type(error).__name__+': '+str(error))
        if primary is not None or receipt['final_errors']:state['status']='failed'
        if primary is None and receipt['final_errors']:raise ValueError('format final artifact/configuration observation failed')

def summary(receipt):
    """Public numeric observation only. Full private capture stays authoritative."""
    state=receipt.get('format_measurement',{});name=state.get('command')
    rows=[r for r in receipt.get('commands',[])if name is not None and r['name']==name]
    need(len(rows)<=1,'one actual measurement invocation')
    actual=sum(type(r.get('pid'))is int and r['pid']>0 for r in rows)
    closed=sum(type(r.get('pid'))is int and r['pid']>0 and r.get('exit')==0 and r.get('reaped')is True and not r.get('timed_out')and not r.get('error')and not r.get('cleanup_errors')for r in rows)
    return dict(status=state.get('status','unexecuted'),planned_processes=1,
        attempted_processes=int(state.get('invocation_attempted',False)),actual_processes=actual,closed_processes=closed,
        observation=state.get('observation'),capture=({k:state['capture'][k]for k in ('bytes','sha256')}if 'capture'in state else None),
        failure_type=state['error'].split(':',1)[0]if state.get('error')else None,
        cross_mode_semantic_agreement=False,whole_program_or_b2_completion=False)

# Exact provider closed-graph reader with one deliberately separate policy:
# this fixed probe is ET_DYN/PIE with PT_INTERP; provider executables are ET_EXEC.
def _libraries(root,executable,interpreter,output,link_inputs,pin):
    # Reuse the existing bounded ELF parser, including its rejection of search,
    # audit and filter policies. No approximate ld.so search is performed here.
    path=pin(Path(root)/'tools/page-entry/namespace.py')
    spec=importlib.util.spec_from_file_location('provider_link_namespace',path)
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    main=namespace.parse(Path(executable).read_bytes())
    interpreter=pin(interpreter);loader=namespace.parse(interpreter.read_bytes())
    need(main['elf_type']==3 and main['interpreter']is not None and
         pin(main['interpreter'])==interpreter,'actual provider PT_INTERP identity')
    need(loader['elf_type']==3 and loader['interpreter']is None and
         loader['soname']is not None,'actual unchained provider interpreter SONAME')
    runtime_names={'libc.so.6','libgcc_s.so.1'}
    need(loader['soname']not in runtime_names,'distinct interpreter SONAME')
    allowed=runtime_names|{loader['soname']}
    rows={};infos={};vdso=0
    for line in output.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)',line):vdso+=1;continue
        match=re.fullmatch(r'\s*(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'closed actual provider loader dependency row')
        name=match[1];alias=match[2];target=pin(alias)
        if name is None or name.startswith('/'):
            need(target==interpreter and(name is None or pin(name)==interpreter),'actual provider interpreter aliases')
            name=loader['soname']
        need(name in allowed and name not in rows,'unique known provider loader object')
        info=namespace.parse(target.read_bytes())
        need(info['elf_type']==3 and info['soname']==name,'actual dependency SONAME/type')
        if name==loader['soname']:need(target==interpreter,'actual needed interpreter identity')
        else:
            selected=link_inputs.get(name)
            need(selected is not None and pin(selected['path'])==target and
                 fact(target)=={k:selected[k]for k in ('bytes','sha256')},'compiler-selected runtime dependency '+name)
        if info['interpreter']is not None:
            need(pin(info['interpreter'])==interpreter,'dependency descriptive PT_INTERP identity')
        need(str(target)not in {r['path']for r in rows.values()},'distinct provider object paths')
        rows[name]=dict(alias=alias,path=str(target),needed=info['needed'],**fact(target));infos[name]=info
    need(vdso==1 and loader['soname']in rows and 'libc.so.6'in rows,'complete actual libc/interpreter listing')
    need(infos[loader['soname']]==loader,'listed interpreter metadata identity')
    # Every DT_NEEDED edge must resolve once, and every listed object must be
    # reachable from the executable or its actual interpreter. Extra objects,
    # missing transitive edges and unsupported SONAMEs cannot be normalized away.
    pending=list(main['needed'])+list(loader['needed']);seen={loader['soname']};at=0
    while at<len(pending):
        name=pending[at];at+=1
        need(name in allowed and name in rows,'every actual provider DT_NEEDED edge resolves')
        if name in seen:continue
        seen.add(name);pending.extend(infos[name]['needed'])
    need(seen==set(rows),'exact reachable provider loader object set')
    return dict(executable=dict(**fact(executable),needed=main['needed']),
                interpreter_soname=loader['soname'],objects=rows,vdso_rows=vdso)
