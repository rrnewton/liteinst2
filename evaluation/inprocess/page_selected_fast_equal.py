#!/usr/bin/env python3
"""Reproduce the scalar/opt-in word equality primitive at an exact committed revision."""
import argparse
from datetime import datetime,timezone
import hashlib,importlib.util,json,os,platform,re,shlex,shutil,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from checks import source
from run import hardware
from page_selected import ENV,fact,need,save
from page_selected_process import invoke
from page_selected_fast_memset import decode
FIXTURE=ROOT/'tools/page-entry/selected/tests/fast_equal'
INPUTS=HERE/'page_selected_fast_equal_inputs.json'
sys.path.insert(0,str(FIXTURE))
import equal_inspect
SELECTED=ROOT/'tools/page-entry/selected'
NATIVE=[('scalar-functional','scalar',False),('fast-functional','fast',False),
        ('scalar-measured-1','scalar',True),('fast-measured-1','fast',True),
        ('fast-measured-2','fast',True),('scalar-measured-2','scalar',True)]
BOUNDS=dict(metadata=[10,512<<20,16<<20,20],inspect=[10,512<<20,16<<20,20],
            build=[20,512<<20,16<<20,30],native=[5,512<<20,16<<20,15])
HELPERS=('li2_equal_oracle','equal')

def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def projection(r,private_receipt=None):
    substitutions=[(str(ROOT),'${REPO_ROOT}')]
    substitutions += [(v['path'],'${TOOL_'+k.upper()+'}')for k,v in r.get('tools',{}).items()]
    substitutions.sort(key=lambda x:len(x[0]),reverse=True)
    def normalized(words):
        result=[]
        for word in words:
            for before,after in substitutions:word=word.replace(before,after)
            if word.startswith('/')or '/home/'in word:word='${PRIVATE_ARGUMENT_SHA256:'+hashlib.sha256(word.encode()).hexdigest()+'}'
            result.append(word)
        return result
    out={k:r.get(k)for k in ('schema','profile','status','expected_revision','source','source_unchanged',
        'started_utc','cpu','hardware','scope','build_status','rust_archive_used','owner_source','input_catalog','numeric_versions','cases')}
    out.update(bounds=BOUNDS,environment=ENV,tool_hashes={k:{z:v[z]for z in ('bytes','sha256')}for k,v in r.get('tools',{}).items()},
        commands=len(r['commands']),commands_sha256=digest(r['commands']),
        private_receipt=private_receipt,
        build_commands=[dict(name=c['name'],argv=normalized(c['argv']),bounds=c['bounds'],
            exit=c.get('exit'),expected_exit=c['expected_exit'],reaped=c.get('reaped'),timed_out=c.get('timed_out'),
            error_type=c.get('error','').split(':',1)[0]if c.get('error')else None,
            cleanup_error_count=len(c.get('cleanup_errors',[])))for c in r['commands']if c['profile']=='build'],
        inputs_sha256=digest(r.get('inputs',{})),artifacts_sha256=digest(r.get('artifacts',{})),
        inspection_sha256=digest(r.get('inspection',{})),
        bodies={mode:{name:{k:v[k]for k in ('bytes','code_hex','sha256')}for name,v in item['final']['functions'].items()}
                for mode,item in r.get('inspection',{}).items()if 'final'in item},
        native_commands=[{k:x.get(k)for k in ('name','exit','expected_exit','reaped','timed_out')}for x in r['commands']if x['profile']=='native'],
        failure_type=r['error'].split(':',1)[0]if r['error']else ('FinalObservationError'if r['final_errors']else None),
        final_error_count=len(r['final_errors']),cleanup_complete=r.get('cleanup_complete',False),
        measurements_qualified=r['status']=='passed',application_performance_credit=False,
        reproduce=['python3','evaluation/inprocess/page_selected_fast_equal.py','--expect-revision',r['expected_revision']],
        recipe=dict(source='actual tracked step_owner.c; no copied helper',
          template='tools/page-entry/selected/tests/fast_equal/build-oracle.sh',compile_commands=4,
          native=[dict(name=n,mode=m,argv=['equal-'+m]+(['m']if t else []))for n,m,t in NATIVE]))
    text=json.dumps(out,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<20000 and not re.search(r'/home/|devbig[0-9]+|internalfb\.com',text)and
         not any(x and len(x)>1 and x in text for x in (str(ROOT),str(Path.home()),platform.node())),
         'small private-location-free prospective projection')
    return text

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True);args=ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,
         'exact committed revision, enabled assertions, one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-fast-equal-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    build=private/'build';build.mkdir()
    r=dict(schema=1,profile='page-selected-fast-equal-v1',status='failed',expected_revision=args.expect_revision,
      source=None,source_unchanged=False,started_utc=stamp,cpu=cpu,
      scope='Actual scalar versus opt-in word equality primitive only. Both functional processes precede all32 retained warm helper-call intervals. No runtime enablement, full-owner qualification or application speed claim.',
      build_status='not_started',rust_archive_used=False,commands=[],cases=[],error=None,final_errors=[],inspection={},header_observations=[])
    pins,aliases,artifacts,tools,versions,presence={},{},{},{},{},{}
    env=dict(ENV)
    def pin(path):
        need(path is not None,'input exists');lexical=str(Path(path).absolute());resolved=Path(lexical).resolve(strict=True)
        need(lexical not in aliases or aliases[lexical]==str(resolved),'lexical alias changed');aliases[lexical]=str(resolved)
        value=fact(resolved);need(str(resolved)not in pins or pins[str(resolved)]==value,'input bytes changed');pins[str(resolved)]=value
        return resolved
    def binary(path):
        path=Path(path);need(path.is_file()and not path.is_symlink(),'regular retained output')
        value=dict(fact(path),mode=path.stat().st_mode&0o777)
        need(str(path)not in artifacts or artifacts[str(path)]==value,'artifact bytes/mode changed');artifacts[str(path)]=value;return path
    def closure():
        need(all(Path(p).exists()==v for p,v in presence.items()),'loader configuration presence')
        need(all(str(Path(a).resolve(strict=True))==p for a,p in aliases.items()),'all lexical input aliases')
        need(all(fact(p)==v for p,v in pins.items()),'source/tool/header input closure')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'exact artifact closure')
    def run(name,argv,profile='metadata'):
        closure();need(not any(c['name']==name for c in r['commands']),'unique capture name')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=BOUNDS[profile],expected_exit=0,
            capture_limit=65536 if profile=='native'else 4<<20,environment=dict(env))
        r['commands'].append(row);out,err=invoke(row,private,cpu)
        need(type(row['exit'])is int and row['exit']==0,'actual command exit '+name);return row,out,err
    expected_outputs=[build/name for name in ('owner-scalar.o','owner-fast.o','equal-scalar','equal-fast')]
    try:
        tools['git']=pin('/usr/bin/git')
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean current source')
        r['hardware']=hardware(cpu)
        catalog=decode(pin(INPUTS).read_bytes())
        need(catalog['schema']==1 and len(catalog['sources'])==28 and
             len({x['path']for x in catalog['sources']})==28,'closed28 tracked source inputs')
        for row in catalog['sources']:
            path=Path(row['path'])
            need(not path.is_absolute()and '..'not in path.parts and
                 row['path'].startswith(('tools/page-entry/','evaluation/inprocess/','evaluation/admission/')),
                 'repository-relative tracked source input')
            need(fact(pin(ROOT/path))=={k:row[k]for k in('bytes','sha256')},'exact committed input catalog row')
        required={str(Path(__file__).resolve().relative_to(ROOT)),
                  'tools/page-entry/selected/step_owner.c',
                  *('tools/page-entry/selected/tests/fast_equal/'+name for name in
                    ('oracle.c','check.py','build-oracle.sh','equal_inspect.py'))}
        need(required<={row['path']for row in catalog['sources']},'actual helper, oracle, reader, recipe, inspector and evaluator pinned')
        owner=pin(SELECTED/'step_owner.c');r['owner_source']=fact(owner);r['input_catalog']=fact(INPUTS)
        for module in tuple(sys.modules.values()):
            file=getattr(module,'__file__',None)
            if file and Path(file).resolve().is_relative_to(ROOT):pin(file)
        for name in ('cc','nm','objdump','readelf'):tools[name]=pin(shutil.which(name,path=ENV['PATH']))
        tools['python']=pin(sys.executable)
        for name in ('cc1','collect2','as','ld'):
            _,out,err=run('resolve-'+name,[tools['cc'],'-print-prog-name='+name]);value=out.decode().strip()
            need(value and not err,'actual C subtool');tools[name]=pin(value if Path(value).is_absolute()else shutil.which(value,path=ENV['PATH']))
        for name in ('cc','nm','objdump','readelf','ld','as','python'):
            _,out,err=run('version-'+name,[tools[name],'--version']);need(not err,'tool version stderr')
            match=re.search(r'\b([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b',out.decode());need(match is not None,'numeric version')
            versions[name]=[int(match[1]),int(match[2]),int(match[3]or 0)]
        for name in ('crt1.o','Scrt1.o','crti.o','crtn.o','crtbegin.o','crtbeginS.o','crtend.o','crtendS.o','libgcc.a','libgcc_s.so','libc.so','libc_nonshared.a'):
            _,out,err=run('link-input-'+name,[tools['cc'],'-print-file-name='+name]);value=out.decode().strip()
            need(not err and Path(value).is_absolute(),'actual C runtime link input');pin(value)
        _,_,err=run('cc-specs',[tools['cc'],'-dumpspecs']);need(not err,'compiler specs stderr')
        for name in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=Path(name).exists()
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        recipe=pin(FIXTURE/'build-oracle.sh')
        lines=[x.strip()for x in recipe.read_text().replace('\\\n',' ').splitlines()if x.strip().startswith('"$cc_bin" ')]
        need(len(lines)==2,'exact object and link recipe lines');commands=[]
        for mode in ('scalar','fast'):
            values={'$cc_bin':str(tools['cc']),'$owner_source':str(owner),'$selected_context':str(SELECTED),
               '$parent_context':str(SELECTED.parent),'$fixture_dir':str(FIXTURE),'$output_dir':str(build),
               '$mode':mode,'$extra':'-DLI2_FAST_EQUAL=1'if mode=='fast'else ''}
            for index,line in enumerate(lines):
                argv=[]
                for word in shlex.split(line):
                    for key,value in values.items():word=word.replace(key,value)
                    need('$'not in word and '`'not in word,'closed actual recipe');
                    if word:argv.append(word)
                need(argv[0]==str(tools['cc'])and argv[-2]=='-o','literal actual compiler/output')
                need(argv.count('-DLI2_FAST_EQUAL=1')==int(mode=='fast')and all(x in argv for x in ('-O2','-g','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror')),'actual matched release flags')
                sources=[x for x in argv[1:-2]if x.endswith('.c')]
                need(sources==[str(owner if index==0 else FIXTURE/'oracle.c')],'exact actual C source')
                if index==0:
                    need(argv.count('-DLI2_EQUAL_ORACLE=1')==1 and argv[-1]==str(build/('owner-'+mode+'.o')),'actual test-only helper wrapper')
                else:need('-DLI2_EQUAL_ORACLE=1'not in argv and argv[-1]==str(build/('equal-'+mode))and argv.count(str(build/('owner-'+mode+'.o')))==1,'actual object linkage')
                flags=[x for x in argv[1:-2]if x not in sources and not x.endswith('.o')and x!='-c'and not x.startswith('-Wl,')]
                row,out,err=run('headers-'+mode+'-'+str(index),[tools['cc'],*flags,'-M','-MT','li2_equal_headers',*sources])
                rule=out.decode().replace('\\\n',' ');need(not err and len(rule.splitlines())==1 and rule.startswith('li2_equal_headers: '),'one complete conditional header rule')
                deps=shlex.split(rule.split(':',1)[1]);need(len(deps)==len(set(deps))and sources[0]in deps and all(Path(x).is_absolute()for x in deps),'actual lexical dependencies')
                observed={x:dict(resolved=str(pin(x)),**fact(x))for x in deps}
                if index==0:need(str(SELECTED/'tf_chain.inc')in observed and str(SELECTED/'oneshot.h')in observed,'actual full profile conditional includes')
                r['header_observations'].append(dict(mode=mode,translation_unit=sources[0],argv=argv,headers=observed,command=row['name']))
                commands.append((mode,index,argv))
        r['build_status']='started'
        for mode,index,argv in commands:
            _,out,err=run(('object-'if index==0 else 'link-')+mode,argv,'build')
            need(out==err==b'','quiet exact C compile/link');binary(argv[-1])
        r['build_status']='compiled'
        for mode in ('scalar','fast'):
            inspected={};r['inspection'][mode]=inspected
            for kind,path in (('object',build/('owner-'+mode+'.o')),('final',build/('equal-'+mode))):
                _,symbols,err=run(mode+'-'+kind+'-symbols',[tools['nm'],'-S','--defined-only',path],'inspect');need(not err,'actual symbol stderr')
                _,code,err=run(mode+'-'+kind+'-body',[tools['objdump'],'-d','-w','-M','att',path],'inspect');need(not err,'actual body stderr')
                inspected[kind]=equal_inspect.body(path,symbols,code,mode=='fast')
                if kind=='object':continue
                need(artifacts[str(path)]['mode']&0o111,'actual executable mode');layout=equal_inspect.layout(path,symbols)
                _,_,err=run(mode+'-elf',[tools['readelf'],'-h','-l','-d','-r','-W',path],'inspect');need(not err,'actual ELF stderr')
                loader=pin(layout['interpreter']);_,out,err=run(mode+'-libraries',[loader,'--list',path]);need(not err,'actual library stderr')
                libraries={};vdso=0
                for line in out.decode().splitlines():
                    if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)',line):vdso+=1;continue
                    match=re.fullmatch(r'\s*(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)',line);need(match is not None,'closed actual dependency row')
                    key=match[1]or'interpreter'
                    if match[1]and match[1].startswith('/'):
                        need(pin(match[1])==pin(match[2])==loader,'both actual interpreter aliases');key='interpreter'
                    need(key not in libraries,'unique dependency');libraries[key]=dict(path=str(pin(match[2])),**fact(match[2]))
                need(vdso==1 and set(libraries)=={'libc.so.6','interpreter'}and libraries['interpreter']['path']==str(loader),'only actual libc/interpreter')
                inspected.update(layout=layout,libraries=libraries)
            need(equal_inspect.linked(inspected['object'],inspected['final']),'actual emitted object-to-final identity');r['inspection'][mode]=inspected
        spec=importlib.util.spec_from_file_location('fast_equal_check',pin(FIXTURE/'check.py'));check=importlib.util.module_from_spec(spec);spec.loader.exec_module(check)
        r['build_status']='passed';baseline=None
        for name,mode,measured in NATIVE:
            if measured:need(len(r['cases'])>=2 and all(x['accepted']for x in r['cases'][:2]),'both functional lanes first')
            case=dict(name=name,mode=mode,measured=measured,accepted=False,actual_exit=None);r['cases'].append(case)
            try:row,out,err=run(name,[build/('equal-'+mode),*(['m']if measured else [])],'native')
            finally:
                if r['commands']and r['commands'][-1]['name']==name:case['actual_exit']=r['commands'][-1].get('exit')
            need(not err and len(out)==4800,'whole actual native record/no stderr')
            result=check.parse(out,mode=='fast',measured)
            functional=out[128:4736]
            if baseline is None:baseline=functional
            need(functional==baseline,'all full functional rows equal scalar baseline')
            case.update(accepted=True,result=result,record=fact(private/(name+'.stdout')))
        need(len(r['cases'])==6 and all(x['accepted']for x in r['cases'])and sum(len(x['result']['nanoseconds'])for x in r['cases']if x['measured'])==32,'closed complete six-process cohort')
        r['status']='passed'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        for path in expected_outputs:
            try:
                if os.path.lexists(path):binary(path)
            except BaseException as exc:r['final_errors'].append('partial artifact '+path.name+': '+repr(exc))
        for alias,path in aliases.items():
            try:need(str(Path(alias).resolve(strict=True))==path,'final alias')
            except BaseException as exc:r['final_errors'].append('alias '+alias+': '+repr(exc))
        for path,before in pins.items():
            try:need(fact(path)==before,'final input')
            except BaseException as exc:r['final_errors'].append('input '+path+': '+repr(exc))
        for path,before in artifacts.items():
            try:need(dict(fact(path),mode=Path(path).stat().st_mode&0o777)==before,'final artifact')
            except BaseException as exc:r['final_errors'].append('artifact '+path+': '+repr(exc))
        for row in r['commands']:
            try:
                need(row.get('reaped')and not row.get('timed_out')and not row.get('error')and not row.get('cleanup_errors')and all(x['closed']for x in row.get('descriptors',[])),'actual cleanup')
                for cap in row.get('captures',{}).values():
                    need(Path(cap['file']).name==cap['file']and fact(private/cap['file'])=={k:cap[k]for k in ('bytes','sha256')},'actual capture bytes')
            except BaseException as exc:r['final_errors'].append('command '+row['name']+': '+repr(exc))
        try:closure()
        except BaseException as exc:r['final_errors'].append('closure: '+repr(exc))
        try:r['source_after']=source();r['source_unchanged']=r['source_after']==r['source'];need(r['source_unchanged'],'source changed')
        except BaseException as exc:r['final_errors'].append('source: '+repr(exc))
        r['cleanup_complete']=all(x.get('reaped')and not x.get('timed_out')and not x.get('error')and not x.get('cleanup_errors')and all(d['closed']for d in x.get('descriptors',[]))for x in r['commands'])
        if r['error']or r['final_errors']or not r['cleanup_complete']:r['status']='failed'
        r.update(inputs=pins,aliases=aliases,artifacts=artifacts,configuration_presence=presence,
          tools={k:dict(path=str(v),**pins[str(v)])for k,v in tools.items()},numeric_versions=versions,environment=env)
        save(private/'receipt.json',r)
        try:
            text=projection(r,fact(private/'receipt.json'))
            public.parent.mkdir(parents=True,exist_ok=True)
            with public.open('x')as f:f.write(text)
        except BaseException as exc:
            r['final_errors'].append('projection: '+repr(exc));r['status']='failed';save(private/'receipt.json',r)
    print(json.dumps(dict(status=r['status'],commands=len(r['commands']),cases=len(r['cases']),receipt=str((private/'receipt.json').relative_to(ROOT)),public=str(public.relative_to(ROOT)))))
    return int(r['status']!='passed')

if __name__=='__main__':raise SystemExit(main())
