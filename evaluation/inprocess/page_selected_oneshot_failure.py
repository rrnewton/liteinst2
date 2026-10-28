"""Reproduce 49 finite one-shot controls using a same-commit passed positive receipt."""
import argparse,hashlib,importlib.util,json,os,platform,re,shlex,shutil,sys
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from page_selected import fact,need,save,elf
from checks import source
from run import hardware
from page_selected_process import invoke
from page_selected_register_time_build import bridge_check
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
SUPPORT=ROOT/'tools/page-entry/selected/tests/oneshot_failure'
sys.path.insert(0,str(SUPPORT))
import record,outcomes,prepare
SUPPORT_FILES=('build.py','recipes.py','prepare.py','launch.py','layout.py','outcomes.py','fixture.c','fixture.h','record.py')

ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',GLIBC_TUNABLES='glibc.pthread.rseq=0',PYTHONDONTWRITEBYTECODE='1')
BOUNDS=dict(build=[60,512<<20,16<<20,120],metadata=[30,512<<20,16<<20,60],inspect=[10,256<<20,4<<20,20],program=[30,512<<20,16<<20,60])
H=lambda b:hashlib.sha256(b).hexdigest()
def decode(b):
    def unique(items):
        out={}
        for k,v in items:need(k not in out,'duplicate JSON key');out[k]=v
        return out
    return json.loads(b,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(ValueError('nonfinite JSON')))

def positive_receipt(path,current,pin,binary):
    """Authenticate retained positive evidence; never rebuild or infer a pass."""
    old=decode(path.read_bytes())
    need(old['profile']=='page-selected-oneshot-v1'and old['committed_product_evidence']is True and
         old['expected_revision']==current['revision'],'actual committed positive profile and exact revision')
    need(old['status']=='passed'and old['source_unchanged']and not old['final_errors']and
         old['source']==old['source_after']==current and old['inputs_before']==old['inputs_after']and
         old['aliases_before']==old['aliases_after']and old['artifacts_before']==old['artifacts_after'],
         'actual closed successful product baseline; no credit from earlier failed run')
    for p,v in old['inputs_before'].items():pin(p,v)
    for p,v in old['aliases_before'].items():
        # Retain the lexical name, not merely its current resolved target.
        need(str(pin(p,old['inputs_before'][v]))==v,'actual positive input alias')
    for p,v in old['artifacts_before'].items():
        q=binary(pin(p,v));need(q.stat().st_mode&0o777==v['mode'],'actual positive artifact mode')
    commands=old['commands'];names=[c['name']for c in commands]
    need(commands and len(set(names))==len(names),'unique actual positive commands')
    # Exact source-derived order from page_selected_oneshot + Build.prepare;
    # before_default inserts the three include observations before their links.
    expected=('source-paths','resolve-cargo','resolve-rustc','resolve-cc1','resolve-collect2',
        'resolve-as','resolve-ld','version-cc','version-cargo','version-rustc','version-python',
        'cargo-metadata','default-headers-0','default-headers-1','selected-build',
        'archive-text-exports','bridge-undefined','bridge-elf','generic-observer-headers',
        'generic-observer-link','oneshot-headers','oneshot-archive-exports','oneshot-link',
        'bridge-symbols','bridge-memset','oneshot-bridge-undefined','fixture-dependencies',
        'fixture-link','fixture-symbols','fixture-assembly','carrier-make','native-loader-list',
        'native','gated')
    need(names==list(expected),'all34 actual positive prerequisite commands in source order')
    for c in commands:
        need(type(c['exit'])is int and c['exit']==0 and c['reaped']is True and c['timed_out']is False and
             not c['error']and not c['cleanup_errors']and all(d['closed']is True for d in c['descriptors']),
             'actual positive command success and closed supervision')
        need(type(c['pid'])is int and c['pid']>0 and {'stdout','stderr'}<=c['captures'].keys(),
             'actual positive process and captures')
        for capture in c['captures'].values():
            need(Path(capture['file']).name==capture['file'],'positive capture filename only')
            pin(path.parent/capture['file'],capture)
        command_file=path.parent/(c['name']+'.json')
        need(str(command_file)in old['artifacts_before']and decode(pin(command_file).read_bytes())==c,
             'exact retained positive command row')
    by_name={c['name']:c for c in commands}
    built=old['build'];archive=built['artifacts']['decoder.a'];linked=old['oneshot_build']
    need(built['status']=='passed'and built['started']is True and built['command_completed']is True and
         not built['final_errors']and
         {k:archive[k]for k in('bytes','sha256','mode')}==old['artifacts_before'][archive['path']]and
         linked['status']=='passed'and linked['translation_units']==16 and
         linked['archive']=={k:archive[k]for k in('bytes','sha256')}and
         linked['argv']==by_name['oneshot-link']['argv']and linked['argv'].count(archive['path'])==1 and
         all(by_name[n]['argv'][-1]==archive['path']for n in('archive-text-exports','oneshot-archive-exports')),
         'same actual completed release archive through both inspections and product link')
    need(len(old['default_include_closure'])==2,'both default production include observations')
    groups=[('default-headers-0',old['default_include_closure'][0],8),
            ('default-headers-1',old['default_include_closure'][1],1),
            ('generic-observer-headers',old['generic_observer_headers'],1),
            ('oneshot-headers',linked,16)]
    for name,state,count in groups:
        command=by_name[name];units=[x for x in state['argv']if x.endswith(('.c','.S'))]
        need(len(units)==count and command['argv'][-count:]==units and '-M'in command['argv'],
             'actual include command and source units '+name)
        raw=pin(path.parent/command['captures']['stdout']['file']).read_bytes()
        rules=raw.decode().replace('\\\n',' ').splitlines()
        need(len(rules)==count and all(x.startswith('li2_timing: ')for x in rules),
             'complete retained compiler-M rules '+name)
        headers={}
        for rule in rules:
            for token in shlex.split(rule.split(':',1)[1]):
                resolved=str(pin(Path(token).absolute()))
                headers[resolved]=old['inputs_before'][resolved]
        need(headers==state['headers']and set(units)<=set(headers),
             'all actual include bytes and translation units bound '+name)
    need([c['name']for c in old['cases']]==['native','gated']and
         all(c['status']=='completed'and c['exit']==0 and c['error']is None for c in old['cases']),
         'both actual completed positive lanes')
    for case in old['cases']:
        row=next(c for c in commands if c['name']==case['name'])
        need(row['pid']==case['pid']and all({k:row['captures'][channel][k]for k in('bytes','sha256')}==case[channel]
             for channel in('stdout','stderr')),'positive lane/process/capture identity')
    return old

def projection(r,receipt,private):
    """Numeric observations and normalized commands; raw frames stay private."""
    digest=lambda v:H(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
    substitutions=[(str(private),'${RUN}'),(str(ROOT),'${REPO_ROOT}')]
    substitutions += [(v['path'],'${TOOL_'+k.upper()+'}')for k,v in r.get('tools',{}).items()]
    substitutions.sort(key=lambda x:len(x[0]),reverse=True)
    def normalized(words):
        result=[]
        for word in words:
            for old,new in substitutions:word=word.replace(old,new)
            if word.startswith('/')or '/home/'in word:word='${PRIVATE_ARGUMENT_SHA256:'+H(word.encode())+'}'
            result.append(word)
        return result
    commands=[dict(name=c['name'],profile=c['profile'],bounds=c['bounds'],argv=normalized(c['argv']),
        actual_argv_sha256=digest(c['argv']),environment_sha256=digest(c['environment']),
        expected_exit=c['expected_exit'],exit=c.get('exit'),duration_ns=c.get('duration_ns'),timed_out=c.get('timed_out'),reaped=c.get('reaped'),
        error_type=c.get('error','').split(':',1)[0]if c.get('error')else None,
        cleanup_error_count=len(c.get('cleanup_errors',[])),
        captures={k:{x:v[x]for x in('bytes','sha256')}for k,v in c.get('captures',{}).items()})for c in r['commands']]
    value={k:r.get(k)for k in('schema','profile','scope','status','expected_revision','started_utc','source',
        'source_unchanged','environment','hardware','bounds','reproduce','selected_case')}
    product=r.get('oneshot_build',{})
    value.update(private_receipt=receipt,
        positive_receipt={k:r.get('positive_receipt',{}).get(k)for k in('bytes','sha256')}if r.get('positive_receipt')else None,
        positive_source=r.get('positive_source'),positive_command_count=r.get('positive_command_count'),
        required_cases=1 if r['selected_case']else 49,required_full_cohort_cases=49,
        attempted_cases=len(r['cases']),qualified_failed_operations=sum(c['status']=='qualified_failed'for c in r['cases']),
        qualified_refused_sites=sum(c['status']=='qualified_refused_original_site'for c in r['cases']),
        full_cohort_qualified=r['status']=='passed',
        cases=[{k:c[k]for k in('mode','expected','status','exit','record','output')if k in c}|{
            'captures':{k:{x:v[x]for x in('bytes','sha256')}for k,v in c.get('captures',{}).items()},
            'full_reports_sha256':digest(c['reports'])if 'reports'in c else None,
            'error_type':c['error'].split(':',1)[0]if c['error']else None}for c in r['cases']],
        command_count=len(commands),commands=commands,command_rows_sha256=digest(r['commands']),
        inputs_sha256=digest(r['inputs_before']),aliases_sha256=digest(r['aliases_before']),
        artifacts_sha256=digest(r['artifacts_before']),
        tools={k:{x:v[x]for x in('bytes','sha256')}for k,v in r.get('tools',{}).items()},
        archive={k:r.get('archive',{}).get(k)for k in('bytes','sha256')},
        actual_bridge={k:r.get('bridge',{}).get(k)for k in('bytes','sha256')},
        derivative_status=product.get('status'),recipe=product.get('recipe'),translation_units=product.get('translation_units'),
        archive_exports=product.get('archive_exports'),header_closure_sha256=digest(product.get('headers',{})),
        reset={k:r.get('reset',{}).get(k)for k in('binding','type','visibility','bytes','sha256')},
        record_bytes=r.get('layout',{}).get('types',{}).get('failure_record',{}).get('bytes'),
        failure_type=r['error'].split(':',1)[0]if r.get('error')else None,
        final_error_count=len(r['final_errors']),performance_credit=False,B2_completion_credit=False,
        command_recipe={'prerequisite':['python3','evaluation/inprocess/page_selected_oneshot.py','--expect-revision',r['expected_revision']],
            'derivative':'C-only exact current build-oneshot.sh recipe, 17 prior compiler-M commands, four owner-entry renames, retained same-source passed release archive.',
            'application':'All49 finite modes via actual fresh exec, fd3 record, sealed namespace; default30CPU/60wall bounds unchanged.'})
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(not any(x and len(x)>1 and x in text for x in(str(ROOT),str(Path.home()),platform.node()))and
         not re.search(r'/home/|devbig[0-9]+|internalfb\.com',text),'public private-data guard')
    return text

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--positive-receipt',type=Path,required=True)
    ap.add_argument('--case',type=int,choices=range(1,50));a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and
         re.fullmatch('[0-9a-f]{40}',a.expect_revision),'exact revision, assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)))
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-oneshot-failure-'+a.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,mode=0o700)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    positive=a.positive_receipt.absolute()
    pins={};aliases={};artifacts={};ns_aliases={};commands=[]
    r=dict(schema=1,profile='page-selected-oneshot-failure-v1',
        scope='Finite same-page native one-shot controls: 48 failed operations and one refused original site; no speed or B2 completion claim',
        status='failed',source=None,expected_revision=a.expect_revision,started_utc=stamp,
        selected_case=a.case,positive_receipt=None,bounds=BOUNDS,hardware=hardware(cpu),
        environment={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'},
        reproduce=['python3','evaluation/inprocess/page_selected_oneshot_failure.py','--expect-revision',a.expect_revision,
                   '--positive-receipt','${PASSED_SAME_REVISION_POSITIVE_RECEIPT}']+(['--case',str(a.case)]if a.case else []),
        commands=commands,cases=[],error=None,final_errors=[],performance_credit=False)
    def pin(path,want=None):
        alias=Path(path).absolute();p=alias.resolve(strict=True);f=fact(p)
        need(want is None or f=={k:want[k]for k in('bytes','sha256')},'exact input '+str(alias))
        need(str(alias)not in aliases or aliases[str(alias)]==str(p),'stable input alias')
        need(str(p)not in pins or pins[str(p)]==f,'stable input bytes')
        aliases[str(alias)]=str(p);pins[str(p)]=f;return p
    def binary(path):
        p=Path(path).resolve(strict=True);f=dict(fact(p),mode=p.stat().st_mode&0o777)
        need(str(p)not in artifacts or artifacts[str(p)]==f,'stable retained artifact')
        artifacts[str(p)]=f;return p
    def stable():
        need(all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'all input aliases')
        need(all(fact(p)==v for p,v in pins.items()),'all input bytes')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'all artifact bytes/modes')
        need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in ns_aliases.items()),'all namespace aliases')
    def run(name,argv,profile='metadata',expected=0,env=None,record_fd=False):
        stable();row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=BOUNDS[profile],
            capture_limit=16<<20,environment=dict(ENV if env is None else env),expected_exit=expected)
        commands.append(row);out,err=invoke(row,private,cpu,record=record_fd)
        need(type(row['exit'])is int and(expected is None or row['exit']==expected),'actual command exit '+name)
        return row,out,err
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    try:
        r['source']=source();need(r['source']['revision']==a.expect_revision,'exact committed context')
        required=[pin(__file__)]+[pin(SUPPORT/name)for name in SUPPORT_FILES]
        positive=pin(positive);r['positive_receipt']=dict(path=str(positive),**fact(positive))
        old=positive_receipt(positive,r['source'],pin,binary)
        need(all(str(p)in old['inputs_before']and fact(p)==old['inputs_before'][str(p)]for p in required),
             'all tracked negative support bytes observed by the same-source positive build')
        r['positive_source']=old['source'];r['positive_hardware']=old['hardware']
        r['positive_command_count']=len(old['commands'])
        tools={name:pin(item['path'],item)for name,item in old['tools'].items()}
        tools['gdb']=pin(shutil.which('gdb',path=ENV['PATH']))
        r['tools']={n:dict(path=str(p),**fact(p))for n,p in tools.items()}
        archive_info=old['build']['artifacts']['decoder.a'];archive=pin(archive_info['path'],archive_info)
        r['archive']=dict(path=str(archive),**fact(archive))
        need(old['build']['status']=='passed'and old['build']['command_completed']and not old['build']['final_errors'],
             'actual retained current release archive')
        builder=SimpleNamespace(tools=tools,environment=dict(old['build']['environment']))
        api=load('failure_build',SUPPORT/'build.py')
        fixture=ROOT/'tools/page-entry/selected/tests/oneshot_integrated'
        check=load('failure_original_check',fixture/'check.py');report=load('failure_product_reports',fixture/'reports.py')
        namespace=load('failure_namespace',ROOT/'tools/page-entry/namespace.py')
        for module in tuple(sys.modules.values()):
            p=getattr(module,'__file__',None)
            if p and Path(p).suffix=='.py'and Path(p).resolve().is_relative_to(ROOT):pin(p)
        # Reapply the unchanged positive output and six-owner completion predicates
        # before any derivative build. The receipt alone does not grant success.
        native=pin(positive.parent/'native.stdout',old['cases'][0]['stdout']).read_bytes()
        gated=pin(positive.parent/'gated.stdout',old['cases'][1]['stdout']).read_bytes()
        positive_reports=report.reports(pin(positive.parent/'gated.stderr',old['cases'][1]['stderr']).read_bytes())
        report.completed(positive_reports,old['cases'][1]['pid'])
        need(positive_reports==old['reports']and check.compare_outputs(native,gated)==old['outputs'],
             'unchanged actual positive full output and completion proof')
        bridge=api.link(builder,dict(archive=archive),private,pin,binary,aliases,run,r)
        r['bridge']=dict(path=str(bridge),**fact(bridge));r['bridge_elf']=bridge_check(bridge)
        _,symbols,err=run('failure-symbols',[tools['nm'],'-S','--defined-only',bridge]);need(not err,'actual symbols')
        rows=[x.split()for x in symbols.decode().splitlines()if x.split()[-1:]==['li2_oneshot_failure_record']]
        need(len(rows)==1 and len(rows[0])==4 and rows[0][2]in('b','B'),'unique actual private BSS record')
        address,size=int(rows[0][0],16),int(rows[0][1],16);_,_,segments=elf(bridge)
        need(0<size<16<<20 and sum(p[0]==1 and p[1]==6 and p[3]<=address<address+size<=p[3]+p[6]for p in segments)==1,
             'actual entire record in writable NX LOAD and unchanged cap')
        r['layout']=api.layout(bridge,private,tools,pin,run,builder.environment)
        need(r['layout']['types']['failure_record']['bytes']==size,'actual symbol and DWARF size agree')
        for name in ('li2_oneshot_initialize','li2_oneshot_nx','li2_oneshot_ud','li2_oneshot_abort_close',
                     'li2_fixture_product_initialize','li2_fixture_product_nx','li2_fixture_product_ud','li2_fixture_product_abort_close'):
            need(sum(x.split()[-1:]==[name.encode()]for x in symbols.splitlines())==1,'one actual wrapper/product entry '+name)
        _,assembly,err=run('failure-memset',[tools['objdump'],'-d','-w','-M','att','--disassemble=memset',bridge]);need(not err,'actual reset bytes')
        r['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
        _,out,err=run('failure-undefined',[tools['nm'],'-u',bridge]);need(not out and not err,'no bridge imports')
        original=pin(old['namespace_plan']['original'],old['artifacts_before'][old['namespace_plan']['original']])
        root=Path(old['namespace_plan']['roots'][0]);interp=pin(old['namespace_plan']['interpreter'])
        interp_name=namespace.parse(original.read_bytes())['interpreter']
        need(namespace.parse(pin('/bin/true').read_bytes())['interpreter']==interp_name,'unchanged actual system PT_INTERP spelling')
        need(pin(interp_name)==interp,'actual PT_INTERP alias and retained interpreter target')
        r['fixture_elf']=check.elf(original.read_bytes(),str(interp_name));need(r['fixture_elf']==old['fixture_elf'],'unchanged actual original ELF')
        _,out,err=run('original-symbols',[tools['nm'],'-n','--defined-only',original]);need(not err,'actual original data address')
        data_rows=[x.split()for x in out.splitlines()if x.split()[-1:]==[b'li2_oneshot_record']]
        need(len(data_rows)==1 and int(data_rows[0][0],16)==12288,'actual complete data snapshot address')
        native=pin(positive.parent/'native.stdout',old['cases'][0]['stdout']).read_bytes();check.output(native)
        carrier=private/'carrier'
        try:
            _,out,err=run('carrier-make',[tools['python'],pin(ROOT/'tools/page-entry/carrier.py'),'make',original,bridge,carrier])
            need(not err,'carrier preparation stderr')
        finally:
            try:
                if carrier.exists()or carrier.is_symlink():binary(carrier)
            except BaseException as exc:
                r['final_errors'].append('carrier partial artifact: '+type(exc).__name__+': '+str(exc))
        got=decode(out);need(got['original_sha256']==fact(original)['sha256']and got['bridge_sha256']==fact(bridge)['sha256']and
            got['interpreter_sha256']==fact(interp)['sha256']and got['carrier_sha256']==fact(carrier)['sha256'],'actual carrier identity')
        adapter=private/'carrier_adapter.py';generated=prepare.generate(adapter);need(fact(binary(adapter))==generated,'exact generated selector adapter')
        objects,description=namespace.plan(original,[root],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
        for obj in objects:pin(obj['path'],dict(bytes=len(obj['bytes']),sha256=H(obj['bytes'])))
        r['namespace_plan']=description
        selected=[a.case]if a.case else list(range(1,50))
        for mode in selected:
            name='failure-'+str(mode);e=record.expected(mode);env=dict(ENV,LI2_ONESHOT_FAILURE=str(mode))
            ns=private/(name+'.namespace');prep=private/(name+'.preparation')
            case=dict(mode=mode,expected=e,status='unqualified',error=None);r['cases'].append(case)
            try:
                argv=[tools['python'],pin(SUPPORT/'launch.py'),'--mode','gated','--original',original,'--carrier',carrier,
                    '--namespace',ns,'--library-root',root,'--preparation',prep,'--record-fd','{record_fd}',
                    '--carrier-adapter',adapter]
                try:
                    row,out,err=run(name,argv,profile='program',expected=None,env=env,record_fd=True)
                finally:
                    if commands and commands[-1]['name']==name:
                        case.update({k:commands[-1][k]for k in('exit','pid','captures')if k in commands[-1]})
                p=decode(binary(prep).read_bytes());st=(private/(name+'.record')).stat()
                need(p['mask']==0 and [x['signal']for x in p['dispositions']]==[x for x in range(1,65)if x not in(9,19)]and
                    all(x['after']==0 for x in p['dispositions'])and p['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino)and
                    p['argv']==[str(original)]and p['environment']=={k:v for k,v in env.items()if k!='PYTHONDONTWRITEBYTECODE'},
                    'actual reset, record FD and explicit test environment')
                actual=decode(binary(ns/'namespace.json').read_bytes());started=decode(binary(ns/'launch.json').read_bytes())
                need(actual['original_sha256']==fact(original)['sha256']and actual['interpreter_sha256']==fact(interp)['sha256']and
                    actual['original']==str(original)and len(actual['objects'])==len(objects),'actual sealed namespace inputs')
                for ar,obj in zip(actual['objects'],objects):
                    need(ar['names']==obj['names']and ar['sha256']==H(obj['bytes'])and ar['size']==len(obj['bytes'])and
                        ar['seals']==namespace.SEALS and ar['device']>0 and ar['inode']>0 and ar['fd']!=3,'complete sealed dependency with distinct FD')
                    for alias in ar['names']:
                        path=ns/alias;target='/proc/self/fd/'+str(ar['fd'])
                        need(path.is_symlink()and os.readlink(path)==target,'actual sealed dependency alias');ns_aliases[str(path)]=target
                target_env={k:v for k,v in env.items()if k!='PYTHONDONTWRITEBYTECODE'}
                target_env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(str(x['fd'])for x in actual['objects']))
                need(started['argv']==[str(original)]and started['carrier_sha256']==fact(carrier)['sha256']and
                    started['environment']==target_env,'only named finite selector added to actual closed carrier environment')
                case['record']=record.read(binary(private/(name+'.record')).read_bytes(),r['layout'],mode,row['pid'],size)
                parsed=report.reports(err);case['reports']=parsed
                need(row['exit']==e['exit'],'exact terminal or refusal-fallback exit')
                if mode==47:
                    outcomes.refused_site_completed(parsed,row['pid']);case['output']=check.compare_outputs(native,out)
                else:
                    need(out==b'','no application output after terminal target-owner failure')
                    outcomes.terminal(parsed,row['pid'],e)
                case['status']='qualified_'+e['operation']
            except Exception as exc:case['error']=type(exc).__name__+': '+str(exc)
        need([c['mode']for c in r['cases']]==selected,'complete exact requested finite cohort')
        need(all(c['error']is None for c in r['cases']),'every actual finite case qualified')
        r['status']='passed_subset'if a.case else 'passed'
    except Exception as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        for p in private.rglob('*'):
            if p.is_file()and not p.is_symlink():
                try:binary(p)
                except BaseException as exc:r['final_errors'].append('partial artifact '+str(p)+': '+type(exc).__name__)
        r['inputs_before']=dict(pins);r['aliases_before']=dict(aliases);r['artifacts_before']=dict(artifacts)
        def observe_source():
            r['source_after']=source();return r['source_after']
        for label,fn in [('all inputs/artifacts',stable),('actual committed context',lambda:need(observe_source()==r['source'],'same source'))]:
            try:fn()
            except BaseException as exc:r['final_errors'].append(label+': '+type(exc).__name__+': '+str(exc))
        for key,values in [('inputs_after',pins),('artifacts_after',artifacts)]:
            r[key]={}
            for p in values:
                try:r[key][p]=dict(fact(p),**({'mode':Path(p).stat().st_mode&0o777}if key=='artifacts_after'else {}))
                except BaseException as exc:r['final_errors'].append(key+': '+type(exc).__name__+': '+str(exc))
        r['aliases_after']={}
        for p in aliases:
            try:r['aliases_after'][p]=str(Path(p).resolve(strict=True))
            except BaseException as exc:r['final_errors'].append('aliases_after: '+type(exc).__name__+': '+str(exc))
        if r['inputs_after']!=r['inputs_before']or r['artifacts_after']!=r['artifacts_before']or r['aliases_after']!=r['aliases_before']:
            r['final_errors'].append('final observed inputs/artifacts/aliases differ')
        r['source_unchanged']=not r['final_errors']and r['source']is not None
        if not r['source_unchanged']:r['status']='failed'
        save(private/'receipt.json',r)
        public.parent.mkdir(parents=True,exist_ok=True)
        with public.open('x')as f:f.write(projection(r,fact(private/'receipt.json'),private))
        print(public.relative_to(ROOT))
    return 0 if r['status']in('passed','passed_subset')else 1
if __name__=='__main__':raise SystemExit(main())
