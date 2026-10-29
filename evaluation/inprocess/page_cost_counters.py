#!/usr/bin/env python3
"""Twelve fixed gated launches; separate observer-cost diagnostic, no DR lane."""
import argparse,copy,csv,hashlib,importlib.util,io,json,os,platform,re,shlex,shutil,statistics,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from page_cost_compare import (ENV,fact,need,save,source,hardware,Build,BUILD_PROFILES,BOUNDS,
    SELECTED,UNITS,MACROS,PROGRAM_ENV,invoke,program_invoke,finalize,before_default,
    recipe,expand,headers,bridge_check,hidden_memset,body_check,pair,cost_reports,digest)
ORDER=tuple((kind,repeat,lane)for repeat in range(3)
    for kind in (('ls','true')if repeat%2==0 else('true','ls'))
    for lane in (('unobserved','counters')if repeat%2==0 else('counters','unobserved')))
NAMES=tuple(f'{kind}-{repeat}-{lane}'for kind,repeat,lane in ORDER)
H=lambda b:hashlib.sha256(b).hexdigest()
MASK=(1<<64)-1
COST_KEYS='version scope status failure_code detail_negative detail_abs clock_id admission maps'.split()
COST_SOURCES={'tools/page-entry/selected/native_pair.h': {'bytes': 6944, 'sha256': '13df301c8f8f1fad0f965f23b88fb60b1e70a45e17d5f2e4108a16a5cb135365'}, 'tools/page-entry/selected/native_pair_lifecycle.inc': {'bytes': 15564, 'sha256': '4784dc61ce918eb6592aca2b054b171f0399124ba11f312391d4e8d12d1fc2a5'}, 'tools/page-entry/selected/native_pair_report.inc': {'bytes': 6251, 'sha256': '18c782b2860b80a5f4f195c68363e5425fa59005ae89016ced43bf526516a0ba'}, 'tools/page-entry/selected/runtime_loader.c': {'bytes': 39243, 'sha256': '33fa6699e7626869a878f9b245e1a44a64c21b53ff4afcb6d4900762c722fb2f'}}


def check(stdout,stderr,pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes,*,workload,observed):
    """Dispatch one exact diagnostic trailer; every original report byte stays exact."""
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete actual report')
    prefix=stderr;cost=None
    if observed:
        lines=[x+b'\n'for x in stderr[:-1].split(b'\n')]
        need(len(lines)>1 and lines[-1].startswith(b'LI2_COST ')and len(lines[-1])<=4096 and b'\r'not in lines[-1]and
             sum(x.startswith(b'LI2_COST ')for x in lines)==1,'exact unique final diagnostic row')
        prefix=b''.join(lines[:-1]);cost=pair.pair_reports.rseq.decode(lines[-1][9:-1])
        need(type(cost)is dict and list(cost)==COST_KEYS and cost['version']==1 and
             cost['scope']=='native_pair_existing_admission_clocks'and cost['clock_id']==4,'exact ordered cost schema')
        need(all(type(cost[k])is int and 0<=cost[k]<=MASK for k in COST_KEYS if k not in('scope','admission','maps')),
             'unsigned exact diagnostic scalars')
        for key,size in(('admission',8),('maps',10)):
            need(type(cost[key])is list and len(cost[key])==size and
                 all(type(x)is int and 0<=x<=MASK for x in cost[key]),'complete typed diagnostic '+key)
    parsed,summary=cost_reports.check(stdout,prefix,pid,exit_code,parent,images,image_bytes,carrier,carrier_bytes,workload=workload)
    if cost is not None:
        need(all(cost[k]==parsed['loader'][k]==0 for k in('status','failure_code','detail_negative','detail_abs')),
             'actual matching successful terminal outcome')
        a,m=cost['admission'],cost['maps'];n=parsed['native'];p=parsed['native_pair']
        need(a[:4]==[1,1,0,0]and a[4]==n['admissions']==p['lifecycle'][12]>0,
             'initialized complete valid aggregate of every actual admission; no overflow/busy prefix')
        need(a[6]<=a[7]and a[4]*a[6]<=a[5]<=a[4]*a[7],'exact unsigned admission sum/min/max bounds')
        retained=[n['first_admission_ns'],*n['revisit_ns']]
        need(len(retained)<=a[4]and all(a[6]<=x<=a[7]for x in retained)and sum(retained)<=a[5],
             'original first/revisit timings are a subset of the all-admission population')
        need(m[0]==m[1]>0 and m[3]==m[5]>0 and m[4]>0 and m[6:]==[0]*4,
             'complete successful pre-report fresh reads, exact mutation count and closed unpoisoned maps state')
    return parsed,summary,cost,prefix


def controls(stdout,stderr,args,*,workload,observed):
    _,_,cost,prefix=check(stdout,stderr,*args,workload=workload,observed=observed)
    original_hash=H(stderr);original=cost_reports.supplied_controls(stdout,prefix,*args,workload=workload)
    names=[];changed=[]
    if observed:
        for key,index,value in [('version',None,2),('scope',None,'wrong'),('status',None,1),
            ('failure_code',None,1),('detail_negative',None,1),('detail_abs',None,1),('clock_id',None,1),
            ('admission',0,0),('admission',1,0),('admission',2,1),('admission',3,1),
            ('admission',4,cost['admission'][4]+1),('admission',5,cost['admission'][4]*cost['admission'][7]+1),
            ('admission',6,cost['admission'][7]+1),('admission',7,cost['admission'][6]-1),('maps',0,cost['maps'][0]+1),('maps',3,cost['maps'][3]+1),
            ('maps',4,0),('maps',6,1),('maps',7,1),('maps',8,1),('maps',9,1)]:
            row=copy.deepcopy(cost)
            if index is None:row[key]=value
            else:row[key][index]=value
            need(row!=cost,'non-vacuous diagnostic mutation')
            changed.append((key+str(index),prefix+b'LI2_COST '+json.dumps(row,separators=(',',':')).encode()+b'\n'))
        row=stderr[len(prefix):]
        changed.extend([('missing',prefix),('duplicate',stderr+row),('wrong_order',row+prefix),
                        ('truncated',stderr[:-1]),('duplicate_key',prefix+row.replace(b'{',b'{"version":1,',1))])
        for name,data in changed:
            refused=False
            try:check(stdout,data,*args,workload=workload,observed=True)
            except ValueError:refused=True
            need(refused,'complete diagnostic reader refuses '+name);names.append(name)
        need(len(names)==27,'all27 distinct additive diagnostic controls')
    need(H(stderr)==original_hash,'original evidence retained')
    return dict(original=original,diagnostic_refusals=names,scope='supplied report mutations only; no additional native subjects')


def build_cost_bridge(builder,products,private,pin,binary,aliases,run,r):
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         fact(archive)=={k:retained[k]for k in('bytes','sha256')},'fresh Build.prepare owns this exact archive')
    output=private/'release';output.mkdir();bridge_recipe=pin(SELECTED/'build-native-pair.sh');rows=recipe(bridge_recipe,'"$cc_bin"')
    need(len(rows)==1,'one explicit two-page native release link recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,
        '$parent_dir':SELECTED.parent,'$archive':archive,'$output':output});argv.insert(1,'-DLI2_COST_PROFILE=1');units=[str(SELECTED.parent/x)for x in UNITS]
    need(argv[-2:]==['-o',str(output/'bridge-native-pair.so')]and
         [x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_COST_PROFILE=1']+['-DLI2_'+x+'=1'for x in MACROS]and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact diagnostic18-TU21-macro native pair release recipe')
    state=r['release_build']=dict(status='failed',recipe=fact(bridge_recipe),archive=fact(archive),argv=argv)
    headers('release-bridge-headers',argv,units,archive,builder,pin,aliases,run,state)
    bridge=Path(argv[-1]);run('release-bridge-link',argv,profile='release_build',env=builder.environment)
    state['bridge']=fact(binary(bridge));state['elf']=bridge_check(bridge)
    _,out,err=run('release-bridge-undefined',[builder.tools['nm'],'-u',bridge],profile='inspect',env=builder.environment)
    need(out==err==b'','actual effect bridge has no unresolved imports')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('release-objdump-version',[objdump,'--version'],env=builder.environment);need(out and not err,'actual objdump identity')
    _,symbols,err=run('release-bridge-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual reset symbol inspection')
    _,assembly,err=run('release-bridge-memset',[objdump,'-d','-w','-M','att','--disassemble=memset',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual reset disassembly');state['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
    state['status']='passed';return bridge



def cohort(builder,products,private,pin,binary,aliases,run,r):
    roots={};bridges={};r['release_builds']={}
    for lane in('unobserved','counters'):
        root=private/lane;root.mkdir();roots[lane]=root;state=r['release_builds'][lane]={}
        def labelled(name,argv,**kwargs):return run(lane+'-'+name,argv,**kwargs)
        bridges[lane]=(pair.build_bridge if lane=='unobserved'else build_cost_bridge)(
            builder,products,root,pin,binary,aliases,labelled,state)
    plain=r['release_builds']['unobserved']['release_build']['argv'];cost=r['release_builds']['counters']['release_build']['argv']
    normalized=[x.replace(str(roots['counters']),str(roots['unobserved']))for x in cost if x!='-DLI2_COST_PROFILE=1']
    need(normalized==plain,'only diagnostic macro and output directory differ in release recipes')
    spec=importlib.util.spec_from_file_location('counter_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    (private/'external-inputs').mkdir();r['namespace_aliases']={};states={}
    for lane in('unobserved','counters'):
        for kind,path,args in [('ls','/bin/ls',['-d','.']),('true','/bin/true',[])]:
            states[kind,lane]=pair.prepare_workload(kind+'-'+lane,path,args,bridges[lane],builder,private,pin,binary,run,r,namespace)
    for kind in('ls','true'):
        left,right=(kind+'-'+lane for lane in('unobserved','counters'))
        need(all(r[key][left]==r[key][right]for key in('system_inputs','namespace_plans','external_inputs')),
             'identical complete original/interpreter/dependency inputs in both variants')
    r['terminal_reports']={};r['reader_controls']={}
    for ordinal,(kind,repeat,lane)in enumerate(ORDER):
        name=NAMES[ordinal];s=states[kind,lane];case=r['cases'][ordinal];case['status']='failed';ns=private/(name+'-namespace')
        argv=[builder.tools['python'],'-B',s['carrier_tool'],'exec-loader','--library-root','/usr/lib64',
              '--namespace',ns,s['carrier'],s['original'],'--',*s['argv']]
        try:
            row,out,err=run(name,argv,profile='program',env=PROGRAM_ENV)
            pair.namespace_join(s,ns,binary,r,namespace)
            args=(row['pid'],row['exit'],row['stdout_provenance_before'],s['images'],s['image_bytes'],fact(s['carrier']),s['carrier_bytes'])
            parsed,summary,cost,_=check(out,err,*args,workload=kind,observed=lane=='counters')
            r['terminal_reports'][name]=parsed;r['reader_controls'][name]=controls(out,err,args,workload=kind,observed=lane=='counters')
            case.update(status='passed',comparison=summary,cost=cost)
        except BaseException as exc:case['error']=type(exc).__name__+': '+str(exc)
        finally:
            attempted=[c for c in r['commands']if c['name']==name]
            if attempted:
                row=attempted[-1];case.update({k:row.get(k)for k in('exit','process_ns','timed_out','reaped','user_cpu_ns','system_cpu_ns',
                    'minor_faults','major_faults','voluntary_switches','involuntary_switches')})
                case['captures']={k:{f:v[f]for f in('bytes','sha256')}for k,v in row.get('captures',{}).items()}
            print(json.dumps({k:case.get(k)for k in('ordinal','workload','lane','status','exit','process_ns','error')}),flush=True)
    need(len(r['cases'])==12 and all(c['status']=='passed'for c in r['cases']),
         'all twelve fixed observer-cost attempts complete; no replacement or dropped failure')


def publish(path,r,private):
    buf=io.StringIO(newline='');writer=csv.writer(buf,lineterminator='\n')
    fields='ordinal workload repeat lane status exit process_ns timed_out reaped user_cpu_ns system_cpu_ns minor_faults major_faults voluntary_switches involuntary_switches'.split()
    cost_names=['admission_'+x for x in('initialized','valid','busy','overflow','count','sum_ns','min_ns','max_ns')]+[
        'maps_'+x for x in('fresh_calls','acquisitions','reuses','invalidations','handler_id','mutation_epoch','active','valid','poisoned','reserved')]
    writer.writerow(fields+cost_names)
    for c in r['cases']:writer.writerow([c.get(k)for k in fields]+(c['cost']['admission']+c['cost']['maps']if c.get('cost')else ['']*18))
    data=buf.getvalue().encode();stats={}
    for kind in('ls','true'):
        stats[kind]={}
        for lane in('unobserved','counters'):
            rows=[c for c in r['cases']if c['workload']==kind and c['lane']==lane];times=[c['process_ns']for c in rows if c['status']=='passed']
            item=stats[kind][lane]=dict(planned=3,passed=len(times))
            if len(times)==3 and r['source_unchanged']and not r['final_errors']:
                q=statistics.quantiles(times,n=4,method='inclusive');item.update(median_ns=statistics.median(times),q1_ns=q[0],q3_ns=q[2],iqr_ns=q[2]-q[0])
        if all('median_ns'in stats[kind][lane]for lane in('unobserved','counters')):
            a,b=(stats[kind][lane]['median_ns']for lane in('unobserved','counters'))
            stats[kind]['observer_overhead']=dict(median_difference_ns=b-a,median_ratio=b/a)
    value={k:r.get(k)for k in('schema','profile','status','expected_revision','source','source_unchanged','cleanup_complete','hardware','cpu','bounds','reproduce','archive','carriers','system_inputs')}
    value.update(statistics=stats,quantiles='inclusive linear interpolation at (n-1)*p; three samples per variant/workload',
        scope='Separate whole-process observer-overhead diagnostic, pre-Popen through reap. Admission counters cover only existing successful prepare-to-post-publish clock intervals; maps snapshot precedes report writes. No first-touch, steady-state or native/DR speedup credit.',
        overhead_scope='Includes counter updates, code/layout differences and extra terminal report write. No subtraction from original benchmark samples; no cache-cold claim.',
        order=[dict(workload=k,repeat=n,lane=l)for k,n,l in ORDER],commands=len(r['commands']),command_rows_sha256=digest(r['commands']),
        private_receipt=fact(private/'receipt.json'),csv=dict(file=path.with_suffix('.csv').name,bytes=len(data),sha256=H(data)),
        tool_versions=r.get('build',{}).get('numeric_versions'),release_builds={k:v.get('release_build',{'status':'not_completed'})for k,v in r.get('release_builds',{}).items()},
        reader_controls={k:dict(original=len(v['original']['refusals']),diagnostic=len(v['diagnostic_refusals']))for k,v in r.get('reader_controls',{}).items()},
        cases=[{k:v for k,v in c.items()if k not in('error','comparison')}for c in r['cases']],
        error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']))
    value['release_builds']={k:{n:s[n]for n in('status','recipe','archive','bridge')if n in s}for k,s in value['release_builds'].items()}
    value['hardware']=dict(value['hardware']);flags=value['hardware'].pop('isa_flags');value['hardware']['isa_flags_sha256']=digest(flags)
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<32<<10 and len(data)<16<<10 and not any(x and len(x)>1 and x in text for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),
         'bounded public numeric diagnostic without host paths/logs')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.with_suffix('.csv').open('xb')as f:f.write(data)
    with path.open('x')as f:f.write(text)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),
         'exact committed revision, assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-cost-counters-'+a.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem
    private.mkdir(parents=True,mode=0o700);public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    bounds=dict(BUILD_PROFILES,**BOUNDS)
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='page-cost-counters-v1',scope='Twelve fixed observer-overhead attempts; original terminal gates and limits retained',
        status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
        cpu=cpu,hardware=hardware(cpu),bounds=bounds,commands=commands,cases=[dict(ordinal=i,workload=k,repeat=n,lane=l,status='not_run') for i,(k,n,l) in enumerate(ORDER)],error=None,final_errors=[],
        reproduce=['python3','evaluation/inprocess/page_cost_counters.py','--expect-revision',a.expect_revision])
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
        for name,want in COST_SOURCES.items():pin(ROOT/name,want)
        products=builder.prepare();r['archive']=fact(products['archive'])
        cohort(builder,products,private,pin,binary,aliases,run,r)
        need(not r['final_errors'],'no retained command errors')
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
