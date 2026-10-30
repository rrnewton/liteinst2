#!/usr/bin/env python3
"""Profile one exact closed-baseline gated launch; never a baseline sample."""
import argparse, collections, csv, hashlib, importlib.util, io, json, os, platform, re, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
sys.dont_write_bytecode = True
ROOT = Path.cwd().resolve(); HERE = ROOT/'evaluation/inprocess'
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(Path(__file__).resolve().parent))
from page_selected import ENV, fact, need, save, interpreter
from checks import source
from run import hardware
import page_native_pair_performance as pair
import page_cost_reports as reports
from page_selected_effect_ls import finalize
from page_selected_register_time_build import recipe, expand
from page_cost_profile import profile, TARGET
import page_cost_kernel as kernel
H = lambda b: hashlib.sha256(b).hexdigest()


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--baseline',required=True);ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--workload',choices=('ls','true'),required=True);a=ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',a.expect_revision)and len(os.sched_getaffinity(0))==1,
         'exact revision, assertions and one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-cost-profile-'+a.workload+'-'+a.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(mode=0o700)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'fresh public result')
    pins={};aliases={};artifacts={};r=dict(schema=1,status='failed',scope='separate full-window profiling diagnostic',
        benchmark_credit=False,qualification=False,expected_revision=a.expect_revision,workload=a.workload,
        hardware=hardware(cpu),cpu=cpu,error=None,final_errors=[],namespace_aliases={})
    def pin(path,want=None):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);v=fact(p)
        need(want is None or v=={k:want[k]for k in('bytes','sha256')},'exact retained input')
        need(str(p)not in pins or pins[str(p)]==v,'input changed during attempt')
        need(str(alias)not in aliases or aliases[str(alias)]==str(p),'input alias changed')
        pins[str(p)]=v;aliases[str(alias)]=str(p);return p
    def binary(path,want=None):
        p=Path(path).resolve(strict=True);v=dict(fact(p),mode=p.stat().st_mode&0o777)
        need(want is None or all(v[k]==want[k]for k in want if k in v),'exact retained artifact bytes/mode')
        need(str(p)not in artifacts or artifacts[str(p)]==v,'retained artifact changed');artifacts[str(p)]=v;return p
    def stable():
        need(all(fact(p)==v for p,v in pins.items()),'input bytes unchanged')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'input aliases unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'artifact bytes/modes unchanged')
        need(all(os.path.lexists(p)==v for p,v in r.get('configuration_presence',{}).items()),'loader configuration presence unchanged')
        finalize(r)
    try:
        r['source']=source();need(r['source']['revision']==a.expect_revision,'exact current committed source')
        baseline=pin(a.baseline);b=json.loads(baseline.read_bytes());bd=baseline.parent
        r['baseline']=dict(fact(baseline),revision=b['source']['revision'],status=b['status'])
        need(b['profile'].startswith('page-cost-compare-')and b['status']in('passed','failed')and
             b['source_unchanged']and b['cleanup_complete']and not b['final_errors']and
             b['source']==b['source_after']and b['inputs_before']==b['inputs_after']and
             b['aliases_before']==b['aliases_after']and b['artifacts_before']==b['artifacts_after'],
             'closed baseline retains its actual status and complete source/artifact closure')
        need(all(c['reaped']and not c['timed_out']and not c['error']and not c['cleanup_errors']and
             all(d['closed']for d in c.get('descriptors',[]))for c in b['commands']), 'all baseline process ownership closed')
        git=pin('/usr/bin/git');native_pins=0
        for path,want in b['inputs_before'].items():
            p=Path(path);rel=p.relative_to(ROOT)if p.is_relative_to(ROOT)else None
            native=rel is not None and (rel.parts[0]in('src','crates')or str(rel).startswith('tools/page-entry/')or str(rel)in('Cargo.toml','Cargo.lock'))
            if native:
                pin(p,want);blob=subprocess.check_output([git,'show',a.expect_revision+':'+str(rel)],timeout=20)
                need(dict(bytes=len(blob),sha256=H(blob))==want,'every baseline native source equals exact HEAD');native_pins+=1
            elif rel is None or rel.parts[0]=='target':pin(p,want)
        need(native_pins>0,'nonempty independently bound native source inventory');r['native_source_pins']=native_pins
        for alias,resolved in b['aliases_before'].items():
            if resolved in pins:need(str(Path(alias).resolve(strict=True))==resolved,'retained baseline lexical alias');aliases[alias]=resolved
        r['configuration_presence']=b['configuration_presence'];need(not r['configuration_presence']['/etc/ld.so.preload'],'no preload')
        build=b['build'];release=b['release_build']
        need(build['status']=='passed'and build['command_completed']and build['configuration_unchanged']and
             not build['final_errors']and release['status']=='passed','actual baseline release/build completion')
        archive=binary(build['artifacts']['decoder.a']['path'],build['artifacts']['decoder.a'])
        need(fact(archive)==b['archive']==release['archive'],'retained exact decoder archive')
        bridge=binary(release['argv'][-1],b['artifacts_before'][release['argv'][-1]])
        need(fact(bridge)==release['bridge'],'retained actual release bridge')
        recipe_path=pin(pair.SELECTED/'build-native-pair.sh',release['recipe']);rows=recipe(recipe_path,'"$cc_bin"');need(len(rows)==1,'one release recipe')
        expected=expand(rows[0],{'$cc_bin':build['tools']['cc']['path'],'$selected_dir':pair.SELECTED,
            '$parent_dir':pair.SELECTED.parent,'$archive':archive,'$output':bridge.parent})
        need(len(rows)==1 and expected==release['argv']and
             [x for x in expected if x.endswith(('.c','.S'))]==[str(pair.SELECTED.parent/x)for x in pair.UNITS]and
             [x for x in expected if x.startswith('-DLI2_')]==['-DLI2_'+x+'=1'for x in pair.MACROS],
             'same complete release recipe, units, flags and profile; no rebuild')
        for c in b['commands']:
            if c['name'].startswith('release-'):
                need(c['exit']==0,'actual baseline release command succeeded')
                for capture in c['captures'].values():
                    cp=bd/capture['file'];need(fact(cp)=={k:capture[k]for k in('bytes','sha256')},'closed build capture bytes');binary(cp,b['artifacts_before'][str(cp)])
        need(sum(c['name']=='release-bridge-link'and c['argv']==expected for c in b['commands'])==1,'one actual exact release link')
        name=a.workload+'-0-gated';rows=[c for c in b['commands']if c['name']==name];need(len(rows)==1,'one original gated launch')
        old=rows[0];need(old['exit']==0 and old['environment']==pair.PROGRAM_ENV and tuple(old['bounds'])==TARGET and
             old['capture_limit']==16<<20,'original successful gated command and exact limits/environment')
        need(sum(c['workload']==a.workload and c['repeat']==0 and c['lane']=='gated'and c['status']=='passed'for c in b['cases'])==1,
             'baseline subject already accepted; do not retrospectively qualify a failed case')
        for capture in old['captures'].values():
            cp=bd/capture['file'];need(fact(cp)=={k:capture[k]for k in('bytes','sha256')},'closed target capture bytes');binary(cp,b['artifacts_before'][str(cp)])
        argv=old['argv'];args=['-d','.']if a.workload=='ls'else[];original=pin('/bin/'+a.workload,b['system_inputs'][a.workload]['original'])
        carrier=binary(argv[8],b['artifacts_before'][argv[8]])
        need(fact(carrier)==b['carriers'][a.workload]and interpreter(carrier)==bridge,'actual retained carrier references same bridge')
        need(argv==[build['tools']['python']['path'],'-B',str(ROOT/'tools/page-entry/carrier.py'),'exec-loader',
             '--library-root','/usr/lib64','--namespace',str(bd/(name+'-namespace')),str(carrier),str(original),'--',str(original),*args],
             'exact original launch command; only fresh namespace changes')
        pin(argv[0],build['tools']['python']);pin(argv[2]);ns=private/'namespace';newargv=list(argv);newargv[7]=str(ns)
        spec=importlib.util.spec_from_file_location('profile_namespace',pin(ROOT/'tools/page-entry/namespace.py'))
        namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
        plan=b['namespace_plans'][a.workload];objects,description=namespace.plan(original,[Path(p)for p in plan['roots']],
            bytes.fromhex(plan['original_sha256']),bytes.fromhex(plan['interpreter_sha256']))
        need(description==plan,'fresh independent namespace plan exactly matches baseline')
        dependencies=[dict(names=x['names'],**fact(pin(x['path'],dict(bytes=len(x['bytes']),sha256=H(x['bytes'])))))for x in objects]
        need(dependencies==b['system_inputs'][a.workload]['dependencies'],'same ordered complete dependency closure')
        images=b['external_inputs'][a.workload];image_bytes=[]
        for x in images:
            cp=bd/'external-inputs'/(x['sha256']+'.elf');need(fact(cp)=={k:x[k]for k in('bytes','sha256')},'complete external image fact');image_bytes.append(binary(cp,b['artifacts_before'][str(cp)]).read_bytes())
        state=dict(objects=objects,description=description,argv=[str(original),*args],carrier=carrier)
        row=dict(name='profile-'+a.workload,argv=newargv,environment=dict(old['environment']),cwd=str(bd),
                 bounds=list(TARGET),capture_limit=16<<20);r['command']=row;r['bridge']=fact(bridge);r['carrier']=fact(carrier)
        for m in tuple(sys.modules.values()):
            p=getattr(m,'__file__',None)
            if p and Path(p).resolve().is_relative_to(ROOT):pin(p)
        r['kernel_snapshot']=kernel.capture(private/'kernel')
        stable();out,err,diagnostic=profile(row,private/'capture',cpu,bridge,release['bridge']);r['diagnostic']=diagnostic
        resolver=kernel.load(private/'kernel',r['kernel_snapshot'])
        r['kernel_counts']=kernel.counts(json.loads((private/'capture/samples.json').read_bytes()),resolver,row['pid'])
        pair.namespace_join(state,ns,binary,r,namespace);r['parsed'],r['terminal']=reports.check(out,err,row['pid'],row['exit'],
            row['stdout_provenance_before'],images,image_bytes,fact(carrier),carrier.read_bytes(),workload=a.workload)
        r['controls']=reports.supplied_controls(out,err,row['pid'],row['exit'],row['stdout_provenance_before'],
            images,image_bytes,fact(carrier),carrier.read_bytes(),workload=a.workload)
        r['status']='passed'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        for m in tuple(sys.modules.values()):
            p=getattr(m,'__file__',None)
            if p and Path(p).resolve().is_relative_to(ROOT):
                try:pin(p)
                except BaseException as exc:r['final_errors'].append('import '+repr(exc))
        owner=private/'capture/owner.json'
        if owner.exists():
            try:r['diagnostic']=json.loads(owner.read_bytes())
            except BaseException as exc:r['final_errors'].append('owner receipt '+repr(exc))
        for p in private.rglob('*'):
            if p.is_file()and not p.is_symlink():
                try:binary(p)
                except BaseException as exc:r['final_errors'].append('artifact '+repr(exc))
        try:stable();r['source_after']=source();need(r['source_after']==r['source'],'current source unchanged')
        except BaseException as exc:r['final_errors'].append('closure '+repr(exc))
        r.update(inputs_before=pins,aliases_before=aliases,artifacts_before=artifacts)
        try:
            r.update(inputs_after={p:fact(p)for p in pins},aliases_after={p:str(Path(p).resolve(strict=True))for p in aliases},
                artifacts_after={p:dict(fact(p),mode=Path(p).stat().st_mode&0o777)for p in artifacts})
            need(all(r[k+'_before']==r[k+'_after']for k in('inputs','aliases','artifacts')),'exact final closure dictionaries')
        except BaseException as exc:r['final_errors'].append('final facts '+repr(exc))
        r['source_unchanged']=not r['final_errors']and r.get('source_after')==r.get('source')
        r['cleanup_complete']=r.get('diagnostic',{}).get('closed')is True
        if r['error']or r['final_errors']or not r['source_unchanged']or not r['cleanup_complete']:r['status']='failed'
        save(private/'receipt.json',r);publish(public,r,private)
        print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)))))
    return 0 if r['status']=='passed'else 1


def publish(public,r,private):
    diagnostic=r.get('diagnostic',{});sample=diagnostic.get('sampling',{});groups=collections.Counter();periods=collections.Counter()
    if sample:
        for row in json.loads((private/'capture/samples.json').read_bytes()):
            key=(row['in_target_exec_window'],row['cpumode'],row['reason'],row['symbol']);groups[key]+=1;periods[key]+=row['period']
        need(sum(groups.values())==sample['samples']and sum(periods.values())==sample['sampled_period_total'],'exact count/period projection')
    buf=io.StringIO();writer=csv.writer(buf);writer.writerow(['in_exec_window','cpumode','reason','symbol','samples','sampled_period_total'])
    for key,n in sorted(groups.items()):writer.writerow([*key,n,periods[key]])
    csv_data=buf.getvalue().encode();tools={}
    for name,argv in [('perf',diagnostic.get('perf',{}).get('argv',[])),('python',diagnostic.get('wrapper_argv',[]))]:
        if argv:tools[name]={k:diagnostic['inputs_before'][str(Path(argv[0]).resolve())][k]for k in('bytes','sha256')}
    value=dict(schema=1,status=r['status'],scope=r['scope'],benchmark_credit=False,qualification=False,
        revision=r['expected_revision'],source=r.get('source'),tools=tools,hardware=r['hardware'],workload=r['workload'],baseline=r.get('baseline'),
        target_exit=r.get('command',{}).get('exit'),profiler_exit=r.get('diagnostic',{}).get('perf',{}).get('exit'),
        source_unchanged=r['source_unchanged'],cleanup_complete=r['cleanup_complete'],final_error_count=len(r['final_errors']),
        error_type=r['error'].split(':',1)[0]if r['error']else None,bridge=r.get('bridge'),carrier=r.get('carrier'),sampling=sample,
        bounds=dict(target=list(TARGET),profiler=r.get('diagnostic',{}).get('perf',{}).get('bounds')),controls=len(r.get('controls',{}).get('refusals',[])),
        private_receipt=fact(private/'receipt.json'),csv=dict(bytes=len(csv_data),sha256=H(csv_data)),
        reproduce=['python3','evaluation/inprocess/page_cost_profile_run.py','--baseline','${CLOSED_BASELINE_RECEIPT}',
                   '--expect-revision',r['expected_revision'],'--workload',r['workload']],
        perf_argv=['${PERF}','record','-e','cpu-clock','-F','99','--strict-freq','--mmap-pages=256','--timestamp','--sample-cpu',
                   '--period','--clockid=mono','--delay=-1','--control=fd:${CONTROL},${ACK}','--pid','${TARGET_PID}','--output','${PERF_DATA}'],
        target_argv=['${PYTHON}','-B','tools/page-entry/carrier.py','exec-loader','--library-root','/usr/lib64',
                     '--namespace','${FRESH_NAMESPACE}','${RETAINED_CARRIER}','${ORIGINAL}','--','${ORIGINAL}','${ARGS}'])
    kernel_table=io.StringIO();kw=csv.writer(kernel_table)
    kw.writerow(['kind','aliases','samples','sampled_period_total'])
    kc=r.get('kernel_counts',{})
    for item in kc.get('symbols',[]):
        kw.writerow(['core_text_symbol_interval','|'.join(item['aliases']),item['samples'],item['sampled_period_total']])
    for reason,n in kc.get('unknown_reasons',{}).items():kw.writerow([reason,'',n,''])
    kernel_data=kernel_table.getvalue().encode();kernel_path=public.with_name(public.stem+'-kernel.csv')
    value['kernel']={k:v for k,v in kc.items()if k!='symbols'}
    value['kernel_build_ids']=r.get('kernel_snapshot',{}).get('kernel_build_ids')
    value['kernel_csv']=dict(file=kernel_path.name,bytes=len(kernel_data),sha256=H(kernel_data),
        scope='Drill-down of actual target kernel samples inside the exec window; already included in main CSV, never added again.')
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<16<<10 and len(csv_data)<64<<10 and len(kernel_data)<32<<10 and not any(x and len(x)>1 and(x in text or x.encode()in csv_data or x.encode()in kernel_data)
         for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'bounded private-path-free public projection')
    with kernel_path.open('xb')as f:f.write(kernel_data)
    with public.with_suffix('.csv').open('xb')as f:f.write(csv_data)
    with public.open('x')as f:f.write(text)

if __name__=='__main__':raise SystemExit(main())
