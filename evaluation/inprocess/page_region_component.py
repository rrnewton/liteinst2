#!/usr/bin/env python3
"""Closed scalar CFG component: unchanged core planner and actual TF owner."""
import argparse,hashlib,importlib.util,json,os,platform,re,shlex,shutil,statistics,sys,tomllib
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
from checks import source
from run import hardware
from page_selected import ENV,fact,need,save,elf
from page_selected_generic_build import Build,PROFILES as BUILD_PROFILES,package_check
from page_selected_process import invoke
from page_selected_register_time_build import headers
ROOT=Path(__file__).resolve().parents[2]
FIXTURE=ROOT/'tools/page-entry/selected/tests/region_cache'
PROFILES=dict(BUILD_PROFILES,native=[5,512<<20,16<<20,15])
CASES=[(u,t,0)for u in(1,2,4)for t in(1,16,256)]+[(4,1,1),(4,1,2)]
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True);args=ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'assertions, exact revision, one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT);stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-region-component-'+args.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=ROOT/'evaluation/inprocess/results'/(stem+'.json')
    r=dict(schema=1,profile='closed-region-component-v1',status='failed',source=None,source_unchanged=False,expected_revision=args.expect_revision,cpu=cpu,started_utc=stamp,bounds=PROFILES,
        reproduce=['python3','evaluation/inprocess/page_region_component.py','--expect-revision',args.expect_revision],commands=[],cases=[dict(unroll=u,trips=t,fault=f,status='not_run',exit=None)for u,t,f in CASES],error=None,final_errors=[])
    pins,artifacts,aliases,packages={},{},{},[]
    def pin(path):
        lexical=str(Path(path).absolute());p=Path(path).resolve(strict=True);v=fact(p)
        need(lexical not in aliases or aliases[lexical]==str(p),'stable input resolution');aliases[lexical]=str(p)
        need(str(p)not in pins or pins[str(p)]==v,'stable input bytes');pins[str(p)]=v;return p
    def artifact(path):return dict(fact(path),mode=Path(path).stat().st_mode&0o777)
    def binary(path):
        p=Path(path).resolve(strict=True);v=artifact(p);need(str(p)not in artifacts or artifacts[str(p)]==v,'stable artifact');artifacts[str(p)]=v;return p
    def closure():
        need(all(fact(p)==v for p,v in pins.items())and all(artifact(p)==v for p,v in artifacts.items())and all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'complete input/artifact/alias closure')
    def run(label,argv,expected=0,profile='native',env=None):
        need(not any(x['name']==label for x in r['commands']),'unique command label');closure()
        row=dict(name=label,argv=list(map(str,argv)),bounds=PROFILES[profile],profile=profile,expected_exit=expected,capture_limit=65536 if profile=='native'else 4<<20,environment=dict(ENV if env is None else env));r['commands'].append(row)
        out,err=invoke(row,private,cpu,record=profile=='native',step=profile=='native')
        need(type(row['exit'])is int and row['exit']==expected,'exact actual exit '+label);return row,out,err
    builder=Build(r,private,pin,binary,run);output=private/'component'
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact committed source');r['hardware']=hardware(cpu)
        git=pin(shutil.which('git',path=ENV['PATH']));_,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z'],profile='metadata');need(not err,'source list stderr')
        for path in out.split(b'\0'):
            if path and not os.fsdecode(path).startswith('evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(path))
        spec=importlib.util.spec_from_file_location('region_check',pin(FIXTURE/'check.py'));reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
        products=builder.prepare();recipe=pin(FIXTURE/'build.sh')
        run('region-prepare',[builder.tools['sh'],recipe,ROOT,products['archive'],output,'prepare'],profile='metadata',env=builder.environment)
        for p in (output/'planner/Cargo.toml',output/'planner/Cargo.lock',output/'planner/src/lib.rs'):binary(p)
        need(fact(output/'planner/src/lib.rs')==fact(FIXTURE/'planner/lib.rs'),'exact compiled adapter source')
        _,out,err=run('region-cargo-metadata',[builder.tools['cargo'],'metadata','--manifest-path',output/'planner/Cargo.toml','--locked','--offline','--format-version','1'],profile='metadata',env=builder.environment)
        need(not err,'complete planner metadata');metadata=json.loads(out);need(Path(metadata['target_directory']).resolve()==ROOT/'target','one repository Cargo target');lock={(p['name'],p['version']):p for p in tomllib.loads((output/'planner/Cargo.lock').read_text())['package']}
        need({(p['name'],p['version'])for p in metadata['packages']}==set(lock),'exact planner dependency closure')
        for p in metadata['packages']:
            name=(p['name'],p['version']);entry=lock[name];manifest=pin(p['manifest_path'])
            if 'checksum'in entry:
                need(p['source']==entry['source'],'exact registry identity');packages.append(dict(name=p['name'],version=p['version'],root=str(manifest.parent),checksum=entry['checksum']))
            else:need(manifest==ROOT/'Cargo.toml'or manifest==output/'planner/Cargo.toml','only actual core and generated adapter path dependencies')
        r['core_registry_before']=[package_check(p)for p in packages]
        # Compiler dependency extraction uses the exact linked three TUs. Its
        # only literal $ token is linker ORIGIN, omitted from -M by headers().
        lines=[shlex.split(x)for x in recipe.read_text().splitlines()if x.startswith('"$cc_bin"')];need(len(lines)==1,'one exact component link recipe')
        values={'$cc_bin':builder.tools['cc'],'$source_dir':FIXTURE,'$root':ROOT,'$decoder_archive':products['archive'],'$output_dir':output}
        argv=[]
        for word in lines[0]:
            for k,v in values.items():word=word.replace(k,str(v))
            need('$'not in word or word=='-Wl,-rpath,$ORIGIN','only literal loader origin');argv.append(word)
        r['component_build']={};sources=list(map(str,(FIXTURE/'component.c',FIXTURE/'machine.S',ROOT/'tools/page-entry/selected/step_owner.c')))
        headers('region-headers',argv,sources,products['archive'],builder,pin,aliases,run,r['component_build'])
        run('region-build',[builder.tools['sh'],recipe,ROOT,products['archive'],output,'build'],profile='build',env=builder.environment)
        exe=binary(output/'region-component');library=binary(output/'libli2_region_plan.so');original_library=binary(ROOT/'target/release/libli2_region_plan.so')
        need(fact(library)==fact(original_library),'immediately retained exact compiled core DSO')
        data,head,segments=elf(exe);interp=[s for s in segments if s[0]==3];need(len(interp)==1,'one actual dynamic interpreter')
        p=interp[0];name=data[p[2]:p[2]+p[5]];need(name.endswith(b'\0')and b'\0'not in name[:-1],'exact interpreter string');loader=pin(os.fsdecode(name[:-1]))
        _,out,err=run('region-library-list',[loader,'--list',exe],profile='inspect',env=builder.environment);need(not err,'actual loader dependency listing')
        r['runtime_libraries']={}
        for line in out.decode().splitlines():
            if 'linux-vdso.so.1'in line:continue
            match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line);need(match is not None,'one resolved actual library')
            path=pin(match[1]);need(path.name not in r['runtime_libraries'],'unique actual runtime library basename')
            if path.name==library.name:need(path==library and fact(path)==fact(library),'exact executed planner DSO path and complete bytes')
            r['runtime_libraries'][path.name]=dict(path=str(path),**fact(path))
        need(library.name in r['runtime_libraries'],'actual Rust planner DSO resolution')
        for c,(u,t,f) in zip(r['cases'],CASES):
            label='region-%d-%d-%d'%(u,t,f);c['status']='failed'
            try:row,out,err=run(label,[exe,str(u),str(t),str(f)],125 if f else 0,env=dict(ENV,GLIBC_TUNABLES='glibc.pthread.rseq=0'))
            finally:
                if r['commands'][-1]['name']==label:c['exit']=r['commands'][-1].get('exit')
            need(not err,'component stderr empty');capture=row['captures']['record'];path=binary(private/capture['file']);need(fact(path)=={k:capture[k]for k in('bytes','sha256')},'whole record capture binding')
            c['result']=reader.read(path.read_bytes(),out,u,t,f,row['exit']);c['record']=fact(path);c['status']='qualified_required_failure'if f else 'qualified_component'
            if not f:
                c['hot_statistics_ns']=[dict(median=statistics.median(xs),q1=statistics.quantiles(xs,n=4,method='inclusive')[0],q3=statistics.quantiles(xs,n=4,method='inclusive')[2])for xs in c['result']['hot_ns']]
        need(len(r['cases'])==11 and [c['status']for c in r['cases']]==['qualified_component']*9+['qualified_required_failure']*2,'complete fixed population')
        r['status']='passed_component'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors']+=builder.finish()
        except BaseException as exc:r['final_errors'].append('build finalization: '+repr(exc))
        try:r['core_registry_after']=[package_check(p)for p in packages];need(r['core_registry_after']==r.get('core_registry_before',[]),'core registry closure')
        except BaseException as exc:r['final_errors'].append('core registry: '+repr(exc))
        for row in r['commands']:
            for cap in row.get('captures',{}).values():
                try:p=private/cap['file'];need(p.parent==private and fact(p)=={k:cap[k]for k in('bytes','sha256')},'complete retained capture');binary(p)
                except BaseException as exc:r['final_errors'].append('capture: '+repr(exc))
        r['inputs_before'],r['artifacts_before'],r['aliases']=pins,artifacts,aliases
        try:closure();r['inputs_after']={p:fact(p)for p in pins};r['artifacts_after']={p:artifact(p)for p in artifacts};r['source_unchanged']=source()==r['source'];need(r['source_unchanged'],'source after')
        except BaseException as exc:r['final_errors'].append('closure: '+repr(exc))
        r['cleanup_complete']=all(x.get('reaped')and not x.get('timed_out')and not x.get('error')and not x.get('cleanup_errors')and all(d['closed']for d in x.get('descriptors',[]))for x in r['commands'])
        if r['error']or r['final_errors']or not r['cleanup_complete']or r['build']['status']!='passed':r['status']='failed'
        save(private/'receipt.json',r)
        hw=dict(r.get('hardware')or{});flags=hw.pop('isa_flags',[]);hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        pub={k:r.get(k)for k in('schema','profile','status','source','source_unchanged','expected_revision','cpu','started_utc','bounds','reproduce','cleanup_complete','cases')}
        pub.update(hardware=hw,private_receipt=fact(private/'receipt.json'),command_count=len(r['commands']),commands_sha256=digest(r['commands']),inputs_sha256=digest(pins),artifacts_sha256=digest(artifacts),failure_type=(r['error']or'').split(':')[0]or None,final_error_count=len(r['final_errors']),
            lanes=['original_guarded_exit','sealed_region','actual_tf_owner'],whole_application_credit=False,
            scope='Finite singleton no-rseq closed read-only CFG component. Required inaccessible-load probes are outside successful core valid-pointer coverage; they revoke/terminate125 without fault resumption. Native original has one guarded-exit signal; cache has entry+exit signals; TF has one NX and TRACE per instruction plus final guard. Timings include actual machine capture and guards; preparation includes source construction, sealing, SHA, core planning and image publication, excludes process/setup. Ten hot samples at identical trip/graph sizes; no speed threshold or ls coverage inference.')
        encoded=json.dumps(pub,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n';need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and x in encoded for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact path-free numerical result');public.parent.mkdir(exist_ok=True)
        with public.open('x')as stream:stream.write(encoded)
    print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)))));return 0 if r['status']=='passed_component'else 1
if __name__=='__main__':raise SystemExit(main())
