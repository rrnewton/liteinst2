#!/usr/bin/env python3
"""Eleven hardware scalar-DAG comparisons plus one separate planner prerequisite."""
import argparse,csv,hashlib,importlib.util,io,json,os,platform,re,shutil,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
from checks import source
from run import hardware
from page_selected import ENV,fact,need,save,elf
from page_selected_generic_build import Build,PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_register_time_build import recipe,expand,headers
ROOT=Path(__file__).resolve().parents[2]
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/scalar_region'
PLANNER=SELECTED/'tests/region_plan'
PROFILES=dict(BUILD_PROFILES,native=[5,512<<20,16<<20,15],planner=[5,512<<20,16<<20,15])
CASES=tuple(range(11))
LEAVES={'evaluation/inprocess/page_selected_generic_build.py': {'bytes': 18638, 'sha256': 'aeaa8efec3e2406c576e9c69110d58a0f281b2d5fe8c6f713444ec8ee297bb11'}, 'tools/page-entry/selected/build.sh': {'bytes': 3436, 'sha256': 'ade5026c751d0e33d8805edcdde32bb5ff8ab32a4ef6921ccf5ce9677ff439ce'}, 'tools/page-entry/selected/decoder/Cargo.lock': {'bytes': 799, 'sha256': '1006555168c3320ddeed45455bf5171086bf3683b78633f839df63819ff8e41e'}, 'tools/page-entry/selected/decoder/Cargo.toml': {'bytes': 528, 'sha256': 'c3a3c369be61f2d88d4c653e4689714827a072431575c94635abf0e9b1ce0122'}, 'tools/page-entry/selected/decoder/src/lib.rs': {'bytes': 9672, 'sha256': '10db769a9e017f96defcacd2df4ac18e8e5adf396f9dd76470abdfd0e31b1ce6'}, 'tools/page-entry/selected/decoder/src/region.rs': {'bytes': 51594, 'sha256': '2c3b9712afb01e82ac797000a397f790565a412f6a6590cab8672dd0b3334e3a'}, 'tools/page-entry/selected/region_decode.h': {'bytes': 7150, 'sha256': 'd9ccb59abd39bff378ecb30460e6d5c45142c2f77636b2c25068db9446a6e529'}, 'tools/page-entry/selected/region_plan.c': {'bytes': 25811, 'sha256': '9f0078897ad07e7b33c5d70e2df42f26311dc651faa7a5b71287dd0a47b5733e'}, 'tools/page-entry/selected/region_plan.h': {'bytes': 7464, 'sha256': '08309b8a6d68964ea22f2ba945dd795370f73a3cd63d49f2a08a68cdf20dbab3'}, 'tools/page-entry/selected/tests/region_cache/machine.S': {'bytes': 3319, 'sha256': 'cc82fc32a554afe85285486f68454203a21386a103b771cd866c72cd11d0a3cf'}, 'tools/page-entry/selected/tests/region_cache/machine.h': {'bytes': 687, 'sha256': 'f1f88f5a4be17022820d753ab188012fe4faf049ca29088fc1ef0c8146c2a185'}, 'tools/page-entry/selected/tests/region_plan/build.sh': {'bytes': 731, 'sha256': '2fabb009b69cd6d732fd05a4a5ec3c830cd0af29efe3aebb816bca9f6a426bb8'}, 'tools/page-entry/selected/tests/region_plan/oracle.c': {'bytes': 13217, 'sha256': 'e82962f86b5a1c858f61efba412e5c7617cf2e1f8295109e55bb0488acdd6c42'}, 'tools/page-entry/selected/tests/scalar_region/README.md': {'bytes': 6473, 'sha256': '6024da37a6507f51b86d0358aa7ecb23134d8ec2f5642ff6c52a057307886d6c'}, 'tools/page-entry/selected/tests/scalar_region/build.sh': {'bytes': 1087, 'sha256': '6afa6af6078b848d4bb68ab53195c34afa79dcaee76e15fada8b47408f096c7d'}, 'tools/page-entry/selected/tests/scalar_region/check.py': {'bytes': 31760, 'sha256': '299a0cfb6b275974024b9fa7e4684769ab2409f45a2d6f06047bf6e1f323fdbe'}, 'tools/page-entry/selected/tests/scalar_region/oracle.c': {'bytes': 50982, 'sha256': '2dfc08afd967acbcf54f3d77e72212775fdab818c35573ed55f92a8d2430dddf'}}
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def planner_result(stdout,stderr,status):
    """The exact C specimen asserts whole post-seal equality internally."""
    def pairs(items):
        result={}
        for key,value in items:
            need(key not in result,'duplicate planner field');result[key]=value
        return result
    need(type(status)is int and status==0 and stderr==b'' and type(stdout)is bytes and 0<len(stdout)<=2048,'bounded actual planner process')
    try:result=json.loads(stdout,object_pairs_hook=pairs)
    except (UnicodeError,json.JSONDecodeError)as exc:raise ValueError('planner JSON')from exc
    expected=dict(version=1,planner_only=1,positive=16,refused=27,corrupt=23,mapped=195,interior_or_outside=827,postseal_equal=1)
    need(type(result)is dict and set(result)==set(expected)and all(type(result[k])is int and result[k]==v for k,v in expected.items()),'all original planner counts and post-seal assertion')
    need(json.dumps(result,separators=(',',':')).encode()+b'\n'==stdout,'canonical complete planner row')
    return result

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True);args=ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'assertions, exact revision, one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT);stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-scalar-region-component-'+args.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=ROOT/'evaluation/inprocess/results'/(stem+'.json');public_csv=public.with_suffix('.csv')
    r=dict(schema=1,profile='scalar-region-component-v1',status='failed',source=None,source_unchanged=False,expected_revision=args.expect_revision,cpu=cpu,started_utc=stamp,bounds=PROFILES,
        reproduce=['python3','evaluation/inprocess/scalar_region_component.py','--expect-revision',args.expect_revision],commands=[],cases=[dict(mode=m,status='not_run',expected_exit=125 if m>=5 else 0,exit=None)for m in CASES],error=None,final_errors=[],planner_prerequisite=dict(planned=1,status='not_run',expected_exit=0,launched=False,hardware_cases=0,generated_executions=0,owner_credit=False))
    pins,artifacts,aliases={},{},{}
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
        row=dict(name=label,argv=list(map(str,argv)),bounds=PROFILES[profile],profile=profile,expected_exit=expected,capture_limit=65536 if profile in('native','planner')else 4<<20,environment=dict(ENV if env is None else env));r['commands'].append(row)
        out,err=invoke(row,private,cpu,record=profile=='native',step=profile=='native')
        need(type(row['exit'])is int and row['exit']==expected,'exact actual exit '+label);return row,out,err

    builder=Build(r,private,pin,binary,run,extra_decoder_sources=('region.rs',));output=private/'component'
    def inspect(label,exe,state,symbols):
        exe=binary(exe);data,head,segments=elf(exe)
        need(head[1]in(2,3)and all(s[2]+s[5]<=len(data)and s[5]<=s[6]for s in segments if s[0]==1)and all(s[1]&3!=3 for s in segments if s[0]==1),'complete ELF loads with W^X')
        interp=[s for s in segments if s[0]==3];need(len(interp)==1,'one actual dynamic interpreter')
        p=interp[0];name=data[p[2]:p[2]+p[5]];need(name.startswith(b'/')and name.endswith(b'\0')and b'\0'not in name[:-1],'exact interpreter string');loader=pin(os.fsdecode(name[:-1]))
        _,out,err=run(label+'-library-list',[loader,'--list',exe],profile='inspect',env=builder.environment);need(not err,'actual loader dependency listing')
        state['runtime_libraries']={}
        for line in out.decode().splitlines():
            if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
            match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line);need(match is not None,'one resolved actual library')
            path=pin(match[1]);need(path.name not in state['runtime_libraries'],'unique actual runtime library basename');state['runtime_libraries'][path.name]=dict(path=str(path),**fact(path))
        need(state['runtime_libraries']and any(v['path']==str(loader)for v in state['runtime_libraries'].values()),'actual interpreter included in closure')
        _,_,err=run(label+'-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',exe],profile='inspect',env=builder.environment);need(not err,'actual ELF inspection stderr')
        _,out,err=run(label+'-symbols',[builder.tools['nm'],'-S','--defined-only',exe],profile='inspect',env=builder.environment);need(not err,'actual symbol inspection stderr')
        state['symbols']={}
        for symbol in symbols:
            rows=[line.split()for line in out.decode().splitlines()if line.split()[-1:]==[symbol]]
            need(len(rows)==1 and len(rows[0])==4 and rows[0][2]=='T','one actual machine/planner text definition');address,size=int(rows[0][0],16),int(rows[0][1],16)
            need(size>0 and sum(s[0]==1 and s[1]==5 and s[3]<=address<address+size<=s[3]+s[5]for s in segments)==1,'whole symbol in actual RX segment')
            state['symbols'][symbol]=dict(address=address,bytes=size)
        state.update(status='passed',artifact=fact(exe));return exe

    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact committed source');r['hardware']=hardware(cpu)
        git=pin(shutil.which('git',path=ENV['PATH']));_,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z'],profile='metadata');need(not err,'source list stderr')
        tracked={os.fsdecode(p)for p in out.split(b'\0')if p}
        need(set(LEAVES)|{'evaluation/inprocess/scalar_region_component.py'}<=tracked,'all new compiler/reader/evaluator leaves committed')
        for path in sorted(tracked):
            if not path.startswith('evaluation/inprocess/results/'):pin(ROOT/path)
        for path,expected in LEAVES.items():need(fact(pin(ROOT/path))==expected,'exact reviewed component leaf '+path)
        spec=importlib.util.spec_from_file_location('scalar_region_check',pin(FIXTURE/'check.py'));reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
        products=builder.prepare();need(builder.extra_decoder_sources==('region.rs',)and builder.decoder_features==('scalar-region',)and r['build']['decoder_features']==['scalar-region'],'exact scalar-region source and feature');build_recipe=pin(FIXTURE/'build.sh')
        commands=recipe(build_recipe,'"$cc_bin"');need(len(commands)==1,'one explicit component compile/link')
        argv=expand(commands[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,'$root':ROOT,'$fixture_dir':FIXTURE,'$decoder_archive':products['archive'],'$output_dir':output})
        sources=list(map(str,(FIXTURE/'oracle.c',SELECTED/'tests/region_cache/machine.S',SELECTED/'region_plan.c')))
        need(argv[-1]==str(output/'scalar-region')and '-O2'in argv and [x for x in argv if x.startswith('-D')]==['-DLI2_FAST_MEMSET=1','-DLI2_FAST_EQUAL=1'],'exact O2/full-byte helper profile')
        r['component_build']=dict(recipe=fact(build_recipe),argv=argv,status='failed')
        headers('scalar-headers',argv,sources,products['archive'],builder,pin,aliases,run,r['component_build'])
        required={str(pin(p))for p in (SELECTED/'region_plan.h',SELECTED/'region_decode.h',SELECTED/'decoder.h',SELECTED/'step_owner.h',SELECTED/'tests/region_cache/machine.h')}
        need(required<=set(r['component_build']['headers']),'actual complete machine/plan/decoder/frame includes')
        run('scalar-build',[builder.tools['sh'],build_recipe,ROOT,SELECTED,products['archive'],output],profile='build',env=builder.environment)
        exe=inspect('scalar',output/'scalar-region',r['component_build'],('region_enter','region_capture','raw','li2_region_plan_page','li2_region_plan_validate','li2_region_map_pc','li2_decoder_region_describe'))
        # This is the fixture's C raw() helper, not the production li2_raw6.
        # Numeric ranges avoid disassembler high-address symbol-name aliases.
        objdump=pin(shutil.which('objdump',path=ENV['PATH']))
        _,version,err=run('scalar-objdump-version',[objdump,'--version'],profile='inspect',env=builder.environment);need(version and not err,'actual disassembler identity')
        symbol=r['component_build']['symbols']['raw'];start=symbol['address'];end=start+symbol['bytes']
        _,assembly,err=run('scalar-raw-body',[objdump,'-d','-w','-M','att','--start-address='+str(start),'--stop-address='+str(end),exe],profile='inspect',env=builder.environment);need(not err,'actual fixture gateway disassembly')
        cursor=start;body=bytearray();instructions=[]
        for line in assembly.decode().splitlines():
            if not re.match(r'\s*[0-9a-f]+:',line):continue
            match=re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line);need(match is not None,'complete actual instruction row')
            pc=int(match[1],16);chunk=bytes.fromhex(match[2]);need(pc==cursor and chunk and pc+len(chunk)<=end,'contiguous whole fixture gateway')
            cursor+=len(chunk);body+=chunk;instructions.append(chunk)
        data,_,segments=elf(exe);loads=[s for s in segments if s[0]==1 and s[1]==5 and s[3]<=start<end<=s[3]+s[5]]
        need(len(loads)==1 and cursor==end and instructions and instructions[-1]==b'\xc3'and sum(x==b'\x0f\x05'for x in instructions)==1,'whole single-syscall returning fixture gateway')
        segment=loads[0];offset=segment[2]+start-segment[3];need(body==data[offset:offset+len(body)],'every disassembled byte equals retained ELF')
        r['component_build']['raw_gateway']=dict(address=start,bytes=len(body),instructions=len(instructions),sha256=hashlib.sha256(body).hexdigest(),scope='fixture raw helper only')

        planner_recipe=pin(PLANNER/'build.sh');planner_output=private/'planner'
        rows=recipe(planner_recipe,'"$cc_bin"');need(len(rows)==1,'one original planner specimen recipe')
        argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,'$root':ROOT,'$archive':products['archive'],'$output':planner_output})
        planner_sources=list(map(str,(PLANNER/'oracle.c',SELECTED/'region_plan.c')))
        need(argv[-2:]==['-o',str(planner_output/'region-plan-oracle')]and '-O2'in argv and '-fstack-usage'in argv and not any(x.startswith('-D')for x in argv),'original planner recipe without test macros')
        planner_build=r['planner_build']=dict(status='failed',recipe=fact(planner_recipe),argv=argv,archive=fact(products['archive']))
        headers('planner-headers',argv,planner_sources,products['archive'],builder,pin,aliases,run,planner_build)
        required={str(pin(p))for p in(SELECTED/'region_plan.h',SELECTED/'region_decode.h',SELECTED/'decoder.h')}
        need(required<=set(planner_build['headers']),'actual planner and304-byte descriptor includes')
        run('planner-build',[builder.tools['sh'],planner_recipe,ROOT,SELECTED,products['archive'],planner_output],profile='build',env=dict(builder.environment,CC=str(builder.tools['cc'])))
        planner_exe=inspect('planner',planner_output/'region-plan-oracle',planner_build,('li2_region_plan_page','li2_region_plan_validate','li2_region_map_pc','li2_decoder_region_describe'))
        # This supplied-source/API prerequisite is outside hardware-mode totals.
        prerequisite=r['planner_prerequisite'];prerequisite['status']='failed'
        try:row,out,err=run('planner-prerequisite',[planner_exe],profile='planner',env=builder.environment)
        finally:
            if r['commands'][-1]['name']=='planner-prerequisite':
                actual=r['commands'][-1];prerequisite.update(exit=actual.get('exit'),duration_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int,captures={k:{n:v[n]for n in('bytes','sha256')}for k,v in actual.get('captures',{}).items()})
        prerequisite['result']=planner_result(out,err,row['exit']);prerequisite['status']='qualified_planner_only'
        prerequisite['allocator_scope']='Whole initial/final allocator tuple equality is asserted by the exact C specimen; only postseal_equal is serialized.'
        for c in r['cases']:
            mode=c['mode'];label='scalar-'+str(mode);c['status']='failed'
            try:
                try:row,out,err=run(label,[exe,str(mode)],c['expected_exit'],env=dict(ENV,GLIBC_TUNABLES='glibc.pthread.rseq=0'))
                finally:
                    if r['commands'][-1]['name']==label:
                        actual=r['commands'][-1];c['exit']=actual.get('exit');c['duration_ns']=actual.get('duration_ns');c['timed_out']=actual.get('timed_out');c['launched']=type(actual.get('pid'))is int
                        retained=actual.get('captures',{}).get('record')
                        if retained is not None:c['record']={k:retained[k]for k in('bytes','sha256')}
                capture=row['captures']['record'];path=binary(private/capture['file']);need(fact(path)=={k:capture[k]for k in('bytes','sha256')},'whole actual record binding')
                record=path.read_bytes();c['record']=fact(path);c['reader_result']=reader.check(record,out,err,row['exit'],mode)
                c['reader_controls']=reader.controls(record,out,err,row['exit'],mode)
                need(len(c['reader_controls'])==47+3*int(mode>=5),'exact actual per-mode reader refusals')
                c['status']='qualified_required_failure'if mode>=5 else 'qualified_component'
            except Exception as exc:
                c['status']='failed';c['error_type']=type(exc).__name__;c['error']=type(exc).__name__+': '+str(exc)
                if r['error']is None:r['error']=c['error']
                last=r['commands'][-1]if r['commands']else{}
                if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[] and isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
        need(len(r['cases'])==11 and [c['status']for c in r['cases']]==['qualified_component']*5+['qualified_required_failure']*6,'complete eleven modes and required failure operations')
        need(not any(c.get('error')for c in r['cases'])and sum(len(c['reader_controls'])for c in r['cases'])==535,'all comparisons plus535 actual-reader refusals')
        r['status']='passed_component'
    except BaseException as exc:
        if r['error']is None:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors']+=builder.finish()
        except BaseException as exc:r['final_errors'].append('build finalization: '+repr(exc))
        for row in r['commands']:
            for cap in row.get('captures',{}).values():
                try:p=private/cap['file'];need(p.parent==private and fact(p)=={k:cap[k]for k in('bytes','sha256')},'complete retained capture');binary(p)
                except BaseException as exc:r['final_errors'].append('capture: '+repr(exc))
        r['inputs_before'],r['artifacts_before'],r['aliases']=pins,artifacts,aliases
        try:closure();r['inputs_after']={p:fact(p)for p in pins};r['artifacts_after']={p:artifact(p)for p in artifacts};r['source_unchanged']=source()==r['source'];need(r['source_unchanged'],'source after')
        except BaseException as exc:r['final_errors'].append('closure: '+repr(exc))
        r['cleanup_complete']=all(x.get('reaped')and not x.get('timed_out')and not x.get('error')and not x.get('cleanup_errors')and all(d['closed']for d in x.get('descriptors',[]))for x in r['commands'])
        if r['error']or r['final_errors']or not r['cleanup_complete']or r['build']['status']!='passed' or r.get('component_build',{}).get('status')!='passed' or r.get('planner_build',{}).get('status')!='passed' or r['planner_prerequisite']['status']!='qualified_planner_only':r['status']='failed'
        r['totals']=dict(required_modes=11,launch_attempts=sum(x.get('profile')=='native'for x in r['commands']),launched=sum(c.get('launched',False)for c in r['cases']),observed_exits=sum(c.get('exit')is not None for c in r['cases']),qualified=sum(c['status'].startswith('qualified_')for c in r['cases']),completed_paths=sum(c['status']=='qualified_component'for c in r['cases']),required_read_failures=sum(c['status']=='qualified_required_failure'for c in r['cases']),reader_refusals=sum(len(c.get('reader_controls',[]))for c in r['cases']))
        save(private/'receipt.json',r)
        hw=dict(r.get('hardware')or{});flags=hw.pop('isa_flags',[]);hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        pub={k:r.get(k)for k in('schema','profile','status','source','source_unchanged','expected_revision','cpu','started_utc','bounds','reproduce','cleanup_complete','totals','planner_prerequisite')}
        pub['cases']=[{**{k:v for k,v in c.items()if k not in('error','reader_controls')},'reader_control_count':len(c.get('reader_controls',[])),'reader_controls_sha256':digest(c.get('reader_controls',[]))}for c in r['cases']]
        pub.update(hardware=hw,private_receipt=fact(private/'receipt.json'),command_count=len(r['commands']),commands_sha256=digest(r['commands']),inputs_sha256=digest(pins),artifacts_sha256=digest(artifacts),failure_type=(r['error']or'').split(':')[0]or None,final_error_count=len(r['final_errors']),whole_application_credit=False,performance_credit=False,
            scope='Required hardware cohort: eleven finite original/generated scalar DAG comparisons, five completed paths and six genuine read faults. The original uses an explicit TF reference; generated code uses no TF. Full GPR/flags including AF/65536-byte FP/mask/TLS/stack/data/operand comparisons and exact fault-PC associations are mandatory; required125 grants no completion or resumption credit. The separate original planner specimen checks16 accepted plans/27 refusals/23 corruptions/195 heads/827 misses and asserts whole post-seal allocator equality; its supplied bytes do not execute. The535 supplied reader refusals add no native credit. Process durations include setup, controls and IO, not throughput. Production lifecycle/rseq/owner and whole-application qualification remain separate.')
        columns=['mode','status','expected_exit','exit','duration_ns','record_bytes','reader_control_count','completed_path','required_read_failure','reference_trace','generated_trace','exit_kind']
        csv_stream=io.StringIO(newline='');writer=csv.writer(csv_stream,lineterminator='\n');writer.writerow(columns)
        for c in pub['cases']:
            observed=c.get('reader_result',{});writer.writerow([c.get(k,'')if k in c else c.get('record',{}).get('bytes','')if k=='record_bytes'else observed.get(k,'')for k in columns])
        csv_bytes=csv_stream.getvalue().encode();need(len(csv_bytes)<=4096,'compact complete eleven-row CSV')
        pub['csv']=dict(file=public_csv.name,bytes=len(csv_bytes),sha256=hashlib.sha256(csv_bytes).hexdigest())
        encoded=json.dumps(pub,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n';need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and (x in encoded or x in csv_stream.getvalue())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact path-free numerical result');public.parent.mkdir(exist_ok=True)
        with public_csv.open('xb')as stream:stream.write(csv_bytes)
        with public.open('x')as stream:stream.write(encoded)
    print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)))));return 0 if r['status']=='passed_component'else 1
if __name__=='__main__':raise SystemExit(main())
