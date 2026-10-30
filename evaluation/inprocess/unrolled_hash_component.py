#!/usr/bin/env python3
"""Nine fixed hardware-original/generated unroll comparisons; component only."""
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
FIXTURE=SELECTED/'tests/unrolled_hash'
PROFILES=dict(BUILD_PROFILES,native=[5,512<<20,16<<20,15])
CASES=tuple(range(9))
LEAVES={'tools/page-entry/selected/tests/unrolled_hash/README.md': {'bytes': 5969, 'sha256': 'eee59b26bf44c05e3e5b8bd1eec552d27476e9b996a935495b1a69fdda2a3774'}, 'tools/page-entry/selected/tests/unrolled_hash/build.sh': {'bytes': 1094, 'sha256': '55ea56c47a3037c94c9b6bbd50946019b3b80da69d6f489cd3d05f9aebfc09ca'}, 'tools/page-entry/selected/tests/unrolled_hash/check.py': {'bytes': 10953, 'sha256': '0f129f3a50a96e0354f7cfae5e76cc345ac45f0e8ab50dc5e2efc31efef88706'}, 'tools/page-entry/selected/tests/unrolled_hash/oracle.c': {'bytes': 30891, 'sha256': '652c09cf77c7a358ee98e54aea6b32961d56b2b9ec9da3e25b99e244707894b1'}, 'tools/page-entry/selected/unrolled_hash.h': {'bytes': 6227, 'sha256': 'c095ac865e0fd9f8773cd6367a704b36afaceafb9901c54ca3e8cb44d52e15a4'}, 'tools/page-entry/selected/unrolled_hash_plan.c': {'bytes': 6566, 'sha256': '2be68dac5c40c2d46ae5c5f2d3c2776a847cc605e7fb0798e5f8b429f69459a9'}, 'tools/page-entry/selected/tests/region_cache/machine.h': {'bytes': 687, 'sha256': 'f1f88f5a4be17022820d753ab188012fe4faf049ca29088fc1ef0c8146c2a185'}, 'tools/page-entry/selected/tests/region_cache/machine.S': {'bytes': 3319, 'sha256': 'cc82fc32a554afe85285486f68454203a21386a103b771cd866c72cd11d0a3cf'}}
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def controls(check,record,stdout,stderr,exit_status,mode):
    """Supplied refusals only, after genuine full check; no synthetic baseline."""
    before,generated=12640,284336
    def flip(at,mask=1):
        value=bytearray(record);value[at]^=mask;return bytes(value)
    offsets=[('version',8),('first_error',32),('cleanup',40),('mode',24),('plan_size',112),('seed_gpr',256),('unused_cpuid',384),('whole_source_tail',6015),('whole_image_tail',10111),('plan_source',10152),('plan_emission',10191),('decoder_code',10112+1880+24),('reference_before_gpr',before),('reference_after_gpr',before+152),('reference_AF',before+280),('reference_selector',before+288),('reference_before_fp_tail',before+65839),('reference_after_fp_tail',before+131375),('entry_frame_padding',before+131376+216),('entry_frame_fp_tail',before+197167),('exit_frame_fp_tail',before+262959),('entry_siginfo',before+262960),('reference_stack_tail',before+263375),('reference_data_tail',before+271567),('reference_raw_pc',before+271568+5*8),('reference_FS',before+271568+7*8),('generated_after_gpr',generated+152),('generated_AF',generated+280),('generated_before_fp_tail',generated+65839),('generated_after_fp_tail',generated+131375),('generated_stack_tail',generated+263375),('generated_data_tail',generated+271567),('generated_trace',generated+271568+2*8),('generated_exit_kind',generated+271568+4*8),('supplied_count',160)]
    trials=[(name,(flip(at,0x10 if name.endswith('_AF')else 1),stdout,stderr,exit_status,mode))for name,at in offsets]
    trials += [('truncated',(record[:-1],stdout,stderr,exit_status,mode)),('appended',(record+b'\0',stdout,stderr,exit_status,mode)),('extra_stdout',(record,stdout+b'\n',stderr,exit_status,mode)),('nonempty_stderr',(record,stdout,b'x',exit_status,mode)),('wrong_exit',(record,stdout,stderr,0 if exit_status else 125,mode))]
    row=json.loads(stdout);row['qualified_comparison']=True
    trials.append(('bool_output',(record,json.dumps(row,separators=(',',':')).encode()+b'\n',stderr,exit_status,mode)))
    if mode>=7:
        trials += [('actual_fault_CR2',(flip(generated+197168+22*8),stdout,stderr,exit_status,mode)),('actual_fault_TF',(flip(generated+197168+17*8+1),stdout,stderr,exit_status,mode))]
    need(len(trials)==41+2*int(mode>=7)and len({x[0]for x in trials})==len(trials),'complete unique supplied controls')
    accepted=[]
    for name,args in trials:
        refused=False
        try:check(*args)
        except ValueError:refused=True
        need(refused,'actual reader accepted supplied corruption '+name);accepted.append(name)
    return accepted

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True);args=ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'assertions, exact revision, one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT);stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-unrolled-hash-component-'+args.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=ROOT/'evaluation/inprocess/results'/(stem+'.json');public_csv=public.with_suffix('.csv')
    r=dict(schema=1,profile='bounded-unrolled-hash-component-v1',status='failed',source=None,source_unchanged=False,expected_revision=args.expect_revision,cpu=cpu,started_utc=stamp,bounds=PROFILES,
        reproduce=['python3','evaluation/inprocess/unrolled_hash_component.py','--expect-revision',args.expect_revision],commands=[],cases=[dict(mode=m,status='not_run',expected_exit=125 if m>=7 else 0,exit=None)for m in CASES],error=None,final_errors=[])
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
        row=dict(name=label,argv=list(map(str,argv)),bounds=PROFILES[profile],profile=profile,expected_exit=expected,capture_limit=65536 if profile=='native'else 4<<20,environment=dict(ENV if env is None else env));r['commands'].append(row)
        out,err=invoke(row,private,cpu,record=profile=='native',step=profile=='native')
        need(type(row['exit'])is int and row['exit']==expected,'exact actual exit '+label);return row,out,err

    builder=Build(r,private,pin,binary,run);output=private/'component'
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact committed source');r['hardware']=hardware(cpu)
        git=pin(shutil.which('git',path=ENV['PATH']));_,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z'],profile='metadata');need(not err,'source list stderr')
        tracked={os.fsdecode(p)for p in out.split(b'\0')if p}
        need(set(LEAVES)|{'evaluation/inprocess/unrolled_hash_component.py'}<=tracked,'all new compiler/reader/evaluator leaves committed')
        for path in sorted(tracked):
            if not path.startswith('evaluation/inprocess/results/'):pin(ROOT/path)
        for path,expected in LEAVES.items():need(fact(pin(ROOT/path))==expected,'exact reviewed component leaf '+path)
        spec=importlib.util.spec_from_file_location('unrolled_hash_check',pin(FIXTURE/'check.py'));reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
        products=builder.prepare();build_recipe=pin(FIXTURE/'build.sh')
        commands=recipe(build_recipe,'"$cc_bin"');need(len(commands)==1,'one explicit component compile/link')
        argv=expand(commands[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,'$root':ROOT,'$fixture_dir':FIXTURE,'$decoder_archive':products['archive'],'$output_dir':output})
        sources=list(map(str,(FIXTURE/'oracle.c',SELECTED/'tests/region_cache/machine.S',SELECTED/'unrolled_hash_plan.c')))
        need(argv[-1]==str(output/'unrolled-hash')and '-O2'in argv and [x for x in argv if x.startswith('-D')]==['-DLI2_FAST_MEMSET=1','-DLI2_FAST_EQUAL=1'],'exact O2/full-byte helper profile')
        r['component_build']=dict(recipe=fact(build_recipe),argv=argv,status='failed')
        headers('unrolled-headers',argv,sources,products['archive'],builder,pin,aliases,run,r['component_build'])
        required={str(pin(p))for p in (SELECTED/'unrolled_hash.h',SELECTED/'decoder.h',SELECTED/'step_owner.h',SELECTED/'tests/region_cache/machine.h')}
        need(required<=set(r['component_build']['headers']),'actual complete machine/plan/decoder/frame includes')
        run('unrolled-build',[builder.tools['sh'],build_recipe,ROOT,SELECTED,products['archive'],output],profile='build',env=builder.environment)
        exe=binary(output/'unrolled-hash');data,head,segments=elf(exe)
        need(head[1]in(2,3)and all(s[2]+s[5]<=len(data)and s[5]<=s[6]for s in segments if s[0]==1)and all(s[1]&3!=3 for s in segments if s[0]==1),'complete ELF loads with W^X')
        interp=[s for s in segments if s[0]==3];need(len(interp)==1,'one actual dynamic interpreter')
        p=interp[0];name=data[p[2]:p[2]+p[5]];need(name.startswith(b'/')and name.endswith(b'\0')and b'\0'not in name[:-1],'exact interpreter string');loader=pin(os.fsdecode(name[:-1]))
        _,out,err=run('unrolled-library-list',[loader,'--list',exe],profile='inspect',env=builder.environment);need(not err,'actual loader dependency listing')
        r['runtime_libraries']={}
        for line in out.decode().splitlines():
            if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
            match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line);need(match is not None,'one resolved actual library')
            path=pin(match[1]);need(path.name not in r['runtime_libraries'],'unique actual runtime library basename');r['runtime_libraries'][path.name]=dict(path=str(path),**fact(path))
        need(r['runtime_libraries']and any(v['path']==str(loader)for v in r['runtime_libraries'].values()),'actual interpreter included in closure')
        _,_,err=run('unrolled-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',exe],profile='inspect',env=builder.environment);need(not err,'actual ELF inspection stderr')
        _,out,err=run('unrolled-symbols',[builder.tools['nm'],'-S','--defined-only',exe],profile='inspect',env=builder.environment);need(not err,'actual symbol inspection stderr')
        r['component_build']['symbols']={}
        for symbol in ('region_enter','region_capture','li2_unrolled_hash_plan_bytes','li2_unrolled_hash_map_pc'):
            rows=[line.split()for line in out.decode().splitlines()if line.split()[-1:]==[symbol]]
            need(len(rows)==1 and len(rows[0])==4 and rows[0][2]=='T','one actual machine/planner text definition');address,size=int(rows[0][0],16),int(rows[0][1],16)
            need(size>0 and sum(s[0]==1 and s[1]==5 and s[3]<=address<address+size<=s[3]+s[5]for s in segments)==1,'whole symbol in actual RX segment')
            r['component_build']['symbols'][symbol]=dict(address=address,bytes=size)
        r['component_build'].update(status='passed',artifact=fact(exe))
        for c in r['cases']:
            mode=c['mode'];label='unrolled-'+str(mode);c['status']='failed'
            try:
                try:row,out,err=run(label,[exe,str(mode)],c['expected_exit'],env=dict(ENV,GLIBC_TUNABLES='glibc.pthread.rseq=0'))
                finally:
                    if r['commands'][-1]['name']==label:
                        actual=r['commands'][-1];c['exit']=actual.get('exit');c['duration_ns']=actual.get('duration_ns');c['timed_out']=actual.get('timed_out');c['launched']=type(actual.get('pid'))is int
                        retained=actual.get('captures',{}).get('record')
                        if retained is not None:c['record']={k:retained[k]for k in('bytes','sha256')}
                capture=row['captures']['record'];path=binary(private/capture['file']);need(fact(path)=={k:capture[k]for k in('bytes','sha256')},'whole actual record binding')
                record=path.read_bytes();c['record']=fact(path);c['reader_result']=reader.check(record,out,err,row['exit'],mode)
                c['reader_controls']=controls(reader.check,record,out,err,row['exit'],mode)
                need(len(c['reader_controls'])==41+2*int(mode>=7),'exact actual per-mode reader refusals')
                c['status']='qualified_required_failure'if mode>=7 else 'qualified_component'
            except Exception as exc:
                c['status']='failed';c['error_type']=type(exc).__name__;c['error']=type(exc).__name__+': '+str(exc)
                if r['error']is None:r['error']=c['error']
                last=r['commands'][-1]if r['commands']else{}
                if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[] and isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
        need(len(r['cases'])==9 and [c['status']for c in r['cases']]==['qualified_component']*7+['qualified_required_failure']*2,'complete nine modes and required failure operations')
        need(not any(c.get('error')for c in r['cases'])and sum(len(c['reader_controls'])for c in r['cases'])==373,'all original comparisons plus373 actual-reader refusals')
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
        if r['error']or r['final_errors']or not r['cleanup_complete']or r['build']['status']!='passed' or r.get('component_build',{}).get('status')!='passed':r['status']='failed'
        r['totals']=dict(required_modes=9,launch_attempts=sum(x.get('profile')=='native'for x in r['commands']),launched=sum(c.get('launched',False)for c in r['cases']),observed_exits=sum(c.get('exit')is not None for c in r['cases']),qualified=sum(c['status'].startswith('qualified_')for c in r['cases']),completed_chunks=sum(c['status']=='qualified_component'for c in r['cases']),completed_loops=sum(c['status']=='qualified_component'and c['mode']!=4 for c in r['cases']),required_read_failures=sum(c['status']=='qualified_required_failure'for c in r['cases']),reader_refusals=sum(len(c.get('reader_controls',[]))for c in r['cases']))
        save(private/'receipt.json',r)
        hw=dict(r.get('hardware')or{});flags=hw.pop('isa_flags',[]);hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        pub={k:r.get(k)for k in('schema','profile','status','source','source_unchanged','expected_revision','cpu','started_utc','bounds','reproduce','cleanup_complete','totals')}
        pub['cases']=[{**{k:v for k,v in c.items()if k not in('error','reader_controls')},'reader_control_count':len(c.get('reader_controls',[])),'reader_controls_sha256':digest(c.get('reader_controls',[]))}for c in r['cases']]
        pub.update(hardware=hw,private_receipt=fact(private/'receipt.json'),command_count=len(r['commands']),commands_sha256=digest(r['commands']),inputs_sha256=digest(pins),artifacts_sha256=digest(artifacts),failure_type=(r['error']or'').split(':')[0]or None,final_error_count=len(r['final_errors']),whole_application_credit=False,performance_credit=False,
            scope='Required cohort: nine finite hardware original/generated comparisons. The original uses an explicit TF reference; generated code uses no TF. NUL65 stops at head64 without loop completion. Two real read faults must exit125 without completion or resumption credit. Every GPR, full flags including AF, full65536B FP, stack and data comparison remains mandatory. The required373 supplied reader refusals add no native credit. Process duration includes setup, controls and IO; it is not throughput. Production controller, rseq and lifecycle qualification remain separate.')
        columns=['mode','status','expected_exit','exit','duration_ns','record_bytes','reader_control_count','completed_chunk','completed_loop','required_read_failure','reference_trace','generated_trace','exit_kind']
        csv_stream=io.StringIO(newline='');writer=csv.writer(csv_stream,lineterminator='\n');writer.writerow(columns)
        for c in pub['cases']:
            observed=c.get('reader_result',{});writer.writerow([c.get(k,'')if k in c else c.get('record',{}).get('bytes','')if k=='record_bytes'else observed.get(k,'')for k in columns])
        csv_bytes=csv_stream.getvalue().encode();need(len(csv_bytes)<=4096,'compact complete nine-row CSV')
        pub['csv']=dict(file=public_csv.name,bytes=len(csv_bytes),sha256=hashlib.sha256(csv_bytes).hexdigest())
        encoded=json.dumps(pub,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n';need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and (x in encoded or x in csv_stream.getvalue())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact path-free numerical result');public.parent.mkdir(exist_ok=True)
        with public_csv.open('xb')as stream:stream.write(csv_bytes)
        with public.open('x')as stream:stream.write(encoded)
    print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)))));return 0 if r['status']=='passed_component'else 1
if __name__=='__main__':raise SystemExit(main())
