#!/usr/bin/env python3
"""Fixed scalar-span component: one metadata case and58 full-state hardware cases.
No production TRACE, rseq, source-owner, certificate or performance credit.
"""
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
FIXTURE=SELECTED/'tests/scalar_span'
PROFILES=dict(BUILD_PROFILES,native=[5,512<<20,16<<20,15],span_metadata=[5,512<<20,16<<20,15])
CASES=tuple(range(58))
LEAVES={'tools/page-entry/selected/decoder/Cargo.toml': {'bytes': 482, 'sha256': '73a3a5b0f8425f9b899be5219396d73973987f79404357184577838f7fcd354e'}, 'tools/page-entry/selected/decoder/src/region.rs': {'bytes': 48896, 'sha256': '238884489e8b82a27040f785a5dde1b446a9b3ae5c29e640a95cd110a5e68cb5'}, 'tools/page-entry/selected/region_decode.h': {'bytes': 7150, 'sha256': 'd9ccb59abd39bff378ecb30460e6d5c45142c2f77636b2c25068db9446a6e529'}, 'tools/page-entry/selected/region_plan.c': {'bytes': 25811, 'sha256': '9f0078897ad07e7b33c5d70e2df42f26311dc651faa7a5b71287dd0a47b5733e'}, 'tools/page-entry/selected/region_plan.h': {'bytes': 7464, 'sha256': '08309b8a6d68964ea22f2ba945dd795370f73a3cd63d49f2a08a68cdf20dbab3'}, 'tools/page-entry/selected/tests/scalar_span/README.md': {'bytes': 2078, 'sha256': '202070825d61e0521865ba921ada59e623bb06b67226e9845073c441933c23bd'}, 'tools/page-entry/selected/tests/scalar_span/build.sh': {'bytes': 1256, 'sha256': '0cc605dfa4991c21f031c85931a4bc77ef83d992ff7f1a1de8fd99af371e974a'}, 'tools/page-entry/selected/tests/scalar_span/check.py': {'bytes': 15087, 'sha256': '787aff4d12303e53941572f325d532a79300876e2aaff86650750254e95579ea'}, 'tools/page-entry/selected/tests/scalar_span/metadata.c': {'bytes': 18770, 'sha256': '4b9ae0f6db501b1799bacb99b59044079e924a42b7ff7f37a6123d244dd4ec64'}, 'tools/page-entry/selected/tests/scalar_span/model.py': {'bytes': 8284, 'sha256': '8c1a624bc4e02ef2b79afd1a86b0d3ebf635dc918be557c71661fbef20d07531'}, 'tools/page-entry/selected/tests/scalar_span/native.c': {'bytes': 31829, 'sha256': '059a702163cac3bafeabc071c0b981f05e632e2e42f6ec247a8a4506ce7fe4fe'}, 'tools/page-entry/selected/tests/scalar_span/puzzles.h': {'bytes': 3300, 'sha256': '6d7e4823665d461075f94ba71df9f946585ec5186ba6baf9c024bbfb945a9461'}, 'evaluation/inprocess/page_selected_generic_build.py': {'bytes': 16263, 'sha256': '6b630a9add422196f36618574d040d0dade8844e4a80185a41ab4e9ced0bff65'}, 'tools/page-entry/selected/build.sh': {'bytes': 3316, 'sha256': '59bcadd67881030b59b1c9854482288eef0dce9f032b8b8e80fd46692876850e'}, 'tools/page-entry/selected/decoder/Cargo.lock': {'bytes': 799, 'sha256': '1006555168c3320ddeed45455bf5171086bf3683b78633f839df63819ff8e41e'}, 'tools/page-entry/selected/decoder/src/lib.rs': {'bytes': 9548, 'sha256': '266401040160c8618cb7d0799356263794a5f4657489234865f3ff9e357e843f'}, 'tools/page-entry/selected/decoder/src/abi.rs': {'bytes': 2353, 'sha256': '7d29aecce77ce21dc34bbaddfe10af32b6994b052a25cd07c92120edb9db5b2c'}, 'tools/page-entry/selected/decoder/src/arena.rs': {'bytes': 5490, 'sha256': '7306a0e12a5cb26fb7a19ea271f828bc2561ab4d03e5bcc9e0273a61eb22bd6b'}, 'tools/page-entry/selected/decoder/src/decode.rs': {'bytes': 8805, 'sha256': 'b7948615ebfb766620e9b082e3cda8b8a480326427d9742c23f4076f7f493160'}, 'tools/page-entry/selected/decoder/src/tf.rs': {'bytes': 45018, 'sha256': 'e09a1c170f50c59f8faa34ecdc69ddfe9e651158f0f00a668ed7ef2c82059e38'}, 'tools/page-entry/selected/decoder/src/write_footprint.rs': {'bytes': 10124, 'sha256': '754fbc625a52f27dfe20ce3353f761586a4eb1640c64fe846634c8d14501dfe7'}, 'tools/page-entry/selected/decoder.h': {'bytes': 2884, 'sha256': 'c09bbc5fba41c268c42d31cdb1bb9946d8ec6aa994eb4093ee7ddb5563aba70e'}, 'tools/page-entry/selected/write_footprint.h': {'bytes': 1518, 'sha256': '80444c8cab68d34ca40145637a82ad11ae986a2eaa708f12558c1be99079b1a2'}, 'tools/page-entry/selected/step_owner.h': {'bytes': 4364, 'sha256': 'aee2b97ec3a10d950066ac1db03a5f01f66717306fb8b7948696e66cad49059a'}, 'tools/page-entry/selected/tests/region_cache/machine.S': {'bytes': 3319, 'sha256': 'cc82fc32a554afe85285486f68454203a21386a103b771cd866c72cd11d0a3cf'}, 'tools/page-entry/selected/tests/region_cache/machine.h': {'bytes': 687, 'sha256': 'f1f88f5a4be17022820d753ab188012fe4faf049ca29088fc1ef0c8146c2a185'}, 'tools/page-entry/selected/tests/scalar_region/oracle.c': {'bytes': 50982, 'sha256': '2dfc08afd967acbcf54f3d77e72212775fdab818c35573ed55f92a8d2430dddf'}, 'tools/page-entry/selected/tests/scalar_region/check.py': {'bytes': 31760, 'sha256': '299a0cfb6b275974024b9fa7e4684769ab2409f45a2d6f06047bf6e1f323fdbe'}, 'tools/page-entry/selected/tests/scalar_region/build.sh': {'bytes': 1087, 'sha256': '6afa6af6078b848d4bb68ab53195c34afa79dcaee76e15fada8b47408f096c7d'}, 'tools/page-entry/selected/tests/decoder/support.c': {'bytes': 1689, 'sha256': '378440c08081156af2807a31809bec956001309b428e0cc29473f0ed2e57b4d2'}}

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True);args=ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'assertions, exact revision, one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT);stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-scalar-span-component-'+args.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=ROOT/'evaluation/inprocess/results'/(stem+'.json');public_csv=public.with_suffix('.csv')
    cases=[dict(kind='metadata',mode=None,status='not_run',expected_exit=0,exit=None)]+[
        dict(kind='native',mode=m,status='not_run',expected_exit=125 if m in(8,9)else 0,exit=None)for m in CASES]
    r=dict(schema=1,profile='scalar-span-component-v1',status='failed',source=None,source_unchanged=False,
        expected_revision=args.expect_revision,cpu=cpu,started_utc=stamp,bounds=PROFILES,
        reproduce=['python3','evaluation/inprocess/scalar_span_component.py','--expect-revision',args.expect_revision],
        commands=[],cases=cases,error=None,final_errors=[],component_build={})
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

    def run(label,argv,expected=0,profile='metadata',env=None):
        need(not any(x['name']==label for x in r['commands']),'unique command label');closure()
        row=dict(name=label,argv=list(map(str,argv)),bounds=PROFILES[profile],profile=profile,expected_exit=expected,
            capture_limit=65536 if profile in('native','span_metadata')else 4<<20,environment=dict(ENV if env is None else env));r['commands'].append(row)
        out,err=invoke(row,private,cpu,record=profile=='native',step=profile=='native')
        need(type(row['exit'])is int and row['exit']==expected,'exact actual exit '+label);return row,out,err

    builder=Build(r,private,pin,binary,run,extra_decoder_sources=('region.rs',),scalar_span=True);output=private/'component'
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
        git=pin(shutil.which('git',path=ENV['PATH']));_,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z']);need(not err,'source list stderr')
        tracked={os.fsdecode(p)for p in out.split(b'\0')if p}
        need(set(LEAVES)|{'evaluation/inprocess/scalar_span_component.py'}<=tracked,'all exact span compiler/reader/evaluator leaves committed')
        for path in sorted(tracked):
            if not path.startswith('evaluation/inprocess/results/'):pin(ROOT/path)
        for path,expected in LEAVES.items():need(fact(pin(ROOT/path))==expected,'exact reviewed span leaf '+path)
        spec=importlib.util.spec_from_file_location('scalar_span_check',pin(FIXTURE/'check.py'));reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
        products=builder.prepare()
        need(builder.extra_decoder_sources==('region.rs',)and builder.decoder_features==('scalar-region','scalar-span')and
            r['build']['decoder_features']==['scalar-region','scalar-span']and r['build']['archive_text_exports']['li2_decoder_span_describe']==1,
            'exact real scalar-span feature/source/archive')
        build_recipe=pin(FIXTURE/'build.sh');commands=recipe(build_recipe,'"$cc_bin"');need(len(commands)==1,'one exact looped two-variant compiler recipe')
        for kind in('metadata','native'):
            support=SELECTED/('tests/region_cache/machine.S'if kind=='native'else'tests/decoder/support.c')
            argv=expand(commands[0],{'$cc_bin':builder.tools['cc'],'$selected':SELECTED,'$root':ROOT,'$fixture':FIXTURE,
                '$kind':kind,'$support':support,'$archive':products['archive'],'$output':output})
            sources=list(map(str,(FIXTURE/(kind+'.c'),support,SELECTED/'region_plan.c')))
            need(argv[-2:]==['-o',str(output/('span-'+kind))]and '-O2'in argv and '-fstack-usage'in argv and
                [x for x in argv if x.startswith('-D')]==['-DLI2_FAST_MEMSET=1','-DLI2_FAST_EQUAL=1','-DLI2_SCALAR_SPAN=1'],
                'exact actual complete compile recipe for both component variants')
            state=r['component_build'][kind]=dict(status='failed',recipe=fact(build_recipe),argv=argv,archive=fact(products['archive']))
            headers(kind+'-headers',argv,sources,products['archive'],builder,pin,aliases,run,state)
            required={str(pin(p))for p in(SELECTED/'region_plan.h',SELECTED/'region_decode.h',SELECTED/'decoder.h')}
            if kind=='native':required|={str(pin(SELECTED/'tests/region_cache/machine.h')),str(pin(SELECTED/'step_owner.h')),str(pin(FIXTURE/'puzzles.h'))}
            else:required.add(str(pin(SELECTED/'write_footprint.h')))
            need(required<=set(state['headers']),'whole actual typed source/header/archive closure')
        run('span-build',[builder.tools['sh'],build_recipe,ROOT,SELECTED,products['archive'],output],profile='build',env=builder.environment)
        symbols=('li2_span_plan_page','li2_span_plan_validate','li2_span_map_pc','li2_decoder_span_describe','li2_decoder_region_describe','li2_decoder_write_footprint')
        executables={kind:inspect(kind,output/('span-'+kind),r['component_build'][kind],symbols+(('region_enter','region_capture','raw')if kind=='native'else()))for kind in('metadata','native')}
        # These are observed C stack frames; Rust/library and kernel-frame stack
        # coverage remains the actual guarded component execution, not inferred.
        stack_files=sorted(output.glob('*.su'));need(stack_files,'actual compiler stack-usage outputs')
        stack_rows=[];stack_totals=dict(metadata=0,native=0)
        for path in stack_files:
            path=binary(path);variants=[kind for kind in('metadata','native')if path.name.startswith('span-'+kind+'-')]
            need(len(variants)==1,'stack output belongs to exactly one actual linked executable');variant=variants[0]
            for line in path.read_text().splitlines():
                parts=line.split('\t');need(len(parts)==3 and re.fullmatch('[0-9]+',parts[1])and parts[2]in('static','dynamic,bounded'),'bounded actual compiler C stack row')
                location,size,kind=parts;site=location.rsplit(':',3);need(len(site)==4 and site[1].isdigit()and site[2].isdigit(),'complete compiler C source location')
                need(str(pin(site[0]))in set().union(*(set(s['headers'])for s in r['component_build'].values())),'stack row comes from actual compiler closure')
                stack_rows.append(dict(file=path.name,variant=variant,function=site[3],bytes=int(size),kind=kind));stack_totals[variant]+=int(size)
        need(all({'li2_span_plan_page','li2_span_plan_validate','li2_span_map_pc'}<=set(x['function']for x in stack_rows if x['variant']==kind)for kind in('metadata','native')),'actual span reconstruction stack frames in both executables')
        need(2*max(stack_totals.values())+65536<=524288,'twice-all-C stack frames of either executable plus64KiB below actual altstack')
        r['c_stack']=dict(rows=stack_rows,per_executable=stack_totals,conservative_bytes=2*max(stack_totals.values())+65536,
            scope='C-only conservative sum; actual native guards cover complete execution, not a Rust stack model')
        objdump=pin(shutil.which('objdump',path=ENV['PATH']))
        _,version,err=run('span-objdump-version',[objdump,'--version'],profile='inspect',env=builder.environment);need(version and not err,'actual disassembler identity')
        raw=r['component_build']['native']['symbols']['raw'];start,end=raw['address'],raw['address']+raw['bytes'];exe=executables['native']
        _,assembly,err=run('span-raw-body',[objdump,'-d','-w','-M','att','--start-address='+str(start),'--stop-address='+str(end),exe],profile='inspect',env=builder.environment);need(not err,'actual fixture gateway disassembly')
        cursor=start;body=bytearray();instructions=[]
        for line in assembly.decode().splitlines():
            if not re.match(r'\s*[0-9a-f]+:',line):continue
            match=re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line);need(match is not None,'complete actual instruction row')
            pc=int(match[1],16);chunk=bytes.fromhex(match[2]);need(pc==cursor and chunk and pc+len(chunk)<=end,'contiguous whole fixture gateway')
            cursor+=len(chunk);body+=chunk;instructions.append(chunk)
        data,_,segments=elf(exe);loads=[s for s in segments if s[0]==1 and s[1]==5 and s[3]<=start<end<=s[3]+s[5]]
        need(len(loads)==1 and cursor==end and instructions and instructions[-1]==b'\xc3'and sum(x==b'\x0f\x05'for x in instructions)==1,'whole single-syscall returning fixture gateway')
        segment=loads[0];offset=segment[2]+start-segment[3];need(body==data[offset:offset+len(body)],'every disassembled byte equals retained ELF')
        r['component_build']['native']['raw_gateway']=dict(address=start,bytes=len(body),instructions=len(instructions),sha256=hashlib.sha256(body).hexdigest())
        for c in r['cases']:
            native=c['kind']=='native';label='span-'+str(c['mode'])if native else'span-metadata';c['status']='failed'
            try:
                try:row,out,err=run(label,[executables[c['kind']],*([str(c['mode'])]if native else[])],c['expected_exit'],profile='native'if native else'span_metadata',env=dict(ENV,GLIBC_TUNABLES='glibc.pthread.rseq=0'))
                finally:
                    if r['commands'][-1]['name']==label:
                        actual=r['commands'][-1];c.update(exit=actual.get('exit'),duration_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int)
                if native:
                    capture=row['captures']['record'];path=binary(private/capture['file']);need(fact(path)=={k:capture[k]for k in('bytes','sha256')},'whole actual612096-byte record binding')
                    record=path.read_bytes();c['record']=fact(path);c['result']=reader.check(record,out,err,row['exit'],c['mode'])
                    c['reader_controls']=reader.controls(record,out,err,row['exit'],c['mode'])
                    need(len(c['reader_controls'])==52+3*int(c['mode']in(8,9)),'all fixed per-mode actual-reader refusals')
                    c['status']='qualified_required_read_failure'if c['mode']in(8,9)else'qualified_component'
                else:c['result']=reader.metadata(out,err,row['exit']);c['status']='qualified_metadata'
            except Exception as exc:
                c['error_type']=type(exc).__name__;c['error']=type(exc).__name__+': '+str(exc)
                if r['error']is None:r['error']=c['error']
                last=r['commands'][-1]if r['commands']else{}
                if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[] and isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
        need([c['status']for c in r['cases']]==['qualified_metadata']+['qualified_required_read_failure'if m in(8,9)else'qualified_component'for m in CASES],
            'complete fixed59 actual subjects including both required faults')
        need(sum(len(c.get('reader_controls',[]))for c in r['cases'])==3022,'all3022 actual supplied-record refusals')
    except BaseException as exc:
        if r['error']is None:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors']+=builder.finish()
        except BaseException as exc:r['final_errors'].append('build finalization: '+repr(exc))
        for row in r['commands']:
            for cap in row.get('captures',{}).values():
                try:p=private/cap['file'];need(p.parent==private and fact(p)=={k:cap[k]for k in('bytes','sha256')},'complete retained capture');binary(p)
                except BaseException as exc:r['final_errors'].append('capture: '+repr(exc))
        r['inputs_before'],r['artifacts_before'],r['aliases_before']=dict(pins),dict(artifacts),dict(aliases)
        r['inputs_after'],r['artifacts_after'],r['aliases_after']={},{},{}
        for name,rows,observe in(('inputs',pins,fact),('artifacts',artifacts,artifact),('aliases',aliases,lambda p:str(Path(p).resolve(strict=True)))):
            for p,want in rows.items():
                try:r[name+'_after'][p]=observe(p);need(r[name+'_after'][p]==want,'same final '+name)
                except BaseException as exc:r['final_errors'].append(name+': '+repr(exc))
        try:r['source_after']=source();r['source_unchanged']=r['source_after']==r['source'];need(r['source_unchanged'],'same final committed source')
        except BaseException as exc:r['final_errors'].append('source: '+repr(exc))
        r['cleanup_complete']=all(x.get('reaped')is True and not x.get('timed_out')and not x.get('error')and x.get('cleanup_errors')==[] and all(d.get('closed')is True for d in x.get('descriptors',[]))for x in r['commands'])
        r['totals']=dict(planned=59,launched=sum(c.get('launched',False)for c in r['cases']),qualified=sum(c['status'].startswith('qualified_')for c in r['cases']),metadata=sum(c['status']=='qualified_metadata'for c in r['cases']),hardware=sum(c['status']in('qualified_component','qualified_required_read_failure')for c in r['cases']),completed_paths=sum(c['status']=='qualified_component'for c in r['cases']),required_read_failures=sum(c['status']=='qualified_required_read_failure'for c in r['cases']),reader_refusals=sum(len(c.get('reader_controls',[]))for c in r['cases']))
        wanted=dict(planned=59,launched=59,qualified=59,metadata=1,hardware=58,completed_paths=56,required_read_failures=2,reader_refusals=3022)
        closed=all(r[n+'_before']==r[n+'_after']for n in('inputs','artifacts','aliases'))
        r['status']='passed_component'if not r['error']and not r['final_errors']and closed and r['source_unchanged']and r['cleanup_complete']and r['build']['status']=='passed'and set(r['component_build'])=={'metadata','native'}and all(s['status']=='passed'for s in r['component_build'].values())and r['totals']==wanted else'failed'
        save(private/'receipt.json',r)
        hw=dict(r.get('hardware')or{});flags=hw.pop('isa_flags',[]);hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        pub={k:r.get(k)for k in('schema','profile','status','source','source_unchanged','expected_revision','cpu','started_utc','bounds','reproduce','cleanup_complete','totals')}
        pub.update(hardware=hw,private_receipt=fact(private/'receipt.json'),command_count=len(r['commands']),commands_sha256=digest(r['commands']),inputs_sha256=digest(pins),artifacts_sha256=digest(artifacts),failure_type=(r['error']or'').split(':')[0]or None,final_error_count=len(r['final_errors']),whole_application_credit=False,performance_credit=False,metadata=r['cases'][0].get('result'),
            scope='Fixed metadata1 plus58 original/generated full-state comparisons;56 complete paths and2 required real read faults. All GPR/flags/AF/FP/masks/TLS/stack/data and exact fault-PC joins remain mandatory.3022 supplied mutations grant no native credit. No production TRACE/source/rseq/certificate owner or performance qualification; old tests remain separate.')
        csv_stream=io.StringIO(newline='');writer=csv.writer(csv_stream,lineterminator='\n');writer.writerow(['kind','mode','status','expected_exit','exit','duration_ns','record_bytes','reader_controls'])
        for c in r['cases']:writer.writerow([c[k]for k in('kind','mode','status','expected_exit','exit')]+[c.get('duration_ns',''),c.get('record',{}).get('bytes',''),len(c.get('reader_controls',[]))])
        csv_bytes=csv_stream.getvalue().encode();need(len(csv_bytes)<=8192,'compact complete59-row CSV')
        pub['csv']=dict(file=public_csv.name,bytes=len(csv_bytes),sha256=hashlib.sha256(csv_bytes).hexdigest())
        encoded=json.dumps(pub,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n';need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and (x in encoded or x in csv_stream.getvalue())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact path-free numerical result');public.parent.mkdir(exist_ok=True)
        with public_csv.open('xb')as stream:stream.write(csv_bytes)
        with public.open('x')as stream:stream.write(encoded)
    print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)))));return 0 if r['status']=='passed_component'else 1
if __name__=='__main__':raise SystemExit(main())
