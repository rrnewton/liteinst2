#!/usr/bin/env python3
"""Eight fixed decoder processes: descriptors, real bounds and sealed allocator."""
import argparse,csv,hashlib,importlib.util,io,json,os,platform,re,shlex,shutil,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
from checks import source
from run import hardware
from page_selected import ENV,fact,need,save,elf
from page_selected_generic_build import Build,PROFILES as BUILD_PROFILES,package_check
from page_selected_process import invoke
from page_selected_register_time_build import headers
from page_selected_components import plain_executable

ROOT=Path(__file__).resolve().parents[2]
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/region_decoder'
PROFILES=dict(BUILD_PROFILES,decoder=[3,256<<20,1<<20,10])
SOURCES=('lib.rs','abi.rs','arena.rs','decode.rs','scan.rs','tf.rs','write_footprint.rs','admission_oneshot.rs','region.rs')
EXTRA_SOURCES=('region.rs',)
CONTROL_COUNTS=(12,4,4,14,22,22,22,4)
# Exact reviewed compiler inputs; source() additionally binds every tracked leaf.
LEAVES={'tools/page-entry/selected/decoder/Cargo.lock': {'bytes': 799, 'sha256': '1006555168c3320ddeed45455bf5171086bf3683b78633f839df63819ff8e41e'}, 'tools/page-entry/selected/decoder/Cargo.toml': {'bytes': 528, 'sha256': 'c3a3c369be61f2d88d4c653e4689714827a072431575c94635abf0e9b1ce0122'}, 'tools/page-entry/selected/decoder/src/arena.rs': {'bytes': 5490, 'sha256': '7306a0e12a5cb26fb7a19ea271f828bc2561ab4d03e5bcc9e0273a61eb22bd6b'}, 'tools/page-entry/selected/decoder/src/lib.rs': {'bytes': 9672, 'sha256': '10db769a9e017f96defcacd2df4ac18e8e5adf396f9dd76470abdfd0e31b1ce6'}, 'tools/page-entry/selected/decoder/src/region.rs': {'bytes': 51594, 'sha256': '2c3b9712afb01e82ac797000a397f790565a412f6a6590cab8672dd0b3334e3a'}, 'tools/page-entry/selected/region_decode.h': {'bytes': 7150, 'sha256': 'd9ccb59abd39bff378ecb30460e6d5c45142c2f77636b2c25068db9446a6e529'}, 'tools/page-entry/selected/tests/decoder/control_driver.c': {'bytes': 1688, 'sha256': 'bca53d2042eb69cd8994144b2a6d56184bebc12a447b3028f584c470ddca4444'}, 'tools/page-entry/selected/tests/decoder/controls.c': {'bytes': 6257, 'sha256': 'da76355e1a95aab7681d92306a229de56bee5da392c356a819ea0a2dd3f78f79'}, 'tools/page-entry/selected/tests/decoder/freestanding/entry.S': {'bytes': 246, 'sha256': 'c6ba11ec490bfd538e92a310093299fdd858b44c92eddaaa9238eab10954594e'}, 'tools/page-entry/selected/tests/decoder/freestanding/harness.c': {'bytes': 4267, 'sha256': '764a9b8ea44a2074c8ab149a04ef084eb36c3697669b7bf84c35bcac5870570b'}, 'tools/page-entry/selected/tests/decoder/support.c': {'bytes': 1689, 'sha256': '378440c08081156af2807a31809bec956001309b428e0cc29473f0ed2e57b4d2'}, 'tools/page-entry/selected/tests/region_decoder/README.md': {'bytes': 4201, 'sha256': '91fc12f6911a8ccb0d36a3e78c6397d31f2fa1367616d8b8a1578b96772d5eed'}, 'tools/page-entry/selected/tests/region_decoder/check.py': {'bytes': 4157, 'sha256': 'fe087905bd39f7fcb443fc542ad64251893b6740d838aa5bc776dae9bbd21e6f'}, 'tools/page-entry/selected/tests/region_decoder/oracle.c': {'bytes': 18147, 'sha256': 'f35e9087d23f6b709b56ff9911935094d36e034bd414c4a06f2ee259e006ed8f'}, 'tools/page-entry/selected/tests/region_decoder/test_exports.rs': {'bytes': 981, 'sha256': '776aca3081a767bb94d0f85e70526f03b4a210f6b596a9006ab31177321ecb13'}}

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True);args=ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'assertions, exact revision, one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT);stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-region-decoder-'+args.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=ROOT/'evaluation/inprocess/results'/(stem+'.json');public_csv=public.with_suffix('.csv')
    labels=('original112','original-fatal102','original-fatal106','original-freestanding','descriptor-matrix','guarded-source','test-busy','test-alloc101')
    r=dict(schema=1,profile='region-decoder-v1',status='failed',source=None,source_unchanged=False,expected_revision=args.expect_revision,cpu=cpu,started_utc=stamp,bounds=PROFILES,
        reproduce=['python3','evaluation/inprocess/region_decoder_qualification.py','--expect-revision',args.expect_revision],commands=[],
        cases=[dict(row=i,label=label,status='not_run',expected_exit=125 if i in(1,2,7)else 0,artifact_scope='test_exports'if i>=6 else'production',exit=None)for i,label in enumerate(labels)],error=None,final_errors=[])
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
    def run(label,argv,expected=0,profile='decoder',env=None):
        need(not any(x['name']==label for x in r['commands']),'unique command label');closure()
        row=dict(name=label,argv=list(map(str,argv)),bounds=PROFILES[profile],profile=profile,expected_exit=expected,capture_limit=1<<20 if profile=='decoder'else 4<<20,environment=dict(ENV if env is None else env));r['commands'].append(row)
        out,err=invoke(row,private,cpu)
        need(type(row['exit'])is int and row['exit']==expected,'exact actual exit '+label);return row,out,err
    builder=Build(r,private,pin,binary,run,extra_decoder_sources=EXTRA_SOURCES)
    output=private/'fixtures'

    def retain(path,destination):
        before=fact(path)
        with Path(path).open('rb')as src,Path(destination).open('xb')as dst:shutil.copyfileobj(src,dst)
        Path(destination).chmod(Path(path).stat().st_mode&0o777)
        need(fact(path)==fact(destination)==before,'whole retained copy');return binary(destination)

    def inspect(label,path,static=False,test=False):
        path=binary(path);data,head,segments=elf(path)
        need(head[1]in(2,3)and all(s[2]+s[5]<=len(data)and s[5]<=s[6]for s in segments if s[0]==1)and all(s[1]&3!=3 for s in segments if s[0]==1),'complete W^X ELF loads')
        result=dict(artifact=fact(path),scope='test_exports'if test else'production')
        if static:
            result['elf']=plain_executable(path)
            _,out,err=run(label+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment);need(out==err==b'','freestanding no imports')
        else:
            interp=[s for s in segments if s[0]==3];need(len(interp)==1,'one real interpreter')
            p=interp[0];name=data[p[2]:p[2]+p[5]];need(name.startswith(b'/')and name.endswith(b'\0')and b'\0'not in name[:-1],'exact interpreter string');loader=pin(os.fsdecode(name[:-1]))
            _,out,err=run(label+'-libraries',[loader,'--list',path],profile='inspect',env=builder.environment);need(not err,'actual loader list stderr')
            libraries={}
            for line in out.decode().splitlines():
                if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
                match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line);need(match is not None,'actual resolved dependency')
                dependency=pin(match[1]);need(dependency.name not in libraries,'unique dependency basename');libraries[dependency.name]=dict(path=str(dependency),**fact(dependency))
            need(libraries and any(x['path']==str(loader)for x in libraries.values()),'interpreter in dependency closure');result['libraries']=libraries
        _,_,err=run(label+'-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',path],profile='inspect',env=builder.environment);need(not err,'actual ELF stderr')
        return result

    def link(label,sources,archive,extra=(),static=False,test=False):
        path=output/label
        flags=['-std=c11','-O2','-Wall','-Wextra','-Werror','-fno-builtin','-fno-tree-loop-distribute-patterns','-mgeneral-regs-only']
        if static:flags+=['-ffreestanding','-fno-stack-protector','-fno-pie','-no-pie','-ffunction-sections','-fdata-sections','-nostdlib']
        argv=[str(builder.tools['cc']),*flags,*extra,*map(str,sources),str(archive),'-Wl,--gc-sections'+(',--no-undefined,-e,_start'if static else''),'-o',str(path)]
        state=dict(argv=argv,status='failed',archive=fact(archive));r.setdefault('fixture_builds',{})[label]=state
        headers(label+'-headers',argv,list(map(str,sources)),archive,builder,pin,aliases,run,state)
        need(str(SELECTED/'decoder.h')in state['headers'],'actual original decoder include')
        if label.startswith('region-'):need(str(SELECTED/'region_decode.h')in state['headers'],'actual304-byte ABI include')
        run(label+'-link',argv,profile='build',env=builder.environment)
        state.update(status='passed',inspection=inspect(label,path,static,test));return path

    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact committed source');r['hardware']=hardware(cpu)
        git=pin(shutil.which('git',path=ENV['PATH']));_,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z'],profile='metadata');need(not err,'source list stderr')
        tracked={os.fsdecode(p)for p in out.split(b'\0')if p}
        need(set(LEAVES)|{'evaluation/inprocess/region_decoder_qualification.py'}<=tracked,'all fixture/reader/evaluator leaves committed')
        for path in sorted(tracked):
            if not path.startswith('evaluation/inprocess/results/'):pin(ROOT/path)
        for path,expected in LEAVES.items():need(fact(pin(ROOT/path))==expected,'exact reviewed decoder input '+path)
        need(EXTRA_SOURCES==('region.rs',)and builder.extra_decoder_sources==EXTRA_SOURCES and builder.decoder_features==('scalar-region',),'exact one new decoder source and feature')
        spec=importlib.util.spec_from_file_location('region_decoder_check',pin(FIXTURE/'check.py'));reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
        products=builder.prepare();archive=products['archive'];output.mkdir()
        _,out,err=run('region-production-exports',[builder.tools['nm'],'-g','--defined-only',archive],profile='inspect',env=builder.environment);need(not err,'production archive symbols')
        rows=[line.split()for line in out.splitlines()]
        need(sum(x[-2:]==[b'T',b'li2_decoder_region_describe']for x in rows)==1 and not any(x and x[-1].startswith(b'li2_region_test_')for x in rows),'one real region export and no test hooks in production archive')
        old=SELECTED/'tests/decoder'
        controls=link('original-controls',[old/'control_driver.c',old/'support.c'],archive)
        free=link('original-free',[old/'freestanding/entry.S',old/'freestanding/harness.c',old/'support.c'],archive,static=True)
        matrix=link('region-production',[FIXTURE/'oracle.c',old/'support.c'],archive)

        # Separate copied crate: all ordinary compiler bytes and Cargo.lock are
        # identical; only the final two real-control exports are appended.
        # The retained production archive/dep-info is already closed above.
        testcrate=private/'test-decoder';(testcrate/'src').mkdir(parents=True)
        test_state=r['test_artifact']=dict(status='failed',source_copies={},production_archive=fact(archive))
        extra=pin(FIXTURE/'test_exports.rs').read_bytes()
        for name in ('Cargo.toml','Cargo.lock'):
            original=pin(SELECTED/'decoder'/name);retained=retain(original,testcrate/name);test_state['source_copies'][name]=fact(retained)
        for name in SOURCES:
            original=pin(SELECTED/'decoder/src'/name);data=original.read_bytes();generated=data+(extra if name=='lib.rs'else b'')
            dest=testcrate/'src'/name
            with dest.open('xb')as stream:stream.write(generated)
            binary(dest);need(dest.read_bytes()==generated and fact(original)==pins[str(original)],'exact test source derivation')
            test_state['source_copies']['src/'+name]=dict(original=fact(original),generated=fact(dest))
        need((testcrate/'src/lib.rs').read_bytes()[:-len(extra)]==(SELECTED/'decoder/src/lib.rs').read_bytes(),'whole production lib restored by one appended-tail inverse')
        test_state['registry_before']=[package_check(p)for p in builder.packages]
        need(test_state['registry_before']==r['build']['registry_before'],'same locked registry before test artifact')
        # A copied crate is a distinct retained compiler-input identity. Keep
        # Cargo from reusing an archive whose dep-info names an earlier copy.
        test_state['rustc_metadata']='li2_region_decoder_control_exports_v1_'+digest(
            dict(crate=str(testcrate),sources=test_state['source_copies']))
        run('test-decoder-build',[builder.tools['cargo'],'rustc','--manifest-path',testcrate/'Cargo.toml','--release','--locked','--offline','--features','scalar-region','-j','1','--','-C','metadata='+test_state['rustc_metadata']],profile='build',env=builder.environment)
        generated_archive=ROOT/'target/release/libli2_page_selected_decoder.a';generated_dep=generated_archive.with_suffix('.d')
        test_archive=retain(generated_archive,output/'test-decoder.a');test_dep=retain(generated_dep,output/'test-decoder.d')
        dep=test_dep.read_text().strip();target=str(generated_archive)+': '
        need(dep.startswith(target)and '\n'not in dep,'test archive dep-info target')
        dependencies=shlex.split(dep[len(target):]);expected={str(testcrate/'src'/n)for n in SOURCES}
        need(set(dependencies)==expected and len(dependencies)==len(expected),'exact nine copied decoder sources')
        test_state['registry_after']=[package_check(p)for p in builder.packages]
        need(test_state['registry_after']==test_state['registry_before'],'whole test registry closure')
        _,out,err=run('region-test-exports',[builder.tools['nm'],'-g','--defined-only',test_archive],profile='inspect',env=builder.environment);need(not err,'test archive symbols')
        rows=[line.split()for line in out.splitlines()]
        for name in ('li2_decoder_region_describe','li2_region_test_busy','li2_region_test_allocate'):
            need(sum(x[-2:]==[b'T',name.encode()]for x in rows)==1,'one actual test/real API text definition')
        need(sorted(x[-1].decode()for x in rows if x and x[-1].startswith(b'li2_region_test_'))==['li2_region_test_allocate','li2_region_test_busy'],'exact two control-only exports')
        test_state.update(status='passed',archive=fact(test_archive),dep_info=fact(test_dep),appended_exports=fact(FIXTURE/'test_exports.rs'))
        test=link('region-test',[FIXTURE/'oracle.c',old/'support.c'],test_archive,extra=['-DLI2_REGION_TEST_EXPORTS=1'],test=True)
        commands=([controls],[controls,'tiny_arena'],[controls,'personality'],[free],[matrix,'0'],[matrix,'1'],[test,'2'],[test,'3'])
        for c,argv in zip(r['cases'],commands):
            label='case-'+c['label'];c['status']='failed'
            try:
                try:row,out,err=run(label,argv,c['expected_exit'],env=builder.environment)
                finally:
                    if r['commands'][-1]['name']==label:
                        actual=r['commands'][-1];c.update(exit=actual.get('exit'),duration_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int)
                c['result']=reader.check(out,err,row['exit'],c['row']);c['reader_controls']=reader.controls(out,err,row['exit'],c['row'])
                need(len(c['reader_controls'])==CONTROL_COUNTS[c['row']],'exact case corruption count')
                c['status']='qualified_required_failure'if c['expected_exit']else'qualified'
            except Exception as exc:
                c['status']='failed';c['error_type']=type(exc).__name__;c['error']=type(exc).__name__+': '+str(exc)
                if r['error']is None:r['error']=c['error']
                last=r['commands'][-1]if r['commands']else{}
                if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[] and isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
        need(len(r['cases'])==8 and all(c['status']==('qualified_required_failure'if c['expected_exit']else'qualified')for c in r['cases'])and not r['error'],'all eight fixed cases passed exact outcomes')
        need(sum(len(c['reader_controls'])for c in r['cases'])==104,'all supplied reader refusals')
        r['status']='passed_decoder'
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
        r['inputs_after'],r['artifacts_after'],r['aliases_after']={},{},{}
        for p in pins:
            try:r['inputs_after'][p]=fact(p)
            except BaseException as exc:r['final_errors'].append('input: '+repr(exc))
        for p in artifacts:
            try:r['artifacts_after'][p]=artifact(p)
            except BaseException as exc:r['final_errors'].append('artifact: '+repr(exc))
        for p in aliases:
            try:r['aliases_after'][p]=str(Path(p).resolve(strict=True))
            except BaseException as exc:r['final_errors'].append('alias: '+repr(exc))
        try:
            r['source_unchanged']=source()==r['source'];need(r['source_unchanged'],'source after')
            need(r['inputs_after']==pins and r['artifacts_after']==artifacts and r['aliases_after']==aliases,'exact final source/artifact/alias dictionaries')
        except BaseException as exc:r['final_errors'].append('closure: '+repr(exc))
        r['cleanup_complete']=all(x.get('reaped')and not x.get('timed_out')and not x.get('error')and not x.get('cleanup_errors')and all(d['closed']for d in x.get('descriptors',[]))for x in r['commands'])
        if r['error']or r['final_errors']or not r['cleanup_complete']or r['build']['status']!='passed' or r.get('test_artifact',{}).get('status')!='passed':r['status']='failed'
        r['totals']=dict(required_processes=8,launch_attempts=sum(x['profile']=='decoder'for x in r['commands']),launched=sum(c.get('launched',False)for c in r['cases']),qualified=sum(c['status'].startswith('qualified')for c in r['cases']),reader_refusals=sum(len(c.get('reader_controls',[]))for c in r['cases']))
        save(private/'receipt.json',r)
        hw=dict(r.get('hardware')or{});flags=hw.pop('isa_flags',[]);hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        pub={k:r.get(k)for k in('schema','profile','status','source','source_unchanged','expected_revision','cpu','started_utc','bounds','reproduce','cleanup_complete','totals')}
        pub['cases']=[{**{k:v for k,v in c.items()if k not in('error','reader_controls')},'reader_control_count':len(c.get('reader_controls',[])),'reader_controls_sha256':digest(c.get('reader_controls',[]))}for c in r['cases']]
        pub.update(hardware=hw,private_receipt=fact(private/'receipt.json'),command_count=len(r['commands']),commands_sha256=digest(r['commands']),inputs_sha256=digest(pins),artifacts_sha256=digest(artifacts),failure_type=(r['error']or'').split(':')[0]or None,final_error_count=len(r['final_errors']),production_archive=r.get('test_artifact',{}).get('production_archive'),test_archive=r.get('test_artifact',{}).get('archive'),
            scope='Actual decoder ABI and allocator only. No supplied instruction bytes execute. Original112/fatal102/106/freestanding remain required. Two marked test-artifact rows use actual guards through appended exports; they do not qualify production exports. Generated execution/full architecture state, source ownership and performance remain separate.',performance_credit=False,runtime_owner_credit=False)
        columns=['row','label','artifact_scope','status','expected_exit','exit','duration_ns','reader_control_count']
        stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(columns)
        for c in pub['cases']:writer.writerow([c.get(k,'')for k in columns])
        csv_bytes=stream.getvalue().encode();need(len(csv_bytes)<=4096,'eight compact numeric rows')
        pub['csv']=dict(file=public_csv.name,bytes=len(csv_bytes),sha256=hashlib.sha256(csv_bytes).hexdigest())
        encoded=json.dumps(pub,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n';need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and(x in encoded or x in stream.getvalue())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'bounded private-path-free projection')
        public.parent.mkdir(exist_ok=True)
        with public_csv.open('xb')as output_stream:output_stream.write(csv_bytes)
        with public.open('x')as output_stream:output_stream.write(encoded)
    print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)))));return 0 if r['status']=='passed_decoder'else 1
if __name__=='__main__':raise SystemExit(main())
