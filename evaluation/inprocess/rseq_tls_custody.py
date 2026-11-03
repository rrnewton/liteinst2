#!/usr/bin/env python3
"""Fixed actual-TU TLS/custody component; supplied boundaries, no native credit."""
import argparse,csv,hashlib,importlib.util,io,json,os,re,stat,sys
from pathlib import Path

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'evaluation/inprocess'),str(ROOT/'tools/page-entry')]
from checks import source
from page_selected import ENV,fact,need,save,elf,interpreter
from page_selected_process import invoke
from page_selected_register_time_build import recipe,expand
from page_selected_register_real import resolved_libraries
from resident_three.build import compile
from loop_ro_current_archive import current_archive
from run import hardware

LEAVES=('maps_phase.inc','maps_view.inc','rseq_guard.c','rseq_guard.h',
        'tests/rseq_tls_custody/build.sh','tests/rseq_tls_custody/check.py',
        'tests/rseq_tls_custody/oracle.c','tests/rseq_tls_custody/prepare.py')
PROFILES=('projected','verified','fresh')
BOUNDS={'finite':[5,512<<20,16<<20,15],
        'metadata':[30,512<<20,16<<20,60],'release_build':[30,512<<20,16<<20,60]}
COMMON=('MAPS_PHASE_REUSE','TF_HANDOFF','TF_SAME_PAGE_LEASE','TF_SEALED_CUSTODY','RSEQ_INACTIVE')
PROGRAM_ENV=dict(ENV,LD_BIND_NOW='1')
SCHEDULE=(('source-roster','finite',0),)+tuple(row for profile in PROFILES for row in (
    (profile+'-prepare','finite',0),(profile+'-headers','metadata',0),
    (profile+'-link','release_build',0),(profile+'-libraries','finite',0),
    *((profile+'-'+str(mode),'finite',0 if mode<2 else 125)for mode in range(10))))


def publish(private,r,args):
    """Small projection of actual rows; omitted subjects remain unobserved."""
    h=lambda value:hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    cases={(c['profile'],c['mode']):c for c in r['cases']}
    need(len(cases)==len(r['cases']),'one actual observation per planned subject')
    commands={c['name']:c for c in r['commands']}
    fields=('profile','mode','expected_exit','status','exit','duration_ns','timed_out','reaped',
            'predicate_refusals','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256')
    stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(fields)
    for profile in PROFILES:
        for mode in range(10):
            case=cases.get((profile,mode),{});row=commands.get(profile+'-'+str(mode),{})
            captures=row.get('captures',{})
            writer.writerow([profile,mode,0 if mode<2 else 125,case.get('status','unobserved'),
                row.get('exit'),row.get('duration_ns'),row.get('timed_out'),row.get('reaped'),
                case.get('result',{}).get('predicate_refusals')]+[
                    captures.get(s,{}).get(k)for s in('stdout','stderr')for k in('bytes','sha256')])
    data=stream.getvalue().encode();csv_path=private/'cases.csv'
    with csv_path.open('xb')as f:f.write(data)
    hw=dict(r['hardware']);hw['isa_flags_sha256']=h(hw.pop('isa_flags'))
    provider=r.get('archive_build',{})
    summary=dict(schema=1,profile=r['profile'],status=r['status'],revision=r['revision'],source=r['source'],
        source_context=r['source_context'],script=r['driver'],cpu=r['cpu'],hardware=hw,bounds=r['bounds'],
        receipt=fact(private/'receipt.json'),commands=len(r['commands']),command_rows_sha256=h(r['commands']),
        planned_subjects=30,observed_subjects=sum(c['status']=='observed'for c in r['cases']),
        required_success_subjects=6,required_refusal_subjects=24,
        actual_predicate_refusals=sum(c.get('result',{}).get('predicate_refusals',0)for c in r['cases']),
        installed_sources=r.get('installed_sources'),source_roster_files=len(r.get('source_roster',{})),
        source_roster_sha256=h(r.get('source_roster',{})),
        archive_provider={k:provider[k]for k in('receipt','revision','cpu','archive','build_prefix',
            'producer_status','producer_subjects','current_compiler_inputs_equal','archive_rebuilt_by_consumer')if k in provider},
        builds={p:dict(executable={k:v['builds'][p]['output'][k]for k in('bytes','sha256')},
            argv_sha256=h(v['builds'][p]['argv']),headers_sha256=h(v['builds'][p]['headers']))
            for p,v in r['builds'].items()if p in v.get('builds',{})and 'output'in v['builds'][p]},
        source_unchanged=r['source_unchanged'],inputs_unchanged=r['inputs_unchanged'],cleanup_complete=r['cleanup_complete'],
        error_type=(r['error']or'').split('(',1)[0]or None,final_error_count=len(r['final_errors']),
        errors_sha256=h(dict(error=r['error'],final_errors=r['final_errors'])),
        csv=dict(file=csv_path.name,**fact(csv_path)),qualification_credit=False,performance_credit=False,
        native_runtime_credit=False,scope=r['scope'],
        timing_scope='Validation child duration only; no matched performance, native qualification or speedup claim.',
        reproduce=['python3.12','-B','evaluation/inprocess/rseq_tls_custody.py','--expect-revision',args.expect_revision,
            '--cpu',str(args.cpu),'--current-build-receipt','$CURRENT_BUILD_RECEIPT',
            '--current-build-sha256',args.current_build_sha256,'--output',
            'target/evaluation/inprocess/rseq-tls-custody-NEW'])
    text=json.dumps(summary,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<12<<10 and len(data)<12<<10 and '/home/'not in text and str(ROOT)not in text,
         'compact public component metadata without host paths or raw logs')
    with(private/'summary.json').open('x')as f:f.write(text)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision',required=True);parser.add_argument('--cpu',type=int,required=True)
    parser.add_argument('--current-build-receipt',type=Path,required=True)
    parser.add_argument('--current-build-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    need(sys.version_info[:2]==(3,12)and not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and
         Path.cwd().resolve()==ROOT and sorted(os.sched_getaffinity(0))==[args.cpu],
         'exact Python/source/root and reserved singleton')
    private=args.output.resolve()
    need(private.parent==ROOT/'target/evaluation/inprocess'and not private.exists(),
         'fresh private output under the natural repository')
    private.mkdir(mode=0o700);receipt=private/'receipt.json'
    r=dict(schema=1,profile='rseq-tls-custody-component-v1',status='failed',revision=args.expect_revision,
        source=source(),cpu=args.cpu,hardware=hardware(args.cpu),driver=fact(__file__),
        argv=[sys.executable,'-B',str(Path(__file__).resolve()),'--expect-revision',args.expect_revision,'--cpu',str(args.cpu),
              '--current-build-receipt',str(args.current_build_receipt),'--current-build-sha256',args.current_build_sha256,
              '--output',str(private)],source_context='installed clean expected revision',
        bounds=BOUNDS,inputs={},input_modes={},aliases={},artifacts={},commands=[],builds={},cases=[],
        source_unchanged=False,inputs_unchanged=False,cleanup_complete=False,error=None,final_errors=[],
        qualification_credit=False,performance_credit=False,native_runtime_credit=False,
        scope='Actual lifecycle/maps/custody and whole rseq TU with real kernel calls; '
              'supplied step/session and exact bounded state-byte registry. Component only.')
    source_roster={};presence={}

    def pin(path):
        alias=Path(path).absolute();q=alias.resolve(strict=True);value=fact(q);mode=stat.S_IMODE(q.stat().st_mode)
        need(q.is_file()and(str(q)not in r['inputs']or r['inputs'][str(q)]==value),
             'whole stable actual input')
        need(str(q)not in r['input_modes']or r['input_modes'][str(q)]==mode,'stable input mode')
        need(str(alias)not in r['aliases']or r['aliases'][str(alias)]==str(q),'stable input alias')
        r['inputs'][str(q)]=value;r['input_modes'][str(q)]=mode;r['aliases'][str(alias)]=str(q);return q

    def binary(path):
        q=Path(path).resolve(strict=True);value=dict(fact(q),mode=stat.S_IMODE(q.stat().st_mode))
        need(q.is_file()and(str(q)not in r['artifacts']or r['artifacts'][str(q)]==value),'whole stable artifact')
        r['artifacts'][str(q)]=value;return q

    def modules():
        for module in tuple(sys.modules.values()):
            name=getattr(module,'__file__',None)
            if name and Path(name).resolve().is_relative_to(ROOT):pin(name)

    def closure():
        need(source()==r['source']and r['source']['revision']==args.expect_revision,'same clean real source')
        need(sorted(os.sched_getaffinity(0))==[args.cpu],'same reserved singleton')
        need(all(fact(p)==v and stat.S_IMODE(Path(p).stat().st_mode)==r['input_modes'][p]
                 for p,v in r['inputs'].items()),'every whole input and mode unchanged')
        need(all(str(Path(p).resolve(strict=True))==q for p,q in r['aliases'].items()),'all aliases unchanged')
        need(all(dict(fact(p),mode=stat.S_IMODE(Path(p).stat().st_mode))==v
                 for p,v in r['artifacts'].items()),'all actual artifacts unchanged')
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence')

    def run(name,argv,profile='metadata',env=None,expected=0):
        modules();closure();index=len(r['commands'])
        need(index<len(SCHEDULE)and(name,profile,expected)==SCHEDULE[index],'fixed complete command schedule')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=BOUNDS[profile],
            capture_limit=16<<20,environment=dict(ENV if env is None else env),expected_exit=expected)
        r['commands'].append(row);save(receipt,r)
        try:out,err=invoke(row,private,args.cpu)
        finally:
            for value in row.get('captures',{}).values():binary(private/value['file'])
            if(private/(name+'.json')).is_file():binary(private/(name+'.json'))
            save(receipt,r)
        need(row['exit']==expected and row['timed_out']is False and row['error']is None and
             row['reaped']is True and row['cleanup_errors']==[]and
             all(v['closed']is True for v in row['descriptors']),
             'literal actual outcome and complete process closure '+name)
        return row,out,err

    def load(name,path):
        path=pin(path);spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
        return module

    try:
        pin(__file__)
        retained,archive,proof=current_archive(args.current_build_receipt,args.current_build_sha256,ROOT,pin,binary,r['aliases'])
        r['archive_build']=proof;tools=retained.tools
        need(pin(sys.executable)==pin(tools['python'])and len(retained.record['dep_info'])==14,
             'actual Python and exact current14-source archive; no Rust rebuild')
        for name in('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload');r['configuration_presence']=presence
        _,out,err=run('source-roster',[tools['git'],'-C',ROOT,'ls-tree','-r','-z',args.expect_revision,'--',
            'tools/page-entry',str(Path(__file__).resolve().relative_to(ROOT))],profile='finite')
        need(not err,'whole Git source roster')
        names=set()
        for entry in out.split(b'\0'):
            if not entry:continue
            meta,name=entry.split(b'\t',1);mode,kind,blob=meta.decode().split();name=name.decode()
            need(kind=='blob'and mode in('100644','100755')and
                 (name.startswith('tools/page-entry/')or name==str(Path(__file__).resolve().relative_to(ROOT)))and
                 '..'not in Path(name).parts and name not in names,'unique regular source entry')
            original=pin(ROOT/name);data=original.read_bytes()
            need(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob and
                 original.stat().st_mode&511==int(mode,8)&511,'whole exact Git blob and mode')
            source_roster[name]=dict(fact(original),mode=int(mode,8)&511,git_blob=blob);names.add(name)
        selected=ROOT/'tools/page-entry/selected';leaf=selected/'tests/rseq_tls_custody'
        required={str(Path(__file__).resolve().relative_to(ROOT))}|{'tools/page-entry/selected/'+name for name in LEAVES}
        need(required<=names,'installed collector, four production changes and four complete fixture leaves are tracked')
        r['source_roster']=source_roster
        r['installed_sources']={name:source_roster['tools/page-entry/selected/'+name]for name in LEAVES}
        reader=load('tls_custody_component_reader',leaf/'check.py')
        namespace=load('tls_custody_namespace',selected.parent/'namespace.py')
        rows=recipe(pin(leaf/'build.sh'),'"$cc_bin"')
        need(len(rows)==1 and rows[0].count('$maps')==1,'one complete compiler recipe/closed profile position')
        for profile in PROFILES:
            output=private/profile;output.mkdir()
            _,out,err=run(profile+'-prepare',[tools['python'],'-B',pin(leaf/'prepare.py'),selected,output],profile='finite',env=retained.environment)
            need(out==err==b''and sorted(p.name for p in output.iterdir())==['loader.inc','rseq.c','source.json','support.inc'],
                 'exact complete generated actual-TU support')
            for q in output.iterdir():binary(q)
            extra=()if profile=='fresh'else('MAPS_MAINTAINED','MAPS_CURRENT_TF')+(
                ('MAPS_DIFFERENTIAL',)if profile=='verified'else())
            values={'$cc_bin':tools['cc'],'$selected_dir':selected,'$parent_dir':selected.parent,
                    '$fixture_dir':leaf,'$output_dir':output,'$archive':archive}
            argv=[]
            for word in rows[0]:
                argv.extend(['-DLI2_'+x+'=1'for x in extra]if word=='$maps'else expand([word],values))
            units=[str(leaf/'oracle.c'),str(output/'rseq.c'),str(selected/'step_owner.c')]
            need([v for v in argv if v.startswith('-D')]==['-DLI2_'+x+'=1'for x in COMMON+extra]and
                 [v for v in argv if v.endswith(('.c','.S'))]==units and argv.count(str(archive))==1 and
                 argv[-2:]==['-o',str(output/'rseq-tls-custody')], 'literal flags/three actual TUs/archive/output')
            state=r['builds'][profile]={}
            def compiler_run(name,argv,profile='metadata'):
                return run(name,argv,profile=profile,env=retained.environment)
            executable=compile(profile,argv,state,pin,binary,compiler_run,fact)
            headers=state['builds'][profile]['headers']
            required=['lifecycle_loader.c','rseq_guard.c','rseq_guard.h','maps_phase.inc','fetch_page_custody.inc']
            if profile!='fresh':required+=['maps_view.inc','fetch_current_custody.inc']
            need(all(str(selected/n)in headers for n in required if n!='lifecycle_loader.c')and
                 str(output/'loader.inc')in headers and str(output/'support.inc')in headers,
                 'actual complete maps/rseq/custody and generated-whole-loader dependency closure')
            data,head,segments=elf(executable)
            need(head[1]in(2,3)and any(p[0]==1 and p[1]==5 and p[3]<=head[4]<p[3]+p[6]for p in segments)and
                 all(not(p[1]&1 and p[1]&2)for p in segments if p[0]in(1,0x6474e551)),
                 'real executable entry and no writable executable load/stack')
            interp=pin(interpreter(executable));need(pin(namespace.parse(data)['interpreter'])==interp,'actual interpreter')
            objects,description=namespace.plan(executable,[Path('/usr/lib64')],
                hashlib.sha256(data).digest(),bytes.fromhex(fact(interp)['sha256']))
            libraries={interp:set()}
            for obj in objects:
                q=pin(obj['path']);need(fact(q)['sha256']==hashlib.sha256(obj['bytes']).hexdigest(),'whole runtime library')
                libraries.setdefault(q,set()).update(obj['names'])
            state['namespace_plan']=description
            _,out,err=run(profile+'-libraries',[interp,'--list',executable],profile='finite',env=PROGRAM_ENV)
            need(not err,'clean actual loader listing');resolved_libraries(out,libraries,interp,pin)
            for mode in range(10):
                name=profile+'-'+str(mode);case=dict(profile=profile,mode=mode,status='failed')
                r['cases'].append(case)
                try:
                    row,out,err=run(name,[executable,str(mode)],profile='finite',expected=0 if mode<2 else 125,env=PROGRAM_ENV)
                    case.update(exit=row['exit'],result=reader.check(out,err,row['exit'],profile,mode),status='observed')
                except Exception as exc:
                    case['error']=repr(exc)
                    if r['error']is None:r['error']=repr(exc)
                    last=r['commands'][-1]
                    need(last['name']==name and last['reaped']is True and last['cleanup_errors']==[]and
                         all(v['closed']is True for v in last['descriptors']),
                         'continue fixed remaining cases only after exact child cleanup')
                    case['exit']=last.get('exit')
        need(len(r['commands'])==len(SCHEDULE)==43 and len(r['cases'])==30 and
             all(c['status']=='observed'for c in r['cases'])and
             sum(c['result']['predicate_refusals']for c in r['cases'])==66,'all fixed commands/subjects/causal predicate controls')
        r['status']='passed_component_only'
    except BaseException as exc:
        if r['error']is None:r['error']=repr(exc)
    finally:
        try:modules();closure();r['source_unchanged']=r['inputs_unchanged']=True
        except BaseException as exc:r['final_errors'].append('closure: '+repr(exc))
        try:
            for row in r['commands']:
                need(row['reaped']is True and row['cleanup_errors']==[]and all(v['closed']is True for v in row['descriptors']),
                     'all actual children reaped and descriptors closed')
                need(json.loads((private/(row['name']+'.json')).read_bytes())==row,'whole saved actual row')
                for value in row['captures'].values():
                    q=private/value['file'];need(q.parent==private and fact(q)=={k:value[k]for k in('bytes','sha256')},'whole capture')
            r['cleanup_complete']=True
        except BaseException as exc:r['final_errors'].append('cleanup: '+repr(exc))
        if r['error']or r['final_errors']:r['status']='failed'
        save(receipt,r)
        publish(private,r,args)
    print(json.dumps(dict(status=r['status'],commands=len(r['commands']),cases=len(r['cases']),error=r['error'],
        final_errors=r['final_errors'],receipt=str(receipt))),flush=True)
    return int(r['status']!='passed_component_only')


if __name__=='__main__':raise SystemExit(main())
