#!/usr/bin/env python3
"""Build the original startup fixture and observe one bounded release counter run.

The native reference retains all 52 instruction PCs and 12 complete frames.
A killed release remains failed; only its independently valid post-reap cells
are reported. This counter experiment does not qualify protected owner state.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_generic_build import Build
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from page_selected_register_time_build import recipe, expand
from page_selected_oneshot_build import before_default
from persistent_dynamic import BOUNDS, H, digest, named, counts, imported_sources, seed_prerequisite
from persistent_epoch_build import FEATURES
from persistent_subentry_build import build_bridge
from startup_loop import extract
from startup_loop_build import inspect_application
from startup_loop_helpers import reader_support, preparation as native_preparation
from startup_counter_terminal import completed_terminal
from unrolled_hash_owner import prepare_inputs
import persistent_group_counter_process as counter_process
import namespace

ROOT = Path(__file__).resolve().parents[2]
SELECTED = ROOT/'tools/page-entry/selected'
FIXTURE = SELECTED/'tests/persistent_interpreter_loop_app'
LAUNCH = ROOT/'evaluation/inprocess/startup_counts/launch_counts.py'
PROFILES = dict(BOUNDS)
TARGET = [30, 512 << 20, 16 << 20, 60]
APP_COUNTS = {2: 32}
MISS_NAMES = ('NONE','ROOT_UNSUPPORTED','SOURCE_INVALID','SOURCE_TRUNCATED','SOURCE_OVERLAP','OUTSIDE_PAIR',
    'HEAD_LIMIT','EXIT_LIMIT','QUEUE_LIMIT','NO_EXIT','RIP_REACH','BRANCH_REACH','FALLTHROUGH_REACH',
    'GUARD_RIP_REACH','GUARD_FOLLOW_REACH','ROOT_SELECTED','SINGLE_MEMBER','LINK_LIMIT')


def preparation(row,directory,original,objects,description,carrier,binary,r):
    """Exact original mode2 launch plus the separately authenticated counter channel."""
    prep=json.loads(binary(directory/'preparation.json').read_bytes())
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']=='gated'and
         prep['pid']==row['pid']and prep['cpu']==[r['cpu']]and prep['reset_mask']==prep['launch_mask']==0 and
         prep['argv']==[str(original),'2','gated']and prep['default_rseq']is False and
         prep['mode']==2 and prep['control']==0 and prep['observer']is None and
         [x['signal']for x in prep['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and
         all(x['after']==0 for x in prep['dispositions']), 'actual exact mode2 signal/argv preparation')
    counter=row['counter_input']
    need(prep['counter']==dict(fd=counter['child_fd'],nonce=counter['nonce'],parent=counter['parent'],
         device=counter['device'],inode=counter['inode'],bytes=4096,logical_bytes=752,initial_seals=6),
         'actual same counter descriptor/header identity across fork and in-place exec')
    ns=directory/'namespace'
    observed=json.loads(binary(ns/'namespace.json').read_bytes())
    launch=json.loads(binary(ns/'launch.json').read_bytes())
    need(all(observed[k]==v for k,v in description.items())and len(observed['objects'])==len(objects)and
         observed['schema_version']==1 and observed['scope']=='explicit_sealed_dependency_namespace'and
         observed['status']=='prepared_not_executed'and observed['directory']==str(ns)and
         observed['search_policy']=='explicit roots; no RPATH/RUNPATH/cache emulation'and
         observed['identity_policy']=='sealed copies and private paths; not filesystem transparency',
         'whole actual namespace equals independently planned source namespace')
    fds=[]
    for obj,item in zip(observed['objects'],objects,strict=True):
        need(obj['names']==item['names']and obj['needed']==item['info']['needed']and
             obj['source']==str(item['path'])and obj['descriptive_pt_interp']==
             (str(item['info']['interpreter'])if item['info']['interpreter']else None)and
             obj['sha256']==H(item['bytes'])and obj['size']==len(item['bytes'])and obj['seals']==namespace.SEALS and
             type(obj['fd'])is int and obj['fd']>2 and obj['fd']not in fds and obj['fd']!=counter['child_fd']and
             type(obj['device'])is int and obj['device']>0 and type(obj['inode'])is int and obj['inode']>0,
             'actual complete sealed dependency identity and separate counter descriptor')
        fds.append(obj['fd'])
        for name in item['names']:
            p=ns/name;value='/proc/self/fd/'+str(obj['fd'])
            need(p.is_symlink()and os.readlink(p)==value,'actual sealed namespace alias')
            r['namespace_aliases'][str(p)]=value
    environment=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',
        LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)),GLIBC_TUNABLES='glibc.pthread.rseq=0',
        LI2_PERSISTENT_INTERPRETER_LOOP_APP_MODE='2',LI2_GROUP_COUNTER_FD=str(counter['child_fd']),
        LI2_GROUP_COUNTER_NONCE=str(counter['nonce']))
    need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',
         argv=prep['argv'],dependency_fds=fds,carrier_sha256=fact(carrier)['sha256'],
         carrier_size=fact(carrier)['bytes'],environment=environment)and prep['late_sonames']==[]and
         prep['environment_source']==str(ns/'launch.json'), 'exact original startup environment plus counter FD/nonce')


def protocol(builder,run,r):
    python=builder.tools['python']
    # The same finite protocol oracle proves split updates remain raw per-cell values.
    _,protocol_out,protocol_err=run('counter-protocol',[python,'-B',ROOT/'evaluation/inprocess/persistent_group_counter_protocol.py'],profile='finite')
    refusals=['truncated','extended']+['header_'+str(i)for i in range(16)]+[
        'tail','wrong_seals','typed_pid','native_padding','nonce','parent','cloexec','read_only',
        'write_seal_with_writer','already_sealed','pwrite_sealed','new_shared_writer','read_only_writer',
        'grow','shrink','add_after_seal']
    prefix=dict(events=9,signals=[2,3,1,0,0],group=dict(zip(counter_process.GROUP_NAMES,(5,2,1,4,1,1,2,2,1,0),strict=True)),
        misses=[0,3]+[0]*16,maps={k:0 for k in counter_process.MAP_NAMES},view={k:0 for k in counter_process.VIEW_NAMES},
        native=dict(attempts=101,admissions=5,closed=4,blocked=89,low_address_refusals=7))
    expected=dict(scope='counter_protocol_only',guest_executions=0,parser_prefix=prefix,refusal_count=34,refusals=refusals)
    need(protocol_err==b''and len(refusals)==34 and protocol_out==(json.dumps(expected,sort_keys=True)+'\n').encode(),
         'whole unchanged split-prefix parser and actual memfd protocol oracle')
    r['counter_protocol']=expected


def cohort(builder,products,private,pin,binary,aliases,run,r,original):
    """Same complete native fixture, then one release subject with sealed counters."""
    reader,unused_owner,native_policy=reader_support(builder,private,pin,binary,run,r)
    image=reader.elf(original.read_bytes(),native_policy)
    r['application_layout']={k:v for k,v in image.items()if k not in ('source','sources')}
    need(digest(counts(reader.APP_CONTROL_COUNTS))==digest(counts(APP_COUNTS)),
         'same complete 32 native application reader refusals')
    seed_reference=seed_prerequisite(builder,private,pin,binary,run,r)
    protocol(builder,run,r)
    holder=r['counter_build']={}
    bridge=build_bridge(builder,products,private,pin,binary,aliases,run,holder,original,
        capture=False,retained_counters=True,differential=False)
    rb=holder['release_build']
    need(rb['status']=='passed'and rb['profile']=='persistent-subentry-counters-v1'and rb['capture']is False and
         rb['counters']is True and rb['retained_counters']is True and rb['active_domain']['unregistered']is True and
         rb['active_domain']['differential']is False and rb['active_domain']['subentry']is True and
         rb['persistent_binding']['mode']=='counters'and rb['persistent_binding']['subentry']is True and
         rb['counter_schema']==dict(version=2,bytes=752,page=4096,initial_seals=6,final_seals=23),
         'distinct exact release-only subentry counter profile and unchanged counter ABI')
    interp,roots,objects,description,images,raws,carrier=prepare_inputs(
        original,bridge,builder,private,pin,binary,run,holder)
    need(fact(interp)==r['application_build']['interpreter'],
         'actual startup interpreter is the exact whole ELF used to extract the fixture source pair')
    r.update(bridge=fact(bridge),archive=fact(products['archive']),original=fact(original),
        carrier=fact(carrier),policy_sha256=rb['persistent_binding']['policy_sha256'])
    imported_sources(pin)
    native=r['cases'][0];native['status']='failed'
    directory=private/native['label'];directory.mkdir()
    argv=[builder.tools['python'],'-B',pin(FIXTURE/'launch.py'),'--root',ROOT,'--role','native',
        '--mode','2','--control','0','--original',original,'--preparation',directory/'preparation.json']
    for path in roots:argv+=['--library-root',path]
    try:row,stdout,stderr=run(native['label'],argv,profile='program',expected=0)
    finally:
        if r['commands'][-1]['name']==native['label']:
            actual=r['commands'][-1]
            native.update(exit=actual.get('exit'),whole_process_ns=actual.get('duration_ns'),
                timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int)
            native['captures']={k:{j:v[j]for j in ('bytes','sha256')}for k,v in actual.get('captures',{}).items()}
    native_preparation(native,row,directory,original,roots,objects,description,carrier,private,binary,r)
    args=(stdout,2,True,row['exit'],image,row['pid'],r['cpu'],seed_reference)
    reference=reader.read(*args)
    need(stderr==b'','actual native reference stderr remains empty')
    native['application_controls']=reader.controls(*args)
    named(native['application_controls'],APP_COUNTS[2],H(stdout))
    native.update(status='observed_native_startup_loop',native_instructions=52,native_full_frames=12)
    enum=pin(SELECTED/'persistent_group_plan.h').read_text()
    block=re.search(r'enum li2_pg_reason\s*\{(.*?)\};',enum,re.S)
    need(block is not None and re.findall(r'LI2_PGD_([A-Z_]+)',block[1])==list(MISS_NAMES)+['REASON_COUNT'],
         'exact typed counter refusal index names')
    case=r['cases'][1];case['status']='failed'
    directory=private/case['label'];directory.mkdir()
    argv=[builder.tools['python'],'-B',pin(LAUNCH),'--root',ROOT,'--role','gated','--mode','2','--control','0',
        '--original',original,'--preparation',directory/'preparation.json','--library-root',roots[0],
        '--library-root',roots[1],'--carrier',carrier,'--namespace',directory/'namespace',
        '--counter-fd','{counter_fd}','--counter-nonce','{counter_nonce}']
    row=dict(name=case['label'],argv=list(map(str,argv)),environment=dict(ENV),profile='program',
        bounds=TARGET,capture_limit=16<<20,expected_exit=0)
    r['target']=row
    try:
        # The same owner creates/seals the descriptor, closes its writer, reaps
        # the target, and only then reads the genuine read-only backing.
        row,stdout,stderr=run(case['label'],argv,profile='program',expected=None,counter=True,row=row)
    finally:
        case.update(exit=row.get('exit'),whole_process_ns=row.get('duration_ns'),
            timed_out=row.get('timed_out'),launched=type(row.get('pid'))is int)
        case['captures']={k:{j:v[j]for j in ('bytes','sha256')}for k,v in row.get('captures',{}).items()}
        if row.get('reaped'):
            preparation(row,directory,original,objects,description,carrier,binary,r)
            r['namespace_complete']=True
    observed=row['counter_observation']
    need(observed['usable']is True,'actual authoritative post-reap counter prefix')
    counter=row['counter_input']
    path=binary(private/row['captures']['counters']['file'])
    need(fact(path)==observed['raw'],'whole actual retained final counter bytes')
    initial=(counter_process.MAGIC,2,752,4096,counter['nonce'],counter['parent'],counter['device'],counter['inode'])
    exact=counter_process.final_counter_prefix(path.read_bytes(),initial,row['pid'],observed['final_seals'])
    need(all(observed[k]==v for k,v in exact.items()),'whole unchanged parser rejoin to actual retained counter bytes')
    r['counts']=dict(exact,miss_reasons=dict(zip(MISS_NAMES,exact['misses'],strict=True)))
    r['counter_collection']='closed_usable_prefix'
    if row['exit']==0:
        need(row['reaped']is True and row['timed_out']is False and row['error']is None and
             row['cleanup_errors']==[],'actual completed target before application/terminal acceptance')
        parsed=reader.read(stdout,2,False,row['exit'],image,row['pid'],r['cpu'],seed_reference)
        # The same complete application model checks all final GPR/flags, source,
        # data, stack and FP bytes. A counter channel is not a protected record.
        need(parsed['source']==reference['source']and parsed['hardware']==reference['hardware']and
             parsed['xcr0']==reference['xcr0'],'same native/reference source and actual same-CPU machine geometry')
        r['terminal']=completed_terminal(stderr,exact)
        r['subentry_counts']={k:r['terminal']['subentry'][k]for k in ('selections','hits','entries','completed')}
        case.update(status='completed_unqualified',application_validated=True)
    else:
        case.update(status='failed',application_validated=False)
    need(row['exit']==0,'counted target failed; post-reap cells do not replace completion')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--interpreter',type=Path,default=Path('/usr/lib64/ld-linux-x86-64.so.2'))
    args=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1,'assertions and one reserved CPU')
    need(re.fullmatch('[0-9a-f]{40}',args.expect_revision),'exact committed revision')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)))
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name=stamp+'-startup-counter-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/name
    private.mkdir(parents=True,exist_ok=False)
    public=ROOT/'evaluation/inprocess/results'/(name+'.json')
    public.parent.mkdir(parents=True,exist_ok=True)
    need(not public.exists()and not public.with_suffix('.csv').exists(),'fresh public result identity')
    receipt=private/'receipt.json'
    r=dict(schema=1,profile='startup-subentry-final-counter-v1',status='failed',revision=args.expect_revision,
        source=None,source_unchanged=False,cleanup_complete=False,namespace_complete=False,
        commands=[],cases=[dict(label='subject-native-2-0',lane='native',mode=2,control=0,expected_exit=0,
            status='unexecuted',launched=False),dict(label='subject-counted-2-0',lane='counted',mode=2,control=0,
            expected_exit=0,status='unexecuted',launched=False)],error=None,final_errors=[],
        cpu=cpu,hardware=hardware(cpu),bounds=PROFILES,namespace_aliases={},
        counter_collection='unavailable',counts=None,terminal=None,subentry_counts=None,
        qualification_credit=False,performance_credit=False,
        scope='Fresh original 52-PC startup fixture and current decoder; counter diagnostic without protected-owner qualification.',
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,bounds=PROFILES['seed'],
            owner_subjects=0,completed_applications=0,performance_credit=False))
    pins,artifacts,aliases,presence={},{},{},{}

    def pin(path):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);value=fact(p)
        need(str(alias) not in aliases or aliases[str(alias)]==str(p),'stable input alias')
        need(str(p) not in pins or pins[str(p)]==value,'stable input bytes')
        pins[str(p)]=value;aliases[str(alias)]=str(p)
        return p

    def binary(path):
        p = Path(path).resolve(strict=True)
        value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable artifact')
        artifacts[str(p)] = value
        return p

    def closure():
        need(all(fact(p) == v for p, v in pins.items()), 'input bytes unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v
                 for p, v in artifacts.items()), 'artifact bytes and modes unchanged')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'input aliases unchanged')
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p)==v for p,v in r['namespace_aliases'].items()),'sealed namespace aliases unchanged')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False, counter=False, row=None):
        closure()
        need(not any(c['name'] == name for c in r['commands']), 'unique command/capture name')
        need(not counter or (not record and profile=='program'and list(PROFILES[profile])==TARGET),
             'only exact release program bounds with a separate counter owner')
        if row is None:
            row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
                       profile=profile, bounds=PROFILES[profile], capture_limit=16 << 20, expected_exit=expected)
        else:
            need(counter and row==dict(name=name,argv=list(map(str,argv)),environment=dict(ENV),
                 profile='program',bounds=TARGET,capture_limit=16<<20,expected_exit=0),
                 'one exact counted subject row before actual invocation')
        r['commands'].append(row)
        try:
            out, err = (counter_process.program_invoke if counter else program_invoke if name.startswith('subject-') else invoke)(row, private, cpu, record=record)
            need(expected is None or row['exit'] == expected, 'actual command exit: ' + name)
            return row, out, err
        finally:
            for item in row.get('captures', {}).values():
                try:
                    p = private / item['file']
                    need(fact(binary(p)) == {k: item[k] for k in ('bytes', 'sha256')}, 'actual capture bytes')
                except BaseException as error:
                    r['final_errors'].append('capture ' + name + ': ' + repr(error))
            try:
                p = private / (name + '.json')
                if p.exists():
                    need(json.loads(binary(p).read_bytes()) == row, 'retained actual command row')
            except BaseException as error:
                r['final_errors'].append('command record ' + name + ': ' + repr(error))

    def build_run(name, argv, profile='metadata', env=None, expected=0):
        before_default(name, argv, builder, pin, aliases, run, r)
        return run(name, argv, profile=profile, expected=expected, env=env)

    builder=Build(r,private,pin,binary,build_run,('region.rs',),
        scalar_span=True,linked_epoch=True,mov_guard=True)

    def compile_subject():
        fixture=SELECTED/'tests/persistent_interpreter_loop_app'
        output=private/'application';output.mkdir()
        script=pin(fixture/'extract.py');interpreter=pin(args.interpreter)
        # The source-owned assembly extractor and an independent complete ELF
        # extraction must agree before the actual compiler consumes any bytes.
        expected=private/'expected-pair.bin';extract(interpreter,expected);binary(expected)
        run('app-extract',[builder.tools['python'],'-I','-B',script,interpreter,output],env=builder.environment)
        pair=binary(output/'interpreter-pair.bin');pin(pair)
        need(pair.read_bytes()==expected.read_bytes(),'whole independently extracted interpreter pair')
        generated=pin(binary(output/'pair.S'))
        script=pin(fixture/'build.sh');linker=pin(fixture/'pure.ld')
        rows=recipe(script,'"$cc"');need(len(rows)==1,'one actual application recipe')
        argv=expand(rows[0],{'$cc':builder.tools['cc'],'$source_dir':fixture,'$output':output})
        units=[str(pin(fixture/n))for n in ('main.c','pure.c','machine.S')]+[str(generated)]
        need([x for x in argv if x.endswith(('.c','.S'))]==units and
             argv[-2:]==['-o',str(output/'persistent-interpreter-loop-app')] and
             '-Wl,-T,'+str(linker) in argv and '-DLI2_FAST_EQUAL=1' in argv and
             all(f in argv for f in ('-O2','-g','-Wall','-Wextra','-Werror','-mgeneral-regs-only',
                 '-mcmodel=large','-fno-pie','-no-pie','-fno-builtin','-fno-strict-aliasing')),
             'exact whole source and no-FP full-range release recipe')
        state=r['application_build']=dict(recipe=fact(script),argv=argv,pair=fact(pair),
            interpreter=fact(interpreter),linker=fact(linker),qualification_credit=False)
        flags=[x for x in argv[1:-2] if x not in units and not x.startswith('-Wl,')]
        _,out,err=run('app-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_app',*units],env=builder.environment)
        rules=out.decode().replace('\\\n',' ').splitlines()
        need(not err and len(rules)==4 and all(x.startswith('li2_app: ') for x in rules),
             'one complete include rule for each actual application translation unit')
        includes={}
        for rule in rules:
            for name in shlex.split(rule.split(':',1)[1]):
                path=Path(name).absolute();resolved=str(pin(path));aliases[str(path)]=resolved
                includes[resolved]=fact(resolved)
        need(set(units)|{str(fixture/'app.h')}<=set(includes),'all actual source/header inputs')
        state['headers']=includes
        _,out,err=run('app-link',argv,profile='release_build',env=builder.environment)
        need(out==err==b'','strict actual application build')
        image=binary(argv[-1]);state['artifact']=fact(image)
        return inspect_application(builder,private,pin,binary,run,state,image,units)

    try:
        r['source']=source()
        need(r['source']['revision']==args.expect_revision,'exact clean revision')
        need(PROFILES['program']==TARGET,'original whole-program target bounds')
        _,names,err=run('tracked-input-list',['git','ls-files','-z','tools/page-entry','evaluation/inprocess'])
        need(not err,'complete tracked input list')
        for raw in names.split(b'\0'):
            if raw:
                path=os.fsdecode(raw)
                if not path.startswith('evaluation/inprocess/results/'):pin(ROOT/path)
        for path in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[path]=os.path.lexists(path)
            if presence[path]:pin(path)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        imported_sources(pin)
        products=builder.prepare()
        need(builder.decoder_features==FEATURES and builder.extra_decoder_sources==('region.rs','mov_guard.rs')and
             builder.record['decoder_features']==list(FEATURES)and builder.record['status']=='passed'and
             builder.record['command_completed']is True,'fresh actual current region/span/linked/MOV decoder')
        r['decoder_archive']=dict(reused=False,archive=fact(products['archive']),features=list(FEATURES),
            current_dep_info_sha256=H(json.dumps(builder.record['dep_info'],sort_keys=True,separators=(',',':')).encode()))
        original=compile_subject()
        cohort(builder,products,private,pin,binary,aliases,run,r,original)
        r['status']='completed_unqualified'
    except BaseException as exc:
        r['error']=type(exc).__name__+': '+str(exc)
    finally:
        r['final_errors'].extend(builder.finish())
        try:
            imported_sources(pin)
            closure()
            need(source()==r['source'],'exact source unchanged')
            r['source_unchanged']=True
        except BaseException as exc:
            r['final_errors'].append(type(exc).__name__+': '+str(exc))
        r['cleanup_complete']=bool(r['commands'])and all(c.get('reaped')is True and c.get('cleanup_errors')==[]and
            all(d['closed']for d in c.get('descriptors',[]))for c in r['commands'])
        target=r.get('target',{})
        r['target_outcome']=('exit_zero'if target.get('exit')==0 else 'failed_prefix')if target.get('pid')else 'not_run'
        if r['error']or r['final_errors']or not r['source_unchanged']or not r['cleanup_complete']or not r['namespace_complete']:
            r['status']='failed'
        r.update(inputs=pins,artifacts=artifacts,aliases=aliases)
        save(receipt,r)
        hw=dict(r['hardware']);flags=hw.pop('isa_flags')
        hw.update(isa_flags_count=len(flags),isa_flags_sha256=H(json.dumps(flags,separators=(',',':')).encode()))
        summary={k:r[k]for k in ('schema','profile','status','revision','source','source_unchanged','cleanup_complete',
            'namespace_complete','cpu','bounds','scope','qualification_credit','performance_credit','counter_collection',
            'counts','terminal','subentry_counts','target_outcome')}
        summary.update(hardware=hw,private_receipt=fact(receipt),private_receipt_file=str(receipt.relative_to(ROOT)),
            original=r.get('original'),carrier=r.get('carrier'),bridge=r.get('bridge'),archive=r.get('archive'),
            policy_sha256=r.get('policy_sha256'),decoder_archive=r.get('decoder_archive'),
            target_exit=target.get('exit'),target_process_ns=target.get('duration_ns'),
            error_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
            tool_versions=builder.record.get('numeric_versions'),
            reproduce=['python3','-B','evaluation/inprocess/startup_counter.py','--expect-revision',args.expect_revision,
                       '--interpreter','REFERENCE_INTERPRETER'],
            counter_protocol={k:r.get('counter_protocol',{}).get(k)for k in ('scope','guest_executions','refusal_count')},
            seed={k:r['seed_prerequisite'].get(k)for k in ('status','exit','whole_process_ns')},
            copy_oracle={k:r.get('application_build',{}).get('copy_oracle',{}).get(k)
                         for k in ('status','counts','body','exit','duration_ns')},
            closure=dict(inputs=len(pins),artifacts=len(artifacts),commands=len(r['commands']),
                captures=sum(len(c.get('captures',{}))for c in r['commands'])))
        summary['cases']=[{k:c[k]for k in ('lane','mode','control','status','expected_exit','exit','whole_process_ns',
            'timed_out','launched','captures','native_instructions','native_full_frames','application_validated')if k in c}for c in r['cases']]
        for observed,case in zip(summary['cases'],r['cases'],strict=True):
            if 'application_controls'in case:
                observed['application_controls']=dict(count=len(case['application_controls']['refusals']),
                    sha256=H(json.dumps(case['application_controls'],sort_keys=True,separators=(',',':')).encode()))
        payload=(json.dumps(summary,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
        need(len(payload)<=32<<10 and all(x.encode()not in payload
             for x in (str(ROOT),str(Path.home()),'/home/',platform.node())if len(x)>1),
             'compact public receipt without host paths or raw logs')
        public.write_bytes(payload)
        with public.with_suffix('.csv').open('w',newline='')as f:
            w=csv.writer(f,lineterminator='\n')
            w.writerow(('revision','kind','name','value','exit','process_ns','status'))
            for case in summary['cases']:
                w.writerow((args.expect_revision,'subject',case['lane'],'',case.get('exit'),case.get('whole_process_ns'),case['status']))
            if r['counts']is not None:
                for key in ('events','signals','group','misses','maps','view','native'):
                    value=r['counts'][key]
                    rows=value.items()if type(value)is dict else enumerate(value)if type(value)is list else [('',value)]
                    for field,number in rows:
                        w.writerow((args.expect_revision,'final_prefix',key+('.'+str(field)if field!=''else ''),number,
                            target.get('exit'),target.get('duration_ns'),r['status']))
            if r['subentry_counts']is not None:
                for key,value in r['subentry_counts'].items():
                    w.writerow((args.expect_revision,'completed_subentry',key,value,target.get('exit'),target.get('duration_ns'),r['status']))
        print(json.dumps(dict(status=r['status'],target_exit=target.get('exit'),receipt=str(public.relative_to(ROOT)))))
    return int(r['status']!='completed_unqualified')


if __name__=='__main__':raise SystemExit(main())
