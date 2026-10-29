#!/usr/bin/env python3
"""Sixty fixed release launches: native, in-process page gate and DynamoRIO."""
import argparse,ctypes,csv,hashlib,importlib.util,io,json,os,platform,re,resource,select,shlex,shutil,signal,statistics,struct,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from page_selected import ENV,fact,need,save,elf,interpreter
from checks import source
from run import hardware
from page_selected_generic_build import Build,PROFILES as BUILD_PROFILES
from page_selected_process import invoke,Action
import page_default_ls_release_provenance as provenance
import page_native_pair_reports as pair_reports
from page_selected_effect_ls import finalize
from page_selected_repeat_lease_ls import PROGRAM_ENV,BOUNDS,SELECTED,UNITS,MACROS as ORIGINAL_MACROS
from page_selected_register_time_build import headers,bridge_check
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
MACROS=('NATIVE_PAIR',)+ORIGINAL_MACROS
from page_selected_register_real import resolved_libraries
from page_selected_oneshot_build import before_default
from page_selected_register_time_build import recipe,expand
from page_selected_register_time_compare import decode
import itertools
import page_native_pair_performance as pair
import page_cost_reports as cost_reports
LANE_ORDER=(('native','gated','dynamorio'),('gated','dynamorio','native'),
    ('dynamorio','native','gated'),('dynamorio','gated','native'),
    ('gated','native','dynamorio'),('native','dynamorio','gated'))
ORDER=tuple((kind,repeat,lane) for repeat in range(10)
    for kind in (('ls','true') if repeat%2==0 else ('true','ls'))
    for lane in LANE_ORDER[repeat%6])
NAMES=tuple(f'{kind}-{repeat}-{lane}' for kind,repeat,lane in ORDER)
H=lambda b:hashlib.sha256(b).hexdigest()
digest=pair.digest

def program_invoke(row, directory, cpu, record=False, step=False):
    process = None
    pidfd = None
    descriptors = []
    start = time.monotonic_ns()
    row.update(exit=None, timed_out=False, reaped=False, error=None, cleanup_errors=[], descriptors=[])
    bounds = row['bounds']
    paths = {name: directory/(row['name']+'.'+name) for name in ('stdout', 'stderr')}
    record_fd = prep_fd = None
    libc = None

    def reset_signals():
        previous = ctypes.c_uint64(0)
        empty = ctypes.c_uint64(0)
        actual = ctypes.c_uint64(1)
        zero, before, after = Action(), Action(), Action()
        if libc.syscall(14, 2, ctypes.byref(empty), ctypes.byref(previous), 8) != 0:
            os._exit(120)
        observations = []
        for number in range(1, 65):
            if number in (9, 19):
                continue
            if libc.syscall(13, number, None, ctypes.byref(before), 8) != 0:
                os._exit(121)
            if libc.syscall(13, number, ctypes.byref(zero), None, 8) != 0:
                os._exit(122)
            if libc.syscall(13, number, None, ctypes.byref(after), 8) != 0 or after.handler:
                os._exit(123)
            observations.append({'signal': number, 'before': int(before.handler or 0),
                                 'after': int(after.handler or 0)})
        if libc.syscall(14, 2, None, ctypes.byref(actual), 8) != 0 or actual.value != 0:
            os._exit(123)
        data = json.dumps({'previous_mask': previous.value, 'mask': actual.value,
                           'dispositions': observations}, separators=(',', ':')).encode()
        if os.write(prep_fd, data) != len(data):
            os._exit(124)
        os.close(prep_fd)

    def prepare():
        os.sched_setaffinity(0, {cpu})
        if step:
            reset_signals()
        for key, value in ((resource.RLIMIT_CPU, bounds[0]), (resource.RLIMIT_AS, bounds[1]),
                           (resource.RLIMIT_FSIZE, bounds[2]), (resource.RLIMIT_CORE, 0)):
            resource.setrlimit(key, (value, value))
        if row.get('nproc') is not None:
            resource.setrlimit(resource.RLIMIT_NPROC, (row['nproc'], row['nproc']))

    def own(name):
        path = directory/(row['name']+'.'+name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        state = {'name': name, 'fd': fd, 'closed': False}
        descriptors.append((fd, state))
        row['descriptors'].append(state)
        paths[name] = path
        return fd

    def close_group():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as exc:
            row['cleanup_errors'].append('kill: '+repr(exc))

    try:
        # Resolve libc before fork inside the retained attempt. Only this
        # diagnostic child's preparation uses it; target handlers do not.
        if step:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.syscall.restype = ctypes.c_long
        if record:
            record_fd = own('record')
            if step:
                need(record_fd == 3, 'standalone step requires actual fixed fd 3')
                prep_fd = own('preparation')
        row['argv'] = [str(record_fd) if value == '{record_fd}' else str(value) for value in row['argv']]
        with paths['stdout'].open('xb') as stdout, paths['stderr'].open('xb') as stderr:
            row['stdout_provenance_before']=provenance.observe(stdout.fileno())
            try:
                usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
                row['process_start_ns'] = time.monotonic_ns()
                process = subprocess.Popen(row['argv'], cwd=directory, env=row.get('environment', ENV),
                                           stdout=stdout, stderr=stderr, start_new_session=True,
                                           pass_fds=tuple(fd for fd, _ in descriptors), preexec_fn=prepare)
                row['pid'] = process.pid
                pidfd = os.pidfd_open(process.pid)
                remaining = bounds[3]-(time.monotonic_ns()-row['process_start_ns'])/1e9
                if remaining <= 0 or not select.select([pidfd], [], [], remaining)[0]:
                    row['timed_out'] = True
                    raise TimeoutError('component wall bound')
                # The unreaped leader pins the process-group number until cleanup.
                close_group()
                row['exit'] = process.wait(timeout=3)
                row['reaped'] = True
                row.setdefault('process_reaped_ns', time.monotonic_ns())
            finally:
                try:
                    row['stdout_provenance_after']=provenance.observe(stdout.fileno())
                    provenance.same(row['stdout_provenance_before'],row['stdout_provenance_after'])
                except BaseException as exc:
                    row['cleanup_errors'].append('parent descriptor identity: '+repr(exc))
    except BaseException as exc:
        row['error'] = type(exc).__name__+': '+str(exc)
    finally:
        if process is not None and process.returncode is None:
            close_group()
            try:
                row['exit'] = process.wait(timeout=3)
                row['reaped'] = True
                row.setdefault('process_reaped_ns', time.monotonic_ns())
            except BaseException as exc:
                row['cleanup_errors'].append('wait: '+repr(exc))
        elif process is not None:
            row['exit'] = process.returncode
            row['reaped'] = True
            row.setdefault('process_reaped_ns', time.monotonic_ns())
        if pidfd is not None:
            try:
                os.close(pidfd)
            except BaseException as exc:
                row['cleanup_errors'].append('pidfd_close: '+repr(exc))
        # Each descriptor leaves the close list before its close is attempted;
        # a failure cannot trigger a later close of a reused numeric descriptor.
        while descriptors:
            fd, state = descriptors.pop()
            try:
                os.close(fd)
                state['closed'] = True
            except BaseException as exc:
                state['error'] = repr(exc)
                row['cleanup_errors'].append(state['name']+'_close: '+repr(exc))
        if 'process_reaped_ns' in row:
            row['process_ns'] = row['process_reaped_ns']-row['process_start_ns']
            usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
            for name,field in (('user_cpu_ns','ru_utime'),('system_cpu_ns','ru_stime')):
                row[name] = round((getattr(usage_after,field)-getattr(usage_before,field))*1e9)
            for name,field in (('minor_faults','ru_minflt'),('major_faults','ru_majflt'),
                               ('voluntary_switches','ru_nvcsw'),('involuntary_switches','ru_nivcsw')):
                row[name] = getattr(usage_after,field)-getattr(usage_before,field)
        row['duration_ns'] = time.monotonic_ns()-start
        row['captures'] = {}
        for name, path in paths.items():
            try:
                row['captures'][name] = dict(fact(path), file=path.name)
            except BaseException as exc:
                row['cleanup_errors'].append(name+'_capture: '+repr(exc))
        try:
            save(directory/(row['name']+'.json'), row)
        except BaseException as exc:
            row['cleanup_errors'].append('command_record: '+repr(exc))
    need(row['reaped'] and not row['timed_out'] and not row['error'] and not row['cleanup_errors'],
         'component process/cleanup failed: '+row['name'])
    need(0 < row['process_ns'] <= bounds[3]*1_000_000_000, 'complete process interval exceeds original wall bound')
    cap = row['capture_limit']
    need(all(row['captures'][name]['bytes'] <= cap for name in ('stdout', 'stderr')), 'capture limit')
    if record:
        need(row['captures']['record']['bytes'] <= bounds[2], 'private record limit')
    if step:
        data = json.loads(paths['preparation'].read_bytes())
        need(data['mask'] == 0 and [x['signal'] for x in data['dispositions']] ==
             [n for n in range(1, 65) if n not in (9, 19)] and
             all(x['after'] == 0 for x in data['dispositions']), 'actual standalone signal preparation')
    return paths['stdout'].read_bytes(), paths['stderr'].read_bytes()


def build_dr(sdk,builder,private,pin,binary,run,r):
    sdk=Path(sdk).resolve(strict=True)
    files={str(p.relative_to(sdk)):fact(pin(p)) for p in sorted(sdk.rglob('*')) if p.is_file()}
    need('bin64/drrun' in files and 'lib64/release/libdynamorio.so' in files,'actual complete SDK')
    r['dynamorio_sdk']=files
    cmake=pin(shutil.which('cmake',path=ENV['PATH']))
    build=private/'dr-null-build'
    env=dict(builder.environment,HOME=str(private/'dr-home'))
    Path(env['HOME']).mkdir()
    run('dr-cmake',[cmake,'-S',HERE/'dynamorio-null','-B',build,
        '-DDynamoRIO_DIR='+str(sdk/'cmake'),'-DCMAKE_BUILD_TYPE=Release',
        '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_C_COMPILER='+str(builder.tools['cc'])],env=env)
    run('dr-build',[cmake,'--build',build,'--parallel','1'],profile='release_build',env=env)
    client=binary(build/'libli2_dr_null.so')
    _,symbols,err=run('dr-client-exports',[builder.tools['nm'],'-D','--defined-only',client],env=env)
    need(not err and len([x for x in symbols.splitlines() if x.split()[-2:]==[b'T',b'dr_client_main']])==1,
         'one actual exported null client entry')
    versions=[x.split() for x in symbols.splitlines() if x.split()[-1:]==[b'_USES_DR_VERSION_']]
    need(len(versions)==1 and len(versions[0])==3,'actual SDK client version export')
    address=int(versions[0][0],16);data=client.read_bytes()
    eh=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(eh[0][:7]==b'\x7fELF\x02\x01\x01' and eh[9]==56,'actual little-endian ELF64 client')
    segments=[struct.unpack_from('<IIQQQQQQ',data,eh[5]+i*eh[9]) for i in range(eh[10])]
    owners=[x for x in segments if x[0]==1 and x[3]<=address and address+4<=x[3]+x[5]]
    need(len(owners)==1 and struct.unpack_from('<I',data,owners[0][2]+address-owners[0][3])[0]==1191,
         'actual file-backed client API version 1191, not a discarded incompatible client')
    entries=json.loads((build/'compile_commands.json').read_bytes())
    need(len(entries)==1 and Path(entries[0]['file']).resolve()==HERE/'dynamorio-null/null.c' and
         '-O3' in shlex.split(entries[0]['command']) and '-DNDEBUG' in shlex.split(entries[0]['command']),
         'actual SDK Release null-client compile')
    for dep in build.rglob('*.o.d'):
        for name in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):pin(name)
    r['dynamorio_client']=fact(client)
    r['dynamorio_build_commands_sha256']=digest(entries)
    return pin(sdk/'bin64/drrun'),client,dict(PROGRAM_ENV,HOME=env['HOME'])


def dr_diagnostics(drrun,client,states,private,pin,binary,run,r,env):
    """Separate syscall trace proves DR's exec-self and internal target loading."""
    trace=pin(shutil.which('strace',path=ENV['PATH']));r['dr_diagnostics']=[]
    for name,program,args,expected,output in [('ls',states['ls']['original'],['-d','.'],0,b'.\n'),
            ('true',states['true']['original'],[],0,b''),('false',pin('/bin/false'),[],1,b'')]:
        path=private/('dr-proof-'+name+'.trace')
        proof=dict(workload=name,status='failed');r['dr_diagnostics'].append(proof)
        try:
            row,out,err=run('dr-proof-'+name,[trace,'-f','-qq','-yy','-s','4096','-o',path,
                '-e','trace=execve,open,openat,mmap,mprotect,close,exit,exit_group',
                drrun,'-quiet','-64','-root',drrun.parent.parent,'-c',client,'--',program,*args],profile='program_dr',env=env,expected=expected)
            data=binary(path).read_bytes();text=data.decode()
            # Default drrun execs DR itself; DR's private loader maps the target.
            # Both executable file mappings must occur in one actual PID.
            rows=text.splitlines();execs=[x for x in rows if 'execve(' in x and
                str(drrun.parent.parent/'lib64/release/libdynamorio.so') in x and '= 0' in x]
            need(len(execs)==1 and '"'+str(program)+'"' in execs[0],'actual DR exec-self with target argv')
            pid=execs[0].split()[0];need(pid.isdecimal(),'actual trace PID')
            rows=rows[rows.index(execs[0])+1:]
            mappings={}
            for label,file in [('target',program),('client',client)]:
                matches=[x for x in rows if x.split()[0]==pid and 'mmap(' in x and 'PROT_EXEC' in x and
                    '<'+str(file)+'>' in x and re.search(r'= 0x[0-9a-f]+$',x)]
                need(matches,'actual file-backed executable '+label+' mapping in DR target PID')
                mappings[label]=len(matches)
            need(any(x.split()[0]==pid and ('exit_group('+str(expected)+')' in x or
                'exit('+str(expected)+')' in x) for x in rows),'actual target-process exit syscall')
            need(out==output and err==b'','exact diagnostic target output/stderr')
            proof.update(status='passed',trace=fact(path),mappings=mappings,exit=expected)
        except BaseException as exc:proof['error']=type(exc).__name__+': '+str(exc)


def cohort(builder,products,private,pin,binary,aliases,run,r,sdk):
    bridge=pair.build_bridge(builder,products,private,pin,binary,aliases,run,r)
    spec=importlib.util.spec_from_file_location('cost_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    (private/'external-inputs').mkdir();r['namespace_aliases']={}
    states={kind:pair.prepare_workload(kind,path,args,bridge,builder,private,pin,binary,run,r,namespace)
            for kind,path,args in [('ls','/bin/ls',['-d','.']),('true','/bin/true',[])]}
    drrun,client,dr_env=build_dr(sdk,builder,private,pin,binary,run,r)
    dr_diagnostics(drrun,client,states,private,pin,binary,run,r,dr_env)
    r['terminal_reports']={};r['reader_controls']={}
    for ordinal,(kind,repeat,lane) in enumerate(ORDER):
        name=NAMES[ordinal];s=states[kind];case=r['cases'][ordinal]
        case['status']='failed';env=PROGRAM_ENV
        if lane=='native':argv=s['argv']
        elif lane=='dynamorio':
            argv=[drrun,'-quiet','-64','-root',drrun.parent.parent,'-c',client,'--',*s['argv']];env=dr_env
        else:
            ns=private/(name+'-namespace')
            argv=[builder.tools['python'],'-B',s['carrier_tool'],'exec-loader','--library-root','/usr/lib64',
                '--namespace',ns,s['carrier'],s['original'],'--',*s['argv']]
        try:
            row,out,err=run(name,argv,profile='program_dr' if lane=='dynamorio' else 'program',env=env)
            need(out==(b'.\n' if kind=='ls' else b''),'exact real program output')
            if lane=='gated':
                pair.namespace_join(s,ns,binary,r,namespace)
                parsed,summary=cost_reports.check(out,err,row['pid'],row['exit'],row['stdout_provenance_before'],
                    s['images'],s['image_bytes'],fact(s['carrier']),s['carrier_bytes'],workload=kind)
                r['terminal_reports'][name]=parsed;case['comparison']=summary
                r['reader_controls'][name]=cost_reports.supplied_controls(out,err,row['pid'],row['exit'],
                    row['stdout_provenance_before'],s['images'],s['image_bytes'],fact(s['carrier']),s['carrier_bytes'],workload=kind)
            else:
                need(err==b'','native/DR stderr exactly empty')
                if lane=='dynamorio':need(all(x['status']=='passed' for x in r['dr_diagnostics']),
                    'separate actual DR target/client load and exit relay controls')
            case['status']='passed'
        except BaseException as exc:case['error']=type(exc).__name__+': '+str(exc)
        finally:
            attempted=[c for c in r['commands'] if c['name']==name]
            if attempted:
                actual=attempted[-1]
                case.update({k:actual.get(k) for k in ('exit','process_ns','timed_out','reaped','user_cpu_ns','system_cpu_ns',
                    'minor_faults','major_faults','voluntary_switches','involuntary_switches')})
                case['captures']={k:{f:v[f] for f in ('bytes','sha256')} for k,v in actual.get('captures',{}).items()}
            print(json.dumps({k:case.get(k) for k in ('ordinal','workload','lane','status','exit','process_ns','error')}),flush=True)
    need(len(r['cases'])==60 and all(c['status']=='passed' for c in r['cases']),
         'all sixty planned attempts must complete; failures retained without replacement')


def publish(path,r,private):
    stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n')
    fields=['ordinal','workload','repeat','lane','status','exit','process_ns','timed_out','reaped',
        'user_cpu_ns','system_cpu_ns','minor_faults','major_faults','voluntary_switches','involuntary_switches']
    writer.writerow(fields)
    for case in r['cases']:writer.writerow([case.get(k) for k in fields])
    data=stream.getvalue().encode();csv_path=path.with_suffix('.csv')
    stats={}
    for kind in ('ls','true'):
        stats[kind]={}
        for lane in ('native','gated','dynamorio'):
            rows=[c for c in r['cases'] if c['workload']==kind and c['lane']==lane]
            times=[c['process_ns'] for c in rows if c['status']=='passed']
            item=stats[kind][lane]=dict(planned=10,passed=len(times))
            if len(times)==10 and r['source_unchanged'] and not r['final_errors']:
                q=statistics.quantiles(times,n=4,method='inclusive')
                item.update(median_ns=statistics.median(times),q1_ns=q[0],q3_ns=q[2],iqr_ns=q[2]-q[0])
    hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw['isa_flags_sha256']=digest(flags)
    value={k:r.get(k) for k in ('schema','profile','status','expected_revision','started_utc','source','source_unchanged',
        'cpu','bounds','reproduce','cleanup_complete','archive','carriers','dynamorio_client')}
    value.update(hardware=hw,private_receipt=fact(private/'receipt.json'),statistics=stats,
        quantiles='Python statistics.quantiles(n=4, method=inclusive), linear interpolation at (n-1)*p; IQR=Q3-Q1',
        whole_process_scope='Monotonic pre-Popen through wait/reap: spawn, exec, runtime/loader, program, and exit. Gated includes Python launch and sealed namespace preparation. Offline bridge/carrier/client builds excluded. No cache-cold claim.',
        cpu_scope='RUSAGE_CHILDREN difference around each sole sequential child, reported CPU seconds converted to ns; microsecond accounting precision. Includes child threads and reaped descendants, excludes measuring parent.',
        order='Ten rounds; program order alternates; lane order cycles all six permutations. All sixty attempts retained; no resampling.',
        commands=len(r['commands']),command_rows_sha256=digest(r['commands']),
        sdk=r.get('dynamorio_sdk'),dr_diagnostics=[{k:v for k,v in x.items() if k!='error'} for x in r.get('dr_diagnostics',[])],
        sdk_scope='Existing DBT-vendored DynamoRIO 11.91.0 SDK; empty client, default release runtime options, frontend quiet/64/root. DR alone has 16 GiB virtual-address allowance for default reservations; native/gated retain 512 MiB. Earlier 512 MiB DR failures remain separate.',
        program_inputs=r.get('system_inputs'),tool_versions=r.get('build',{}).get('numeric_versions'),
        bridge=r.get('release_build',{}).get('bridge'),release_build_status=r.get('release_build',{}).get('status'),
        reader_controls={k:len(v['refusals']) for k,v in r.get('reader_controls',{}).items()},
        terminals={k:v for k,v in r.get('terminal_reports',{}).items()},
        csv=dict(file=csv_path.name,bytes=len(data),sha256=H(data)),
        error_type=r['error'].split(':',1)[0] if r['error'] else None,final_error_count=len(r['final_errors']),
        sample_failures=[dict(sample=c['ordinal'],error_type=c.get('error','not_run').split(':',1)[0])
            for c in r['cases'] if c['status']!='passed'],
        recipes=dict(native_ls=['/bin/ls','-d','.'],native_true=['/bin/true'],
            gated=['python3','-B','tools/page-entry/carrier.py','exec-loader','--library-root','/usr/lib64',
                '--namespace','${UNIQUE_NAMESPACE}','${CARRIER}','${ORIGINAL}','--','${ORIGINAL}','${ARGS}'],
            dynamorio=['${SDK}/bin64/drrun','-quiet','-64','-root','${SDK}','-c','${NULL_CLIENT}','--','${ORIGINAL}','${ARGS}'],
            release=['sh','tools/page-entry/selected/build-native-pair.sh','${FRESH_ARCHIVE}','${OUTPUT}'],
            environment='PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC LD_BIND_NOW=1; DR private HOME; gated sealed dependency environment; same private cwd'))
    # Terminal detail stays private; retain only numerical route/closure totals.
    value['terminals']={k:{n:p[n] for n in ('native','native_pair','maps_cost','admission_cost') if n in p}
                        for k,p in r.get('terminal_reports',{}).items()}
    text=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<64<<10 and len(data)<16<<10 and not any(x and len(x)>1 and x in text
        for x in (str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public summary without private paths')
    path.parent.mkdir(parents=True,exist_ok=True)
    with csv_path.open('xb') as f:f.write(data)
    with path.open('x') as f:f.write(text)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True);ap.add_argument('--sdk',required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),
         'exact committed revision, assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-cost-compare-'+a.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem
    private.mkdir(parents=True,mode=0o700);public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    # DR reserves 1 GiB VM plus 8 GiB heap by default; this comparator has its
    # own virtual-address allowance. Original native/gated bounds stay exact.
    bounds=dict(BUILD_PROFILES,**BOUNDS,program_dr=[30,16<<30,16<<20,60])
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='page-cost-compare-v2',scope='Sixty fixed whole-process release attempts; existing gated qualification and limits retained',
        status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
        cpu=cpu,hardware=hardware(cpu),bounds=bounds,commands=commands,cases=[dict(ordinal=i,workload=k,repeat=n,lane=l,status='not_run') for i,(k,n,l) in enumerate(ORDER)],error=None,final_errors=[],
        reproduce=['python3','evaluation/inprocess/page_cost_compare.py','--expect-revision',a.expect_revision,'--sdk','${SDK}'])
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
        products=builder.prepare();r['archive']=fact(products['archive'])
        cohort(builder,products,private,pin,binary,aliases,run,r,a.sdk)
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
