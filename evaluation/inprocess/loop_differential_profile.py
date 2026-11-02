#!/usr/bin/env python3
"""One user-DWARF or explicit kernel-callchain differential observation.

Reserve one CPU; use Python3.12 and a fresh target/evaluation/inprocess output.
The failed six-command smoke remains failed. No builds, altered target limits,
counter substitute, owner qualification, successful-target or timing credit.
The same-PID adapter opens a fresh record FD before the original launcher exec;
both Python wrappers are included in the measured/sampled process envelope.
"""
import argparse, collections, fcntl, hashlib, json, os, re, resource, stat, sys
from pathlib import Path

sys.dont_write_bytecode = True
SUBJECT = [30, 512 << 20, 16 << 20, 60]
ENV = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1')
ORIGIN = 'c9d8b4a4dc4a72761005d048aa5ad868125e382a'


def need(ok, why):
    if not ok: raise ValueError(why)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, sort_keys=True, indent=2, allow_nan=False)
        f.write('\n'); f.flush(); os.fsync(f.fileno())


def record_child(config, expected):
    """No fork; open only the missing record FD, then exec the exact launcher."""
    raw = Path(config).read_bytes()
    need(digest(raw) == expected, 'whole parent-owned adapter configuration')
    c = json.loads(raw)
    need(set(c) == {'argv','environment','cpu','record','observed','python','launcher'} and
         dict(os.environ) == c['environment'] == ENV and
         sorted(os.sched_getaffinity(0)) == [c['cpu']] and
         [list(resource.getrlimit(k)) for k in (resource.RLIMIT_CPU,resource.RLIMIT_AS,resource.RLIMIT_FSIZE)] ==
         [[n,n] for n in SUBJECT[:3]] and resource.getrlimit(resource.RLIMIT_CORE) == (0,0),
         'exact child environment, affinity and original target limits')
    need(c['argv'][0] == str(Path(sys.executable).resolve()) == c['python'] and
         c['argv'][1:3] == ['-B',c['launcher']] and
         c['argv'].count('--record-fd') == 1 and c['argv'][-2:] == ['--record-fd','3'],
         'one exact original launcher and observer argument')
    fd = None
    try:
        fd = os.open(c['record'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        s = os.fstat(fd)
        need(fd == 3 and stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600 and
             s.st_size == 0 and s.st_nlink == 1 and os.lseek(fd,0,os.SEEK_CUR) == 0,
             'exclusive fresh normal-open record is actual FD3')
        os.set_inheritable(fd, True)
        need(os.get_inheritable(fd) and fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE == os.O_WRONLY,
             'record descriptor access and inheritance')
        observed = dict(pid=os.getpid(), parent=os.getppid(), group=os.getpgrp(),
            argv=c['argv'], environment=dict(os.environ), cpu=sorted(os.sched_getaffinity(0)),
            record=dict(fd=3,device=s.st_dev,inode=s.st_ino,mode=0o600,bytes=0,nlink=1,
                        access=os.O_WRONLY,inheritable=True))
        save(c['observed'], observed)
        now = os.stat(c['record'], follow_symlinks=False)
        need((now.st_dev,now.st_ino,now.st_size,now.st_nlink) == (s.st_dev,s.st_ino,0,1),
             'same record path immediately before original exec')
        os.execve(c['argv'][0],c['argv'],c['environment'])
        raise RuntimeError('original launcher exec returned')
    finally:
        if fd is not None: os.close(fd)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--smoke-receipt', type=Path, required=True)
    ap.add_argument('--smoke-receipt-sha256', required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--kernel-callchains', action='store_true')
    a = ap.parse_args(); root = Path.cwd().resolve()
    sys.path[:0] = [str(root/'evaluation/inprocess'),str(root/'tools/page-entry')]
    from checks import source
    from run import hardware
    from page_selected import fact, interpreter
    from page_selected_process import invoke
    from page_cost_profile import profile, TARGET, PERF
    from persistent_dynamic_profile import observer_libraries
    from persistent_dynamic_profile_read import script_argv, attribute
    from persistent_dynamic import imported_sources
    from persistent_loop_native_build import preparation
    import namespace
    if a.kernel_callchains:
        import page_cost_kernel as kernel
        from page_cost_profile_read import callchain_counts
    need(not sys.flags.optimize and sys.version_info[:2] == (3,12) and len(os.sched_getaffinity(0)) == 1 and
         re.fullmatch('[0-9a-f]{40}',a.expect_revision) and list(TARGET) == SUBJECT and
         re.fullmatch('[0-9a-f]{64}',a.smoke_receipt_sha256), 'exact reviewed subject/profile and source request')
    cpu = next(iter(os.sched_getaffinity(0))); output = a.output.absolute()
    need(output.parent == root/'target/evaluation/inprocess' and not output.exists(), 'fresh direct-child output')
    output.mkdir(mode=0o700)
    pins, artifacts, aliases = {}, {}, {}
    r = dict(schema=1,profile='loop-differential-user-dwarf-diagnostic-v1',status='failed',cpu=cpu,
        hardware=hardware(cpu),argv=[sys.executable,'-B',*sys.argv],source=None,compiled_source=None,
        subject_bounds=SUBJECT,observer_bounds=list(PERF),unwinder_bounds=list(PERF),commands=[],
        qualification_credit=False,performance_credit=False,owner_credit=False,successful_target_credit=False,
        original_smoke_reclassified=False,source_unchanged=False,inputs_unchanged=False,
        cleanup_complete=False,error=None,final_errors=[],namespace_aliases={})
    if a.kernel_callchains:
        r.update(profile='loop-differential-kernel-callchains-diagnostic-v1',kernel_callchains=True,
                 unwinder_bounds=None,resource_usage='not collected by unchanged kernel-callchain profile')
    def pin(path, expected=None):
        lexical = Path(path).absolute(); p = lexical.resolve(strict=True); v = fact(p)
        if expected is not None:
            need(all(v[k] == expected[k] for k in ('bytes','sha256')) and
                 ('mode' not in expected or stat.S_IMODE(p.stat().st_mode) == expected['mode']), 'whole recorded input '+str(p))
        need(str(p) not in pins or pins[str(p)] == v, 'stable input identity')
        need(str(lexical) not in aliases or aliases[str(lexical)] == str(p), 'stable input alias')
        pins[str(p)] = v; aliases[str(lexical)] = str(p); return p
    def binary(path):
        p = pin(path); artifacts[str(p)] = dict(pins[str(p)],mode=stat.S_IMODE(p.stat().st_mode)); return p
    def stable():
        need(source() == r['source'] and os.sched_getaffinity(0) == {cpu}, 'unchanged current observer source and CPU')
        need(all(fact(p) == v for p,v in pins.items()), 'whole pinned source, binary, observer and original evidence unchanged')
        need(all(str(Path(p).resolve(strict=True)) == v for p,v in aliases.items()), 'whole input aliases unchanged')
        need(all(dict(fact(p),mode=stat.S_IMODE(Path(p).stat().st_mode)) == v for p,v in artifacts.items()),
             'same retained artifact bytes and modes')
    def run(name,argv,env):
        stable(); row = dict(name=name,argv=list(map(str,argv)),environment=env,bounds=list(PERF),capture_limit=16<<20)
        r['commands'].append(row); out,err = invoke(row,output,cpu)
        need(row['exit'] == 0 and not row['timed_out'] and row['reaped'] and not row['cleanup_errors'], 'bounded observer tool '+name)
        return out,err
    try:
        r['source'] = source(); need(r['source']['revision'] == a.expect_revision, 'exact clean current observer revision')
        pin(__file__); imported_sources(pin)
        origin_path = pin(a.smoke_receipt)
        need(pins[str(origin_path)]['sha256'] == a.smoke_receipt_sha256 and origin_path.name == 'receipt.json' and
             origin_path.parent.parent == root/'target/evaluation/inprocess', 'exact closed smoke receipt')
        old = json.loads(origin_path.read_bytes()); r['compiled_source'] = old['source']
        need(old['profile'] == 'loop-guard-cancel-smoke-v1' and old['status'] == 'failed' and
             old['revision'] == old['source']['revision'] == ORIGIN and old['source']['tracked_clean'] is True and
             old['source']['head_sources_match'] is True and old['source_unchanged'] is old['inputs_unchanged'] is old['cleanup_complete'] is True and
             old['final_errors'] == [] and old['bounds'] == SUBJECT and old['owner_credit'] is old['qualification_credit'] is old['performance_credit'] is False,
             'literal closed historical smoke failure; no eligibility or revision substitution')
        # This includes every recorded production/recipe/launcher source and tool.
        # Current main may differ elsewhere; the actual compiled-source inputs may not.
        for p,v in old['inputs'].items(): pin(p,v)
        for lexical,actual in old['aliases'].items():
            need(str(Path(lexical).resolve(strict=True)) == actual and
                 (lexical not in aliases or aliases[lexical] == actual), 'original input alias')
            aliases[lexical] = actual
        for p,v in old['artifacts'].items(): binary(pin(p,v))
        names = ['maintained-build','maintained-carrier','subject-maintained-0-0',
                 'differential-build','differential-carrier','subject-differential-0-0']
        need([c['name'] for c in old['commands']] == names, 'all original six commands retained')
        for c in old['commands']:
            need(c['bounds'] == SUBJECT and c['capture_limit'] == 16<<20 and c['expected_exit'] == 0 and
                 c['reaped'] is True and c['timed_out'] is False and c['error'] is None and c['cleanup_errors'] == [] and
                 type(c['descriptors']) is list and all(d['closed'] is True for d in c['descriptors']), 'closed original command')
            need(json.loads(pin(origin_path.parent/(c['name']+'.json')).read_bytes()) == c, 'whole original command row')
            for v in c['captures'].values():
                need(Path(v['file']).name == v['file'], 'local original capture')
                pin(origin_path.parent/v['file'],v)
        need([c['exit'] for c in old['commands']] == [0,0,0,0,0,-9], 'original exits stay literal')
        lane = old['lanes'][1]
        need([v['lane'] for v in old['lanes']] == ['maintained','differential'] and lane['status'] == 'failed' and
             lane['terminal'] is None and old['lanes'][0]['status'] == 'exit_zero_diagnostic_only', 'two original outcomes unchanged')
        prior = old['commands'][-1]; build,carrier_row = old['commands'][3:5]
        original = pin(lane['namespace_plan']['original'],lane['subject_artifacts']['original'])
        interp = pin(lane['namespace_plan']['interpreter'],lane['subject_artifacts']['interpreter'])
        generated = origin_path.parent/'differential/build'
        bridge = pin(generated/'bridge-persistent-loop-differential.so',lane['subject_artifacts']['bridge'])
        carrier = pin(origin_path.parent/'differential/carrier',lane['subject_artifacts']['carrier'])
        python = pin(prior['argv'][0]); launch = pin(root/'tools/page-entry/selected/tests/tunables_loop_paired_app/launch.py')
        need(str(python) == str(Path(sys.executable).resolve()) and
             carrier_row['argv'] == [str(python),'-B',str(root/'tools/page-entry/carrier.py'),'make',str(original),str(bridge),str(carrier)] and
             build['argv'][1:] == [str(root/'tools/page-entry/selected/build-persistent-loop-differential.sh'),
                                  build['argv'][2],str(original),str(generated)] and
             fact(pin(build['argv'][2])) == old['reused_inputs']['archive'] and interpreter(carrier) == bridge,
             'exact original differential recipe, archive, carrier and bridge')
        roots = [original.parent]
        objects,description = namespace.plan(original,roots,bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
        need(objects == [] and description == lane['namespace_plan'] and
             namespace.parse(original.read_bytes()) == dict(elf_type=2,needed=[],soname=None,interpreter=interp) and
             namespace.parse(interp.read_bytes()) == dict(elf_type=3,needed=[],soname=None,interpreter=None), 'original complete no-DT_NEEDED fixture')
        old_subject = origin_path.parent/'differential/subject'
        argv = [str(python),'-B',str(launch),'--root',str(root),'--role','gated','--case','0','--placement','0','--control','0',
                '--original',str(original),'--preparation',str(old_subject/'preparation.json'),'--library-root',str(original.parent),
                '--carrier',str(carrier),'--namespace',str(old_subject/'namespace'),'--record-fd','3']
        need(prior['argv'] == argv and prior['environment'] == ENV, 'whole actual original differential launcher tuple')
        subject = output/'subject'; subject.mkdir()
        for key,value in (('--preparation',subject/'preparation.json'),('--namespace',subject/'namespace')):
            argv[argv.index(key)+1] = str(value)
        capture = output/'capture'; record = capture/'target.record'; observed_path = capture/'record-adapter.json'
        config = output/'record-config.json'
        save(config,dict(argv=argv,environment=ENV,cpu=cpu,record=str(record),observed=str(observed_path),python=str(python),launcher=str(launch)))
        pin(config); driver = pin(__file__)
        row = dict(name='differential-0-0-user-dwarf',argv=[str(python),'-I',str(driver),'--record-child',str(config),fact(config)['sha256']],
                   environment=ENV,cwd=str(origin_path.parent),bounds=SUBJECT,capture_limit=16<<20,expected_exit=0)
        if a.kernel_callchains: row['name'] = 'differential-0-0-kernel-callchains'
        r.update(target=row,original_launcher_argv=argv,original_receipt=fact(origin_path),original_subject=prior,
                 bridge=fact(bridge),carrier=fact(carrier),compiled_sources_equal_current=True)
        perf = pin('/usr/bin/perf'); perfinterp = pin(interpreter(perf))
        listed,errors = run('perf-libraries',[perfinterp,'--list',perf],ENV)
        need(not errors, 'actual observer library listing')
        libs = observer_libraries(listed,perfinterp,pin)
        r['observer_libraries'] = {str(p):fact(p) for p in libs}
        if a.kernel_callchains:
            r['kernel_snapshot'] = kernel.capture(output/'kernel')
            for p in (output/'kernel').iterdir(): binary(p)
        imported_sources(pin); stable()
        if a.kernel_callchains:
            out,err,owner = profile(row,capture,cpu,bridge,fact(bridge),perf=str(perf),kernel_callchains=True,user_dwarf=False)
            need(owner['sampling']['full_exec_exit_envelope'] and owner['sampling']['loss_free'] and 'usage' not in row,
                 'complete loss-free kernel-callchain envelope; no invented wait4 usage')
        else:
            out,err,owner = profile(row,capture,cpu,bridge,fact(bridge),perf=str(perf),user_dwarf=True)
        r['diagnostic'] = owner
        if not a.kernel_callchains:
            need(owner['sampling']['full_exec_exit_envelope'] and owner['sampling']['loss_free'], 'complete loss-free user-DWARF envelope')
        observed = json.loads(binary(observed_path).read_bytes()); s = record.stat()
        need(observed == dict(pid=row['pid'],parent=owner['owner_pid'],group=row['pid'],argv=argv,environment=ENV,cpu=[cpu],
             record=dict(fd=3,device=s.st_dev,inode=s.st_ino,mode=0o600,bytes=0,nlink=1,access=os.O_WRONLY,inheritable=True)) and
             stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1 and s.st_size <= 16<<20,
             'same actual child-open record from adapter through reaped target')
        row['captures'] = {k:dict(file=str(p.relative_to(output)),**fact(binary(p))) for k,p in
                           (('stdout',capture/'target.stdout'),('stderr',capture/'target.stderr'),('record',record))}
        preparation(dict(lane=1,mode=0,placement=0,control=0),row,subject,original,roots,objects,description,carrier,output,binary,r)
        r['record_closed'] = dict(parent_never_owned=True,child_reaped=row['reaped'],children_after=owner['children_after'])
        if a.kernel_callchains:
            samples = json.loads((capture/'samples.json').read_bytes())
            resolver = kernel.load(output/'kernel',r['kernel_snapshot'])
            r['kernel_counts'] = kernel.counts(samples,resolver,row['pid'])
            chains = callchain_counts(samples,resolver,row['pid'])
            need(chains['kernel_samples'] == r['kernel_counts']['kernel_samples'] and
                 chains['kernel_sampled_period_total'] == r['kernel_counts']['kernel_sampled_period_total'],
                 'all kernel caller samples and periods equal the unchanged leaf population')
            blob = (json.dumps(chains,sort_keys=True,separators=(',',':'))+'\n').encode()
            need(len(blob) <= 16<<20, 'complete bounded kernel caller table')
            with (output/'callchains.json').open('xb') as f:
                f.write(blob); f.flush(); os.fsync(f.fileno())
            r['callchains'] = dict(fact(binary(output/'callchains.json')),
                **{k:v for k,v in chains.items() if k not in ('disjoint','inclusive')})
            user = collections.Counter(); periods = collections.Counter(); bins = {}; user_n = user_period = 0
            for x in samples:
                if x['pid'] != row['pid'] or not x['in_target_exec_window']: continue
                need(x['cpumode'] in (1,2), 'only actual kernel/user modes inside target exec window')
                second = (x['time']-owner['release_ns'])//1_000_000_000
                need(0 <= second < 60, 'kernel-mode sample in original target wall interval')
                bucket = bins.setdefault(second,collections.Counter())
                bucket['kernel' if x['cpumode'] == 1 else 'user'] += x['period']
                if x['cpumode'] == 2:
                    key = (x['reason'],x['symbol']); user[key] += 1; periods[key] += x['period']
                    user_n += 1; user_period += x['period']
            need(sum(user.values()) == user_n and sum(periods.values()) == user_period,
                 'every actual in-window user leaf retained without fabricated user callchains')
            r['user_flat'] = dict(samples=user_n,sampled_period_total=user_period,
                rows=[dict(reason=k[0],symbol=k[1],samples=n,sampled_period_total=periods[k])
                      for k,n in sorted(user.items(),key=lambda x:(-x[1],str(x[0])))],user_callchains=False)
            r['timeline'] = [dict(second=s,period=sum(v.values()),cpumode_periods=dict(v)) for s,v in sorted(bins.items())]
            need(sum(x['period'] for x in r['timeline']) == user_period+r['kernel_counts']['kernel_sampled_period_total'],
                 'complete user-plus-kernel sampled-period timeline')
        else:
            symfs = output/'symfs'; copy = symfs/str(bridge).lstrip('/'); copy.parent.mkdir(parents=True)
            copy.write_bytes(bridge.read_bytes()); copy.chmod(0o444); pin(copy,fact(bridge))
            env = dict(owner['perf']['environment'],DEBUGINFOD_CACHE_PATH=str(capture/'cache'))
            text,unwind_err = run('user-dwarf-unwind',script_argv(perf,capture/'perf.data',symfs),env)
            r['unwinder_stderr'] = fact(output/'user-dwarf-unwind.stderr')
            r['attribution'] = attribute(capture,bridge,text,row['pid'])
            details = json.loads((capture/'unwound.json').read_bytes()); bins = {}
            for x in details:
                second = (x['time_ns']-owner['release_ns'])//1_000_000_000
                need(0 <= second < 60, 'sample in original target wall interval')
                bucket = bins.setdefault(second,collections.Counter()); bucket[x['leaf']] += x['period']
            r['timeline'] = [dict(second=s,period=sum(v.values()),leaf_periods=dict(v)) for s,v in sorted(bins.items())]
            need(sum(x['period'] for x in r['timeline']) == r['attribution']['period'], 'complete sampled-period timeline')
        r['target_outcome'] = 'exit_zero' if row['exit'] == 0 else 'failed_prefix'
        r['status'] = 'observed_kernel_callchains_diagnostic_only' if a.kernel_callchains else 'observed_user_dwarf_diagnostic_only'
    except BaseException as e: r['error'] = type(e).__name__+': '+str(e)
    finally:
        owner_path = output/'capture/owner.json'
        if owner_path.exists(): r['diagnostic'] = json.loads(owner_path.read_bytes())
        try:
            imported_sources(pin); stable(); r['source_unchanged'] = r['inputs_unchanged'] = True
            for p in output.rglob('*'):
                if p.is_file() and not p.is_symlink(): binary(p)
        except BaseException as e: r['final_errors'].append(type(e).__name__+': '+str(e))
        r['cleanup_complete'] = r.get('diagnostic',{}).get('closed') is True and all(
            c.get('reaped') is True and c.get('cleanup_errors') == [] and
            all(d.get('closed') is True for d in c.get('descriptors',[])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        r.update(inputs=pins,artifacts=artifacts,aliases=aliases,
            scope='One unchanged differential capture fixture with fresh record/namespace. User-only sampled stacks include both same-PID Python wrappers; wait4 independently records user/system CPU and RSS. No kernel stack, complete unwind, kill-cause, timing, successful-subject or qualification inference.')
        if a.kernel_callchains:
            r['scope'] = ('One unchanged differential capture fixture with fresh record/namespace and both same-PID wrappers. '
                'Actual99Hz user/kernel samples, kernel-only bounded callchains and flat user leaves. Core symbol intervals, '
                'named-anchor priority, unknowns and overlapping inclusive paths stay explicit; no complete unwind, wait4 usage, '
                'whole-CPU causal allocation, kill-cause, timing, successful-subject or qualification inference.')
        save(output/'receipt.json',r)
    print(json.dumps(dict(status=r['status'],target_exit=r.get('target',{}).get('exit'),receipt=str(output/'receipt.json'))),flush=True)
    return int(r['status'] != ('observed_kernel_callchains_diagnostic_only' if a.kernel_callchains else 'observed_user_dwarf_diagnostic_only'))


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--record-child': record_child(sys.argv[2],sys.argv[3])
    else: raise SystemExit(main())
