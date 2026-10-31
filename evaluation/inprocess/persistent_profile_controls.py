"""Five exact retained-input refusals; no target, perf, or unwind execution."""
import argparse, hashlib, json, os, re, resource, shutil, signal, struct, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = 'evaluation/inprocess/persistent_profile_controls.py'
MODULES = ('evaluation/inprocess/persistent_dynamic_profile_read.py',
           'evaluation/inprocess/page_cost_profile_read.py')
BOUNDS = (30, 1 << 30, 128 << 20, 80)
EXPECTED = (
    'each no-inherit ID_INDEX binds one actual event/any-CPU/attached thread',
    'complete sample on reserved CPU',
    'DWARF sample PID/TID equals the actual attached ID_INDEX thread',
    'exact no-inherit DUMMY retains task/MMAP2/COMM_EXEC child tracking',
    'exact attached-thread EXIT only; no unbound child scope',
)


def need(value, message):
    if not value:
        raise ValueError(message)


def fact(path):
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def context(root, receipt_path, expected=None):
    raw = receipt_path.read_bytes()
    need(0 < len(raw) <= 16 << 20, 'bounded complete supplied receipt')
    driver = fact(Path(__file__).resolve())
    receipt_fact = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    if expected is not None:
        need([receipt_fact['sha256'], driver['sha256']] == expected,
             'parent-bound actual receipt and portable driver')
    receipt = json.loads(raw)
    need(re.fullmatch('[0-9a-f]{40}', receipt['source_revision']) and
         receipt['profile'] == 'persistent-resident-per-thread-user-dwarf-counters-v3',
         'exact closed v3 producer domain and revision')
    pins = {str(receipt_path):receipt_fact, str(Path(__file__).resolve()):driver}
    def pin(path, wanted):
        path = path.resolve(strict=True)
        wanted = {key:wanted[key] for key in ('bytes','sha256')}
        need(fact(path) == wanted, 'exact retained input: '+str(path))
        need(str(path) not in pins or pins[str(path)] == wanted, 'consistent input identity')
        pins[str(path)] = wanted
        return path
    owner_path = receipt_path.parent/'capture/owner.json'
    owner_raw = owner_path.read_bytes(); owner = json.loads(owner_raw)
    need(receipt['diagnostic'] == owner, 'whole actual protected owner receipt')
    pin(owner_path, dict(bytes=len(owner_raw), sha256=hashlib.sha256(owner_raw).hexdigest()))
    need(receipt['status'] == 'observed_unqualified'
         and receipt['source_unchanged'] is True and receipt['cleanup_complete'] is True
         and receipt['error'] is None and receipt['final_errors'] == [], 'exact closed loss-free producer')
    need(owner['closed'] is True and owner['error'] is None and owner['target']['exit'] == -9
         and owner['sampling']['loss_free'] is True and owner['sampling']['lost_samples'] == 0
         and owner['sampling']['full_exec_exit_envelope'] is True,
         'preserved failed target and actual positive parser baseline')
    need(owner['format'] == receipt['profile'] and owner['cpu'] == receipt['cpu'] and
         owner['inputs_before'] == owner['inputs_after'] and owner['cleanup_errors'] == [] and
         owner['children_before'] == owner['children_after'] == 'ECHILD' and
         receipt['bounds']['profiler'] == list(BOUNDS), 'complete original observer and input closure')
    for name in MODULES:
        matches = [(p,v) for p,v in owner['inputs_before'].items() if p.endswith('/'+name)]
        need(len(matches) == 1 and receipt['inputs'][matches[0][0]] ==
             {k:matches[0][1][k] for k in ('bytes','sha256')}, 'one source-owned reader input')
        pin(root/name, matches[0][1])
    python = Path(sys.executable).resolve()
    recorded_python = owner['wrapper_argv'][0]
    need(receipt['observer_tools']['wrapper_python'] ==
         {k:owner['inputs_before'][recorded_python][k] for k in ('bytes','sha256')},
         'actual producer Python joins its owner input')
    pin(python, receipt['observer_tools']['wrapper_python'])
    perf = pin(receipt_path.parent/'capture/perf.data', owner['captures']['perf.data'])
    identity = owner['bridge_identity_after']
    bridge = Path(identity['after']['pathname'])
    need(bridge.is_absolute() and receipt['bridge'] == {k:identity[k] for k in ('bytes','sha256')}
         and receipt['bridge'] == {k:owner['inputs_before'][str(bridge)][k] for k in ('bytes','sha256')},
         'whole actual ELF joins owner and producer')
    bridge = pin(bridge, receipt['bridge'])
    spec = dict(revision=receipt['source_revision'], perf=str(perf), bridge=str(bridge),
        modules=MODULES, driver=driver, receipt=receipt_fact, python=fact(python),
        capture_cpu=owner['cpu'], target_exit=owner['target']['exit'],
        hardware={k:receipt['hardware'][k] for k in ('architecture','vendor_id','model name',
            'cpu family','model','stepping','microcode','kernel_version')})
    return spec, owner, pins


def stable(pins):
    for name, expected in pins.items():
        need(fact(Path(name)) == expected, 'unchanged original input: '+name)


def worker(root, out, receipt_path, expected):
    spec, owner, pins = context(root, receipt_path, expected)
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         'isolated standard-library startup')
    need(len(os.sched_getaffinity(0)) == 1, 'one externally reserved CPU')
    for key, bound in zip((resource.RLIMIT_CPU, resource.RLIMIT_AS, resource.RLIMIT_FSIZE), BOUNDS):
        need(resource.getrlimit(key) == (bound, bound), 'original observer resource bound')
    sys.path.insert(0, str(root/'evaluation/inprocess'))
    import persistent_dynamic_profile_read as reader
    original = (root/spec['perf']).read_bytes()
    header, entry, attrs, attrbytes, start, size = struct.unpack_from('<6Q', original, 8)
    need((header, entry, attrbytes) == (104, 160, 320), 'actual complete paired attributes')
    positions = {}; cursor = start
    while cursor < start+size:
        kind, misc, length = struct.unpack_from('<IHH', original, cursor)
        need(length >= 8 and cursor+length <= start+size, 'actual complete record extent')
        if kind in (69, 9, 4): positions.setdefault(kind, []).append(cursor)
        cursor += length
    need(cursor == start+size and len(positions[69]) == len(positions[4]) == 1
         and positions[9], 'one actual ID_INDEX/EXIT and real samples')
    index = positions[69][0]; sample = positions[9][0]; exit_at = positions[4][0]
    cpu = owner['cpu']; pid = owner['target']['pid']
    changes = (
        ('id_index_sentinel', index+32, '<Q', (1 << 64)-1, cpu),
        ('sample_cpu', sample+40, '<I', cpu, cpu ^ 1),
        ('sample_pid_tid', sample+24, '<II', (pid, pid), (pid+1, pid+1)),
        ('dummy_task_flag', attrs+entry+40, '<Q', 0x463963761, 0x463963761 ^ (1 << 13)),
        ('exit_becomes_fork', exit_at, '<I', 4, 7),
    )
    rows = []; scratch = out/'scratch'; scratch.mkdir()
    try:
        for (name, offset, fmt, before, after), expected in zip(changes, EXPECTED):
            before = before if isinstance(before, tuple) else (before,)
            after = after if isinstance(after, tuple) else (after,)
            need(struct.unpack_from(fmt, original, offset) == before, 'actual mutation operand '+name)
            changed = bytearray(original); struct.pack_into(fmt, changed, offset, *after)
            need(changed[:offset] == original[:offset] and
                 changed[offset+struct.calcsize(fmt):] == original[offset+struct.calcsize(fmt):]
                 and changed != original, 'one exact mutation '+name)
            case = scratch/name; case.mkdir(); path = case/'perf.data'; path.write_bytes(changed)
            row = dict(name=name, offset=offset, before=list(before), after=list(after),
                       mutant=fact(path), expected=expected, status='failed')
            rows.append(row); began = time.monotonic_ns()
            try:
                try:
                    reader.summarize(path, root/spec['bridge'], pid, cpu, case,
                        owner['release_ns'], owner['target_exit_ready_ns'],
                        bridge_identity=owner['bridge_identity_after'], per_thread=True,
                        online_range=tuple(owner['online_cpu_range']))
                except ValueError as error:
                    row['observed'] = str(error)
                    need(str(error) == expected, 'wrong refusal for '+name+': '+str(error))
                else:
                    raise ValueError('mutated input accepted: '+name)
                row['status'] = 'rejected_exactly'
            finally:
                row['elapsed_ns'] = time.monotonic_ns()-began
                shutil.rmtree(case)
                (out/'controls.json').write_text(json.dumps(rows, sort_keys=True, indent=2)+'\n')
        allowed = {str((root/name).resolve()) for name in spec['modules']} | {str(Path(__file__).resolve())}
        for module in tuple(sys.modules.values()):
            name = getattr(module, '__file__', None)
            if name:
                path = Path(name).resolve()
                need(str(path) in allowed or path.is_relative_to(Path(sys.base_prefix).resolve()),
                     'standard library or exact two-reader import closure: '+str(path))
        need(len(rows) == 5 and all(x['status'] == 'rejected_exactly' for x in rows), 'all five exact refusals')
    finally:
        shutil.rmtree(scratch)
        stable(pins)


def limits():
    for key, bound in zip((resource.RLIMIT_CPU, resource.RLIMIT_AS, resource.RLIMIT_FSIZE), BOUNDS):
        resource.setrlimit(key, (bound, bound))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', nargs=2, help=argparse.SUPPRESS)
    args = parser.parse_args(); root = ROOT; out = args.output.resolve()
    receipt_path = args.receipt.resolve(strict=True)
    need(Path(__file__).resolve() == root/SCRIPT and not sys.flags.optimize,
         'canonical repository script with assertions enabled')
    out.relative_to(root/'target'); need(out != root/'target', 'private fresh child directory only')
    if args.worker:
        worker(root, out, receipt_path, args.worker); return
    spec, owner, pins = context(root, receipt_path)
    need(len(os.sched_getaffinity(0)) == 1, 'one externally reserved CPU')
    out.mkdir(); started = time.monotonic_ns()
    argv = [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()),
            '--receipt', str(receipt_path), '--output', str(out), '--worker',
            spec['receipt']['sha256'], spec['driver']['sha256']]
    result = dict(status='failed', revision=spec['revision'], argv=argv, bounds=list(BOUNDS),
        affinity=sorted(os.sched_getaffinity(0)), target_executions=0, perf_executions=0,
        qualification=False, performance_credit=False, inputs=pins, error=None, final_errors=[])
    child = None
    try:
        with (out/'stdout').open('xb') as stdout, (out/'stderr').open('xb') as stderr:
            child = subprocess.Popen(argv, cwd=root, env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},
                stdout=stdout, stderr=stderr, start_new_session=True, preexec_fn=limits)
            try: result['exit'] = child.wait(timeout=BOUNDS[3])
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL); result['exit'] = child.wait(); raise
        need(result['exit'] == 0, 'bounded reader child must pass all five exact refusals')
        result['controls'] = json.loads((out/'controls.json').read_bytes())
        need(len(result['controls']) == 5 and
             [x['expected'] for x in result['controls']] == list(EXPECTED) and
             all(x['status'] == 'rejected_exactly' for x in result['controls']), 'complete actual five-control result')
        result['status'] = 'passed'
    except BaseException as error:
        result['error'] = type(error).__name__+': '+str(error)
    finally:
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL); child.wait()
        # Only this fresh invocation's scratch is ever removed, including a timeout.
        if (out/'scratch').exists(): shutil.rmtree(out/'scratch')
        result['cleanup_complete'] = child is not None and child.poll() is not None and not (out/'scratch').exists()
        try: stable(pins); result['inputs_unchanged'] = True
        except BaseException as error:
            result['inputs_unchanged'] = False; result['final_errors'].append(str(error)); result['status'] = 'failed'
        result['elapsed_ns'] = time.monotonic_ns()-started
        result['captures'] = {p.name:fact(p) for p in out.iterdir() if p.is_file()}
        (out/'RESULT.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
        summary = dict(schema=1, status=result['status'], capture_revision=spec['revision'],
            source_profile='persistent-resident-per-thread-user-dwarf-counters-v3',
            source_target_exit=spec['target_exit'], capture_cpu=spec['capture_cpu'],
            capture_hardware=spec['hardware'], control_affinity=result['affinity'], bounds=list(BOUNDS),
            elapsed_ns=result['elapsed_ns'], control_count=len(result.get('controls',[])),
            controls=result.get('controls',[]), cleanup_complete=result['cleanup_complete'],
            inputs_unchanged=result['inputs_unchanged'], target_executions=0, perf_executions=0,
            qualification=False, performance_credit=False,
            receipt=spec['receipt'], private_result=fact(out/'RESULT.json'),
            script=spec['driver'], python=spec['python'],
            perf_input=pins[spec['perf']], bridge=pins[spec['bridge']],
            readers={Path(name).name:pins[str(root/name)] for name in MODULES},
            reproduction=['python3','-I','-S','-B',SCRIPT,'--receipt','<closed-v3-receipt.json>',
                '--output','target/<fresh-private-output>'],
            scope='Exactly five mutations of one retained real capture; one externally reserved CPU. '
                  'No original target, perf or unwind rerun. The original failed target stays failed.')
        text = json.dumps(summary, sort_keys=True, indent=2)+'\n'
        need(len(text.encode()) <= 32 << 10, 'bounded sanitized public summary')
        (out/'summary.json').write_text(text)
    raise SystemExit(0 if result['status'] == 'passed' else 1)


if __name__ == '__main__':
    main()
