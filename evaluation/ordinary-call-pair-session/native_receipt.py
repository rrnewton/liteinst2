"""Private original-address prerequisite audit; no process launch or session loop.

The caller must authenticate this source and supply the root-frozen manifest
hash before execution. Fabricated JSON cannot supply the manifest's custody.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import types

ROOT = Path(__file__).resolve().parents[2]
MIB = 1048576
PROFILE = 'normal-call-pair-original-rust-v1'
LAUNCHER_SHA = '5665c1dd0b98ff0884fd3132ed807b33e814463d226158f532ea4605ea90b7e5'
SDK_SHA = '71b2377e8ac9539b4777a8181dccd4e23cdc56372e4cb60743ba94ccedd59c42'
SOURCE_PINS = {'evaluation/ordinary-module-session/reproduce.py': {'bytes': 57511, 'sha256': '4389493950775ca1c494bf7e28ff8326cbd61d2fbbda0ef53af953a4ff24f659'}, 'evaluation/ordinary-module-native/reproduce.py': {'bytes': 44878, 'sha256': '5cce60e76d7ec2011c8facb0a5c1101e0100e13aac8ed9b6317846de35fd3146'}, 'evaluation/ordinary-call-pair-native/reproduce.py': {'bytes': 45011, 'sha256': '540f43ef7c29fc2f260ed9cc25ca0c6c749d4ee0714e5705cf25938af4401ea6'}, 'evaluation/ordinary-csv/reproduce.py': {'bytes': 13439, 'sha256': 'ae70dac850876452d1f09a8480d4381a5814846e1a7e394a33f620bb00699cf3'}, 'evaluation/ordinary-module/reproduce.py': {'bytes': 17353, 'sha256': '60a73415980261fa1f1176f58423da8c77bf6775c2033def4f7469c74677c84c'}, 'evaluation/ordinary-rust-invoke-native/caller.py': {'bytes': 3565, 'sha256': 'aa2d28441c9b477e5e85fea0a61b160cb5026c55bbc129c2b40502c3a5d12d4c'}, 'evaluation/ordinary-call-pair-native/call_pair_native.py': {'bytes': 13366, 'sha256': '928933236372eb8ea8333e05b980708644d6196a2df50757262a2e4e7c41ce1c'}, 'tools/rapid-profiler/selected-work/check_output.py': {'bytes': 7232, 'sha256': '5855c42be2b9a42e85b121f9d8b763e51747f842c8cf85e05dc1736a4f10e4a9'}, 'evaluation/ordinary-rust-invoke-native/reproduce.py': {'bytes': 23732, 'sha256': '434ffdc1be5107a408767d81e85a77ee1a21878b482b8bcb0951e0ee4c4f38de'}, 'evaluation/ordinary-leaf-set-native/reproduce.py': {'bytes': 38376, 'sha256': 'b0aee80e836f0e78fba601d12cdbdbc86cff21a95bf8c1add71b490a5a7f6349'}, 'evaluation/ordinary-leaf-set-session/reproduce.py': {'bytes': 47290, 'sha256': 'be48a4c172579a93278a08b806f2820912033ac3795a2411706f6350c550a844'}, 'tools/rapid-profiler/reference-work/check_output.py': {'bytes': 17495, 'sha256': 'a5e0683ade47a94913afb53a15123a53b316172d8d9936f3a925b8a2b64b7189'}, 'tools/rapid-profiler/verify_normal_interval.py': {'bytes': 58210, 'sha256': '7a1e480c8fb815bb62165773650a0f8590c5bdc6ba39fc1189c63bceb1e085a7'}, 'tools/rapid-profiler/verify_strnlen_interval.py': {'bytes': 34037, 'sha256': '9a37fa20311984d5ba755458e7858578165e0d7a2df583599a1b2057e50e6126'}}
MODULES = {'recipe': 'evaluation/ordinary-module-session/reproduce.py', 'native': 'evaluation/ordinary-module-native/reproduce.py', 'native_recipe': 'evaluation/ordinary-call-pair-native/reproduce.py', 'csv': 'evaluation/ordinary-csv/reproduce.py', 'module': 'evaluation/ordinary-module/reproduce.py', 'caller': 'evaluation/ordinary-rust-invoke-native/caller.py', 'checker': 'evaluation/ordinary-call-pair-native/call_pair_native.py', 'census': 'tools/rapid-profiler/selected-work/check_output.py', 'copied': 'evaluation/ordinary-rust-invoke-native/reproduce.py', 'leaf': 'evaluation/ordinary-leaf-set-native/reproduce.py', 'library': 'evaluation/ordinary-leaf-set-session/reproduce.py', 'legacy': 'tools/rapid-profiler/reference-work/check_output.py', 'normal': 'tools/rapid-profiler/verify_normal_interval.py', 'whole': 'tools/rapid-profiler/verify_strnlen_interval.py'}
REQUIRED_NATIVE = ('evaluation/admission/processes.py', 'evaluation/ordinary-call-pair-native/README.md', 'evaluation/ordinary-call-pair-native/call_pair_native.py', 'evaluation/ordinary-call-pair-native/controls.py', 'evaluation/ordinary-call-pair-native/reproduce.py', 'evaluation/ordinary-call-pair-native/runner_controls.py', 'evaluation/ordinary-csv/reproduce.py', 'evaluation/ordinary-leaf-set-native/controls.py', 'evaluation/ordinary-leaf-set-native/leaf_set_native.py', 'evaluation/ordinary-leaf-set-native/reproduce.py', 'evaluation/ordinary-leaf-set-native/runner_controls.py', 'evaluation/ordinary-leaf-set-session/reproduce.py', 'evaluation/ordinary-module-native/controls.py', 'evaluation/ordinary-module-native/module_native.py', 'evaluation/ordinary-module-native/reproduce.py', 'evaluation/ordinary-module-session/controls.py', 'evaluation/ordinary-module-session/corpus.py', 'evaluation/ordinary-module-session/output.py', 'evaluation/ordinary-module-session/produce.py', 'evaluation/ordinary-module-session/reproduce.py', 'evaluation/ordinary-module/reproduce.py', 'evaluation/ordinary-rust-invoke-native/caller.py', 'evaluation/ordinary-rust-invoke-native/controls.py', 'evaluation/ordinary-rust-invoke-native/reproduce.py', 'evaluation/ordinary-rust-invoke-native/runner_controls.py', 'evaluation/ordinary-rust-invoke-native/rust_invoke.py', 'tests/call_tree_truth.rs', 'tests/support/native_call_pair.rs', 'tests/support/native_call_pair/parent.rs', 'tests/support/native_call_pair/phase.rs', 'tests/support/native_call_pair/tests.rs', 'tests/support/native_call_pair/trace.rs', 'tests/support/native_copied_capture.rs', 'tests/support/native_copied_rust.rs', 'tests/support/native_copied_rust/effects.rs', 'tests/support/native_normal_caller.rs', 'tests/support/native_normal_module.rs', 'tools/rapid-profiler/native-interval/normal/rust_invoke_artifact.rs', 'tools/rapid-profiler/normal-work/call_pair.c', 'tools/rapid-profiler/normal-work/csv_fields.c', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state.rs', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/caller.rs', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/check.rs', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/check/tests.rs', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/held.rs', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/lifecycle.rs', 'tools/rapid-profiler/selected-work/check_output.py', 'tools/rapid-profiler/strnlen-work/localize.map', 'tools/rapid-profiler/verify_normal_session.py', 'tools/unwind-oracle/bounded_command.py', 'tests/support/native_call_pair/witness.rs', 'tests/support/native_call_pair/trace_join.rs', 'tests/support/native_call_pair/trace_join/tests.rs', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/witness.rs')
SCOPE = ('Native original-address192 prerequisite only; no Schedule, K-exhaustion, '
         'FunctionClosed, bank-reuse, whole-worker, performance or full-A5 credit.')
ATTESTED = ('Original-address caller/E8/physical RET/full state remain native producer obligations.',
            'Owned normal closure and allocator return are source-joined, not new physical witnesses.',
            'Root manifest origin and exclusive no-writer custody are external obligations.',
            'Numeric coverage aggregates do not reconstruct dynamic set membership.')


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')


def _equal(actual, expected):
    # In particular, JSON true does not equal the required integer1.
    assert _canonical(actual) == _canonical(expected)


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            assert key not in result
            result[key] = value
        return result
    def invalid(value):
        raise AssertionError('nonfinite JSON')
    return json.loads(data.decode('ascii'), object_pairs_hook=pairs, parse_constant=invalid)


def _pin(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def _first(pins, name, actual, expected=None):
    if expected is not None:
        _equal(actual, _shape(expected))
    if name in pins:
        _equal(actual, pins[name])
    else:
        pins[name] = dict(actual)
    return pins[name]


def _shape(value, file=False):
    assert type(value) is dict and set(value) == ({'path', 'bytes', 'sha256'} if file else {'bytes', 'sha256'})
    assert type(value['bytes']) is int and 0 <= value['bytes'] <= 512*MIB
    assert type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256'])
    if file:
        assert type(value['path']) is str and len(value['path'].encode()) <= 4096
        _path(value['path'])
    return {k: value[k] for k in ('bytes', 'sha256')}


def _path(value):
    assert type(value) is str and '\0' not in value
    p = Path(value)
    assert p.is_absolute() and str(p) == value and '..' not in p.parts
    assert p.resolve(strict=True) == p
    return p


def _read(path, cap):
    # Literal bounded held-FD read contract from ordinary-module-session.
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap
        data = f.read(cap + 1)
        assert len(data) == before.st_size <= cap
        assert identity(before) == identity(os.fstat(f.fileno())) == identity(Path(path).lstat())
    return data


def _module(name, path, data):
    # Execute the exact authenticated source bytes, not a second pathname read.
    m = types.ModuleType('_call_pair_receipt_'+name)
    m.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), m.__dict__)
    return m


def _helpers():
    held = {}
    for name, value in SOURCE_PINS.items():
        data = _read(_path(str(ROOT/name)), MIB)
        _equal(_pin(data), value)
        held[name] = data
    return {name: _module(name, ROOT/path, held[path]) for name, path in MODULES.items()}


def _derive(h, module_symbols, parent_disassembly, child_disassembly, caller_disassembly, caller_symbols):
    n, r = h['native'], h['native_recipe']
    pv, pl = n.selection(module_symbols, 'csv_summary', 80)
    cv, cl = n.selection(module_symbols, 'csv_fields', 256)
    parent = r.parent_geometry(n.geometry(parent_disassembly, 'csv_summary', pv, pl), pv, pl, cv)
    child = dict(n.body_geometry(n.geometry(child_disassembly, 'csv_fields', cv, cl), cv, cl), elf_va=cv)
    shape = h['csv'].caller_geometry(caller_disassembly.decode('ascii'))
    h['module'].caller_symbols(caller_symbols.decode('ascii'), shape)
    decoded = n.geometry(caller_disassembly, 'liteinst_csv_call_and_store', shape['elf_va'], shape['length'])
    caller = h['caller'].geometry(decoded, shape['elf_va'], shape['length'])
    extra = r.stack_geometry(decoded, shape['elf_va'], shape['length'], 256)
    assert extra['delta'] == caller['subject_rsp_delta']
    assert extra['call_offset'] == caller['call_offset']
    assert extra['continuation_offset'] == caller['continuation_offset'] == shape['continuation_offset']
    caller['lowest_stack'] = extra['lowest_stack']
    h['checker'].geometry(parent, child, caller)
    return dict(parent=parent, child=child, caller=caller)


def derive_native_geometry(module_symbols, parent_disassembly, child_disassembly, caller_disassembly, caller_symbols):
    return _derive(_helpers(), module_symbols, parent_disassembly, child_disassembly, caller_disassembly, caller_symbols)


def _zero(closed):
    assert closed['cleanup_complete'] is True and closed['termination'] is None
    assert type(closed['exit_code']) is int and closed['exit_code'] == 0
    assert type(closed['reaped_descendants']) is int and closed['reaped_descendants'] == 0


def _root_guard(launcher, p, result, closed, request, protocol_sha):
    profile = launcher.validate_protocol(p)
    assert p['profile'] == 'call-pair-original-native'
    for key, expected in dict(profile=p['profile'], qualification=profile, revision=p['revision'], attempts=1,
            selected_outcome='CLOSED_EXIT_0', status='CLOSED_EXIT_0_RECIPE_AUDIT_REQUIRED',
            source_verified_after=True, protocol_sha256=protocol_sha, outer_seconds=1200, cleanup_seconds=3).items():
        _equal(result[key], expected)
    assert 'error' not in result
    timeout = result['owner_timeout_seconds']
    assert type(timeout) in (float, int) and math.isfinite(timeout) and 0 < timeout <= 1200
    _equal(closed, result['closed'])
    _zero(closed)
    argv, env = launcher.command_environment(p)
    _equal(request, dict(command=argv, env=env, cwd=p['paths']['root'], tag=p['tag'], profile=p['profile'],
        limits=p['limits'], protocol_sha256=protocol_sha, attempts=1, retries=0))
    return profile, env


def _closed_read(closed, reader):
    _zero(closed)
    return reader()


def _plan(r, revision, tag, cpus):
    return dict(revision=revision, stages=r.STAGES, catalog=r.catalog(), profile=PROFILE, attempts=1, retries=0,
        pairs=192, children=384, target_calls=768, target_returns=768, outer_returns=384, normal_reaps=384,
        pair_seconds=15, walk_steps=20000, native_cpu_seconds=480, native_wall_seconds=510, native_file_bytes=MIB,
        outer_seconds=1200, outer_log_bytes=8*MIB, reservation_tag=tag, affinity=cpus,
        reservation_authority='external hard owner only', scope=r.SCOPE)


def _result_header(result, r, revision, tag, cpus):
    for key, value in dict(kind='call-pair-original-native-release-v1', status='CALL_PAIR_ORIGINAL_NATIVE_LOCAL_COMPLETE',
            revision=revision, custody_closed=True, retention_verified=True, affinity=cpus,
            cpu_roles=dict(supervisor_build_controls=cpus, native_parent_and_tracees=cpus[1]),
            reservation_tag=tag, scope=r.SCOPE, originals=[], installed=[], controls=[], prerequisites={}).items():
        _equal(result[key], value)
    assert not any(key in result for key in ('error', 'final_error', 'projection_error'))
    assert [s['name'] for s in result['stages']] == list(r.STAGES)
    _equal(result['planned_stages'], result['stages'])
    for s in result['stages']:
        assert set(s) == {'name', 'status', 'closed'} and s['status'] == 'CLOSED_EXIT_0'
        _zero(s['closed'])
    b = result['evidence_budget']
    _equal({k:b[k] for k in ('limit','final_allowance','held_bytes','reservation_active','exceeded')},
           dict(limit=2048*MIB, final_allowance=64*MIB, held_bytes=0, reservation_active=False, exceeded=False))
    assert type(b['charged_rounded_bytes']) is int and 0 <= b['charged_rounded_bytes'] <= (2048-64)*MIB
    row = result['cohort']
    for key, value in dict(name='call-pair', status='LOCAL_NATIVE_CHECKS_COMPLETE', attempts=1,
            required_pairs=192, catalog=r.catalog(), prefix_error=None, affinity_before=cpus, affinity_after=cpus).items():
        _equal(row[key], value)
    _equal(row['closed'], result['stages'][-1]['closed'])


def _environment(p, tools):
    paths = p['paths']
    return dict(HOME=paths['user_home'], CARGO_HOME=paths['cargo_home'], PATH=paths['toolchain']+'/bin:/usr/bin:/bin',
        RUSTC=str(tools['rustc']), RUSTDOC=str(tools['rustdoc']), CC=str(tools['gcc']), CARGO_TARGET_DIR=str(ROOT/'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1',
        LITEINST_EVALUATION='1', TMPDIR=str(Path(paths['raw'])/'tmp'))


def _census(h, value, observed_sdk):
    r, n = h['native_recipe'], h['native']
    sdk = r.SDK_CONTROLS
    encoded = (json.dumps(list(sdk), separators=(',', ':'))+'\n').encode('ascii')
    assert len(sdk) == len(set(sdk)) == 30 and _pin(encoded)['sha256'] == SDK_SHA
    r.selected_inventory(observed_sdk, sdk)
    prior = n.calibration_manifest(h['legacy'], h['normal'], h['whole'])
    inventory = list(value['calibrations'])+[n.IGNORED]
    manifest = r.calibration_inventory(h['leaf'], prior, inventory, n.IGNORED)
    expected = dict(calibrations=manifest, ignored={n.IGNORED:n.IGNORE_REASON}, ordinary=r.ORDINARY_CONTROLS,
        sdk=sdk, core=r.CORE_CONTROLS, old_python=[n.PYTHON_CONTROLS,h['recipe'].PYTHON_CONTROLS,
        h['copied'].PYTHON_CONTROLS,h['copied'].RUNNER_CONTROLS,h['leaf'].LEAF_CONTROLS,h['leaf'].EFFICIENCY_RUNNER_CONTROLS],
        checker=r.PYTHON_CONTROLS, runner=r.RUNNER_CONTROLS)
    _equal(value, expected)
    return manifest


def _commands(h, raw, tools, bins):
    r, n = h['native_recipe'], h['native']
    commands = {}
    def add(name, argv, build=False):
        assert name not in commands
        commands[name] = (list(map(str,argv)), (120,180,128*MIB) if build else (20,30,MIB))
    for name in ('cc1','collect2','as','ld'): add('tool-'+name,[tools['gcc'],'-print-prog-name='+name])
    add('module-build',[tools['gcc'],*n.MODULE_FLAGS,ROOT/'tools/rapid-profiler/normal-work/call_pair.c','-o',raw/'module-trusted.so'])
    add('module-symbols',[tools['readelf'],'--wide','--syms',raw/'module-trusted.so'])
    for label,symbol,binary in [('parent','csv_summary',raw/'module-trusted.so'),('child','csv_fields',raw/'module-trusted.so'),
            ('application-caller','liteinst_csv_call_and_store',raw/'application-trusted')]:
        add(label+'-disassembly',[tools['objdump'],'-d','-M','intel','--insn-width=16','--disassemble='+symbol,binary])
    add('application-caller-symbols',h['recipe'].caller_symbol_command(tools,raw/'application-trusted'))
    cargo=['--locked','--offline','--release','--jobs','4','-p','rapid-profiler','--message-format=json-render-diagnostics']
    add('application-build',[tools['cargo'],'build','--bin','ordinary-interval',*cargo],True)
    add('state-build',[tools['cargo'],'test','--test','frontend-native-calibrations','--no-run',*cargo],True)
    add('ordinary-build',[tools['cargo'],'test','--bin','ordinary-interval','--no-run',*cargo],True)
    add('sdk-build',[tools['cargo'],'test','--lib','--no-run',*cargo],True)
    add('core-build',[tools['cargo'],'test','--lib','--no-run','--locked','--offline','--release','--jobs','4','-p','liteinst2','--message-format=json-render-diagnostics'],True)
    add('state-list',[bins['state'],'--list']);add('state-controls',[bins['state'],'--test-threads=1'])
    for target,subgroups in [('ordinary',[('ordinary-oracle-controls','oracle::native_ordinary::normal_caller::call_pair::'),
            ('ordinary-check-controls','normal::call_pair_state::check::tests::'),('ordinary-owner-controls','normal::call_pair_state::caller::tests::')]),
            ('sdk',[('frontend-controls','frontend_native::module::ordinary::call_pair::tests::'),('site-controls','frontend_native::always_on::site::ordinary::call_pair::tests::'),('runtime-controls','frontend_native::always_on::normal::call_pair::tests::')]),
            ('core',[('stack-profile-controls','trampoline::stack_profile_tests::'),('stack-trace-controls','frame_trace::tests::call_pair_stack::')])]:
        add(target+'-list',[bins[target],'--list'])
        for name,prefix in subgroups:add(name,[bins[target],prefix,'--test-threads=1'])
    for name,path in [('legacy-python-controls','ordinary-module-native/controls.py'),('session-python-controls','ordinary-module-session/controls.py'),
            ('copied-python-controls','ordinary-rust-invoke-native/controls.py'),('copied-runner-controls','ordinary-rust-invoke-native/runner_controls.py'),
            ('leaf-python-controls','ordinary-leaf-set-native/controls.py'),('leaf-runner-controls','ordinary-leaf-set-native/runner_controls.py'),
            ('python-controls','ordinary-call-pair-native/controls.py'),('runner-controls','ordinary-call-pair-native/runner_controls.py')]:
        add(name,[tools['python'],'-B',ROOT/'evaluation'/path,'-v'])
    assert set(commands) == set(r.STAGES[:-1]) and len(commands) == 36
    return commands


def _bounded(h, raw, tools, env, stage, command, request, receipt, closed, parent, stdout, stderr, pins, wanted):
    name=stage['name'];d=raw/name;io=raw/(name+'-io');argv,(cpu,wall,cap)=wanted
    helper=ROOT/'tools/unwind-oracle/bounded_command.py'
    _equal(request,dict(argv=argv,cwd=str(ROOT),env=env,stdout=str(io/'stdout.txt'),stderr=str(io/'stderr.txt'),cpu_seconds=cpu,wall_seconds=wall,file_bytes=cap))
    _equal(command,dict(argv=[str(tools['python']),'-B',str(helper),'--request',str(io/'request.json'),'--receipt',str(io/'receipt.json')],
        cwd=str(ROOT),env=env,wall_seconds=wall+25,log_bytes=MIB))
    _equal(closed,stage['closed']);_zero(closed)
    assert _pin(parent)['sha256']==closed['private_log_sha256']
    _equal(_json(parent),dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True))
    assert h['recipe'].bounded_join(receipt,closed,pins[str(io/'request.json')],pins[str(helper)],_pin(stdout),_pin(stderr))==0


def _outputs(h, get, result, raw):
    r,n,c=h['native_recipe'],h['native'],h['census']
    def streams(name,cap=MIB):return get(raw/(name+'-io')/'stdout.txt',cap),get(raw/(name+'-io')/'stderr.txt',cap)
    sdk=c.census(*streams('sdk-list'));manifest=_census(h,_json(get(raw/'controls.json',MIB)),sdk)
    state=c.census(*streams('state-list'))
    assert len(state)==len(set(state)) and set(state)==set(manifest)|{n.IGNORED}
    n.calibration_output(*streams('state-controls'),manifest)
    for target,wanted,names in [('ordinary',r.ORDINARY_CONTROLS,('ordinary-oracle-controls','ordinary-check-controls','ordinary-owner-controls')),
            ('sdk',r.SDK_CONTROLS,('frontend-controls','site-controls','runtime-controls')),
            ('core',r.CORE_CONTROLS,('stack-profile-controls','stack-trace-controls'))]:
        inventory=c.census(*streams(target+'-list'));r.selected_inventory(inventory,wanted)
        for name in names:
            request=_json(get(raw/(name+'-io')/'request.json',MIB));prefix=request['argv'][1]
            selected=[n for n in wanted if n.startswith(prefix)];assert selected
            c.controls(*streams(name),selected,inventory)
    n.python_output(*streams('legacy-python-controls'));h['recipe'].python_controls(*streams('session-python-controls'))
    for name,names in [('copied-python-controls',h['copied'].PYTHON_CONTROLS),('copied-runner-controls',h['copied'].RUNNER_CONTROLS),
            ('leaf-python-controls',h['leaf'].LEAF_CONTROLS),('leaf-runner-controls',h['leaf'].EFFICIENCY_RUNNER_CONTROLS),
            ('python-controls',r.PYTHON_CONTROLS),('runner-controls',r.RUNNER_CONTROLS)]:h['copied'].python_controls(*streams(name),names)
    assert streams('module-build')==(b'',b'')
    for name in ('module-symbols','parent-disassembly','child-disassembly','application-caller-disassembly','application-caller-symbols'):
        assert streams(name)[1]==b''
    geometry=_derive(h,*[streams(n)[0] for n in ('module-symbols','parent-disassembly','child-disassembly','application-caller-disassembly','application-caller-symbols')])
    _equal(geometry,_json(get(raw/'geometry.json',MIB)))
    parsed=h['checker'].check_with_work(get(raw/'native/output/call-pair-state-pairs.csv',524288),get(raw/'native/output/call-pair-state-coverage.csv',16384),get(raw/'native/output/call-pair-state-work.csv',524288),
        get(raw/'native/stdout.txt',1024),get(raw/'native/stderr.txt',MIB),**geometry)
    assert parsed['status']=='CALL_PAIR_ORIGINAL_TRANSCRIPT_VALIDATED'
    _equal(parsed['rows'],result['cohort']['observed']);_equal(parsed['comparisons'],result['cohort']['comparisons'])
    assert len(parsed['rows'])==192 and len(parsed['coverage'])==12
    assert [sum(r[k] for r in parsed['rows']) for k in ('target_calls','target_returns','outer_returns','normal_reaps')]==[768,768,384,384]
    return geometry,parsed


def accept_native(run, receipt_path, receipt_sha256, *, expected):
    """Audit an already closed prerequisite; never creates or renews an owner.

    run is the authenticated existing Run. expected and the manifest hash are
    frozen by the root before the session; they must not be filled from a result.
    """
    assert set(expected)=={'revision','protocol_pin','source_pins','tool_pins','module_pin','application_pin','geometry'}
    assert re.fullmatch('[0-9a-f]{40}',expected['revision']) and re.fullmatch('[0-9a-f]{64}',receipt_sha256)
    assert expected['revision']==run.a.revision and run.safe is True
    _equal(expected['source_pins'],run.sources)
    _equal(expected['tool_pins'],run.tool_pins)
    run.unchanged()
    h=_helpers();recipe=h['recipe'];r=h['native_recipe'];n=h['native'];first={}
    def take(path,cap,value=None):
        path=_path(str(path));data=_read(path,cap);actual=_pin(data)
        run.remember(path,_first(first,str(path),actual,value),cap=cap)
        return data
    def file(value,cap):
        return take(_path(value['path']),cap,_shape(value,True))
    data=take(receipt_path,16384);assert _pin(data)['sha256']==receipt_sha256
    manifest=_json(data);assert data==_canonical(manifest)
    assert set(manifest)=={'schema','version','revision','profile','protocol','launcher_result','recipe_result'}
    for key,value in dict(schema='call-pair-native-prerequisite-v1',version=1,revision=expected['revision'],profile=PROFILE).items():_equal(manifest[key],value)
    _equal(manifest['protocol'],expected['protocol_pin'])
    protocol_data=file(manifest['protocol'],2*MIB);p=_json(protocol_data);assert protocol_data==_canonical(p)
    assert p['revision']==expected['revision'] and p['paths']['root']==str(ROOT)
    assert p['launcher']['sha256']==LAUNCHER_SHA
    launcher_data=file(p['launcher'],MIB);launcher=_module('launcher',Path(p['launcher']['path']),launcher_data)
    launcher.validate_protocol(p)
    paths={k:Path(v) for k,v in p['paths'].items()};raw,capture=paths['raw'],paths['capture']
    def git(*args,directory=ROOT):
        value=subprocess.check_output([run.tools['git'],'-C',directory,*args],env=run.env,timeout=15)
        assert len(value)<=32*MIB;return value
    def names(extra,root_domain=False):
        selectors=['src',*(['crates'] if root_domain else []),'tests/support','tools/rapid-profiler','Cargo.toml','Cargo.lock','README.md','build.rs',*(['.cargo'] if root_domain else []),':(glob)**/Cargo.toml',*extra]
        found=git('ls-files','-z','--',*selectors).decode().rstrip('\0').split('\0')
        assert all(found) and len(found)==len(set(found)) and set(extra)<=set(found);return set(found)
    native_names=names(REQUIRED_NATIVE);root_names=names([*launcher.COMMON,*launcher.EXTRA[p['profile']]],True)
    assert set(p['source_pins'])==root_names
    # run's complete source inventory was authenticated to clean current Git by
    # its owner, then rechecked by unchanged() above. Do this join before logs.
    for name in native_names|root_names:
        value=expected['source_pins'][str(ROOT/name)];_shape(value)
        if name in root_names:_equal(p['source_pins'][name],value)
        take(ROOT/name,512*MIB,value)
    for name,value in SOURCE_PINS.items():_equal(expected['source_pins'][str(ROOT/name)],value)
    for name in ('native_receipt.py','receipt_controls.py'):
        take(ROOT/'evaluation/ordinary-call-pair-session'/name,MIB,expected['source_pins'][str(ROOT/'evaluation/ordinary-call-pair-session'/name)])
    allocator=_path(str(paths['allocator_root']))
    assert set(p['allocator_sources'])=={str(q.relative_to(allocator)) for q in (allocator/'py/dagrun').rglob('*.py')}
    assert git('rev-parse','HEAD',directory=allocator).decode().strip()==p['allocator_revision']
    for name,digest in p['allocator_sources'].items():
        source=take(allocator/name,MIB);assert _pin(source)['sha256']==digest
        assert source==git('show',p['allocator_revision']+':'+name,directory=allocator)
    tools={key:_path(value['path']) for key,value in p['tools'].items()}
    for key in ('cargo','rustc','rustdoc','git','gcc','readelf','objdump','bash','rg','python'):
        assert tools[key]==run.tools[key]
    for value in p['tools'].values():
        _equal(_shape(value,True),expected['tool_pins'][value['path']]);file(value,512*MIB)
    assert manifest['launcher_result']['path']==str(capture/'result.json') and manifest['recipe_result']['path']==str(raw/'result.json')
    root_result=_json(file(manifest['launcher_result'],256*1024));rootpins=root_result['retained']
    rootpaths={capture/'protocol.json',capture/'request.json',capture/'closed.json',capture/'outer.log',paths['log_dir']/'outer.log'}
    assert set(rootpins)==set(map(str,rootpaths))
    def rootget(path,cap):return take(path,cap,rootpins[str(path)])
    _equal(_json(rootget(capture/'protocol.json',2*MIB)),p)
    closed=_json(rootget(capture/'closed.json',MIB));request=_json(rootget(capture/'request.json',MIB))
    profile,outer_env=_root_guard(launcher,p,root_result,closed,request,_pin(protocol_data)['sha256'])
    # This is the first output read. Unknown/nonzero closure never reaches it.
    log=_closed_read(closed,lambda:launcher.closed_log(closed,lambda:rootget(paths['log_dir']/'outer.log',8*MIB)))
    assert rootget(capture/'outer.log',8*MIB)==log
    reservation=launcher.allocator_return(log,closed,profile);_equal(reservation,root_result['reservation'])
    assert reservation['status']=='SOURCE_JOINED_NORMAL_ALLOCATOR_RETURN' and reservation['ledger_readback'] is False
    _equal(root_result['allocator_execution_paths'],launcher.execution_paths(p,outer_env))
    cpus=sorted(reservation['cores']);assert len(cpus)==len(set(cpus))==3
    result=_json(file(manifest['recipe_result'],16*MIB));_result_header(result,r,expected['revision'],p['tag'],cpus)
    _equal(reservation['recipe_summary'],dict(status=result['status'],profile=PROFILE,cohort_status=result['cohort']['status'],attempts=1,
        observed_rows=192,custody_closed=True,external_owner_required=True,scope=r.SCOPE))
    retained=result['retained'];assert type(retained) is dict and retained
    _equal(result['build_space_exclusions'],[str(raw/'tmp')])
    for name,value in retained.items():
        q=_path(name);assert q.is_relative_to(raw) or q.is_relative_to(ROOT/'target')
        assert not q.is_relative_to(raw/'tmp');_shape(value)
    def get(path,cap):return take(path,cap,retained[str(path)])
    sources=_json(get(raw/'sources-before.json',16*MIB))
    _equal(sources,_json(get(raw/'sources-after.json',16*MIB)))
    for key in ('sources_before','sources_after'):_equal(result[key],retained[str(raw/('sources-'+key.split('_')[1]+'.json'))])
    assert set(sources)=={str(ROOT/name) for name in native_names}
    for name in native_names:_equal(sources[str(ROOT/name)],expected['source_pins'][str(ROOT/name)])
    native_tools=_json(get(raw/'tools.json',MIB));_equal(native_tools,result['tool_pins'])
    _equal(result['tools'],retained[str(raw/'tools.json')])
    for name,value in native_tools.items():
        _equal(value,expected['tool_pins'][name]);take(_path(name),512*MIB,value)
    required_tools={str(tools[key]) for key in ('cargo','rustc','rustdoc','git','gcc','readelf','objdump','bash','rg','python')}
    env=_environment(p,tools);r.tool_alias(tools,env)
    for label in ('cc1','collect2','as','ld'):
        stdout=get(raw/('tool-'+label+'-io')/'stdout.txt',MIB);assert get(raw/('tool-'+label+'-io')/'stderr.txt',MIB)==b''
        assert stdout.endswith(b'\n') and stdout.count(b'\n')==1
        report=stdout[:-1].decode('utf-8');tool=Path(report) if '/' in report else Path(h['native_recipe'].shutil.which(report,path=env['PATH']) or '')
        tool=tool.resolve(strict=True);assert tool.is_absolute();required_tools.add(str(tool));assert str(tool) in native_tools
    assert set(native_tools)==required_tools
    bins={}
    for label,target,source,kind,test in [('application','ordinary-interval','ordinary-interval/main.rs','bin',False),
            ('state','frontend-native-calibrations','native-interval/calibrations.rs','test',True),('ordinary','ordinary-interval','ordinary-interval/main.rs','bin',True),
            ('sdk',None,None,None,None),('core',None,None,None,None)]:
        out=get(raw/(label+'-build-io')/'stdout.txt',128*MIB)
        binary,product=(h['library'].library_artifact(out) if label=='sdk' else r.core_product(out) if label=='core' else n.artifact(out,target,source,kind,test))
        assert binary.resolve(strict=True)==binary;get(binary,512*MIB)
        _equal(_json(get(raw/(label+'-artifact.json'),MIB)),dict(product=product,binary=retained[str(binary)]));bins[label]=binary
    commands=_commands(h,raw,tools,bins)
    for stage in result['stages'][:-1]:
        name=stage['name'];io=raw/(name+'-io');d=raw/name;cap=commands[name][1][2]
        _bounded(h,raw,tools,env,stage,_json(get(d/'command.json',MIB)),_json(get(io/'request.json',MIB)),
            _json(get(io/'receipt.json',MIB)),_json(get(d/'closed.json',MIB)),get(d/'parent.log',MIB),get(io/'stdout.txt',cap),get(io/'stderr.txt',cap),sources|retained,commands[name])
        assert get(ROOT/'target/evaluation'/raw.name/(name+'.log'),MIB)==get(d/'parent.log',MIB)
    _equal(_json(get(raw/'initial-plan.json',MIB)),_plan(r,expected['revision'],p['tag'],cpus))
    _equal(_json(get(raw/'native/attempt.json',MIB)),dict(status='FAILED',attempts=1))
    g=expected['geometry'];h['checker'].geometry(**g)
    req=_json(get(raw/'native/request.json',MIB));r.request_shape(req,cpus)
    _equal({k:v for k,v in req.items() if k!='pins'},dict(argv=list(map(str,[raw/'application-candidate','normal-call-pair-state',raw/'module-candidate.so',raw/'module-trusted.so',
        g['parent']['elf_va'],g['parent']['length'],g['child']['elf_va'],g['child']['length'],raw/'application-candidate',raw/'application-trusted',raw/'native/output',cpus[1]])),
        cwd=str(ROOT),env=env,stdout=str(raw/'native/stdout.txt'),stderr=str(raw/'native/stderr.txt'),cpu=cpus[1]))
    allpins=sources|native_tools|retained
    # Exactly the pins present before request creation; subsequent native evidence
    # and final publication cannot be retroactively placed in its input manifest.
    later={str(raw/'native/request.json'),str(raw/'native/attempt.json'),str(raw/'native-outer/command.json'),str(raw/'native-outer/closed.json'),
        str(raw/'native-outer/parent.log'),str(ROOT/'target/evaluation'/raw.name/'native-outer.log'),str(raw/'sources-after.json'),str(raw/'public-result.json')}
    later.update(name for name in retained if Path(name).is_relative_to(raw/'native') and name!=str(raw/'native/request.json'))
    _equal(req['pins'],{name:value for name,value in allpins.items() if name not in later})
    native_command=dict(argv=[str(tools['python']),'-B',str(ROOT/'evaluation/ordinary-call-pair-native/reproduce.py'),'--native-request',str(raw/'native/request.json'),retained[str(raw/'native/request.json')]['sha256']],cwd=str(ROOT),env=env,wall_seconds=510,log_bytes=MIB)
    _equal(_json(get(raw/'native-outer/command.json',MIB)),native_command)
    nc=_json(get(raw/'native-outer/closed.json',MIB));_equal(nc,result['stages'][-1]['closed']);_zero(nc)
    assert get(raw/'native-outer/parent.log',MIB)==get(ROOT/'target/evaluation'/raw.name/'native-outer.log',MIB)==b''
    assert nc['private_log_sha256']==_pin(b'')['sha256']
    output=raw/'native/output'
    assert output.is_dir() and not output.is_symlink()
    assert {q.name for q in output.iterdir()}=={'call-pair-state-pairs.csv','call-pair-state-coverage.csv','call-pair-state-work.csv'}
    for name in ('module-trusted.so','module-candidate.so'):_equal(retained[str(raw/name)],expected['module_pin']);get(raw/name,MIB)
    for name in ('application-trusted','application-candidate'):_equal(retained[str(raw/name)],expected['application_pin']);get(raw/name,512*MIB)
    _equal(retained[str(bins['application'])],expected['application_pin'])
    for paths_to_check in ((raw/'module-trusted.so',raw/'module-candidate.so'),(bins['application'],raw/'application-trusted',raw/'application-candidate')):
        stats=[q.stat() for q in paths_to_check];assert len({(s.st_dev,s.st_ino) for s in stats})==len(stats)
        assert all(stat.S_ISREG(s.st_mode) for s in stats)
    assert (raw/'application-candidate').stat().st_mode & 0o777==0o700
    geometry,parsed=_outputs(h,get,result,raw);_equal(geometry,expected['geometry'])
    _equal(result['geometry'],retained[str(raw/'geometry.json')])
    public_input=dict(result,cohort=dict(result['cohort'],catalog=r.catalog()))
    _equal(_json(get(raw/'public-result.json',16*MIB)),r.public_projection(public_input))
    _equal(result['public_projection'],retained[str(raw/'public-result.json')])
    # Retain/check every original completed pin, including nonessential diagnostic
    # streams. Never turn a final observation into a new expected hash.
    for name,value in retained.items():take(Path(name),512*MIB,value)
    for name,value in first.items():_equal(_pin(_read(Path(name),max(MIB,value['bytes']))),value)
    run.unchanged();r.tool_alias(tools,env)
    return dict(status='CALL_PAIR_NATIVE_PREREQUISITE_ACCEPTED',revision=expected['revision'],profile=PROFILE,
        receipt=dict(path=str(receipt_path),**first[str(receipt_path)]),protocol=manifest['protocol'],launcher_result=manifest['launcher_result'],
        recipe_result=manifest['recipe_result'],geometry=geometry,module_pin=expected['module_pin'],application_pin=expected['application_pin'],
        rows=parsed['rows'],coverage=parsed['coverage'],counts=dict(pairs=192,children=384,normal_reaps=384,target_calls=768,target_returns=768,outer_returns=384),
        source_attested=list(ATTESTED),scope=SCOPE)
