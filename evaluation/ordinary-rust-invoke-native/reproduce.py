#!/usr/bin/env python3
"""One fixed release copied-Rust-body cohort; no Schedule or performance claim.

Use a fresh hard three-CPU reservation and external 1200-second/8 MiB owner.
The traced cohort uses the middle reserved CPU, a 510-second outer wall and
480 CPU seconds per process; unchanged native pair bounds remain 15s/20000.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MIB = 1048576
SCOPE = ('Complete extracted Rust caller body under explicit machine entry conditions only; '
         'no application-callsite Rust ABI, original-address, whole worker, Schedule, '
         'performance or full-A5 qualification.')
STAGES = tuple('tool-'+n for n in ('cc1', 'collect2', 'as', 'ld')) + (
    'module-build', 'module-symbols', 'csv_fields-disassembly', 'strnlen-disassembly',
    'application-build', 'application-caller-disassembly', 'application-caller-symbols',
    'native-build', 'state-build', 'state-list', 'state-controls',
    'legacy-python-controls', 'session-python-controls', 'python-controls', 'runner-controls', 'native-outer')
RUNNER_CONTROLS = ('test_complete_caller_geometry_and_all_stack_operations',
                   'test_caller_extent_flow_stack_and_geometry_refusals',
                   'test_request_coordinates_and_cpu_are_exact',
                   'test_fixed_plan_and_closure_cannot_relabel_failure')
# The checker control inventory is frozen independently in the source packet.
PYTHON_CONTROLS = ('test_complete_fixed_population_preserves_raw_tables_and_scope', 'test_all_framing_columns_and_unsigned_domains', 'test_population_order_missing_duplicate_extra_rows', 'test_selected_inputs_results_and_raw_outer_rax', 'test_comparisons_steps_and_terminal_conservation', 'test_caller_parent_geometry_is_required', 'test_selected_body_geometry_and_ret_union_are_required', 'test_csv_subset_and_length_full_coverage_are_distinct', 'test_length_read_domains_and_csv_absence_are_required', 'test_source_local_import_and_optimization_refusal')


def python_controls(stdout, stderr, names):
    assert stdout == b'' and type(stderr) is bytes and names and len(names) == len(set(names))
    lines = stderr.decode('ascii').splitlines()
    assert len(lines) == len(names)+5
    for name, line in zip(sorted(names), lines):
        assert re.fullmatch(re.escape(name)+r' \(__main__\.Controls(?:\.'+re.escape(name)+r')?\) \.\.\. ok', line)
    tail = lines[len(names):]
    assert tail[0] == tail[3] == '' and tail[4] == 'OK' and re.fullmatch('-+', tail[1])
    assert re.fullmatch(rf'Ran {len(names)} tests in [0-9]+\.[0-9]+s', tail[2])


def request_shape(request, cpus):
    assert set(request) == {'argv', 'cwd', 'env', 'stdout', 'stderr', 'pins', 'cpu'}
    assert type(cpus) is list and len(cpus) == 3 and cpus == sorted(set(cpus))
    assert all(type(cpu) is int and 0 <= cpu < 1024 for cpu in cpus)
    assert type(request['cpu']) is int and request['cpu'] == cpus[1]
    argv = request['argv']
    assert type(argv) is list and len(argv) == 11 and all(type(x) is str and '\0' not in x for x in argv)
    assert argv[:2] == [str(ROOT/'target/release/frontend-native-oracle'), 'normal-rust-invoke-state']
    assert all(re.fullmatch('[1-9][0-9]{0,19}', argv[i]) for i in (4, 5, 6, 7))
    cv, cl, lv, ll = map(int, argv[4:8])
    assert 5 <= cl <= 256 and 5 <= ll <= 80
    assert cv + cl <= lv and lv + ll < 1 << 64 and cv//4096 == (lv+ll-1)//4096
    cohort = Path(request['stdout']).parent; raw = cohort.parent
    assert raw.is_absolute() and raw.resolve(strict=True) == raw and raw.is_relative_to(ROOT/'ignored')
    assert cohort.name == 'native' and cohort.resolve(strict=True) == cohort
    assert request['stdout'] == str(cohort/'stdout.txt') and request['stderr'] == str(cohort/'stderr.txt')
    assert argv[2:4] == [str(raw/'module-candidate.so'), str(raw/'module-trusted.so')]
    assert argv[8:] == [str(raw/'application-candidate'), str(raw/'application-trusted'), str(cohort/'output')]
    assert request['cwd'] == str(ROOT) and type(request['env']) is dict and request['env']['LITEINST_EVALUATION'] == '1'
    assert {str(HERE/'reproduce.py'), argv[0], *argv[2:4], *argv[8:10]} <= request['pins'].keys()
    return cohort


def native_exec(path, expected_hash):
    # Bootstrap every imported helper from the closed request's source pins.
    assert re.fullmatch('[0-9a-f]{64}', expected_hash)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        before = os.fstat(f.fileno()); assert stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MIB
        data = f.read(MIB+1); after = os.fstat(f.fileno())
        assert before == after and len(data) == before.st_size
    assert hashlib.sha256(data).hexdigest() == expected_hash
    req = json.loads(data); cpus = sorted(os.sched_getaffinity(0)); cohort = request_shape(req, cpus)
    assert path == cohort/'request.json'
    helper = ROOT/'evaluation/ordinary-module-native/reproduce.py'
    content = helper.read_bytes(); assert len(content) <= MIB
    assert req['pins'][str(helper)] == dict(bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
    spec = importlib.util.spec_from_file_location('_copied_native_limits', helper)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    module.pins_ok(req['pins'])
    os.sched_setaffinity(0, {req['cpu']}); assert sorted(os.sched_getaffinity(0)) == [req['cpu']]
    # Exact existing same-PID 480CPU/1MiB/510wall native owner contract.
    module._native_exec(path, expected_hash, lambda value: request_shape(value, cpus))


def accept_closure(row, closed, parent_log):
    assert row['status'] == 'FAILED' and type(row['attempts']) is int and row['attempts'] == 1
    assert closed['cleanup_complete'] is True
    assert hashlib.sha256(parent_log).hexdigest() == closed['private_log_sha256']
    assert type(closed['exit_code']) is int and closed['exit_code'] == 0 and closed['termination'] is None
    assert type(closed['reaped_descendants']) is int and closed['reaped_descendants'] == 0
    assert parent_log == b''


def fixed_row():
    return dict(status='UNRUN', attempts=0, required_pairs=48, required_children=96,
                required_target_calls=96, required_target_returns=96,
                required_outer_returns=96, required_normal_reaps=96)


def main():
    started = time.monotonic()
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    ap.add_argument('--reservation-tag', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    assert re.fullmatch('[A-Za-z0-9_.-]{1,128}', a.reservation_tag)
    assert HERE == ROOT/'evaluation/ordinary-rust-invoke-native'
    for p in (ROOT, a.toolchain, a.user_home, a.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert a.raw.is_absolute() and a.raw.parent.resolve(strict=True) == a.raw.parent
    assert a.raw.is_relative_to(ROOT/'ignored') and not os.path.lexists(a.raw)
    assert not os.path.lexists(ROOT/'target/evaluation'/a.raw.name)
    os.chdir(ROOT)
    tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc', 'rustdoc')}
    tools.update({n: Path('/usr/bin', n).resolve(strict=True)
                  for n in ('git', 'gcc', 'readelf', 'objdump', 'bash', 'rg')})
    tools['python'] = Path(sys.executable).resolve(strict=True)
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home),
        PATH=str(a.toolchain/'bin')+':/usr/bin:/bin', RUSTC=str(tools['rustc']), RUSTDOC=str(tools['rustdoc']),
        CC=str(tools['gcc']), CARGO_TARGET_DIR=str(ROOT/'target'), CARGO_INCREMENTAL='0',
        CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',
        CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true', CARGO_TERM_COLOR='never', LC_ALL='C',
        PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', LITEINST_EVALUATION='1', TMPDIR=str(a.raw/'tmp'))
    # No project helper executes before its exact clean-Git bootstrap check.
    def git(*args):
        data = subprocess.check_output(['/usr/bin/git', '-C', ROOT, *args], env=env, timeout=15)
        assert len(data) <= 32*1024*1024
        return data

    assert git('rev-parse', '--show-toplevel').decode().strip() == str(ROOT)
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    for name in ('evaluation/ordinary-rust-invoke-native/reproduce.py', 'evaluation/ordinary-module-session/reproduce.py'):
        path = ROOT/name
        assert not path.is_symlink() and path.is_file() and path.stat().st_size <= 1024*1024
        assert path.read_bytes() == git('show', a.revision+':'+name)
    spec = importlib.util.spec_from_file_location('_owner_target_recipe', ROOT/'evaluation/ordinary-module-session/reproduce.py')
    assert spec and spec.loader
    recipe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recipe)
    required = set(recipe.MODULES.values()) | {
        'evaluation/ordinary-rust-invoke-native/reproduce.py', 'evaluation/ordinary-rust-invoke-native/rust_invoke.py',
        'evaluation/ordinary-rust-invoke-native/controls.py', 'evaluation/ordinary-rust-invoke-native/caller.py',
        'evaluation/ordinary-rust-invoke-native/runner_controls.py', 'evaluation/ordinary-module-session/reproduce.py',
        'evaluation/ordinary-module-native/controls.py', 'evaluation/ordinary-module-session/controls.py',
        'tools/unwind-oracle/bounded_command.py', 'tests/call_tree_truth.rs',
        'tools/rapid-profiler/normal-work/csv_fields.c', 'tools/rapid-profiler/strnlen-work/strnlen.c',
        'tools/rapid-profiler/strnlen-work/localize.map'}
    names = git('ls-files', '-z', '--', 'src', 'tests/support', 'tools/rapid-profiler',
                'Cargo.toml', 'Cargo.lock', 'README.md', 'build.rs', ':(glob)**/Cargo.toml',
                *sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required <= set(names)
    sources = {}
    for name in names:
        data = recipe.read(ROOT/name)
        assert data == git('show', a.revision+':'+name)
        sources[str(ROOT/name)] = recipe.pin(data)
    for name, expected in (('evaluation/admission/processes.py', recipe.OWNER_SHA),
                          ('tools/unwind-oracle/bounded_command.py', recipe.BOUNDED_SHA),
                          ('evaluation/ordinary-module-session/corpus.py', recipe.CORPUS_SHA)):
        assert sources[str(ROOT/name)]['sha256'] == expected
    tool_pins = {str(path): recipe.pin(recipe.read(path, 512*recipe.MIB)) for path in tools.values()}
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    modules = {key: recipe.load(key, ROOT/path) for key, path in recipe.MODULES.items()}
    modules['copied'] = recipe.load('copied_rust_output', HERE/'rust_invoke.py')
    modules['caller_geometry'] = recipe.load('copied_rust_caller', HERE/'caller.py')
    native = modules['native']
    assert sources[str(ROOT/'tools/rapid-profiler/normal-work/csv_fields.c')]['sha256'] == native.CSV_SOURCE_SHA
    assert sources[str(ROOT/'tools/rapid-profiler/strnlen-work/strnlen.c')]['sha256'] == native.LENGTH_SOURCE_SHA
    a.raw.mkdir(mode=0o700)
    (a.raw/'tmp').mkdir()
    run = recipe.Run(a, a.raw, tools, env, sources, modules, started, tool_pins)
    run.deadline = started + 1200
    row = fixed_row()
    run.result.update(kind='copied-rust-invoke-qualification-v1', scope=SCOPE,
        originals=[], installed=[], controls=[], prerequisites={'copied': row},
        cpu_roles=dict(supervisor=run.cpus, native_parent_and_tracees=run.cpus[1]),
        planned_stages=[dict(name=n, status='UNRUN') for n in STAGES])
    try:
        run.result['sources_before'] = run.freeze(a.raw/'sources-before.json', sources, cap=16*MIB)
        run.result['plan'] = run.freeze(a.raw/'initial-plan.json', dict(revision=a.revision,
            stages=STAGES, cohort=dict(row), attempts=1, retries=0, pair_seconds=15,
            steps_per_child=20000, native_wall_seconds=510, native_cpu_seconds=480,
            outer_seconds=1200, outer_log_bytes=8*MIB, table_bytes=65536,
            affinity=run.cpus, reservation_tag=a.reservation_tag,
            reservation_authority='external owner only', scope=SCOPE))
        for name in ('cc1', 'collect2', 'as', 'ld'):
            out, err = run.stage('tool-'+name, [tools['gcc'], '-print-prog-name='+name])
            assert err == b'' and out.endswith(b'\n') and out.count(b'\n') == 1
            reported = out[:-1].decode('utf-8')
            path = Path(reported) if '/' in reported else Path(shutil.which(reported, path=env['PATH']) or '')
            assert path.is_absolute(); path = path.resolve(strict=True)
            value = recipe.pin(recipe.read(path, 512*MIB))
            if str(path) in run.tool_pins: assert run.tool_pins[str(path)] == value
            else: run.tool_pins[str(path)] = value
        run.result['tools'] = run.freeze(a.raw/'tools.json', run.tool_pins)
        trusted, candidate = a.raw/'module-trusted.so', a.raw/'module-candidate.so'
        out, err = run.stage('module-build', [tools['gcc'], *native.MODULE_FLAGS,
            ROOT/'tools/rapid-profiler/normal-work/csv_fields.c', ROOT/'tools/rapid-profiler/strnlen-work/strnlen.c',
            '-o', trusted], generated=((trusted, MIB),))
        assert out == err == b''
        content = recipe.read(trusted, MIB); assert content
        run.budget.charge(str(candidate), len(content))
        with candidate.open('xb') as f: f.write(content)
        assert (candidate.stat().st_dev, candidate.stat().st_ino) != (trusted.stat().st_dev, trusted.stat().st_ino)
        run.remember(candidate, run.retained[str(trusted)])
        symbols, err = run.stage('module-symbols', [tools['readelf'], '--wide', '--syms', trusted])
        assert err == b''
        spans = [native.selection(symbols, name, ceiling) for name, ceiling in (('csv_fields', 256), ('strnlen', 80))]
        (csv_va, csv_size), (length_va, length_size) = spans
        assert csv_va + csv_size <= length_va and csv_va//4096 == (length_va+length_size-1)//4096
        bodies = []
        for name, (va, size) in zip(('csv_fields', 'strnlen'), spans):
            out, err = run.stage(name+'-disassembly', [tools['objdump'], '-d', '-M', 'intel', '--insn-width=16',
                                                     '--disassemble='+name, trusted])
            assert err == b''
            bodies.append(native.body_geometry(native.geometry(out, name, va, size), va, size, name == 'strnlen'))
        cargo = ['--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler', '--message-format=json-render-diagnostics']
        out, _ = run.stage('application-build', [tools['cargo'], 'build', '--bin', 'ordinary-interval', *cargo], 120, 180, 128*MIB)
        application, product = native.artifact(out, 'ordinary-interval', 'ordinary-interval/main.rs', 'bin', False)
        run.remember(application)
        run.result['application'] = run.freeze(a.raw/'application-artifact.json', dict(product=product, binary=run.retained[str(application)]))
        app_bytes = recipe.read(application, 512*MIB)
        app_trusted, app_candidate = a.raw/'application-trusted', a.raw/'application-candidate'
        for path in (app_trusted, app_candidate):
            run.budget.charge(str(path), len(app_bytes))
            with path.open('xb') as f: f.write(app_bytes)
            run.remember(path, run.retained[str(application)])
        assert len({(p.stat().st_dev, p.stat().st_ino) for p in (application, app_trusted, app_candidate)}) == 3
        disassembly, err = run.stage('application-caller-disassembly', [tools['objdump'], '-d', '-M', 'intel', '--insn-width=16',
            '--disassemble=liteinst_csv_call_and_store', app_trusted])
        assert err == b''
        shape = modules['csv'].caller_geometry(disassembly.decode('ascii'))
        symbols, err = run.stage('application-caller-symbols', recipe.caller_symbol_command(tools, app_trusted))
        assert err == b''; modules['module'].caller_symbols(symbols.decode('ascii'), shape)
        caller = modules['caller_geometry'].geometry(native.geometry(disassembly, 'liteinst_csv_call_and_store', shape['elf_va'], shape['length']),
                                                    shape['elf_va'], shape['length'])
        assert caller['continuation_offset'] == shape['continuation_offset']
        run.result['geometry'] = run.freeze(a.raw/'geometry.json', dict(selections=spans, bodies=bodies, caller=caller,
            application=run.retained[str(app_trusted)], module=run.retained[str(trusted)]))
        bins = {}
        for label, target, source, kind, test, flags in (
            ('native', 'frontend-native-oracle', 'native-interval/main.rs', 'bin', False, ['build', '--bin', 'frontend-native-oracle']),
            ('state', 'frontend-native-calibrations', 'native-interval/calibrations.rs', 'test', True, ['test', '--test', 'frontend-native-calibrations', '--no-run'])):
            out, _ = run.stage(label+'-build', [tools['cargo'], *flags, *cargo], 120, 180, 128*MIB)
            binary, product = native.artifact(out, target, source, kind, test)
            run.remember(binary); bins[label] = binary
            run.freeze(a.raw/(label+'-artifact.json'), dict(product=product, binary=run.retained[str(binary)]))
        peers = {key: recipe.load('copied_'+key, ROOT/native.MODULES[key]) for key in ('legacy', 'normal', 'whole')}
        manifest = native.calibration_manifest(peers['legacy'], peers['normal'], peers['whole'])
        assert len(manifest) == 179
        out, err = run.stage('state-list', [bins['state'], '--list'])
        inventory = modules['census'].census(out, err)
        assert set(inventory) == set(manifest) | {native.IGNORED}
        run.freeze(a.raw/'controls.json', dict(rust=manifest, ignored={native.IGNORED: native.IGNORE_REASON},
            python=PYTHON_CONTROLS, runner=RUNNER_CONTROLS, legacy_python=native.PYTHON_CONTROLS, session_python=recipe.PYTHON_CONTROLS))
        out, err = run.stage('state-controls', [bins['state'], '--test-threads=1'])
        native.calibration_output(out, err, manifest)
        out, err = run.stage('legacy-python-controls', [tools['python'], '-B', ROOT/'evaluation/ordinary-module-native/controls.py', '-v'])
        native.python_output(out, err)
        out, err = run.stage('session-python-controls', [tools['python'], '-B', ROOT/'evaluation/ordinary-module-session/controls.py', '-v'])
        recipe.python_controls(out, err)
        out, err = run.stage('python-controls', [tools['python'], '-B', HERE/'controls.py', '-v'])
        python_controls(out, err, PYTHON_CONTROLS)
        out, err = run.stage('runner-controls', [tools['python'], '-B', HERE/'runner_controls.py', '-v'])
        python_controls(out, err, RUNNER_CONTROLS)
        cohort = a.raw/'native'; cohort.mkdir()
        request = dict(argv=list(map(str, [bins['native'], 'normal-rust-invoke-state', candidate, trusted,
            csv_va, csv_size, length_va, length_size, app_candidate, app_trusted, cohort/'output'])),
            cwd=str(ROOT), env=env, stdout=str(cohort/'stdout.txt'), stderr=str(cohort/'stderr.txt'),
            cpu=run.cpus[1], pins=run.sources | run.tool_pins | run.retained)
        request_shape(request, run.cpus)
        request_pin = run.freeze(cohort/'request.json', request)
        command = [tools['python'], '-B', HERE/'reproduce.py', '--native-request', cohort/'request.json', request_pin['sha256']]
        run.command('native-outer', command, 510)
        assert row == fixed_row()
        row.update(status='FAILED', attempts=1)
        run.freeze(cohort/'attempt.json', row)
        directory, closed = run.owned('native-outer', command, 510, growth=16*MIB)
        row['closed'] = closed
        assert run.safe
        for name, cap in (('stdout.txt', 1024), ('stderr.txt', MIB),
                          ('output/copied-rust-pairs.csv', 65536), ('output/copied-rust-coverage.csv', 65536)):
            path = cohort/name
            if path.exists(): run.remember(path, cap=cap)
        accept_closure(row, closed, recipe.read(directory/'parent.log', MIB))
        output = cohort/'output'; assert output.is_dir() and not output.is_symlink()
        assert {p.name for p in output.iterdir()} == {'copied-rust-pairs.csv', 'copied-rust-coverage.csv'}
        parsed = modules['copied'].check(recipe.read(output/'copied-rust-pairs.csv', 65536),
            recipe.read(output/'copied-rust-coverage.csv', 65536), recipe.read(cohort/'stdout.txt', 1024),
            recipe.read(cohort/'stderr.txt', MIB), bodies=bodies, caller=caller)
        assert parsed['status'] == 'COPIED_RUST_INVOKE_TRANSCRIPT_VALIDATED'
        run.closed_inventory(cohort); run.budget.complete(); run.unchanged()
        row.update(status='COPIED_RUST_INVOKE_STATE_PASS', comparisons=parsed['comparisons'], pairs=48,
                   children=96, target_calls=96, target_returns=96, outer_returns=96, normal_reaps=96)
        assert tuple(r['name'] for r in run.result['stages']) == STAGES
        run.result['sources_after'] = run.freeze(a.raw/'sources-after.json', sources, cap=16*MIB)
        run.result['status'] = 'COPIED_RUST_INVOKE_QUALIFICATION_PASS'
    except BaseException as error:
        run.result['error'] = type(error).__name__
    finally:
        run.budget.stopped()
        run.result.update(end_utc=dt.datetime.now(dt.timezone.utc).isoformat(), load_after=list(os.getloadavg()),
            custody_closed=run.safe, retained=dict(run.retained), tool_pins=dict(run.tool_pins),
            evidence_budget=run.budget.summary(), build_space_exclusions=[str(p) for p in run.build_scratch])
        seen = {r['name']: r for r in run.result['stages']}
        run.result['planned_stages'] = [seen.get(n, dict(name=n, status='UNRUN')) for n in STAGES]
        try:
            assert run.safe and not run.budget.exceeded
            run.closed_inventory(a.raw)
            assert run.budget.used <= recipe.EVIDENCE_LIMIT-recipe.FINAL_ALLOWANCE
            run.unchanged(); run.result['retention_verified'] = True
        except BaseException as error:
            run.result.update(status='FAILED', final_error=type(error).__name__)
        run.result.update(retained=dict(run.retained), evidence_budget=run.budget.summary())
        recipe.save(a.raw/'result.json', run.result, 16*MIB)
    print(json.dumps(dict(status=run.result['status'], cohort=row, custody_closed=run.safe, scope=SCOPE)))
    return 0 if run.result['status'] == 'COPIED_RUST_INVOKE_QUALIFICATION_PASS' else 1


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--native-request':
        try:
            native_exec(Path(sys.argv[2]), sys.argv[3])
        except BaseException as error:
            print('copied-Rust native exec FAILED: '+type(error).__name__, file=sys.stderr, flush=True)
            raise SystemExit(127)
    raise SystemExit(main())
