#!/usr/bin/env python3
"""Four targeted module-session owner cases, once each; no Schedule/state oracle.

Use an external 1200-second/8 MiB process owner with three reserved CPUs.
This isolated qualification cannot replace a full campaign prerequisite/result.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import argparse
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
STAGES = tuple('tool-' + n for n in ('cc1', 'collect2', 'as', 'ld')) + (
    'module-build', 'module-symbols', 'csv_fields-disassembly', 'strnlen-disassembly',
    'application-build', 'application-caller-disassembly', 'application-caller-symbols',
    'ordinary-build', 'ordinary-list', 'ordinary-controls', 'python-controls',
    'owner-1-outer', 'owner-2-outer', 'owner-3-outer', 'owner-4-outer')
SCOPE = ('Isolated module-session ownership qualification only; no native-state oracle, '
         'Schedule/deadline, performance, full-campaign or retrospective qualification credit. '
         'Existing cases preserve owners/refusals/reclamation; they do not restage a reclaimed '
         'bank or qualify execution after shell restaging.')


def main():
    started = time.monotonic()
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    ap.add_argument('--reservation-tag', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    assert re.fullmatch('[A-Za-z0-9_.-]{1,128}', a.reservation_tag)
    assert HERE == ROOT/'evaluation/ordinary-module-session'
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
    for name in ('owners.py', 'reproduce.py'):
        path = HERE/name
        assert not path.is_symlink() and path.is_file() and path.stat().st_size <= 1024*1024
        assert path.read_bytes() == git('show', a.revision+':evaluation/ordinary-module-session/'+name)
    spec = importlib.util.spec_from_file_location('_owner_target_recipe', HERE/'reproduce.py')
    assert spec and spec.loader
    recipe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recipe)
    required = set(recipe.MODULES.values()) | {
        'evaluation/ordinary-module-session/owners.py', 'evaluation/ordinary-module-session/reproduce.py',
        'evaluation/ordinary-module-session/controls.py', 'tools/unwind-oracle/bounded_command.py',
        'tests/call_tree_truth.rs', 'tools/rapid-profiler/normal-work/csv_fields.c',
        'tools/rapid-profiler/strnlen-work/strnlen.c', 'tools/rapid-profiler/strnlen-work/localize.map'}
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
    native = modules['native']
    assert sources[str(ROOT/'tools/rapid-profiler/normal-work/csv_fields.c')]['sha256'] == native.CSV_SOURCE_SHA
    assert sources[str(ROOT/'tools/rapid-profiler/strnlen-work/strnlen.c')]['sha256'] == native.LENGTH_SOURCE_SHA
    a.raw.mkdir(mode=0o700)
    (a.raw/'tmp').mkdir()
    run = recipe.Run(a, a.raw, tools, env, sources, modules, started, tool_pins)
    run.deadline = started + 1200
    cases = [dict(k=k, direction=direction, status='UNRUN', attempts=0)
             for k in (10, 1000) for direction in ('csv-length', 'length-csv')]
    run.result.update(kind='module-session-owner-target-v1', scope=SCOPE, originals=[], installed=[], controls=[],
        prerequisites={'owner': dict(status='UNRUN', attempts=0, rows=cases)},
        planned_stages=[dict(name=n, status='UNRUN') for n in STAGES])
    try:
        run.result['sources_before'] = run.freeze(a.raw/'sources-before.json', sources, cap=16*recipe.MIB)
        run.result['plan'] = run.freeze(a.raw/'initial-plan.json', dict(revision=a.revision, cases=cases,
            stages=list(STAGES), attempts_per_case=1, retries=0, outer_seconds=1200, outer_log_bytes=8*recipe.MIB,
            application_seconds=15, cpu_seconds=20, inner_wall_seconds=30, owner_wall_seconds=55,
            stream_bytes=recipe.MIB, rust_controls=47, python_controls=26,
            affinity=run.cpus, reservation_tag=a.reservation_tag, reservation_authority='external owner only',
            evidence_limit=recipe.EVIDENCE_LIMIT, final_allowance=recipe.FINAL_ALLOWANCE, scope=SCOPE))
        for name in ('cc1', 'collect2', 'as', 'ld'):
            out, err = run.stage('tool-'+name, [tools['gcc'], '-print-prog-name='+name])
            assert err == b'' and out.endswith(b'\n') and out.count(b'\n') == 1
            reported = out[:-1].decode('utf-8')
            path = Path(reported) if '/' in reported else Path(shutil.which(reported, path=env['PATH']) or '')
            assert path.is_absolute()
            path = path.resolve(strict=True)
            value = recipe.pin(recipe.read(path, 512*recipe.MIB))
            if str(path) in run.tool_pins:
                assert run.tool_pins[str(path)] == value
            else:
                run.tool_pins[str(path)] = value
        run.result['tools'] = run.freeze(a.raw/'tools.json', run.tool_pins)
        trusted, candidate = a.raw/'module-trusted.so', a.raw/'module-candidate.so'
        out, err = run.stage('module-build', [tools['gcc'], *native.MODULE_FLAGS,
            ROOT/'tools/rapid-profiler/normal-work/csv_fields.c', ROOT/'tools/rapid-profiler/strnlen-work/strnlen.c',
            '-o', trusted], generated=((trusted, recipe.MIB),))
        assert out == err == b''
        content = recipe.read(trusted, recipe.MIB)
        assert content
        run.budget.charge(str(candidate), len(content))
        with candidate.open('xb') as f:
            f.write(content)
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
        out, _ = run.stage('application-build', [tools['cargo'], 'build', '--bin', 'ordinary-interval', *cargo], 120, 180, 128*recipe.MIB)
        binary, product = native.artifact(out, 'ordinary-interval', 'ordinary-interval/main.rs', 'bin', False)
        run.remember(binary)
        run.result['application'] = run.freeze(a.raw/'application-artifact.json', dict(product=product, binary=run.retained[str(binary)]))
        shape = recipe.caller(run, 'application-caller', binary)
        geometry = dict(csv_va=csv_va, csv_length=csv_size, length_va=length_va, length_length=length_size,
                        returns=[body['returns'] for body in bodies], continuation=shape['continuation_offset'])
        run.result['geometry'] = run.freeze(a.raw/'geometry.json', dict(geometry=geometry, selections=spans,
            bodies=bodies, caller=shape, candidate=run.retained[str(candidate)], final=run.retained[str(trusted)]))
        out, _ = run.stage('ordinary-build', [tools['cargo'], 'test', '--bin', 'ordinary-interval', '--no-run', *cargo], 120, 180, 128*recipe.MIB)
        test_binary, product = native.artifact(out, 'ordinary-interval', 'ordinary-interval/main.rs', 'bin', True)
        run.remember(test_binary)
        run.result['test_artifact'] = run.freeze(a.raw/'ordinary-artifact.json', dict(product=product, binary=run.retained[str(test_binary)]))
        out, err = run.stage('ordinary-list', [test_binary, '--list'])
        inventory = modules['census'].census(out, err)
        expected = recipe.ordinary_inventory(inventory, modules['single'], modules['module'], recipe.OWNER_CONTROLS)
        assert len(expected) == 47
        run.result['control_manifest'] = run.freeze(a.raw/'controls.json', dict(rust=list(expected), python=list(recipe.PYTHON_CONTROLS)))
        out, err = run.stage('ordinary-controls', [test_binary, *expected, '--exact', '--test-threads=1'])
        run.result['rust_controls'] = modules['census'].controls(out, err, expected, inventory)
        out, err = run.stage('python-controls', [tools['python'], '-B', HERE/'controls.py', '-v'])
        recipe.python_controls(out, err)
        assert len(recipe.PYTHON_CONTROLS) == 26
        run.result['python_controls'] = dict(status='PASS', names=list(recipe.PYTHON_CONTROLS), count=26)
        recipe.owner_gate(run, binary, geometry, candidate, trusted)
        rows = run.result['prerequisites']['owner']['rows']
        assert [(row['k'], row['direction']) for row in rows] == [(row['k'], row['direction']) for row in cases]
        assert all(row['attempts'] == 1 and row['status'] == 'OWNER_FUNCTIONAL_PASS' for row in rows)
        assert tuple(row['name'] for row in run.result['stages']) == STAGES
        run.unchanged()
        run.result['sources_after'] = run.freeze(a.raw/'sources-after.json', sources, cap=16*recipe.MIB)
        run.result['status'] = 'OWNER_QUALIFICATION_PASS'
    except BaseException as error:
        run.result['error'] = type(error).__name__
    finally:
        # Preserve first pins; inventory partial files only with closed custody.
        run.budget.stopped()
        run.result.update(end_utc=dt.datetime.now(dt.timezone.utc).isoformat(), load_after=list(os.getloadavg()),
            custody_closed=run.safe, retained=dict(run.retained), tool_pins=dict(run.tool_pins),
            evidence_budget=run.budget.summary(), build_space_exclusions=[str(p) for p in run.build_scratch])
        seen = {row['name']: row for row in run.result['stages']}
        run.result['planned_stages'] = [seen.get(name, dict(name=name, status='UNRUN')) for name in STAGES]
        try:
            assert run.safe and not run.budget.exceeded
            run.closed_inventory(a.raw)
            assert run.budget.used <= recipe.EVIDENCE_LIMIT - recipe.FINAL_ALLOWANCE
            run.unchanged()
            run.result['retention_verified'] = True
        except BaseException as error:
            run.result.update(status='FAILED', final_error=type(error).__name__)
        run.result.update(retained=dict(run.retained), evidence_budget=run.budget.summary())
        recipe.save(a.raw/'result.json', run.result, 16*recipe.MIB)
    rows = run.result['prerequisites']['owner']['rows']
    print(json.dumps(dict(status=run.result['status'], cases=[dict(k=row['k'], direction=row['direction'],
        status=row['status'], attempts=row['attempts']) for row in rows], custody_closed=run.safe, scope=SCOPE)))
    return 0 if run.result['status'] == 'OWNER_QUALIFICATION_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
