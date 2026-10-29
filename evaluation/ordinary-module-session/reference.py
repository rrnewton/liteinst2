#!/usr/bin/env python3
"""One targeted original-reference qualification; no installed or timing runs.

Use an external 1200-second/8 MiB process owner with three reserved CPUs.
Every one of the 32 accepted populations and eight malformed frames runs once.
This cannot supply a missing reference to an earlier failed campaign.
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


def main():
    started = time.monotonic()
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    ap.add_argument('--reservation-tag', required=True)
    ap.add_argument('--raw', type=Path, required=True)
    a = ap.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    assert re.fullmatch('[A-Za-z0-9_.-]{1,128}', a.reservation_tag)
    assert a.raw.is_absolute() and a.raw.parent.resolve(strict=True) == a.raw.parent
    assert a.raw.is_relative_to(ROOT/'ignored') and not a.raw.exists()
    os.chdir(ROOT)
    env = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', TMPDIR=str(a.raw/'tmp'))
    # Bootstrap authentication must not execute helpers from the file it checks.
    def git(*args):
        return subprocess.check_output(['/usr/bin/git', '-C', ROOT, *args], env=env, timeout=15)

    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    for name in ('reference.py', 'reproduce.py'):
        path = HERE/name
        assert not path.is_symlink() and path.is_file() and path.stat().st_size <= 1024*1024
        assert path.read_bytes() == git('show', a.revision+':evaluation/ordinary-module-session/'+name)
    spec = importlib.util.spec_from_file_location('_reference_recipe', HERE/'reproduce.py')
    recipe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recipe)
    tools = {n: Path('/usr/bin', n).resolve(strict=True) for n in ('git','gcc','readelf','objdump','bash','rg')}
    tools['python'] = Path(sys.executable).resolve(strict=True)

    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    required = set(recipe.MODULES.values()) | {
        'evaluation/ordinary-module-session/reference.py', 'evaluation/ordinary-module-session/reproduce.py',
        'evaluation/ordinary-module-session/original.c',
        'evaluation/ordinary-module-session/original_mount_controls.c',
        'tools/unwind-oracle/bounded_command.py', 'tools/rapid-profiler/normal-work/csv_fields.c',
        'tools/rapid-profiler/strnlen-work/strnlen.c', 'tools/rapid-profiler/strnlen-work/localize.map'}
    sources = {}
    for name in sorted(required):
        content = recipe.read(ROOT/name)
        assert content == git('show', a.revision+':'+name)
        sources[str(ROOT/name)] = recipe.pin(content)
    assert sources[str(ROOT/'evaluation/admission/processes.py')]['sha256'] == recipe.OWNER_SHA
    assert sources[str(ROOT/'tools/unwind-oracle/bounded_command.py')]['sha256'] == recipe.BOUNDED_SHA
    assert sources[str(ROOT/'evaluation/ordinary-module-session/corpus.py')]['sha256'] == recipe.CORPUS_SHA
    tool_pins = {str(path): recipe.pin(recipe.read(path, 512*recipe.MIB)) for path in tools.values()}
    modules = {key: recipe.load(key, ROOT/path) for key, path in recipe.MODULES.items()}
    a.raw.mkdir(mode=0o700)
    (a.raw/'tmp').mkdir()
    run = recipe.Run(a, a.raw, tools, env, sources, modules, started, tool_pins)
    run.deadline = started + 1200
    run.result['installed'] = []
    run.result['prerequisites'] = {}
    run.result['scope'] = 'Targeted original references only; no installed application, Schedule, performance or retrospective campaign credit.'
    run.freeze(a.raw/'sources-before.json', sources)
    run.freeze(a.raw/'initial-plan.json', dict(revision=a.revision, original_children=32, malformed_children=8,
        attempts=1, retries=0, outer_seconds=1200, application_seconds=15, cpu_seconds=20, inner_wall_seconds=30,
        owner_wall_seconds=55, stream_bytes=recipe.CAP, cpus=run.cpus, reservation_tag=a.reservation_tag,
        scope=run.result['scope']))
    try:
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
        flags = ['-O2','-std=c11','-Wall','-Wextra','-Werror']
        parser = a.raw/'mount-identity-controls'
        out, err = run.stage('mount-controls-build', [tools['gcc'], *flags, HERE/'original_mount_controls.c', '-ldl', '-o', parser], generated=((parser, recipe.MIB),))
        assert out == err == b''
        out, err = run.stage('mount-controls', [parser])
        assert out == b'ORIGINAL_MOUNT_CONTROLS_PASS controls=6\n' and err == b''
        dso = a.raw/'original-module.so'
        out, err = run.stage('module-build', [tools['gcc'], *modules['native'].MODULE_FLAGS,
            ROOT/'tools/rapid-profiler/normal-work/csv_fields.c', ROOT/'tools/rapid-profiler/strnlen-work/strnlen.c', '-o', dso],
            generated=((dso, recipe.MIB),))
        assert out == err == b''
        symbols, err = run.stage('module-symbols', [tools['readelf'], '--wide', '--syms', dso])
        assert err == b''
        spans = [modules['native'].selection(symbols, name, ceiling) for name, ceiling in [('csv_fields',256),('strnlen',80)]]
        (csv_va,csv_size), (length_va,length_size) = spans
        assert csv_va + csv_size <= length_va and csv_va//4096 == (length_va+length_size-1)//4096
        for name, (va, size) in zip(('csv_fields','strnlen'), spans):
            out, err = run.stage(name+'-disassembly', [tools['objdump'],'-d','-M','intel','--insn-width=16','--disassemble='+name,dso])
            assert err == b''
            modules['native'].body_geometry(modules['native'].geometry(out,name,va,size),va,size,name=='strnlen')
        original = a.raw/'original'
        out, err = run.stage('original-build', [tools['gcc'], *flags, '-fno-stack-protector','-fomit-frame-pointer',
            '-fcf-protection=none','-fno-builtin','-Wl,--build-id=none,-z,now,-z,noexecstack',HERE/'original.c','-ldl','-o',original],
            generated=((original, recipe.MIB),))
        assert out == err == b''
        shape = recipe.caller(run, 'original-caller', original)
        run.freeze(a.raw/'geometry.json', dict(selections=spans, caller=shape, dso=run.retained[str(dso)]))
        records = []
        for row in run.result['originals']:
            case = modules['producer'].case_spec(modules['corpus'], row['case'])
            population = tuple((r.payload,r.fields) for r in case['records'])
            records.append(population)
            path = a.raw/('original-%02d.bin' % row['case'])
            with path.open('xb') as f: f.write(recipe.frame(population))
            run.remember(path)
            directory = a.raw/('original-%02d' % row['case'])
            row.update(directory=str(directory), request=run.request(directory,[original,dso,csv_va,csv_size,length_va,length_size,path,run.cpus[1]]))
            run.plan_bounded(directory.name+'-owner', directory, row['request'])
        controls = []
        for name, content in recipe.malformed_frames():
            path = a.raw/('malformed-'+name+'.bin')
            with path.open('xb') as f: f.write(content)
            run.remember(path)
            directory = a.raw/('malformed-'+name)
            req = run.request(directory,[original,dso,csv_va,csv_size,length_va,length_size,path,run.cpus[1]])
            controls.append(dict(name=name,directory=str(directory),request=req,attempts=0,status='UNRUN'))
            run.plan_bounded(directory.name+'-owner',directory,req)
        run.result['controls'] = controls
        run.freeze(a.raw/'case-plan.json', dict(originals=run.result['originals'], malformed=controls), cap=16*recipe.MIB)
        for row in controls + run.result['originals']:
            run.unchanged()
            recipe.bounded_ready(run,row['request'])
            assert row['status'] == 'UNRUN' and row['attempts'] == 0
            row.update(status='FAILED',attempts=1)
            directory=Path(row['directory'])
            code,out,err = run.bounded(directory.name+'-owner',directory,row['request'])
            try:
                if 'case' in row:
                    assert code == 0
                    modules['output'].original_check(out,err,records=records[row['case']],lengths=(csv_size,length_size),cpu=run.cpus[1])
                    row.update(status='REFERENCE_PASS',records=len(records[row['case']]),calls=2*len(records[row['case']]),child_exit=code,normal_reaps=1)
                else:
                    modules['output'].original_refusal(out,err,code,row['name'])
                    row.update(status='EXPECTED_INPUT_REFUSAL',child_exit=code,normal_reaps=1)
            except (AssertionError,ValueError,UnicodeError) as error:
                row['error'] = type(error).__name__
            run.freeze(a.raw/(directory.name+'-outcome.json'),row)
        assert all(r['status']=='REFERENCE_PASS' for r in run.result['originals'])
        assert all(r['status']=='EXPECTED_INPUT_REFUSAL' for r in controls)
        run.result['status']='REFERENCE_PASS'
    except BaseException as error:
        run.result['error']=type(error).__name__
    finally:
        run.result['end_utc']=dt.datetime.now(dt.timezone.utc).isoformat()
        run.result['load_after']=list(os.getloadavg())
        run.result['custody_closed']=run.safe
        if run.safe:
            try:
                run.closed_inventory(a.raw)
                run.unchanged()
                run.result['retention_verified']=True
            except BaseException as error:
                run.result['final_error']=type(error).__name__
                run.result['status']='FAILED'
        else:
            run.result['status']='FAILED'
        run.result['retained']=run.retained
        recipe.save(a.raw/'result.json',run.result,32*recipe.MIB)
    print(json.dumps(dict(status=run.result['status'], originals=[r['status'] for r in run.result['originals']],
        malformed=[r['status'] for r in run.result['controls']], custody_closed=run.safe)))
    return 0 if run.result['status']=='REFERENCE_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
