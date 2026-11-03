#!/usr/bin/env python3
"""Compile installed arena source with the existing shared recipe; no guest execution."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'evaluation/inprocess'), str(ROOT/'tools/page-entry')]
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_process import invoke
from persistent_dynamic import BOUNDS, imported_sources
from loop_ro_current_archive import current_archive
from loop_resident_rx_build import build_rx

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('expect-revision', 'output', 'current-build', 'current-build-sha256'):
        p.add_argument('--'+name, required=True)
    a = p.parse_args()
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize and
         Path.cwd().resolve() == ROOT and len(os.sched_getaffinity(0)) == 1,
         'Python3.12 with assertions and reserved singleton CPU')
    cpu = next(iter(os.sched_getaffinity(0)))
    private = Path(a.output).absolute()
    need(private.parent == ROOT/'target/evaluation/inprocess', 'confined fresh output')
    private.mkdir(mode=0o700)
    pins = {}; aliases = {}; artifacts = {}
    r = dict(schema=1, profile='loop-translation-arena-compile-v1', status='failed',
        revision=a.expect_revision, source=source(), cpu=cpu, hardware=hardware(cpu),
        bounds=BOUNDS, commands=[], builds={}, inputs=pins, aliases=aliases, artifacts=artifacts,
        error=None, final_errors=[], source_unchanged=False, inputs_unchanged=False,
        cleanup_complete=False, qualification_credit=False, native_credit=False,
        performance_credit=False, subjects=0)
    schedule = tuple((mode+'-'+name, profile) for mode in ('release', 'differential')
        for name, profile in (('build','release_build'), ('headers','metadata'),
                              ('undefined','inspect'), ('symbols','inspect')))
    def pin(path):
        alias = Path(os.path.abspath(path)); path = alias.resolve(strict=True)
        value = fact(path)
        need(str(path) not in pins or pins[str(path)] == value, 'unchanged input')
        need(str(alias) not in aliases or aliases[str(alias)] == str(path), 'unchanged alias')
        pins[str(path)] = value; aliases[str(alias)] = str(path)
        return path
    def binary(path):
        path = Path(path).resolve(strict=True); value = dict(fact(path), mode=path.stat().st_mode&0o777)
        need(str(path) not in artifacts or artifacts[str(path)] == value, 'unchanged artifact')
        artifacts[str(path)] = value
        return path
    def stable():
        need(os.sched_getaffinity(0) == {cpu}, 'same reserved CPU')
        need(all(fact(p) == v for p,v in pins.items()), 'whole unchanged inputs')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777) == v
                 for p,v in artifacts.items()), 'whole unchanged artifacts')
        need(all(str(Path(p).resolve(strict=True)) == v for p,v in aliases.items()), 'same aliases')
    try:
        need(r['source']['revision'] == a.expect_revision, 'exact clean installed revision')
        pin(__file__)
        builder, archive, r['archive_provider'] = current_archive(
            a.current_build, a.current_build_sha256, ROOT, pin, binary, aliases)
        original = pin('/bin/true')
        imported_sources(pin)
        for mode in ('release', 'differential'):
            directory = private/mode; directory.mkdir()
            def run(name, argv, profile='metadata', expected=0, env=None):
                stable(); name = mode+'-'+name
                need(len(r['commands']) < len(schedule) and schedule[len(r['commands'])] == (name,profile)
                     and expected == 0, 'exact eight original compile/inspection children')
                row = dict(name=name, argv=list(map(str,argv)), profile=profile,
                    bounds=BOUNDS[profile], environment=dict(ENV if env is None else env),
                    capture_limit=16<<20, expected_exit=0)
                r['commands'].append(row)
                try:
                    out, err = invoke(row, private, cpu)
                    need(row['exit'] == 0, 'required compiler exit: '+name)
                    return row, out, err
                finally:
                    for value in row.get('captures',{}).values(): binary(private/value['file'])
                    print(json.dumps({k:row.get(k) for k in ('name','exit','duration_ns','error')}), flush=True)
            state = r['builds'][mode] = {}
            bridge = build_rx(builder, archive, original, directory, pin, binary, aliases,
                run, state, mode, cache8=True, group_descriptor=True, arena=True)
            need(binary(bridge).is_file() and state['status'] == 'compiled_diagnostic_only',
                 'complete original shared builder closure')
        need(len(r['commands']) == 8, 'all eight children')
        r['status'] = 'compiled_diagnostic_only'
    except BaseException as error:
        r['error'] = type(error).__name__+': '+str(error)
    finally:
        try:
            imported_sources(pin); stable()
            need(source() == r['source'], 'unchanged exact source revision')
            r['source_unchanged'] = r['inputs_unchanged'] = True
        except BaseException as error: r['final_errors'].append(repr(error))
        r['cleanup_complete'] = all(c.get('reaped') is True and c.get('cleanup_errors') == [] and
            all(d['closed'] is True for d in c.get('descriptors',[])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        save(private/'receipt.json',r)
    print(json.dumps({k:r[k] for k in ('status','error','final_errors','cleanup_complete')}),flush=True)
    return int(r['status'] != 'compiled_diagnostic_only')

if __name__ == '__main__': raise SystemExit(main())
