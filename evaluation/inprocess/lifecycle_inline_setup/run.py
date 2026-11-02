#!/usr/bin/env python3
"""Portable lifecycle setup: four tool probes, then the unchanged26-command application oracle."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'evaluation/inprocess'))
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_process import invoke
from persistent_dynamic import BOUNDS, imported_sources
from persistent_loop_lifecycle_native_build import compile_subject

APPLICATION_SCHEDULE = (
    ('app-interpreter-headers', 'metadata'), ('app-interpreter-link', 'release_build'),
    ('app-interpreter-undefined', 'inspect'), ('app-interpreter-symbols', 'inspect'),
    ('app-headers', 'metadata'), ('app-link', 'release_build'), ('app-undefined', 'inspect'),
    ('app-elf', 'inspect'), ('app-objdump-version', 'metadata'), ('app-symbols', 'inspect'),
    *((f'app-body-{name}', 'inspect') for name in
      ('main', 'lc_inputs', 'lc_model_init', 'lc_advance', 'copy', 'same', 'ua_data_pattern', 'ua_stack_pattern')),
    ('app-copy-headers', 'finite'), ('app-pure-preprocess', 'finite'),
    ('copy-pure-preprocess', 'finite'), ('app-copy-link', 'finite'),
    ('app-copy-symbols', 'finite'), ('app-copy-body', 'finite'),
    ('app-copy-libraries', 'finite'), ('app-copy-run', 'finite'))
DISCOVERY = tuple(('resolve-' + name, 'metadata') for name in ('cc1', 'collect2', 'as', 'ld'))
SCHEDULE = DISCOVERY + APPLICATION_SCHEDULE
FIXTURE = ROOT / 'tools/page-entry/selected/tests/tunables_lifecycle_app'
FIXED = {
    FIXTURE / 'main.c': (16087, '083da7f67cd7ac3b225eb09163ace187697d62d26c0d02dcc0b7b3a543b04c60'),
    FIXTURE / 'read.py': (26850, '1dd16ee8252ff52c7d52b8b3682e2e35258e6885deba2276015a1070272905ac')}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--cc', default='gcc')
    ap.add_argument('--nm', default='nm')
    ap.add_argument('--readelf', default='readelf')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize and
         re.fullmatch('[0-9a-f]{40}', a.expect_revision), 'unoptimized Python3.12 and exact source identity')
    cpus = sorted(os.sched_getaffinity(0))
    need(len(cpus) == 1, 'one externally reserved CPU')
    cpu = cpus[0]
    os.chdir(ROOT)
    output = a.output.absolute()
    need(output.parent == ROOT / 'target/evaluation/inprocess' and not output.exists(), 'fresh direct-child output')
    output.mkdir(parents=True, exist_ok=False)
    pins, artifacts, aliases = {}, {}, {}
    r = dict(schema=1, profile='lifecycle-application-setup-v1', status='failed',
        revision=a.expect_revision, cpu=cpu, hardware=hardware(cpu), source=None,
        driver=fact(__file__), argv=[sys.executable, '-B', *sys.argv], commands=[],
        bounds=dict(BOUNDS), source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
        error=None, final_errors=[], lifecycle_subjects=0, lifecycle_controls_executed=False,
        qualification_credit=False, performance_credit=False,
        discovery_commands=4, application_commands=26)
    started = time.monotonic_ns()

    def pin(path):
        lexical = Path(os.path.abspath(path)); p = lexical.resolve(strict=True); value = fact(p)
        need(str(lexical) not in aliases or aliases[str(lexical)] == str(p), 'stable input alias')
        need(str(p) not in pins or pins[str(p)] == value, 'stable whole input bytes')
        aliases[str(lexical)] = str(p); pins[str(p)] = value
        return p

    def binary(path):
        p = Path(path).resolve(strict=True); value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable complete artifact bytes and mode')
        artifacts[str(p)] = value
        return p

    def closure():
        need(all(fact(p) == v for p, v in pins.items()), 'whole inputs unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v for p, v in artifacts.items()),
             'whole artifacts unchanged')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'whole aliases unchanged')
        need(all(os.path.lexists(p) == v for p, v in r.get('presence', {}).items()), 'loader presence unchanged')

    def run(name, argv, profile='metadata', env=None):
        closure()
        need(sorted(os.sched_getaffinity(0)) == [cpu], 'same reserved CPU before every child')
        need(len(r['commands']) < len(SCHEDULE) and (name, profile) == SCHEDULE[len(r['commands'])],
             'complete original application/inspection/copy-oracle order')
        pin(argv[0])
        row = dict(name=name, argv=list(map(str, argv)), profile=profile,
            environment=dict(ENV if env is None else env), bounds=BOUNDS[profile],
            capture_limit=16 << 20, expected_exit=0)
        r['commands'].append(row)
        try:
            out, err = invoke(row, output, cpu)
            need(type(row['exit']) is int and row['exit'] == 0 and row['timed_out'] is False and
                 row['error'] is None and row['reaped'] is True and row['cleanup_errors'] == [] and
                 row['descriptors'] == [], 'original bounded setup command and complete cleanup')
            return row, out, err
        finally:
            for capture in row.get('captures', {}).values():
                try:
                    need(fact(binary(output / capture['file'])) == {k: capture[k] for k in ('bytes', 'sha256')},
                         'whole actual command capture')
                except BaseException as error:
                    r['final_errors'].append('capture ' + name + ': ' + repr(error))
            try:
                p = output / (name + '.json')
                if p.exists():
                    need(json.loads(binary(p).read_bytes()) == row, 'whole retained command row')
            except BaseException as error:
                r['final_errors'].append('command ' + name + ': ' + repr(error))

    try:
        r['source'] = source()
        need(r['source']['revision'] == a.expect_revision, 'exact clean reviewed source')
        pin(__file__); pin(sys.executable); imported_sources(pin)
        for p, (size, sha) in FIXED.items():
            need(fact(pin(p)) == dict(bytes=size, sha256=sha), 'exact reviewed inline fixture and source pin')
        r['presence'] = {p: os.path.lexists(p) for p in ('/etc/ld.so.cache', '/etc/ld.so.preload')}
        need(not r['presence']['/etc/ld.so.preload'], 'no global preload')
        for p, present in r['presence'].items():
            if present: pin(p)
        tools = {'python': pin(sys.executable)}
        for name in ('cc', 'nm', 'readelf'):
            resolved = shutil.which(getattr(a, name), path=ENV['PATH'])
            need(resolved is not None, 'actual executable tool ' + name)
            tools[name] = pin(resolved)
        environment = dict(ENV, LI2_CC=str(tools['cc']), LI2_PYTHON=str(tools['python']))
        for name in ('cc1', 'collect2', 'as', 'ld'):
            _, out, err = run('resolve-' + name, [tools['cc'], '-print-prog-name=' + name], env=environment)
            need(not err and out.endswith(b'\n') and out.count(b'\n') == 1, 'one actual compiler subprogram ' + name)
            resolved = shutil.which(out.decode().strip(), path=ENV['PATH'])
            need(resolved is not None, 'resolved actual compiler subprogram ' + name)
            tools[name] = pin(resolved)
        r['tool_provenance'] = {name: dict(path=str(p), **fact(p)) for name, p in tools.items()}
        builder = SimpleNamespace(tools=tools, environment=environment)
        application = compile_subject(builder, output, pin, binary, aliases, run, r)
        need(tuple((x['name'], x['profile']) for x in r['commands']) == SCHEDULE and
             len(DISCOVERY) == 4 and len(APPLICATION_SCHEDULE) == 26,
             'four discovery commands then all26 original setup commands completed')
        need(r['application_build']['status'] == r['application_build']['copy_oracle']['status'] == 'passed',
             'full unchanged emitted-body and actual copy-oracle proofs')
        r['application'] = dict(path=str(application), **fact(application))
        r['status'] = 'observed_application_setup'
    except BaseException as error:
        r['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        try:
            imported_sources(pin); closure()
            need(source() == r['source'] and fact(__file__) == r['driver'] and
                 sorted(os.sched_getaffinity(0)) == [cpu], 'same whole tracked source/driver/CPU at closure')
            r['source_unchanged'] = r['inputs_unchanged'] = True
        except BaseException as error:
            r['final_errors'].append(type(error).__name__ + ': ' + str(error))
        r['cleanup_complete'] = all(x.get('reaped') is True and x.get('cleanup_errors') == [] and
            type(x.get('descriptors')) is list and all(d['closed'] is True for d in x['descriptors']) for x in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        r.update(inputs=pins, artifacts=artifacts, aliases=aliases, duration_ns=time.monotonic_ns() - started)
        save(output / 'receipt.json', r)
    print(json.dumps(dict(status=r['status'], error=r['error'], commands=len(r['commands']),
        receipt=fact(output / 'receipt.json'), lifecycle_subjects=0, qualification_credit=False), sort_keys=True))
    return int(r['status'] != 'observed_application_setup')


if __name__ == '__main__':
    raise SystemExit(main())
