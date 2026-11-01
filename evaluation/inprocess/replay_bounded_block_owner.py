#!/usr/bin/env python3
"""Offline reader regression only; never rerun or reclassify PB attempt 2.

Run under an externally reserved singleton CPU with --cpu N --output FRESH.json.
The retained subject CPU remains 218. This process may use another reserved CPU.
Only the authenticated pure native-policy classifier is loaded as native code.
No builder, evaluator main, reader_support, subprocess, or guest is invoked.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import struct
import sys
import time
import types

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'target/evaluation/inprocess/bounded-block-owner-attempt-2'
TESTS = ROOT / 'tools/page-entry/selected/tests'
RECEIPT = dict(bytes=1492183, sha256='b70d1294042cebd9fd7a0acaf531c1872827a28bb859d2ccee60e6997c493ef4')
OWNER = dict(bytes=80496, sha256='45bd47c4ea62114e4dc76841c3fbfba4b2f187cbec8f0769cd4b6a7251549d26')
APP = dict(bytes=38702, sha256='421c344ff53a1f4c359ae0c121068ab26936501e2bb8fb3040c612f4d2c2cc15')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def fact(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def normalized(value):
    return json.loads(json.dumps(value, sort_keys=True))


def population(value, count, original=None):
    names = value['refusals']
    need(type(names) is list and all(type(n) is str and n for n in names) and
         len(names) == len(set(names)) == count and
         type(value['native_operations']) is int and value['native_operations'] == 0,
         'exact unchanged supplied-control population')
    if original is not None:
        need(value['original_sha256'] == fact(original)['sha256'], 'whole original control input')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cpu', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(sorted(os.sched_getaffinity(0)) == [args.cpu], 'one externally reserved regression CPU')
    output = args.output.resolve()
    need(not output.exists() and output.parent.is_dir() and not output.is_relative_to(BASE),
         'fresh separate result; historical receipt and cohort are immutable')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (900, 900))
    resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('regression wall limit')))
    signal.alarm(1200)
    start = time.monotonic_ns()
    checked, modules = {}, []
    result = dict(schema=1, scope='reader_regression_only', status='failed',
                  historical_receipt=RECEIPT, historical_status='failed', cpu=args.cpu,
                  retained_subject_cpu=218, bounds=dict(cpu_seconds=900, wall_seconds=1200,
                  address_space_bytes=512 << 20, cpu_count=1),
                  new_subjects=0, child_commands=0, qualification_credit=False,
                  performance_credit=False, terminal_reports_replayed=False, lanes={}, errors=[])

    def take(path, expected):
        path = Path(path).resolve()
        data = path.read_bytes()
        want = {k: expected[k] for k in ('bytes', 'sha256')}
        need(fact(data) == want, 'whole input identity: ' + str(path))
        if 'mode' in expected:
            need(path.stat().st_mode & 0o7777 == expected['mode'], 'input mode: ' + str(path))
        row = dict(want, mode=path.stat().st_mode & 0o7777)
        need(str(path) not in checked or checked[str(path)] == row, 'consistent input identity')
        checked[str(path)] = row
        return data

    def load(name, path):
        need(str(path.resolve()) in checked, 'reader source authenticated before import')
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)
        return module

    def source_closure():
        pending, seen, paths = list(modules), set(), set()
        while pending:
            module = pending.pop()
            if id(module) in seen:
                continue
            seen.add(id(module))
            path = getattr(module, '__file__', None)
            if path is None or not Path(path).resolve().is_relative_to(ROOT):
                continue
            path = str(Path(path).resolve())
            need(path in checked, 'every imported repository module authenticated: ' + path)
            paths.add(path)
            pending.extend(v for v in vars(module).values() if isinstance(v, types.ModuleType))
        result['imported_sources'] = sorted(paths)

    try:
        take(__file__, fact(Path(__file__).read_bytes()))
        r = json.loads(take(BASE / 'receipt.json', RECEIPT))
        need(r['status'] == 'failed' and r['profile'] == 'bounded-block-owner-v1' and
             r['revision'] == '6a4095b40e5d41817e0c19eb3703cf1b8b4dae20' and r['cpu'] == 218 and
             r['source_unchanged'] is True and r['inputs_unchanged'] is True and
             r['cleanup_complete'] is True and r['final_errors'] == [], 'exact closed failed attempt 2')
        result['historical_revision'] = r['revision']
        result['historical_error'] = r['error']
        result['historical_hardware'] = r['hardware']
        catalog = dict(r['inputs'])
        catalog.update(r['artifacts'])

        def retained(path, extra=None):
            path = Path(path).resolve()
            need(str(path) in catalog, 'retained input/artifact in exact historical receipt')
            data = take(path, catalog[str(path)])
            if extra is not None:
                need(fact(data) == {k: extra[k] for k in ('bytes', 'sha256')}, 'retained role identity')
            return data

        for path, expected in r['inputs'].items():
            if Path(path).is_relative_to(TESTS) and path.endswith('.py'):
                if Path(path) == TESTS / 'persistent_block_owner/read.py':
                    expected = OWNER
                elif Path(path) == TESTS / 'persistent_block_app/read.py':
                    expected = APP
                take(path, expected)
        app = load('regression_pb_app', TESTS / 'persistent_block_app/read.py')
        owner = load('regression_pb_owner', TESTS / 'persistent_block_owner/read.py')
        seed = load('regression_seed', TESTS / 'provider_app/seed_probe/read.py')
        xstate = load('regression_xstate', TESTS / 'b2_reference/xstate.py')
        source_closure()
        result['readers'] = dict(owner=OWNER, application=APP)
        need(owner.CONTROL_COUNTS == {0: 204} and app.APP_CONTROL_COUNTS == {0: 40} and
             app.PAIR_CONTROL_COUNTS == {0: 36}, 'original unchanged control populations')
        policy = BASE / 'native-policy.so'
        retained(policy, r['reader_support']['native_policy'])
        lib = ctypes.CDLL(str(policy))
        lib.li2_native_policy.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
        lib.li2_native_policy.restype = ctypes.c_uint
        native_policy = lambda data: lib.li2_native_policy(data, len(data))

        def command(name):
            rows = [x for x in r['commands'] if x['name'] == name]
            need(len(rows) == 1, 'one retained original command')
            row = rows[0]
            need(row['exit'] == row['expected_exit'] == 0 and row['timed_out'] is False and
                 row['reaped'] is True and row['cleanup_errors'] == [] and
                 all(d['closed'] is True for d in row['descriptors']), 'actual successful closed child')
            return row

        def captures(row):
            return {kind: retained(BASE / value['file'], value) for kind, value in row['captures'].items()}

        sr = command('seed-prerequisite'); sc = captures(sr)
        need(sr['bounds'] == [5, 512 << 20, 16 << 20, 15] and sc['stderr'] == b'' and
             r['seed_prerequisite']['status'] == 'passed', 'unchanged actual same-CPU seed prerequisite')
        raw = sc['stdout']; h = struct.unpack_from('<16Q', raw, 128)
        cp = [struct.unpack_from('<6I', raw, 256 + 24*i) for i in range(67)]
        facts = xstate.profile(cp, h[8], h[10], h[12], h[5], h[6])
        profile = seed.read(raw, retained(BASE / 'seed-probe', r['seed_prerequisite']['elf']),
                            facts, xstate, cpu=r['cpu'], pid=sr['pid'])
        need(seed.require(profile, facts, cpu=r['cpu']) == bytes(16) and
             normalized(profile) == r['seed_prerequisite']['profile'] and
             normalized(facts) == r['seed_prerequisite']['format'], 'whole original seed derivation')
        reference = (seed, xstate, profile, facts)
        original_path = BASE / 'application/persistent-block-app'
        original = retained(original_path, r['application_build']['artifact'])
        interp_path = Path(r['application_build']['interpreter']['path'])
        interp = retained(interp_path, r['application_build']['interpreter'])
        app_layout = app.elf(original, native_policy)
        projected = {k: v for k, v in app_layout.items() if k not in ('source', 'sources')}
        projected['source_pairs'] = [fact(v) for v in app_layout['source_pairs']]
        need(normalized(projected) == r['application_layout'], 'same whole application ELF model')

        native = None
        for lane in ('native', 'maintained', 'differential'):
            observed = result['lanes'][lane] = dict(status='failed')
            try:
                label = 'subject-' + lane + '-0-0'; row = command(label); capture = captures(row)
                need(row['bounds'] == [30, 512 << 20, 16 << 20, 60], 'original subject bounds unchanged')
                prep = json.loads(retained(BASE / label / 'preparation.json'))
                need(prep['pid'] == row['pid'] and prep['cpu'] == [r['cpu']] and
                     prep['mode'] == prep['control'] == 0 and
                     prep['role'] == ('native' if lane == 'native' else 'gated'), 'actual retained preparation')
                args_app = (capture['stdout'], 0, lane == 'native', row['exit'], app_layout,
                            row['pid'], r['cpu'], reference)
                parsed = app.read(*args_app)
                if lane == 'native':
                    need(capture['stderr'] == b'', 'actual native empty stderr')
                    observed['application_controls'] = population(app.controls(*args_app), 40, capture['stdout'])
                    need(observed['application_controls'] == r['cases'][0]['application_controls'],
                         'unchanged literal native refusal names')
                    native = parsed
                else:
                    holder = r['lanes'][lane]; subject = holder['subject_artifacts']
                    build = BASE / (lane + '-build')
                    suffix = 'persistent-block-' + ('capture' if lane == 'maintained' else 'differential')
                    bridge = retained(build / suffix / ('bridge-' + suffix + '.so'), subject['bridge'])
                    carrier = retained(build / 'carrier', subject['carrier'])
                    layout = json.loads(retained(build / 'owner-dwarf-layout.json', holder['owner_layout']['artifact']))
                    need(holder['owner_layout']['bridge'] == subject['bridge'], 'actual DWARF belongs to bridge')
                    ns = BASE / label / 'namespace'
                    manifest = json.loads(retained(ns / 'namespace.json'))
                    launch = json.loads(retained(ns / 'launch.json'))
                    need(manifest['objects'] == [] and manifest['original'] == str(original_path) and
                         manifest['interpreter'] == str(interp_path) and
                         manifest['original_sha256'] == fact(original)['sha256'] and
                         manifest['interpreter_sha256'] == fact(interp)['sha256'] and
                         launch['dependency_fds'] == [] and launch['argv'] == [str(original_path), '0', 'gated'] and
                         launch['carrier_sha256'] == fact(carrier)['sha256'] and
                         launch['carrier_size'] == len(carrier), 'exact empty-dependency image inventory')
                    need(subject['original'] == fact(original) and subject['interpreter'] == fact(interp),
                         'same original and interpreter across lanes')
                    image = dict(objects={0: dict(data=original, carrier_bytes=len(carrier), kind=1),
                                          1: dict(data=interp, carrier_bytes=len(interp), kind=2)},
                                 main_object=0, interpreter_object=1, uid=os.getuid(), bridge=bridge,
                                 persistent_binding=holder['release_build']['persistent_binding'],
                                 headers=holder['release_build']['headers'], app_symbols=app_layout['symbols'])
                    args_owner = (capture['record'], layout, image, parsed, row['pid'], r['cpu'], row['exit'])
                    actual = owner.read(*args_owner)
                    observed['owner_controls'] = population(owner.controls(*args_owner), 204, capture['record'])
                    need(native is not None, 'complete same-capture native reference')
                    observed['pair'] = app.pair(native, parsed, actual)
                    observed['pair_controls'] = population(app.pair_controls(native, parsed, actual), 36)
                    historical = next(c for c in r['cases'] if c['lane'] == lane)
                    need(observed['pair'] == historical['pair'] and
                         observed['pair_controls'] == historical['pair_controls'], 'unchanged whole pair and36 refusal names')
                observed['status'] = 'passed'
            except Exception as error:
                observed['error'] = type(error).__name__ + ': ' + str(error)
                result['errors'].append(lane + ': ' + observed['error'])
                if isinstance(error, TimeoutError):
                    raise
        need(list(result['lanes']) == ['native', 'maintained', 'differential'] and
             all(x['status'] == 'passed' for x in result['lanes'].values()), 'all fixed regression lanes')
        result['status'] = 'passed'
    except Exception as error:
        result['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        signal.alarm(0)
        try:
            source_closure()
            for path, expected in list(checked.items()):
                take(path, expected)
            need(sorted(os.sched_getaffinity(0)) == [args.cpu], 'unchanged singleton regression CPU')
            result['inputs_unchanged'] = True
        except Exception as error:
            result['status'] = 'failed'; result['inputs_unchanged'] = False
            result['errors'].append('closure: ' + type(error).__name__ + ': ' + str(error))
        result['inputs'] = checked
        result['duration_ns'] = time.monotonic_ns() - start
        with output.open('x') as stream:
            json.dump(result, stream, sort_keys=True, indent=2); stream.write('\n')
    print(json.dumps(dict(scope=result['scope'], status=result['status'], errors=result['errors'],
                          output=str(output), **fact(output.read_bytes())), sort_keys=True))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
