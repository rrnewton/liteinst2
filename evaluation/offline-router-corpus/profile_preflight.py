#!/usr/bin/env python3
"""One instrumented, read-only observer-child preflight; never native evidence.

Example (all inputs are previously frozen; OUT must be new under ROOT/ignored):
  python3 -B evaluation/offline-router-corpus/profile_preflight.py \
    --root "$ROOT" --final-profile "$PROFILE" --final-profile-sha256 "$PROFILE_SHA" \
    --accept-contract-sha256 "$CONTRACT_SHA" --child-request "$CHILD" \
    --child-request-sha256 "$CHILD_SHA" --output "$OUT"

The external profile digest selects reviewed launcher code. The contract digest
explicitly accepts that code's existing unsafe caller premises; this diagnostic
grants no new authority. Actual checked callbacks reconstruct the entire Session
and observer build. Their bounded read-only Git subprocesses remain unchanged.
No producer, compiler, verifier, observer, measurement child or candidate is run.
No candidate copy or memfd is created. There is one pass and no retry.

Profiling includes authentication and cleanup. It stops before sealed transport
and exec, retaining the last build/session stability and inherited-signal checks.
Stats are instrumented diagnostics, NOT performance or qualification results.
"""
import argparse
import cProfile
import hashlib
import io
import json
import marshal
import os
from pathlib import Path
import pstats
import re
import stat
import sys
import time
import types

MIB = 1048576
LAUNCHER = 'evaluation/offline-router-native/native_launch.py'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
         'canonical SHA256')
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns]


def read(path, cap=MIB):
    """Bootstrap before importing checked code: bounded, all-component no-follow."""
    path = Path(path)
    need(path.is_absolute() and str(path) == os.path.normpath(str(path)),
         'canonical absolute input')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap,
                 'bounded regular input')
            raw = bytearray()
            while len(raw) < before.st_size:
                part = os.read(fd, min(65536, before.st_size - len(raw)))
                need(part, 'short input read')
                raw.extend(part)
            need(not os.read(fd, 1) and stamp(before) == stamp(os.fstat(fd)) ==
                 stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                 'stable whole input')
            return bytes(raw), dict(path=str(path), bytes=len(raw),
                                   sha256=sha(raw), stat=stamp(before))
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def constant(_):
        raise ValueError('nonfinite JSON')

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def authenticate_launcher(args):
    raw, profile_pin = read(args.final_profile)
    need(sha(raw) == digest(args.final_profile_sha256), 'external final profile digest')
    profile = decode(raw)
    need(type(profile) is dict and type(profile.get('native_sources')) is dict and
         type(profile.get('contract')) is dict, 'profile source/contract binding')
    need(profile['contract'].get('sha256') == digest(args.accept_contract_sha256),
         'explicit accepted contract')
    wanted = digest(profile['native_sources'].get(LAUNCHER))
    path = args.root / LAUNCHER
    source, source_pin = read(path, 2 * MIB)
    need(sha(source) == wanted, 'profile-pinned actual launcher bytes')
    # Execute exactly the authenticated buffer, never a second path-based read.
    module = types.ModuleType('_li2_profiled_native_launch')
    module.__file__ = str(path)
    exec(compile(source, str(path), 'exec'), module.__dict__)
    return module, dict(final_profile=profile_pin, launcher=source_pin)


class Output:
    """Fresh private directory; exclusive writes stay anchored to its descriptor."""
    def __init__(self, root, path):
        need(path.is_absolute() and path.is_relative_to(root / 'ignored') and
             path.parent.resolve(strict=True) == path.parent,
             'new output under canonical root/ignored')
        path.mkdir(mode=0o700)  # Existing paths, including symlinks, refuse.
        self.path = path
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.identity = stamp(os.fstat(self.fd))[:3]

    def check(self):
        need(stamp(os.fstat(self.fd))[:3] == self.identity ==
             stamp(os.stat(self.path, follow_symlinks=False))[:3], 'output directory replaced')

    def write(self, name, raw):
        self.check()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                need(stream.write(raw) == len(raw), 'whole diagnostic output')
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        self.check()
        return dict(bytes=len(raw), sha256=sha(raw))

    def close(self):
        os.close(self.fd)


def error_record(error):
    """Preserve a callback's chained error if its own cleanup raised as well."""
    chain, seen = [], set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        chain.append(dict(type=type(error).__name__, message=str(error)))
        error = error.__cause__ if error.__cause__ is not None else error.__context__
    return chain


def preflight(launch, args, phase, owners):
    final, session = phase('open_session', lambda: launch.open_session(
        args.root, args.final_profile, args.final_profile_sha256,
        args.accept_contract_sha256))
    owners.append(('close_session', session))
    phase('check_launcher_source', lambda: session.check_source(launch.NATIVE + 'native_launch.py'))
    wire = phase('load_wire', lambda: launch.source(
        args.root, launch.NATIVE + 'native_wire.py',
        session.check_source(launch.NATIVE + 'native_wire.py')))
    raw, capsule_pin = phase('read_child_capsule', lambda: launch.read(args.child_request))
    launch.need(launch.sha(raw) == digest(args.child_request_sha256),
                'exact prospective child request capsule')
    work = launch.decode(raw)
    launch.need(set(work) == {'schema', 'program', 'main', 'dataset', 'wire'} and
                work['schema'] == 'LI2NATIVE-OBSERVE-CHILD-1' and
                work['program'] in launch.PROGRAMS, 'finite observer child schema')
    phase('bind_main_copy', lambda: session.bind_main_copy(work['program'], work['main']))
    request = phase('request', lambda: session.request(work['program'], work['dataset']))
    encoded = phase('encode_request', lambda: wire.encode(request))
    saved, pin = phase('read_wire', lambda: launch.read(work['wire']['path'], wire.CAP))
    launch.need(pin == work['wire'] and saved == encoded, 'whole prospective Request reconstruction')
    _, store, binary, stable = phase('observer_build', lambda: launch.observer_build(session, args.root))
    owners.append(('close_build', store))
    phase('no_capabilities', lambda: final.no_capabilities(binary))
    # The production child seals a memfd here. This diagnostic never calls sealed.
    phase('build_stable', stable)
    phase('session_stable', session.stable)
    phase('child_signals', launch.child_signals)
    return dict(child_capsule=capsule_pin, wire=pin, program=work['program'])


def run(args):
    need(not sys.flags.optimize, 'assertions required')
    need(args.root.is_absolute() and args.root.resolve(strict=True) == args.root,
         'canonical checkout root')
    for value in (args.final_profile_sha256, args.accept_contract_sha256,
                  args.child_request_sha256):
        digest(value)
    output = Output(args.root, args.output)
    profiler = cProfile.Profile()
    owners, phases = [], []
    report = dict(schema='LI2-READONLY-PREFLIGHT-PROFILE-2', instrumented=True,
                  primary_error=None, cleanup_errors=[], diagnostic_errors=[],
                  phases=phases, files={}, inputs={}, preflight_complete=False,
                  memfd_created=False, candidate_copies_created=0,
                  observer_dispatches=0, measurement_child_dispatches=0,
                  native_dispatches=0, qualification_complete=False, performance_eligible=False)

    def phase(name, action):
        wall, cpu = time.monotonic(), time.process_time()
        try:
            return action()
        finally:
            phases.append(dict(name=name, wall_seconds=time.monotonic() - wall,
                               cpu_seconds=time.process_time() - cpu))

    try:
        profiler.enable()
        try:
            launch, pins = phase('authenticate_launcher', lambda: authenticate_launcher(args))
            report['inputs'].update(pins)
            report['inputs'].update(preflight(launch, args, phase, owners))
            report['preflight_complete'] = True
        except BaseException as error:
            report['primary_error'] = error_record(error)
        finally:
            # Attempt every close independently; never overwrite the primary failure.
            for name, owner in reversed(owners):
                try:
                    phase(name, owner.close)
                except BaseException as error:
                    report['cleanup_errors'].append(dict(phase=name, errors=error_record(error)))
            profiler.disable()
        # Independent attempts: a cleanup or stats-write failure cannot skip the others.
        def binary_stats():
            profiler.create_stats()
            return marshal.dumps(profiler.stats)

        def text_stats():
            text = io.StringIO()
            pstats.Stats(profiler, stream=text).strip_dirs().sort_stats('cumulative').print_stats(60)
            return text.getvalue().encode('utf-8')

        for name, render in (('profile.pstats', binary_stats), ('profile.txt', text_stats)):
            try:
                report['files'][name] = output.write(name, render())
            except BaseException as error:
                report['diagnostic_errors'].append(dict(file=name, errors=error_record(error)))
        ok = report['preflight_complete'] and report['primary_error'] is None and not (
            report['cleanup_errors'] or report['diagnostic_errors'])
        report['preflight_complete'] = ok
        report['status'] = 'DIAGNOSTIC_COMPLETE' if ok else 'DIAGNOSTIC_FAILED'
        output.write('closed.json', (json.dumps(report, indent=2) + '\n').encode('utf-8'))
        os.fsync(output.fd)
        return 0 if ok else 1
    finally:
        output.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'final-profile', 'child-request', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('final-profile-sha256', 'accept-contract-sha256', 'child-request-sha256'):
        parser.add_argument('--' + name, required=True)
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
