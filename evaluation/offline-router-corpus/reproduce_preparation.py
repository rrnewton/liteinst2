#!/usr/bin/env python3
"""One explicit bounded stage; preparation never automatically launches a population."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import types

MIB = 1048576
ARTIFACT = 'evaluation/adjacent-b2/artifact-verifier/'
NATIVE = 'evaluation/offline-router-native/'
CORPUS = 'evaluation/offline-router-corpus/'
PROCESS = 'evaluation/admission/processes.py'
PROCESS_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
SOURCE_ROOTS = ('Cargo.toml', 'Cargo.lock', 'build.rs', '.cargo', 'crates', 'src',
                'tools', 'tests', 'examples', 'evaluation')
STAGES = {
    'controls': [CORPUS + 'reproduce_preparation.py', 'controls-inner'],
    'profiler-controls': [CORPUS + 'profile_preflight_controls.py'],
    'reproducer-controls': [CORPUS + 'reproduce_preparation_controls.py'],
    'source-freeze': [ARTIFACT + 'freeze_startup_sources.py'],
    'platform': [CORPUS + 'platform_inputs.py'],
    'producer': [ARTIFACT + 'startup_produce.py'],
    'producer-absolute': [ARTIFACT + 'startup_produce.py'],
    'verifier-build': [ARTIFACT + 'startup_verifier_build.py'],
    'saved': [ARTIFACT + 'verify_saved.py'],
    'bootstrap': [ARTIFACT + 'startup_bootstrap.py'],
    'kernel-basis': [NATIVE + 'kernel_basis.py', 'capture'],
    'observer-plan': [NATIVE + 'prepare_profile.py', 'observer-plan'],
    'observer-build': [NATIVE + 'native_launch.py', 'build-observer'],
    'final-profile': [NATIVE + 'prepare_profile.py', 'final-profile'],
    'final-profile-absolute-prerequisites': [NATIVE + 'prepare_profile.py', 'final-profile-absolute-prerequisites'],
    'final-profile-kernel-config-off': [NATIVE + 'prepare_profile.py', 'final-profile-kernel-config-off'],
    'observe-kernel-config-off': [NATIVE + 'native_launch.py', 'observe'],
    'n01-kernel-config-off': [NATIVE + 'native_launch.py', 'n01'],
    'probe': [NATIVE + 'probe_xstate.py'],
    'observe': [NATIVE + 'native_launch.py', 'observe'],
    'n01': [NATIVE + 'native_launch.py', 'n01'],
}
COMMON = ('capture', 'capture-sha256', 'diagnostic', 'diagnostic-sha256', 'verifier-build',
    'verifier-build-sha256', 'verifier-lock-sha256', 'startup-binding', 'startup-binding-sha256',
    'source-profile', 'source-profile-sha256')
NATIVE_FLAGS = ('root', 'final-profile', 'final-profile-sha256', 'accept-contract-sha256', 'output')
FLAGS = {
    'controls': (), 'profiler-controls': (), 'reproducer-controls': (),
    'source-freeze': ('output',), 'platform': ('output',),
    'producer': ('output', 'toolchain', 'cargo-home', 'user-home', 'host-inventory', 'contract-record',
        'source-profile', 'host-inventory-sha256', 'contract-sha256', 'source-profile-sha256', 'original-profile'),
    'verifier-build': ('output', 'source-profile', 'source-profile-sha256', 'toolchain', 'cargo-home', 'user-home'),
    'saved': COMMON + ('output',), 'bootstrap': COMMON + ('output', 'main-joins', 'main-joins-sha256'),
    'kernel-basis': ('root', 'release', 'headers', 'output'),
    'observer-plan': ('root', 'native-revision', 'source-profile', 'source-profile-sha256', 'capture',
        'capture-sha256', 'build-output', 'binary-output', 'output'),
    'observer-build': ('root', 'build-plan', 'build-plan-sha256'),
    'final-profile': ('inputs', 'inputs-sha256', 'output'),
    'final-profile-absolute-prerequisites': ('inputs', 'inputs-sha256', 'output'), 'probe': ('raw-output',),
    'observe': NATIVE_FLAGS, 'n01': NATIVE_FLAGS,
    'final-profile-kernel-config-off': ('inputs', 'inputs-sha256', 'output'),
    'observe-kernel-config-off': NATIVE_FLAGS + ('accept-kernel-basis-sha256',),
    'n01-kernel-config-off': NATIVE_FLAGS + ('accept-kernel-basis-sha256',),
}

ABSOLUTE_STARTUP = 'elf-disassembly-null-jumps-static-exec-router-absolute-prerequisites-v1'
FLAGS['producer-absolute'] = FLAGS['producer'] + ('startup-profile',)
PRODUCER_STAGES = ('producer', 'producer-absolute')



def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    def constant(_value):
        raise ValueError('nonfinite JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def read(path, expected=None):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'canonical input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= MIB, 'bounded regular input')
        raw = bytearray()
        while len(raw) <= MIB:
            part = os.read(fd, min(65536, MIB + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        stamp = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) ==
             stamp(path.lstat()), 'stable whole input')
        need(expected is None or sha(raw) == expected, 'external input SHA256')
        return bytes(raw)
    finally:
        os.close(fd)


def write(path, value):
    raw = (json.dumps(value, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return sha(raw)


def git(root, *args):
    return subprocess.check_output(['/usr/bin/git', '--no-optional-locks', '-C', str(root), *args],
                                   env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}, timeout=15)


def snapshot(root, revision):
    need(root.is_absolute() and root.resolve(strict=True) == root, 'canonical checkout')
    need(git(root, 'rev-parse', 'HEAD').decode().strip() == revision, 'exact committed revision')
    need(not git(root, 'diff', '--binary', 'HEAD', '--'), 'clean tracked source')
    need(not git(root, 'ls-files', '--others', '--exclude-standard', '--', *SOURCE_ROOTS),
         'no untracked source inputs')
    return dict(base=revision, working_source_sha256={})


def private(root, output):
    need(output.is_absolute() and output.is_relative_to(root / 'ignored') and
         output.parent.resolve(strict=True) == output.parent, 'fresh canonical ignored output')
    need(not os.path.lexists(output), 'output must be new')


def command(root, python, plan):
    need(set(plan) == {'schema', 'stage', 'arguments', 'history'} and
         plan['schema'] == 'LI2-PREPARATION-COMMAND-1', 'exact command plan')
    stage, tail = plan['stage'], plan['arguments']
    need(stage in STAGES and type(tail) is list and all(type(v) is str and '\0' not in v for v in tail),
         'finite preparation stage and argv')
    flags = {'--' + v for v in FLAGS[stage]}
    need(len(tail) == 2*len(flags) and set(tail[::2]) == flags and
         all(not value.startswith('--') for value in tail[1::2]), 'exact unique flags; no aliases or overrides')
    history = plan['history']
    need(type(history) is list and (len(history) <= 64 if stage in PRODUCER_STAGES else not history),
         'explicit zero through 64 producer histories; no history for other stages')
    if stage in ('controls', 'profiler-controls', 'reproducer-controls'):
        need(tail == [], 'all control cases; no filtering')
    if stage in PRODUCER_STAGES:
        need('--failure-history' not in tail and tail.count('--original-profile') == 1 and
             tail[tail.index('--original-profile') + 1] == 'startup-original-facts-readonly-headerpad-v1',
             'unchanged readonly original profile and explicit history')
    if stage == 'producer-absolute':
        need(tail[tail.index('--startup-profile') + 1] == ABSOLUTE_STARTUP,
             'exact absolute prerequisite startup profile')
    if stage in ('observe', 'n01', 'observe-kernel-config-off', 'n01-kernel-config-off'):
        values = dict(zip(tail[::2], tail[1::2]))
        accepted = values['--accept-contract-sha256']
        need(len(accepted) == 64 and all(c in '0123456789abcdef' for c in accepted), 'explicit contract SHA256')
        profile = decode(read(values['--final-profile'], values['--final-profile-sha256']))
        need(profile['contract']['sha256'] == accepted, 'explicit acceptance matches exact profile contract')
        if stage.endswith('-kernel-config-off'):
            kernel = values['--accept-kernel-basis-sha256']
            need(len(kernel) == 64 and all(c in '0123456789abcdef' for c in kernel) and
                 profile['schema'] == 'LI2STARTUP-FINAL-PROFILE-4' and profile['kernel_basis']['sha256'] == kernel,
                 'separate exact acceptance of explicit kernel-config profile')
        else:
            need(profile.get('schema') != 'LI2STARTUP-FINAL-PROFILE-4', 'kernel mode requires its named stage and separate acceptance')
    references = []
    for reference in history:
        need(type(reference) is dict and set(reference) == {'path', 'sha256'}, 'exact history reference')
        read(reference['path'], reference['sha256'])
        references.append(reference['path'])
    need(len(set(references)) == len(references), 'distinct historical closures')
    result = [str(python), '-B', *STAGES[stage], *tail]
    if stage == 'profiler-controls':
        result.append(str(root / CORPUS / 'profile_preflight.py'))
    for path in references:
        result.extend(['--failure-history', path])
    return result


def environment(args):
    need(args.python == Path(sys.executable).resolve(), 'same canonical invoking Python')
    for path in (args.python, args.toolchain, args.cargo_home, args.user_home, args.temporary):
        need(path.is_absolute() and path.resolve(strict=True) == path, 'canonical tool, home and temp input')
    env = dict(HOME=str(args.user_home), PATH=str(args.toolchain / 'bin') + ':/usr/bin:/bin',
        RUSTC=str(args.toolchain / 'bin/rustc'), RUSTDOC=str(args.toolchain / 'bin/rustdoc'),
        CARGO_HOME=str(args.cargo_home), CARGO_TARGET_DIR=str(args.root / 'target'), CARGO_INCREMENTAL='0',
        CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never', LANG='C.UTF-8',
        LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1', LITEINST_EVALUATION='1')
    for profile in ('DEV', 'TEST'):
        for key, value in dict(DEBUG='0', OPT_LEVEL='0', DEBUG_ASSERTIONS='true', OVERFLOW_CHECKS='true').items():
            env['CARGO_PROFILE_' + profile + '_' + key] = value
    env.update({key: str(args.temporary) for key in ('TMPDIR', 'TEMP', 'TMP')})
    return env


def run(args):
    before = snapshot(args.root, args.revision)
    need(Path(__file__).resolve() == args.root / CORPUS / 'reproduce_preparation.py', 'tracked driver location')
    need(read(Path(__file__).resolve()) == git(args.root, 'show', args.revision + ':' + CORPUS + 'reproduce_preparation.py'),
         'actual committed driver bytes')
    raw = read(args.plan, args.plan_sha256)
    plan = decode(raw)
    argv, env = command(args.root, args.python, plan), environment(args)
    tail = plan['arguments']
    for flag, expected in [('--root', args.root), ('--native-revision', args.revision)]:
        if flag in tail:
            need(tail.count(flag) == 1 and tail[tail.index(flag)+1] == str(expected), 'same declared root/revision')
    if plan['stage'] in (*PRODUCER_STAGES, 'verifier-build'):
        for flag, value in [('--toolchain', args.toolchain), ('--cargo-home', args.cargo_home), ('--user-home', args.user_home)]:
            need(tail.count(flag) == 1 and tail[tail.index(flag)+1] == str(value), 'same controlled build environment')
    if plan['stage'] == 'probe':
        need(len(tail) == 2 and tail[0] == '--raw-output', 'exact measured probe argv')
        private(args.root, Path(tail[1]))
    helper_raw = read(args.root / PROCESS, PROCESS_SHA)
    need(helper_raw == git(args.root, 'show', args.revision + ':' + PROCESS), 'committed command owner')
    helper = types.ModuleType('_preparation_owner')
    helper.__file__ = str(args.root / PROCESS)
    exec(compile(helper_raw, helper.__file__, 'exec'), helper.__dict__)
    private(args.root, args.output)
    args.output.mkdir(mode=0o700)
    log = args.root / 'target/evaluation/preparation' / (sha(str(args.output).encode()) + '.log')
    log.parent.mkdir(parents=True, exist_ok=True)
    need(not os.path.lexists(log), 'new bounded raw log')
    load = lambda: Path('/proc/loadavg').read_text().split()[:3]
    record = dict(**before, command=argv, env=env, wall_limit_seconds=1200, output_limit_bytes=8*MIB,
        reserved_cpus=sorted(os.sched_getaffinity(0)), load_before=load(), hardware='AMD EPYC Zen 5 dev host',
        attempts=1, plan_sha256=args.plan_sha256, driver_sha256=sha(read(Path(__file__).resolve())))
    write(args.output / 'planned.json', record)
    errors, closed, unchanged = [], None, False
    try:
        os.chdir(args.root)
        closed = helper.run_command(argv, env, log, 1200, 8*MIB)
        if closed['cleanup_complete']:
            data = log.read_bytes()
            need(sha(data) == closed['private_log_sha256'], 'exact closed raw log')
            with (args.output / 'owner.log').open('xb') as output:
                output.write(data)
    except BaseException as error:
        errors.append(type(error).__name__ + ': ' + str(error))
    finally:
        try:
            unchanged = snapshot(args.root, args.revision) == before and read(args.plan, args.plan_sha256) == raw
            for reference in plan['history']:
                read(reference['path'], reference['sha256'])
            if plan['stage'] in ('observe', 'n01', 'observe-kernel-config-off', 'n01-kernel-config-off'):
                values = dict(zip(tail[::2], tail[1::2]))
                read(values['--final-profile'], values['--final-profile-sha256'])
        except BaseException as error:
            errors.append(type(error).__name__ + ': ' + str(error))
        try:
            after_load = load()
        except BaseException as error:
            after_load = None
            errors.append(type(error).__name__ + ': ' + str(error))
        complete = (not errors and unchanged and closed is not None and closed['exit_code'] == 0 and
                    closed['termination'] is None and closed['cleanup_complete'] and closed['reaped_descendants'] == 0)
        # Preserve the real child outcome; existing readers consume only closed.
        record.update(command_closed=closed, closed=closed if complete else None,
                      load_after=after_load, source_unchanged=unchanged, errors=errors)
        write(args.output / 'owner.json', record)
    return 0 if complete else 1


def final_inputs(args, *, kernel_config_off=False):
    snapshot(args.root, args.revision)
    need(read(Path(__file__).resolve()) == git(args.root, 'show', args.revision + ':' + CORPUS + 'reproduce_preparation.py'),
         'actual committed assembler bytes')
    held = {}
    def pin(path, expected=None):
        raw = read(path, expected)
        need(str(path) not in held or held[str(path)] == raw, 'same input cannot rebind')
        held[str(path)] = raw
        return raw
    value = decode(pin(args.plan, args.plan_sha256))
    fields = {'schema', 'producer', 'verifier', 'joins', 'bootstrap', 'observer_plan', 'observer_build', 'contract', 'xstate'}
    if kernel_config_off: fields.add('kernel_basis')
    need(set(value) == fields and value['schema'] == ('LI2-PREPARATION-REFERENCES-2' if kernel_config_off else
         'LI2-PREPARATION-REFERENCES-1'), 'complete explicit references; no prior input/receipt cloning')
    def ref(path):
        return dict(path=str(path), sha256=sha(pin(Path(path))))
    def directory(path):
        return dict(directory=path, sha256=sha(pin(Path(path) / 'closed.json')))
    producer, verifier = Path(value['producer']), Path(value['verifier'])
    arguments = {}
    for key, path, leaf in [('capture', producer/'originals', 'closed.json'),
            ('diagnostic', producer/'producer', 'receipt.json'), ('verifier_build', verifier/'build', 'closed.json'),
            ('startup_binding', producer/'startup-binding.json', None), ('main_joins', Path(value['joins']), 'closed.json')]:
        arguments[key] = str(path)
        arguments[key + '_sha256'] = sha(pin(path / leaf if leaf else path))
    arguments['verifier_lock_sha256'] = sha(pin(args.root / ARTIFACT / 'Cargo.lock'))
    need(set(value['xstate']) == {'owner_source', 'owner_receipt', 'log', 'raw'}, 'all four probe inputs')
    references = [value['contract'], *value['xstate'].values()]
    if kernel_config_off: references.append(value['kernel_basis'])
    for reference in references:
        need(set(reference) == {'path', 'sha256'}, 'explicit externally pinned input')
        pin(reference['path'], reference['sha256'])
    result = dict(schema='LI2NATIVE-FINAL-PROFILE-INPUTS-2' if kernel_config_off else 'LI2NATIVE-FINAL-PROFILE-INPUTS-1',
        root=str(args.root), native_revision=args.revision,
        observer_plan=ref(value['observer_plan']), arguments=arguments, bootstrap=directory(value['bootstrap']),
        contract=value['contract'], observer_build=directory(value['observer_build']), xstate=value['xstate'])
    if kernel_config_off: result['kernel_basis'] = value['kernel_basis']
    snapshot(args.root, args.revision)
    for path, raw in held.items():
        need(read(path) == raw, 'input changed before prospective publication')
    private(args.root, args.output)
    write(args.output, result)
    return 0


def main():
    need(not sys.flags.optimize, 'assertions required')
    if sys.argv[1:] == ['controls-inner']:
        exits = []
        for directory in (ARTIFACT.rstrip('/'), NATIVE.rstrip('/')):
            argv = [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', directory, '-p', '*controls.py']
            print(json.dumps(dict(command=argv)), flush=True)
            code = subprocess.run(argv).returncode
            print(json.dumps(dict(command=argv, exit=code)), flush=True)
            exits.append(code)
        return int(any(exits))
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('mode', choices=('run', 'final-inputs', 'final-inputs-kernel-config-off'))
    for name in ('root', 'plan', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('revision', 'plan-sha256'):
        parser.add_argument('--' + name, required=True)
    for name in ('python', 'toolchain', 'cargo-home', 'user-home', 'temporary'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    if args.mode == 'run':
        need(all(getattr(args, name) is not None for name in ('python', 'toolchain', 'cargo_home', 'user_home', 'temporary')),
             'explicit controlled environment')
    if args.mode == 'final-inputs-kernel-config-off': return final_inputs(args, kernel_config_off=True)
    return run(args) if args.mode == 'run' else final_inputs(args)


if __name__ == '__main__':
    raise SystemExit(main())
