"""Explicit unsafe final startup admission, with no launch side effects.

open_session is for the separately pinned, reviewed launcher. Its caller accepts
all obligations in the exact contract SHA; neither a receipt nor sealed request
bytes can make that acceptance on the caller's behalf. Unknown safe authority
continues to refuse. Sessions must live through all child cleanup, with stable()
before and after EACH child. The same-user Python object is not a security token.
"""
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import types

MIB = 1048576
NATIVE = 'evaluation/offline-router-native/'
CRATE = 'evaluation/adjacent-b2/artifact-verifier/'
PROGRAMS = ('checksum', 'rle-roundtrip')
PACKAGE_SHA = '13a5e8655f23c933a016908e3a875a089368a7a4be8a1891d4409f36b0d99bd2'
REQUIRED_NATIVE = {
    NATIVE+name for name in ('package.py', 'final_admission.py', 'final_bootstrap.py',
        'final_platform.py', 'final_controls.py', 'n01.py', 'n01_controls.py', 'package_controls.py',
        'native_launch.py', 'native_wire.py',
        'observer/Cargo.toml', 'observer/Cargo.lock', 'observer/src/lib.rs', 'observer/src/main.rs', 'observer/src/tests.rs',
        'observer/src/wire.rs')}
ARGUMENTS = ('capture', 'capture_sha256', 'diagnostic', 'diagnostic_sha256', 'verifier_build',
    'verifier_build_sha256', 'verifier_lock_sha256', 'startup_binding', 'startup_binding_sha256',
    'main_joins', 'main_joins_sha256')


def need(ok, detail):
    if not ok:
        raise ValueError(detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def read_file(path, cap=MIB):
    """Bounded no-follow all-component read before any external source import."""
    path = Path(path)
    need(path.is_absolute() and str(path) == os.path.normpath(str(path)) and
         all(part not in ('.', '..') for part in path.parts), 'canonical absolute final input')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap, 'bounded regular final input')
            raw = bytearray()
            while len(raw) < before.st_size:
                part = os.read(fd, min(65536, before.st_size-len(raw)))
                need(part, 'short final input'); raw.extend(part)
            need(not os.read(fd, 1) and stamp(os.fstat(fd)) == stamp(before) ==
                 stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'stable final input read')
            return bytes(raw), dict(path=str(path), bytes=len(raw), sha256=sha(raw), stat=stamp(before))
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def decode(raw):
    need(type(raw) is bytes and len(raw) <= MIB, 'bounded final profile')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate final profile key'); result[key] = value
        return result
    def constant(_):
        raise ValueError('nonfinite final profile')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, 'canonical final digest')
    return value


def reference(value, directory=False):
    field = 'directory' if directory else 'path'
    need(type(value) is dict and set(value) == {field, 'sha256'}, 'exact frozen reference')
    digest(value['sha256'])
    return Path(value[field])


def safe_admit(*_args, **_kwargs):
    raise ValueError('NO_SUPPORTED_SAFE_AUTHORITY: receipts and sealed bytes do not grant unsafe launch authority')


def load_source(raw, path):
    module = types.ModuleType('_li2_final_'+path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def no_capabilities(pin):
    need(pin['stat'][2] & 0o6000 == 0, 'no set-ID execution input')
    try:
        raw = os.getxattr(pin['path'], 'security.capability', follow_symlinks=False)
    except OSError as error:
        need(error.errno == errno.ENODATA, 'capability attribute absent under the unchanged runtime contract')
    else:
        raise ValueError('no file capability attribute, including empty attributes')


class Session:
    """Pinned complete two-program session. Only open_session constructs one.

    request() returns a fresh value; mutable exported summaries are never used as
    authorization. The caller remains responsible for normal exec, controlled
    inherited signal state, empty env, absolute limits and completed cleanup.
    """
    def __init__(self, key, profile, programs, execution, package, held, store, stable):
        need(key is _CONSTRUCTION, 'explicit final authority constructor')
        self.profile = copy.deepcopy(profile)
        self._profile = copy.deepcopy(profile)
        self.programs = copy.deepcopy(programs)
        self._programs = copy.deepcopy(programs)
        self._execution = copy.deepcopy(execution)
        self._package, self._held, self._store, self._stable = package, held, store, stable
        self._closed = False
        self._bound = set()

    def stable(self):
        need(not self._closed, 'live final admission owners')
        self._stable()
        self._held.verify()
        for program in self._bound:
            no_capabilities(self._programs[program]['main_pin'])

    def execution_inputs(self):
        """Already reconstructed build tools/env/config; never child envp."""
        self.stable()
        return copy.deepcopy(self._execution)

    def check_source(self, relative):
        need(relative in self._profile['native_sources'], 'launcher/helper in separate final source profile')
        self.stable()
        return self._profile['native_sources'][relative]

    def bind_main_copy(self, program, pin):
        """Admit one distinct exact executable copy without changing W01 source."""
        self.stable()
        need(program in PROGRAMS and program not in self._bound, 'one executable copy per full program')
        item = self._programs[program]
        raw = self._held.retain(pin, 16*MIB)
        need(raw == item['main_bytes'] and pin['path'] != item['main_pin']['path'] and
             pin['stat'][:2] != item['main_pin']['stat'][:2] and stat.S_IMODE(pin['stat'][2]) == 0o700,
             'distinct exact owned executable candidate copy')
        need(os.stat(pin['path'], follow_symlinks=False).st_uid == os.geteuid(), 'owned candidate copy')
        root = Path(self._profile['_root'])
        need(Path(pin['path']).is_relative_to(root/'ignored') and pin['stat'][1] != 0,
             'private candidate execution copy')
        no_capabilities(pin)
        item['main_pin'] = copy.deepcopy(pin)
        item['observer_objects']['main']['file'] = copy.deepcopy(pin)
        self.programs[program] = copy.deepcopy(item)
        self._bound.add(program)
        self.stable()

    def request(self, program, dataset_pin):
        self.stable()
        need(program in self._bound, 'actual executable copy required before request')
        need(Path(dataset_pin['path']).is_relative_to(Path(self._profile['_root'])/'ignored'), 'private fixed dataset')
        self._held.retain(dataset_pin, 65536)
        item = self._programs[program]
        value = dict(copy.deepcopy(item['observer_objects']), dataset=copy.deepcopy(dataset_pin),
            entry=item['entry'], entry_bytes=item['entry_bytes'],
            completion_relative=item['completion_relative'], completion_file_offset=item['completion_file_offset'],
            xstate_bytes=self._profile['reviewed']['xstate_bytes'])
        self.stable()
        return value

    def close(self):
        if not self._closed:
            try:
                self.stable()
            finally:
                self._closed = True
                try: self._held.close()
                finally: self._store.close()


_CONSTRUCTION = object()


def open_session(root, profile_path, profile_sha256, accept_contract_sha256):
    """UNSAFE API: caller explicitly accepts the exact platform obligations.

    The separate profile is frozen only after source integration and actual DSO
    inspection. Its whole-facts hashes record independent review of ALL linked
    constructors/relocations, not a substitute for reconstructing those facts.
    No producer, verifier, compiler, candidate or observer is dispatched here.
    Existing artifact readers can issue only their read-only Git identity probes.
    """
    need(not sys.flags.optimize, 'assertions required')
    root = Path(root)
    need(root.is_absolute() and root.resolve(strict=True) == root, 'canonical checkout')
    need(Path(profile_path).is_relative_to(root/'ignored'), 'separate private final profile')
    raw, profile_pin = read_file(profile_path)
    need(sha(raw) == digest(profile_sha256), 'externally frozen final checker profile')
    profile = decode(raw)
    need(set(profile) == {'schema', 'native_revision', 'native_sources', 'artifact_source_profile', 'arguments', 'bootstrap',
        'contract', 'reviewed', 'observer'} and profile['schema'] in ('LI2STARTUP-FINAL-PROFILE-1', 'LI2STARTUP-FINAL-PROFILE-2'),
         'explicit final profile shape')
    namespace_profile = profile['schema'] == 'LI2STARTUP-FINAL-PROFILE-2'
    need(type(profile['native_revision']) is str and re.fullmatch('[0-9a-f]{40}', profile['native_revision']) is not None,
         'actual separately committed native source revision')
    source_map = profile['native_sources']
    need(type(source_map) is dict and REQUIRED_NATIVE <= set(source_map) and len(source_map) <= 128,
         'complete separately pinned native source roster')
    if namespace_profile:
        need({NATIVE+'dependency_constructors.py', NATIVE+'dependency_constructor_controls.py'} <= set(source_map),
             'separately pinned complete-namespace resolver/control source')
    source_records = {str(profile_path): (raw, profile_pin)}
    sources = {}
    for relative, expected in source_map.items():
        need(type(relative) is str and relative.startswith(NATIVE) and
             '..' not in Path(relative).parts and not Path(relative).is_absolute(), 'native source path scope')
        contents, pin = read_file(root/relative, 2*MIB)
        need(sha(contents) == digest(expected), 'exact final source bytes')
        source_records[str(root/relative)] = (contents, pin)
        sources[relative] = contents
    need(source_map[NATIVE+'package.py'] == PACKAGE_SHA, 'unchanged package resolver v2')
    platform = load_source(sources[NATIVE+'final_platform.py'], root/NATIVE/'final_platform.py')
    reader = load_source(sources[NATIVE+'final_bootstrap.py'], root/NATIVE/'final_bootstrap.py')
    dependency = load_source(sources[NATIVE+'dependency_constructors.py'], root/NATIVE/'dependency_constructors.py') if namespace_profile else None
    package = load_source(sources[NATIVE+'package.py'], root/NATIVE/'package.py')
    # The running entrypoint is included, but no caller can turn arbitrary new
    # source into authority merely by changing a map: the externally supplied
    # profile SHA is the reviewed code authority accepted by this unsafe caller.
    need(Path(__file__).resolve(strict=True) == root/NATIVE/'final_admission.py', 'actual integrated final entrypoint')
    oldref = profile['artifact_source_profile']
    oldpath = reference(oldref)
    oldraw, oldpin = read_file(oldpath)
    need(sha(oldraw) == oldref['sha256'], 'frozen original artifact source profile')
    source_records[str(oldpath)] = (oldraw, oldpin)
    old = decode(oldraw)
    need(type(old.get('sources')) is dict, 'complete original artifact source inventory')
    def artifact(name):
        relative = CRATE+name
        contents, pin = read_file(root/relative, 2*MIB)
        need(relative in old['sources'] and sha(contents) == digest(old['sources'][relative]), 'exact artifact reader source')
        source_records[str(root/relative)] = (contents, pin)
        return load_source(contents, root/relative)
    legacy = artifact('verify_saved.py')
    ctx, a = legacy.context(root)
    custody = artifact('startup_custody.py')
    pinloader = artifact('startup_pins.py')
    pins = pinloader.load(ctx, oldpath, oldref['sha256'])
    modules = {name: artifact(name+'.py') for name in ('startup_originals', 'startup_saved', 'startup_completed',
        'startup_produce', 'startup_bootstrap', 'startup_dso')}
    for name in ('startup_custody.py', 'startup_pins.py', 'startup_originals.py', 'startup_saved.py'):
        need(old['sources'][CRATE+name] == legacy.STARTUP_MODULES[name], 'unchanged authenticated common reader binding')
    values = profile['arguments']
    need(type(values) is dict and set(values) == set(ARGUMENTS), 'whole saved artifact argument roster')
    args = types.SimpleNamespace(source_profile=oldpath, source_profile_sha256=oldref['sha256'])
    for name, value in values.items():
        if name.endswith('_sha256'):
            setattr(args, name, digest(value))
        else:
            path = custody.absolute(value)
            need(path.is_relative_to(root/'ignored'), 'private saved capture argument')
            setattr(args, name, path)
    reference(profile['bootstrap'], directory=True)
    contract_path = reference(profile['contract'])
    need(profile['contract']['sha256'] == digest(accept_contract_sha256), 'caller explicitly accepts this unsafe contract')
    contract_raw, contract_pin = read_file(contract_path)
    need(sha(contract_raw) == accept_contract_sha256, 'exact explicitly accepted contract bytes')
    source_records[str(contract_path)] = (contract_raw, contract_pin)
    reviewed = profile['reviewed']
    platform.keys(reviewed, ('dependencies', 'bootstraps', 'xstate_bytes'), 'whole actual-facts review roster')
    if namespace_profile:
        platform.keys(reviewed['dependencies'], PROGRAMS, 'both complete dependency namespaces reviewed')
        for program in PROGRAMS:
            platform.keys(reviewed['dependencies'][program], platform.ROLES, 'all per-program platform objects reviewed')
    else:
        platform.keys(reviewed['dependencies'], platform.ROLES, 'all platform objects reviewed')
    platform.keys(reviewed['bootstraps'], PROGRAMS, 'both whole bootstrap rosters reviewed')
    dependency_hashes = [h for program in PROGRAMS for h in reviewed['dependencies'][program].values()] if namespace_profile else list(reviewed['dependencies'].values())
    for h in [*dependency_hashes, *reviewed['bootstraps'].values()]: digest(h)
    need(type(reviewed['xstate_bytes']) is int and 576 <= reviewed['xstate_bytes'] <= 16384, 'unchanged observer xstate bound')
    platform.keys(profile['observer'], ('binary', 'build'), 'actual observer binary/build reference')
    reference(profile['observer']['build'], directory=True)
    store = custody.Store(2*1024*MIB)
    held = package.Custody()
    try:
        observer_directory = custody.absolute(str(reference(profile['observer']['build'], directory=True)))
        need(observer_directory.is_relative_to(root/'ignored'), 'private actual observer build closure')
        observer_raw = store.read(observer_directory/'closed.json', MIB)
        need(sha(observer_raw) == profile['observer']['build']['sha256'], 'actual frozen observer build receipt bytes')
        held.retain(profile['observer']['binary'], 16*MIB)
        need(profile['observer']['binary']['stat'][2] & 0o111, 'actual executable observer copy')
        no_capabilities(profile['observer']['binary'])
        # The launcher separately reconstructs this build's Cargo/raw closure
        # before invoking it. Retention here prevents placeholder pins and drift,
        # and does not reinterpret this receipt as executable-build proof.
        saved = reader.authenticate(ctx, a, legacy, custody, pins, modules['startup_originals'],
            modules['startup_saved'], modules['startup_completed'], modules['startup_produce'],
            modules['startup_bootstrap'], modules['startup_dso'], args, store, profile['bootstrap'])
        def native_source_profile():
            revision = profile['native_revision']
            def git(*argv):
                return subprocess.check_output(['/usr/bin/git', '-C', str(root), *argv],
                    env=saved['completed']['captured']['env'], timeout=15)
            names = git('ls-tree', '-r', '--name-only', revision, '--', NATIVE).decode('utf-8').splitlines()
            need(set(source_map) == set(names), 'complete separately committed native inventory')
            for relative, expected in source_map.items():
                length = git('cat-file', '-s', revision+':'+relative).decode('ascii').strip()
                need(length == str(len(sources[relative])), 'exact committed native source size')
                need(sha(git('show', revision+':'+relative)) == expected, 'actual committed native source bytes')
        native_source_profile()
        value, dependencies = platform.contract(contract_raw, accept_contract_sha256, package, held)
        dso = modules['startup_dso']
        facts, objects = {}, {}
        for role in platform.ROLES:
            if not namespace_profile:
                facts[role] = platform.library_facts(dependencies[role], role, package, dso)
                need(sha(platform.canonical(facts[role])) == reviewed['dependencies'][role], 'whole actual platform facts reviewed')
            objects[role] = platform.object_pages(dependencies[role], value['files'][role], package, dso)
            no_capabilities(value['files'][role])
        programs = {}
        for program in PROGRAMS:
            item = saved['programs'][program]
            need(sha(platform.canonical(item['linked'])) == reviewed['bootstraps'][program],
                 'whole actual bootstrap facts reviewed, including every constructor/finalizer')
            if namespace_profile:
                namespace = dependency.Namespace(dict(main=item['main']['product']['candidate.elf'],
                    bootstrap=item['bootstrap'], **dependencies), package, dso)
                for role in platform.ROLES:
                    scoped = platform.library_facts_v2(dependencies[role], role, package, dso, namespace)
                    need(sha(platform.canonical(scoped)) == reviewed['dependencies'][program][role],
                         'whole actual per-program dependency namespace facts reviewed')
            entry = platform.main_facts(item, value, accept_contract_sha256, package, dso,
                dependency=dependency if namespace_profile else None)
            main = item['main']; main_pin = main['main_pin']; bootstrap_pin = item['bootstrap_pin']
            need(held.retain(main_pin, 16*MIB) == main['product']['candidate.elf'] and
                 held.retain(bootstrap_pin, 16*MIB) == item['bootstrap'], 'current whole joined main/bootstrap inputs')
            no_capabilities(bootstrap_pin)
            completion = item['linked']['completion']
            observer_objects = dict(main=platform.object_pages(main['product']['candidate.elf'], main_pin, package, dso),
                loader=objects['loader'], bootstrap=platform.object_pages(item['bootstrap'], bootstrap_pin, package, dso),
                dependencies=[objects['libc'], objects['libgcc']])
            need(sum(len(obj['pages']) for obj in [observer_objects['main'], observer_objects['loader'],
                observer_objects['bootstrap'], *observer_objects['dependencies']]) <= 65536, 'unchanged aggregate observer page bound')
            programs[program] = dict(main_pin=main_pin, main_bytes=main['product']['candidate.elf'],
                original_bytes=main['original'], bootstrap_pin=bootstrap_pin, bootstrap_bytes=item['bootstrap'],
                linked_facts=item['linked'], observer_objects=observer_objects,
                completion_relative=completion['address'], completion_file_offset=completion['file_offset'], **entry)
        def stable():
            saved['stable']()
            native_source_profile()
            for path, (contents, pin) in source_records.items():
                actual, current = read_file(path, max(MIB, len(contents)))
                need(actual == contents and platform.exact(current, pin), 'final checker/input source identity drift')
            current, _ = platform.contract(contract_raw, accept_contract_sha256, package, held)
            need(platform.exact(current, value), 'platform contract drift')
            no_capabilities(profile['observer']['binary'])
            for pin in value['files'].values(): no_capabilities(pin)
            for item in programs.values(): no_capabilities(item['bootstrap_pin'])
        result_profile = copy.deepcopy(profile)
        result_profile['_root'] = str(root)
        execution = dict(saved['completed']['captured'], configurations=saved['completed']['configurations'],
            configuration_profile=saved['completed']['plan']['configuration_profile'])
        session = Session(_CONSTRUCTION, result_profile, programs, execution, package, held, store, stable)
        session.stable()
        return session
    except BaseException:
        try: held.close()
        finally: store.close()
        raise
