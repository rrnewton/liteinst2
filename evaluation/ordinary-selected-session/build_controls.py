#!/usr/bin/env python3
"""Fabricated public-builder inputs and closure joins; no compiler/native proof."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
builder = load('_selected_public_builder_controls', HERE / 'build.py')
driver = load('_selected_public_builder_driver_controls', HERE / 'reproduce.py')
owner = load('_selected_public_builder_owner_controls', HERE / 'owner.py')
inherited = load('_selected_public_builder_inherited_controls', driver.ROOT / driver.RECIPE)
processes = load('_selected_public_builder_processes_controls', driver.ROOT / 'evaluation/admission/processes.py')
MIB = 1048576
REVISION = 'a' * 40
DIRECTORY = Path('/fabricated/public-build')
PYTHON = '/fabricated/tools/python'
HARDWARE = 'AMD EPYC Zen 5 dev host'
OPTIONS = ('phase', 'revision', 'reservation-tag', 'raw', 'toolchain', 'user-home',
           'cargo-home', 'hardware')
TEST_OPTIONS = ('build', 'build-sha', 'build-owner', 'build-owner-sha')
ROOTS = ('.cargo', 'src', 'crates', 'tools', 'Cargo.toml', 'Cargo.lock', 'build.rs',
         'evaluation/ordinary-selected-session')


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def invocation(producer):
    keys = OPTIONS + (TEST_OPTIONS if producer['phase'] == 'tests' else ())
    producer['invocation'] = [PYTHON, '-B', 'evaluation/ordinary-selected-session/build.py',
                              *[word for key in keys for word in ('--' + key, producer['options'][key])]]


def schema_fixture(phase='products'):
    options = dict(phase=phase, revision=REVISION, **{'reservation-tag': 'fabricated-3cpu',
        'raw': str(DIRECTORY), 'toolchain': '/fabricated/toolchain',
        'user-home': '/fabricated/user', 'cargo-home': '/fabricated/cargo', 'hardware': HARDWARE})
    previous = None
    if phase == 'tests':
        previous = dict(path='/fabricated/products/result.json', sha256='b' * 64)
        options.update(build=previous['path'], **{'build-sha': previous['sha256'],
            'build-owner': '/fabricated/owners/products.json', 'build-owner-sha': 'c' * 64})
    producer = dict(schema='selected-session-public-build-v1', phase=phase, revision=REVISION,
        recipe='evaluation/ordinary-selected-session/build.py', recipe_sha256='d' * 64,
        invocation=[], options=options,
        source_before=dict(path=str(DIRECTORY / 'sources-before.json'), bytes=100, sha256='e' * 64),
        source_after=dict(path=str(DIRECTORY / 'sources-after.json'), bytes=100, sha256='e' * 64))
    invocation(producer)
    return producer, previous


def accepted_invocation(producer, previous=None):
    return driver.public_build_invocation(producer, producer.get('phase', 'products'), REVISION, DIRECTORY,
                                          PYTHON, HARDWARE, previous)


def owner_options(phase):
    options = dict(phase=phase, revision=REVISION, **{'reservation-tag': 'fabricated-3cpu',
        'owner': '/fabricated/owners/phase.json', 'raw': str(DIRECTORY),
        'toolchain': '/fabricated/toolchain', 'user-home': '/fabricated/user',
        'cargo-home': '/fabricated/cargo', 'hardware': HARDWARE})
    stems = (() if phase == 'products' else ('build', 'build-owner'))
    if phase == 'controls': stems += ('test-product', 'test-owner')
    if phase == 'campaign': stems += ('controls', 'controls-owner', 'geometry')
    for name in stems:
        options[name] = '/fabricated/inputs/' + name + '.json'
        options[name + '-sha'] = 'b' * 64
    return options


class MemoryRecipe:
    pin = staticmethod(pin)
    bounded_join = staticmethod(inherited.bounded_join)

    def __init__(self, files):
        self.files = files
        self.after_read = None

    def read(self, path, cap):
        value = self.files[str(path)]
        assert len(value) <= cap
        if self.after_read is not None:
            callback, self.after_read = self.after_read, None
            callback()
        return value


class Budget:
    def __init__(self):
        self.active = False
        self.completed = 0
        self.charges = []

    def charge(self, path, size):
        self.charges.append((path, size))

    def complete(self):
        assert self.active
        self.active = False
        self.completed += 1


class MemoryRun:
    def __init__(self, files=None):
        self.files = {} if files is None else files
        self.raw = DIRECTORY
        self.a = SimpleNamespace(revision=REVISION)
        self.env = {'FIXTURE': 'not-executed'}
        self.tools = {'python': Path(PYTHON)}
        self.safe = True
        self.retained = {}
        self.sources = {}
        self.budget = Budget()
        self.events = []

    def remember(self, path, expected=None, cap=512 * MIB):
        raw = self.files[str(path)]
        assert len(raw) <= cap
        actual = pin(raw)
        assert expected is None or actual == expected
        if str(path) in self.retained:
            assert self.retained[str(path)] == actual
        else:
            self.retained[str(path)] = actual
        self.events.append(('remember', str(path)))
        return actual

    def unchanged(self):
        assert self.safe
        for path, expected in self.retained.items():
            assert pin(self.files[path]) == expected
        self.events.append(('unchanged',))

    def freeze(self, path, value):
        assert str(path) not in self.files
        self.files[str(path)] = canonical(value)
        self.remember(path)
        self.events.append(('freeze', str(path)))


class InventoryGit:
    def __init__(self):
        self.files = {name: ('fixture:' + name).encode('ascii') for name in (
            '.cargo/config.toml', 'Cargo.toml', 'Cargo.lock', 'build.rs', 'src/lib.rs',
            'crates/helper/src/lib.rs', 'tools/rapid-profiler/ordinary-interval/main.rs',
            'evaluation/ordinary-selected-session/build.py',
            'evaluation/ordinary-selected-session/build_controls.py',
            'evaluation/ordinary-selected-session/leaves.c',
            'evaluation/ordinary-selected-session/reference.c')}
        self.current = sorted(self.files)
        self.committed = list(self.current)
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        if args == ('ls-files', '-z', '--', *ROOTS):
            names = self.current
        elif args == ('ls-tree', '-r', '--name-only', '-z', REVISION, '--', *ROOTS):
            names = self.committed
        else:
            assert len(args) == 2 and args[0] == 'show' and args[1].startswith(REVISION + ':')
            return self.files[args[1][41:]]
        return ('\0'.join(names) + '\0').encode('ascii')


def source_fixture():
    git = InventoryGit()
    run = MemoryRun()
    run.sources = {str(builder.ROOT / name): pin(raw) for name, raw in git.files.items()}
    return run, git


def fresh_fixture(phase='products'):
    producer, previous = schema_fixture(phase)
    recipe_path = driver.ROOT / driver.PUBLIC_BUILD_RECIPE
    raw_recipe = b'fabricated published builder bytes\n'
    run = MemoryRun({str(recipe_path): raw_recipe})
    run.sources = {str(recipe_path): pin(raw_recipe),
                   str(driver.ROOT / 'tests/support/isolated_native_test.rs'): pin(b'full source census')}
    producer['recipe_sha256'] = pin(raw_recipe)['sha256']
    for label in ('source_before', 'source_after'):
        path = producer[label]['path']
        run.files[path] = canonical(run.sources)
        producer[label] = dict(path=path, **pin(run.files[path]))
    tools = {'python': {'path': PYTHON}, **{name: {'path': '/fabricated/toolchain/bin/' + name}
                                          for name in ('cargo', 'rustc', 'rustdoc')}}
    base = dict(tools=tools, hardware=HARDWARE,
                environment={'HOME': '/fabricated/user', 'CARGO_HOME': '/fabricated/cargo'})
    record = dict(producer=producer, revision=REVISION)
    if phase == 'products':
        record.update(base)
    else:
        record['original_build_receipt'] = previous
        run.retained[producer['options']['build-owner']] = {'bytes': 123, 'sha256': 'c' * 64}
    owner = dict(command=list(producer['invocation']), reserved_cpus=[7, 8, 9])
    git_bytes = [raw_recipe]

    def git(*args):
        assert args == ('show', REVISION + ':' + driver.PUBLIC_BUILD_RECIPE)
        return git_bytes[0]

    return run, MemoryRecipe(run.files), record, owner, base, git, git_bytes


class TokenPath:
    """Only a fabricated file token; no actual path is opened or mapped."""
    def __init__(self, name, run, identity, mutation=None):
        self.name, self.run, self.identity, self.mutation = name, run, identity, mutation
        self.opens = 0

    def __str__(self):
        return self.name

    def stat(self):
        return SimpleNamespace(st_dev=self.identity[0], st_ino=self.identity[1])

    def open(self, mode):
        assert mode == 'xb' and self.name not in self.run.files
        self.opens += 1
        return self

    def __enter__(self):
        return self

    def write(self, raw):
        self.run.files[self.name] = raw if self.mutation is None else self.mutation(raw)
        return len(raw)

    def __exit__(self, *_):
        return False


def copy_fixture():
    run = MemoryRun({'/fabricated/source': b'first authenticated product'})
    source = TokenPath('/fabricated/source', run, (12, 101))
    destination = TokenPath('/fabricated/copy', run, (12, 102))
    run.retained[str(source)] = pin(run.files[str(source)])
    return run, MemoryRecipe(run.files), source, destination


class BoundedRun(MemoryRun):
    def __init__(self, mutation=None, code=0, unknown=False):
        super().__init__()
        self.mutation, self.code, self.unknown = mutation, code, unknown
        self.calls = []
        helper = str(driver.ROOT / 'tools/unwind-oracle/bounded_command.py')
        self.sources[helper] = pin(b'fixed existing bounded helper')

    def owned(self, name, argv, wall, growth=None):
        assert not self.calls
        self.calls.append((name, list(map(str, argv)), wall, growth))
        self.budget.active = True
        if self.unknown:
            self.safe = False
            raise RuntimeError('fabricated unknown owner closure')
        directory = self.raw / (name + '-fabricated-owner')
        parent = canonical(dict(exit=self.code, wall_timeout=False, absence_proof='ECHILD',
                                descendants=0, success=self.code == 0))
        closed = dict(exit_code=0 if self.code == 0 else 1, cleanup_complete=True,
                      reaped_descendants=0, termination=None, private_log_sha256=pin(parent)['sha256'])
        self.files[str(directory / 'parent.log')] = parent
        self.files[str(self.raw / 'stdout')] = b'fabricated compiler output'
        self.files[str(self.raw / 'stderr')] = b''
        helper = str(driver.ROOT / 'tools/unwind-oracle/bounded_command.py')
        receipt = dict(exit=self.code, absence_proof='ECHILD', inputs_unchanged=True,
            wall_timeout=False, unexpected_descendants=[], cleanup_events=[], aborted=None, cleanup_error=None,
            request_sha256=self.retained[str(self.raw / 'request.json')]['sha256'],
            helper_sha256=self.sources[helper]['sha256'],
            stdout_sha256=pin(self.files[str(self.raw / 'stdout')])['sha256'],
            stderr_sha256=pin(self.files[str(self.raw / 'stderr')])['sha256'])
        if self.mutation is not None:
            self.mutation(self, directory, closed, receipt)
        self.files[str(self.raw / 'receipt.json')] = canonical(receipt)
        return directory, closed


def memory_blob(run, recipe, path, data):
    assert str(path) not in run.files
    run.files[str(path)] = data
    run.remember(path, recipe.pin(data))


def bounded_call(run, limits=(20, 30, 4 * MIB), writer=memory_blob):
    # Only writes and the process owner are fabricated. The production wrapper,
    # driver.closed_stage and inherited bounded_join all run unchanged.
    proxy = SimpleNamespace(write_blob=writer, closed_stage=driver.closed_stage)
    with patch.object(Path, 'resolve', lambda path, strict=False: path):
        return builder.bounded(run, proxy, MemoryRecipe(run.files), 'fixture', run.raw,
                               ['/fabricated/compiler', '--fixed'], limits)


class ArchiveToken(TokenPath):
    def __init__(self, name, run, mode='valid'):
        super().__init__(str(name), run, (12, 103))
        self.mode = mode

    def is_relative_to(self, path):
        return Path(self.name).is_relative_to(path)

    def open(self, mode):
        assert mode == 'xb'
        if self.mode == 'open-error': raise OSError('fabricated archive open error')
        if self.name in self.run.files: raise FileExistsError('archive already exists')
        return super().open(mode)

    def write(self, raw):
        if self.mode == 'write-error': raise OSError('fabricated archive write error')
        if self.mode == 'short-write':
            self.run.files[self.name] = raw[:-1]
            return len(raw) - 1
        return super().write(raw)

    def __exit__(self, *_):
        if self.mode == 'close-error': raise OSError('fabricated archive close error')
        return False


class ArchiveRecipe(MemoryRecipe):
    def __init__(self, files, capture, archive, mode='valid'):
        super().__init__(files)
        self.capture, self.archive, self.mode = str(capture), str(archive), mode
        self.read_calls = []

    def read(self, path, cap):
        self.read_calls.append((str(path), cap))
        assert cap == 8 * MIB
        if ((str(path) == self.capture and self.mode == 'capture-read-error') or
                (str(path) == self.archive and self.mode == 'archive-read-error')):
            raise OSError('fabricated stable read error')
        raw = super().read(path, cap)
        if str(path) == self.archive and self.mode == 'readback-drift':
            return raw + b' drift'
        return raw


def archive_fixture(mode='valid', raw=b'captured owner output\n'):
    capture_path, archive_path = owner.log_paths(owner.ROOT / 'ignored/fabricated-owner.json')
    run = MemoryRun({str(capture_path): raw})
    capture = ArchiveToken(capture_path, run)
    archive = ArchiveToken(archive_path, run, mode)
    recipe = ArchiveRecipe(run.files, capture, archive, mode)
    closed = dict(exit_code=0, termination=None, cleanup_complete=True, reaped_descendants=0,
                  private_log_sha256=pin(raw)['sha256'])
    return run, recipe, closed, capture, archive


class Controls(unittest.TestCase):
    def test_public_owner_has_exact_four_commands_and_fixed_bounds(self):
        common = ('phase', 'revision', 'reservation-tag', 'owner', 'raw', 'toolchain',
                  'user-home', 'cargo-home', 'hardware')
        extra = {'products': (), 'tests': ('build', 'build-sha', 'build-owner', 'build-owner-sha'),
            'controls': ('build', 'build-sha', 'build-owner', 'build-owner-sha',
                         'test-product', 'test-product-sha', 'test-owner', 'test-owner-sha'),
            'campaign': ('build', 'build-sha', 'build-owner', 'build-owner-sha',
                         'controls', 'controls-sha', 'controls-owner', 'controls-owner-sha',
                         'geometry', 'geometry-sha')}
        self.assertEqual(owner.COMMON, common)
        self.assertEqual(owner.EXTRAS, extra)
        self.assertEqual((owner.WALL_SECONDS, owner.OUTPUT_BYTES), (1200, 8 * MIB))
        for phase in ('products', 'tests', 'controls', 'campaign'):
            options = owner_options(phase)
            for script in ('evaluation/ordinary-selected-session/owner.py', str(owner.HERE / 'owner.py')):
                invocation, command = owner.commands(options, PYTHON, script)
                self.assertEqual(invocation, [PYTHON, '-B', script,
                    *[word for key in common + extra[phase] for word in ('--' + key, options[key])]])
                child_keys = ('phase', 'revision', 'reservation-tag', 'raw', 'toolchain', 'user-home', 'cargo-home')
                if phase in ('products', 'tests'): child_keys += ('hardware',)
                child_keys += extra[phase]
                target = owner.HERE / ('build.py' if phase in ('products', 'tests') else 'reproduce.py')
                self.assertEqual(command, [PYTHON, '-B', str(target),
                    *[word for key in child_keys for word in ('--' + key, options[key])]])
                self.assertNotIn('--owner', command)

    def test_public_owner_refuses_unknown_extra_missing_and_malformed_options(self):
        script = 'evaluation/ordinary-selected-session/owner.py'
        for phase in ('products', 'tests', 'controls', 'campaign'):
            original = owner_options(phase)
            for name in original:
                options = dict(original); del options[name]
                with self.assertRaises((AssertionError, KeyError), msg=phase + '/' + name):
                    owner.commands(options, PYTHON, script)
            for name, value in (('phase', 'arbitrary-executable'), ('command', '/bin/sh'),
                    ('revision', REVISION[:-1]), ('reservation-tag', 'bad tag'), ('raw', 'relative'),
                    ('owner', 'relative.json'), ('hardware', 'bad\nhardware'), ('hardware', '\u00e9'),
                    ('hardware', 'x' * 161), ('toolchain', None)):
                options = dict(original); options[name] = value
                with self.assertRaises(AssertionError, msg=phase + '/' + name):
                    owner.commands(options, PYTHON, script)
            for name in original:
                if name.endswith('-sha'):
                    options = dict(original); options[name] = 'F' * 64
                    with self.assertRaises(AssertionError, msg=phase + '/' + name):
                        owner.commands(options, PYTHON, script)
            with self.assertRaises(AssertionError): owner.commands(original, PYTHON, '/tmp/another-owner.py')
        options = owner_options('products'); options.update(build='/fabricated/result.json', **{'build-sha': 'b' * 64})
        with self.assertRaises(AssertionError): owner.commands(options, PYTHON, script)

    def test_public_owner_environment_drops_inherited_execution_overrides(self):
        options = owner_options('campaign')
        with patch.dict(owner.os.environ, {'LD_PRELOAD': '/fabricated/never-loaded.so',
                'LD_LIBRARY_PATH': '/fabricated/injected', 'PYTHONPATH': '/fabricated/injected',
                'RUSTFLAGS': '--injected', 'CARGO_TARGET_DIR': '/fabricated/injected',
                'PATH': '/fabricated/injected', 'HOME': '/fabricated/injected'}, clear=False):
            actual = owner.environment(options)
        self.assertEqual(actual, dict(HOME='/fabricated/user', CARGO_HOME='/fabricated/cargo',
            PATH='/fabricated/toolchain/bin:/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1',
            PYTHONNOUSERSITE='1', LC_ALL='C'))

    def test_stage_limits_and_test_command_are_fixed(self):
        self.assertEqual(builder.OUTER_SECONDS, {'products': 1200, 'tests': 600})
        self.assertEqual([builder.stage_limits(index) for index in range(12)],
                         [(120, 180, 128 * MIB)] * 4 + [(20, 30, 4 * MIB)] * 8)
        for index in (-1, 12, True, False, 0.0, '0', None):
            with self.assertRaises(AssertionError):
                builder.stage_limits(index)
        self.assertEqual(builder.test_command('/fabricated/cargo'),
            ['/fabricated/cargo', 'test', '--release', '-p', 'rapid-profiler', '--bin',
             'ordinary-interval', '--no-run', '--locked', '--offline', '--jobs', '4',
             '--message-format=json-render-diagnostics'])

    def test_source_inventory_requires_complete_committed_census_and_pins(self):
        self.assertEqual(builder.BUILD_SOURCE_ROOTS, ROOTS)
        run, git = source_fixture()
        expected = {name: pin(raw)['sha256'] for name, raw in git.files.items()}
        self.assertEqual(builder.source_inventory(run, git), expected)
        self.assertEqual(len(git.calls), len(expected) + 2)
        for mode in ('missing', 'extra', 'duplicate', 'reordered', 'empty'):
            run, git = source_fixture()
            if mode == 'missing': git.current.pop()
            elif mode == 'extra': git.current.append('src/new.rs')
            elif mode == 'duplicate': git.current.append(git.current[0])
            elif mode == 'reordered': git.current.reverse()
            else: git.current = []
            with self.assertRaises(AssertionError, msg=mode):
                builder.source_inventory(run, git)
        for name in expected:
            for mode in ('git-blob', 'source-pin'):
                run, git = source_fixture()
                if mode == 'git-blob': git.files[name] += b' drift'
                else: run.sources[str(builder.ROOT / name)]['sha256'] = '0' * 64
                with self.assertRaises(AssertionError, msg=name + '/' + mode):
                    builder.source_inventory(run, git)

    def test_product_producer_schema_and_canonical_argv_are_exact(self):
        self.assertEqual(driver.PUBLIC_BUILD_OPTIONS, OPTIONS)
        self.assertEqual(driver.PUBLIC_TEST_OPTIONS, TEST_OPTIONS)
        original, _ = schema_fixture()
        self.assertEqual(accepted_invocation(original), original['invocation'])
        for key in original:
            value = copy.deepcopy(original); del value[key]
            with self.assertRaises(AssertionError, msg=key): accepted_invocation(value)
        mutations = (
            lambda p: p.update(extra=True),
            lambda p: p.update(schema='selected-session-public-build-v2'),
            lambda p: p.update(recipe='ignored/private-build.py'),
            lambda p: p.update(revision=REVISION[:-1] + 'b'),
            lambda p: p.update(recipe_sha256='G' * 64),
            lambda p: p['options'].update(extra='unexpected'),
            lambda p: p['options'].update(raw='/fabricated/elsewhere'),
            lambda p: p['options'].update(**{'reservation-tag': 'bad tag'}),
            lambda p: p['options'].update(toolchain='relative'),
            lambda p: p['options'].update(hardware=''),
            lambda p: p['invocation'].__setitem__(0, '/fabricated/other-python'),
            lambda p: p['invocation'].__setitem__(1, '-O'),
            lambda p: p['invocation'].extend(['--phase', 'products']),
            lambda p: p['invocation'].__setitem__(slice(3, 7), p['invocation'][5:7] + p['invocation'][3:5]),
        )
        for mutate in mutations:
            value = copy.deepcopy(original); mutate(value)
            with self.assertRaises(AssertionError): accepted_invocation(value)
        with self.assertRaises(AssertionError): accepted_invocation(original, {'path': '/unexpected'})

    def test_test_producer_requires_exact_previous_receipt_and_owner_options(self):
        original, previous = schema_fixture('tests')
        self.assertEqual(accepted_invocation(original, previous), original['invocation'])
        with self.assertRaises(AssertionError): accepted_invocation(original)
        for key, replacement in (('build', '/fabricated/wrong.json'), ('build-sha', 'f' * 64),
                                 ('build-owner', 'relative-owner.json'), ('build-owner-sha', 'f' * 63)):
            value = copy.deepcopy(original)
            value['options'][key] = replacement; invocation(value)
            with self.assertRaises(AssertionError, msg=key): accepted_invocation(value, previous)
        for key in TEST_OPTIONS:
            value = copy.deepcopy(original); del value['options'][key]
            with self.assertRaises(AssertionError, msg=key): accepted_invocation(value, previous)
        value = copy.deepcopy(original); value['options']['revision'] = 'b' * 40; invocation(value)
        with self.assertRaises(AssertionError): accepted_invocation(value, previous)

    def test_snapshot_pins_require_exact_paths_sizes_and_digest_grammar(self):
        for label in ('source_before', 'source_after'):
            for key, replacement in (('path', str(DIRECTORY / 'wrong.json')), ('bytes', 0),
                    ('bytes', True), ('bytes', 16 * MIB + 1), ('sha256', 'f' * 63), ('sha256', 'F' * 64)):
                value, _ = schema_fixture(); value[label][key] = replacement
                with self.assertRaises(AssertionError, msg=label + '/' + key): accepted_invocation(value)
            value, _ = schema_fixture(); value[label]['extra'] = 1
            with self.assertRaises(AssertionError): accepted_invocation(value)

    def test_fresh_producer_binds_owner_source_snapshots_and_environment(self):
        for phase in ('products', 'tests'):
            for mode in ('valid', 'owner-argv', 'owner-cpus', 'recipe-pin', 'git-blob',
                         'current-pin', 'before-snapshot', 'after-snapshot', 'home', 'cargo-home',
                         'toolchain', 'previous-owner'):
                if phase == 'products' and mode == 'previous-owner': continue
                run, recipe, record, owner, base, git, git_bytes = fresh_fixture(phase)
                p = record['producer']
                env = record['environment'] if phase == 'products' else base['environment']
                if mode == 'owner-argv': owner['command'][-1] = 'different hardware'
                elif mode == 'owner-cpus': owner['reserved_cpus'].pop()
                elif mode == 'recipe-pin': p['recipe_sha256'] = '0' * 64
                elif mode == 'git-blob': git_bytes[0] += b' changed'
                elif mode == 'current-pin': run.sources[str(driver.ROOT / driver.PUBLIC_BUILD_RECIPE)]['sha256'] = '0' * 64
                elif mode in ('before-snapshot', 'after-snapshot'):
                    label = 'source_before' if mode == 'before-snapshot' else 'source_after'
                    changed = copy.deepcopy(run.sources)
                    del changed[str(driver.ROOT / 'tests/support/isolated_native_test.rs')]
                    path = p[label]['path']; run.files[path] = canonical(changed)
                    p[label] = dict(path=path, **pin(run.files[path]))
                elif mode == 'home': env['HOME'] = '/different/home'
                elif mode == 'cargo-home': env['CARGO_HOME'] = '/different/cargo'
                elif mode == 'toolchain':
                    p['options']['toolchain'] = '/different/toolchain'; invocation(p); owner['command'] = list(p['invocation'])
                elif mode == 'previous-owner': run.retained[p['options']['build-owner']]['sha256'] = '0' * 64
                with patch.object(Path, 'resolve', lambda path, strict=False: path), patch.object(Path, 'is_dir', return_value=True):
                    args = (run, recipe, record, owner, DIRECTORY, phase, git, base if phase == 'tests' else None)
                    if mode == 'valid': driver.fresh_build_producer(*args)
                    else:
                        with self.assertRaises(AssertionError, msg=phase + '/' + mode): driver.fresh_build_producer(*args)

    def test_product_copy_keeps_first_pin_and_independent_inode(self):
        run, recipe, source, destination = copy_fixture()
        expected = copy.deepcopy(run.retained[str(source)])
        with patch.object(builder.os, 'chmod') as chmod:
            self.assertEqual(builder.copy_product(run, recipe, source, destination), expected)
        self.assertEqual(run.retained[str(source)], expected)
        self.assertEqual(run.retained[str(destination)], expected)
        self.assertEqual(run.files[str(source)], run.files[str(destination)])
        self.assertEqual(destination.opens, 1)
        self.assertEqual(run.budget.charges, [(str(destination), expected['bytes'])])
        self.assertEqual(chmod.call_args.args, (destination, 0o755))
        self.assertEqual(run.events[-1], ('unchanged',))

    def test_product_copy_refuses_source_destination_and_identity_mutations(self):
        for mode in ('changed-before-read', 'changed-after-read', 'same-inode', 'copy-mutated'):
            run, recipe, source, destination = copy_fixture()
            if mode == 'changed-before-read': run.files[str(source)] += b' changed'
            elif mode == 'changed-after-read': recipe.after_read = lambda: run.files.__setitem__(str(source), b'replacement')
            elif mode == 'same-inode': destination.identity = source.identity
            else: destination.mutation = lambda raw: raw + b' changed'
            with patch.object(builder.os, 'chmod'), self.assertRaises(AssertionError, msg=mode):
                builder.copy_product(run, recipe, source, destination)
            self.assertNotIn(('unchanged',), run.events)
            self.assertEqual(destination.opens, 0 if mode.startswith('changed-') else 1)
            if mode.startswith('changed-'): self.assertEqual(run.budget.charges, [])

    def test_bounded_stage_keeps_exact_transport_and_limits(self):
        for limits in ((20, 30, 4 * MIB), (120, 180, 128 * MIB)):
            run = BoundedRun()
            row, out, err = bounded_call(run, limits)
            request = json.loads(run.files[str(run.raw / 'request.json')])
            self.assertEqual(request, dict(argv=['/fabricated/compiler', '--fixed'], cwd=str(builder.ROOT),
                env=run.env, stdout=str(run.raw / 'stdout'), stderr=str(run.raw / 'stderr'),
                cpu_seconds=limits[0], wall_seconds=limits[1], file_bytes=limits[2]))
            self.assertEqual(run.calls, [('fixture-owner', [PYTHON, '-B',
                str(builder.ROOT / 'tools/unwind-oracle/bounded_command.py'), '--request',
                str(run.raw / 'request.json'), '--receipt', str(run.raw / 'receipt.json')],
                limits[1] + 25, 2 * limits[2] + 10 * MIB)])
            self.assertEqual(set(row), {'name', 'request_sha256', 'receipt_sha256', 'closed', 'stdout_sha256', 'stderr_sha256'})
            self.assertEqual(row['name'], 'fixture')
            self.assertEqual(row['request_sha256'], run.retained[str(run.raw / 'request.json')]['sha256'])
            self.assertEqual(row['receipt_sha256'], run.retained[str(run.raw / 'receipt.json')]['sha256'])
            self.assertEqual((out, err), (b'fabricated compiler output', b''))
            self.assertTrue(run.safe); self.assertFalse(run.budget.active)
            self.assertEqual(run.budget.completed, 1)

    def test_bounded_stage_rejects_receipt_owner_and_output_mutations(self):
        mutations = (
            lambda run, d, closed, r: r.update(request_sha256='0' * 64),
            lambda run, d, closed, r: r.update(helper_sha256='0' * 64),
            lambda run, d, closed, r: r.update(stdout_sha256='0' * 64),
            lambda run, d, closed, r: r.update(stderr_sha256='0' * 64),
            lambda run, d, closed, r: r.update(inputs_unchanged=False),
            lambda run, d, closed, r: r.update(wall_timeout=True),
            lambda run, d, closed, r: r.update(absence_proof='not-ECHILD'),
            lambda run, d, closed, r: r.update(unexpected_descendants=[123]),
            lambda run, d, closed, r: r.update(cleanup_events=['rescue']),
            lambda run, d, closed, r: r.update(aborted='aborted'),
            lambda run, d, closed, r: r.update(cleanup_error='failure'),
            lambda run, d, closed, r: closed.update(cleanup_complete=False),
            lambda run, d, closed, r: closed.update(reaped_descendants=1),
            lambda run, d, closed, r: closed.update(termination='deadline'),
            lambda run, d, closed, r: closed.update(private_log_sha256='0' * 64),
            lambda run, d, closed, r: run.files.__setitem__(str(run.raw / 'request.json'), b'{}\n'),
            lambda run, d, closed, r: run.files.__setitem__(str(run.raw / 'stdout'), b'changed output'),
            lambda run, d, closed, r: run.files.__setitem__(str(run.raw / 'stderr'), b'changed error'),
        )
        for mutate in mutations:
            run = BoundedRun(mutate)
            with self.assertRaises(AssertionError): bounded_call(run)
            self.assertFalse(run.safe); self.assertTrue(run.budget.active)
            self.assertEqual(run.budget.completed, 0)
            self.assertEqual(len(run.calls), 1)
            for name in ('request.json', 'closed.json', 'receipt.json', 'owner.log', 'stdout', 'stderr'):
                self.assertIn(str(run.raw / name), run.files)

    def test_closed_nonzero_build_stage_is_retained_without_retry(self):
        for code in (1, 2):
            run = BoundedRun(code=code)
            with self.assertRaises(AssertionError): bounded_call(run)
            self.assertTrue(run.safe); self.assertFalse(run.budget.active)
            self.assertEqual(run.budget.completed, 1); self.assertEqual(len(run.calls), 1)
            self.assertEqual(json.loads(run.files[str(run.raw / 'receipt.json')])['exit'], code)
            self.assertEqual(json.loads(run.files[str(run.raw / 'closed.json')])['exit_code'], 1)
            self.assertIn(str(run.raw / 'owner.log'), run.retained)

    def test_uncertain_owner_or_unarchived_closure_keeps_budget_and_refuses_safety(self):
        for mode in ('unknown-owner', 'closed-write', 'parent-write'):
            run = BoundedRun(unknown=mode == 'unknown-owner')
            original_freeze = run.freeze

            def freeze(path, value):
                if mode == 'closed-write' and path == run.raw / 'closed.json':
                    raise OSError('fabricated closed receipt write failure')
                original_freeze(path, value)

            def writer(*args):
                if mode == 'parent-write':
                    raise OSError('fabricated parent log write failure')
                memory_blob(*args)

            run.freeze = freeze
            with self.assertRaises(RuntimeError if mode == 'unknown-owner' else OSError, msg=mode):
                bounded_call(run, writer=writer)
            self.assertFalse(run.safe); self.assertTrue(run.budget.active)
            self.assertEqual(run.budget.completed, 0); self.assertEqual(len(run.calls), 1)
            self.assertIn(str(run.raw / 'request.json'), run.retained)
            self.assertEqual(str(run.raw / 'closed.json') in run.files, mode == 'parent-write')
            self.assertNotIn(str(run.raw / 'owner.log'), run.files)

    def test_public_capture_reaches_actual_owner_target_namespace_precondition(self):
        output = owner.ROOT / 'ignored/actual-placement-control.json'
        capture, archive = owner.log_paths(output)
        label = hashlib.sha256(str(output).encode('utf-8')).hexdigest()
        self.assertEqual(capture, owner.ROOT / 'target/evaluation' / ('selected-public-owner-' + label) / 'owner.log')
        self.assertEqual(archive, output.with_suffix('.log'))
        self.assertNotEqual(owner.log_paths(output.with_name('another.json'))[0], capture)
        self.assertEqual(processes.ROOT, owner.ROOT)
        # Invalid bounds stop before opening a log or any ownership/syscall work.
        # This exercises the actual unchanged F01 placement check, not a copy.
        with patch.object(Path, 'resolve', lambda path, strict=False: path), \
                patch.object(processes.subprocess, 'Popen', side_effect=AssertionError('must not spawn')) as popen, \
                patch.object(Path, 'open', side_effect=AssertionError('must not open')) as opened, \
                patch.object(processes, '_preflight', side_effect=AssertionError('must not preflight')) as preflight:
            with self.assertRaisesRegex(ValueError, '^invalid command bounds$'):
                processes.run_command(['/fabricated/not-executed'], {}, capture, 0, 8 * MIB)
            with self.assertRaisesRegex(ValueError, '^private log must remain under target/evaluation$'):
                processes.run_command(['/fabricated/not-executed'], {}, archive, 0, 8 * MIB)
        popen.assert_not_called(); opened.assert_not_called(); preflight.assert_not_called()
        for bad in (Path('relative.json'), owner.ROOT / 'target/owner.json', owner.ROOT / 'ignored/owner.txt'):
            with self.assertRaises(AssertionError): owner.log_paths(bad)

    def test_public_capture_directory_is_fresh_canonical_and_never_reused(self):
        output = owner.ROOT / 'ignored/fresh-placement-control.json'
        capture, archive = owner.log_paths(output)
        base = owner.ROOT / 'target/evaluation'
        calls, existing = [], set()

        def mkdir(path, *args, **kwargs):
            self.assertEqual(args, ())
            calls.append((path, kwargs))
            if path == base:
                self.assertEqual(kwargs, {'parents': True, 'exist_ok': True})
            else:
                self.assertEqual(path, capture.parent)
                self.assertEqual(kwargs, {'mode': 0o700, 'exist_ok': False})
                if path in existing: raise FileExistsError('owned capture directory already exists')
                existing.add(path)

        with patch.object(Path, 'mkdir', mkdir), patch.object(Path, 'resolve', lambda path, strict=False: path), \
                patch.object(owner.os.path, 'lexists', return_value=False):
            self.assertEqual(owner.prepare_log(output), (capture, archive))
            with self.assertRaises(FileExistsError): owner.prepare_log(output)
        self.assertEqual(len(calls), 4)
        for misplaced in (base, capture.parent):
            existing.clear(); calls.clear()

            def resolve(path, strict=False):
                return owner.ROOT / 'fabricated-elsewhere' if path == misplaced else path

            with patch.object(Path, 'mkdir', mkdir), patch.object(Path, 'resolve', resolve), \
                    patch.object(owner.os.path, 'lexists', return_value=False), self.assertRaises(AssertionError):
                owner.prepare_log(output)
        for collision in (capture, archive):
            existing.clear()
            with patch.object(Path, 'mkdir', mkdir), patch.object(Path, 'resolve', lambda path, strict=False: path), \
                    patch.object(owner.os.path, 'lexists', lambda path: path == collision), self.assertRaises(AssertionError):
                owner.prepare_log(output)

    def test_closed_log_archive_keeps_first_digest_exact_bytes_and_exclusive_copy(self):
        for raw in (b'', b'actual raw\x00\xff owner bytes\n'):
            run, recipe, closed, capture, archive = archive_fixture(raw=raw)
            original = copy.deepcopy(closed)
            self.assertIs(owner.archive_closed_log(recipe, closed, capture, archive), True)
            self.assertEqual(closed, original)
            self.assertEqual(run.files[str(archive)], raw)
            self.assertEqual(recipe.read_calls, [(str(capture), 8 * MIB), (str(archive), 8 * MIB)])
            self.assertEqual(archive.opens, 1)
            with self.assertRaises(FileExistsError): owner.archive_closed_log(recipe, closed, capture, archive)
            self.assertEqual(archive.opens, 1)
            self.assertEqual(run.files[str(archive)], raw)

    def test_closed_log_archive_refuses_digest_read_copy_and_readback_failures(self):
        for mode in ('wrong-digest', 'capture-read-error', 'open-error', 'write-error', 'short-write',
                     'close-error', 'archive-read-error', 'readback-drift', 'capture-outside', 'archive-outside'):
            run, recipe, closed, capture, archive = archive_fixture(mode)
            if mode == 'wrong-digest': closed['private_log_sha256'] = '0' * 64
            elif mode == 'capture-outside': capture.name = str(owner.ROOT / 'ignored/wrong.log')
            elif mode == 'archive-outside': archive.name = str(owner.ROOT / 'target/evaluation/wrong.log')
            original = copy.deepcopy(closed)
            with self.assertRaises((AssertionError, OSError), msg=mode):
                owner.archive_closed_log(recipe, closed, capture, archive)
            self.assertEqual(closed, original)
            if mode in ('capture-outside', 'archive-outside'): self.assertEqual(recipe.read_calls, [])
            if mode in ('wrong-digest', 'capture-read-error', 'open-error', 'capture-outside', 'archive-outside'):
                self.assertEqual(archive.opens, 0)
                self.assertNotIn(str(archive), run.files)

    def test_unknown_cleanup_does_zero_wrapper_log_io_even_with_exit_zero(self):
        for cleanup in (False, None, 0, 1, 'true'):
            closed = dict(cleanup_complete=cleanup, exit_code=0, private_log_sha256='0' * 64)
            calls = []

            def command(*args):
                calls.append(args)
                return closed

            recipe = SimpleNamespace(read=lambda *_: self.fail('unknown capture was read'))
            capture, archive = object(), object()
            self.assertIs(owner.archive_closed_log(recipe, closed, capture, archive), False)
            with patch.object(owner, 'archive_closed_log', side_effect=AssertionError('unknown closure reached archive')) as archived:
                result = owner.own_command(SimpleNamespace(run_command=command), recipe,
                    ['fixed-child'], {'FIXED': 'env'}, capture, archive)
            archived.assert_not_called()
            self.assertEqual(calls, [(['fixed-child'], {'FIXED': 'env'}, capture, 1200, 8 * MIB)])
            self.assertEqual(result, dict(closed=closed, log_archived=False))
            self.assertIs(result['closed'], closed)

    def test_public_owner_keeps_api_and_archive_failures_once_without_false_closure(self):
        for mode in ('valid', 'closed-failure', 'api-error', 'wrong-digest', 'capture-read-error',
                     'open-error', 'short-write', 'archive-read-error', 'readback-drift'):
            run, recipe, closed, capture, archive = archive_fixture(mode)
            if mode == 'closed-failure': closed.update(exit_code=1, termination='output_limit')
            if mode == 'wrong-digest': closed['private_log_sha256'] = '0' * 64
            calls = []

            def command(*args):
                calls.append(args)
                if mode == 'api-error': raise OSError('fabricated capture failure')
                return closed

            result = owner.own_command(SimpleNamespace(run_command=command), recipe,
                                      ['fixed-child'], {'FIXED': 'env'}, capture, archive)
            self.assertEqual(calls, [(['fixed-child'], {'FIXED': 'env'}, capture, 1200, 8 * MIB)])
            if mode == 'api-error':
                self.assertEqual(result, dict(closed=None, log_archived=False,
                                              owner_error='OSError: fabricated capture failure'))
                self.assertEqual(recipe.read_calls, []); self.assertEqual(archive.opens, 0)
            else:
                self.assertIs(result['closed'], closed)
                if mode in ('valid', 'closed-failure'):
                    self.assertEqual(result, dict(closed=closed, log_archived=True))
                    self.assertEqual(run.files[str(archive)], run.files[str(capture)])
                else:
                    self.assertIs(result['log_archived'], False)
                    self.assertIsInstance(result['log_error'], str)
                    self.assertTrue(result['log_error'])


if __name__ == '__main__':
    unittest.main()
