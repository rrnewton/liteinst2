#!/usr/bin/env python3
"""Fresh native reproduction of the fixed common corpus; no historical admissions.

Run from outside the clean pinned checkout. Private command/capture files remain
under --raw; public/ contains only normalized contexts and compact numbers.
"""
import argparse
import csv
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import runpy
import shlex
import stat
import struct
import subprocess
import sys
import traceback
from types import SimpleNamespace

REVISION = 'e8a8b6d447673aa7b98e00ff18df2eedf5e07d82'
MIB = 1048576
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
PROFILE = 'owned-foreign-neighbors-v1'
RECORDING = '--recording-profile=bounded-journal-v1'
CORE_ARGS = ['--planning-profile=' + PROFILE, '--entry-router=linux-x86-64-private-altstack-v1']
ORIGINALS = dict(unstripped='987b20efe393a0a2ca0293cd5601ba323b3f8292c9f1b5fab8a22b3124d3cff8',
                stripped='1c7c66c58376c98df1dc3e5fd76d3c22a82ad7e96ef7aee1543a7c5b90a6f529')
CELLS = [(h, s, v) for h in ('null', 'journal') for s in ('jump-site', 'heap-write') for v in ORIGINALS]
CORE_ORDER = [h + '-' + s + '-' + v for h in ('null', 'journal') for s in ('heap-write', 'jump-site') for v in ORIGINALS]
LANES = ('core', 'stock-algorithm', 'bootstrap-patched-reference')
DATASETS = ('empty', 'singleton', 'pair-reverse', 'equal-17', 'sorted-17', 'reverse-17', 'duplicates-17', 'mixed-64')
# Filled from exact Git source by the proposal author, never from runtime output.
SOURCE_PINS = {
    "Cargo.lock": "5fd8ffbfedaa58242734525342062c5c2dc7924377ae62d6d91408453cfe1f7e",
    "Cargo.toml": "4f19980341acf68a101ee80cb748cc5d0894e7a35e3fddf35a6df422855a0dea",
    "evaluation/admission/processes.py": "0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f",
    "evaluation/e9-common-app/build_inventory.py": "3414588bcc7dd3f2bd27e5a43228f379ef5df84131406f4eecb8962fa60a2c8a",
    "evaluation/e9-common-app/observe_originals.py": "17b8b9164d485b60b71ddcb85e9173d31d99a360ba3cb23305334d33c562af05",
    "evaluation/e9-common-app/prepare_subject.py": "79945a0bfdc7ffa9b1ea2ed265669709e278bb6d82c5676731dab547eadc278c",
    "evaluation/e9-common-app/produce.py": "d528896f9485367fa10582f7a88bb09dfac95757555982f6d268af469d0011a0",
    "evaluation/e9-common-app/recording_pairs.py": "3d3290740ca465adb7827efdf921d1b2f74942ca078956f818c92371e3397a23",
    "evaluation/e9-common-app/run_candidates.py": "e78e8494300eceb91e8ddc46c7e202eca052dac99ef22d0eca518a372116331a",
    "evaluation/e9-common-app/run_core_pairs.py": "3402c169a984e72915e44d86233a9c39e8a5dee245807370e905657a979cf763",
    "evaluation/e9-common-app/run_e9_pairs.py": "2755adc1c6127fa8eaae1560af5748a3876b62ba3a767889f8d3eba07c793be0",
    "evaluation/required-gates.py": "6d71d2a6518b8d93e136fb5fcb8170dded37e7bcfa0eae2c1fdefb1582a1fb8b",
    "tests/support/e9_common_app.rs": "faec58111347cc1c0d41c0fa47862207ae8938f7b4caddad98b4afc3043699ae",
    "tests/support/e9_common_core_pages.rs": "a23d6e230831f5ff54d19b95394ac21c5c0a5cd4dd083a62ad1416f3c44c620e",
    "tests/support/e9_common_core.rs": "0feda92bd5c0d5f0ae5cfb151fe39899f1afc3996ba9511fed99ed8526be3c32",
    "tests/support/e9_common_e9.rs": "92712fecdfbb2a0f7d77cd86b4ae2b5f451e17eea2c87ac096ad64ed0673eae5",
    "tests/support/e9_common_recording.rs": "d0419f184093a5c1ef658028c7a8a2869dea8c849a5da44cd1f191c3b5085bc7",
    "tests/support/e9_common_recording_native.rs": "a3e8d4e326bada12b9c77c4770cfab6d44dbb59a6eb82d4a5517542602d8d129",
    "tests/support/e9_common_seed.instructions.tsv": "74afc406acb8eb7742695afdf0e610a7e77afbaa6fb1498463a9e8ae85901fcd",
    "tests/support/e9_common_seed.rs": "df1678dc0d0a5eede05d76d592048d5065d983fa44ba42c6d5dd7da9d297c2e3",
    "tests/support/elf_exec_driver.rs": "25f5ba3d2b47b7ffd525f3a5398b93d83f5e06ea14ceaecddd45b16dceae6130",
    "tools/elf-rewrite/Cargo.toml": "efa2528a5905f3a0d4d4424dfedff8d5fcba7365a03d63f969b4a613629e544f",
    "tools/elf-rewrite/compare-sites.py": "797b396392ec3459a21a37f4a41b15a47b9f478dfe92c5d2cf436041d282876f",
    "tools/elf-rewrite/e9-null-witness.py": "32ec75c907736332b3b55570c952d9952faccd9e857564b0e696ccc368736e0c",
    "tools/elf-rewrite/e9-sites.py": "5904a13ec1fcb8b6801dcff12ac1fe5a1154b884555bbd9fbc24521f9bc6949f",
    "tools/elf-rewrite/examples/common_sites.rs": "3dd3074b35f037109af696904dbed8ae13168c11f009bf65924ecd9f7c7289b5",
    "tools/elf-rewrite/examples/verify_common_core.rs": "42374e3c7a42be44e534a9fc97ece05e3d6796d1d02dc9f41ddd919afb1f799b",
    "tools/unwind-oracle/bounded_command.py": "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def read(p, limit=128 * MIB):
    p = Path(p)
    assert p.is_absolute() and p.parent.resolve(strict=True) == p.parent and not p.is_symlink()
    six = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        a = os.fstat(f.fileno())
        assert stat.S_ISREG(a.st_mode) and 0 <= a.st_size <= limit
        b = f.read(a.st_size + 1)
        assert len(b) == a.st_size and six(a) == six(os.fstat(f.fileno())) == six(p.lstat())
    return b, dict(sha256=sha(b), bytes=len(b), stat=six(a))


def write(p, value):
    p = Path(p)
    b = value if isinstance(value, bytes) else (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    with p.open('xb') as f:
        f.write(b)


def js(p):
    return json.loads(read(p)[0])


def descriptor(p):
    b, _ = read(p)
    return dict(path=str(p), bytes=len(b), sha256=sha(b))


def journal(pcs):
    assert type(pcs) is bytes and len(pcs) % 8 == 0 and len(pcs) // 8 <= 16384
    return (struct.pack('<8Q', 0x6c69326a6f75726e, 1, 16384, 0, len(pcs) // 8, 0, 0, 0)
            + pcs + bytes(131072 - len(pcs)) + struct.pack('<Q', 0x7265636f72647321))

def rows(b):
    return list(csv.DictReader(io.StringIO(b.decode()), delimiter='\t'))


def fields(b, header):
    lines = b.decode().splitlines()
    assert lines[0] == header
    result = {}
    for line in lines[1:]:
        key, value = line.split('\t')
        assert key not in result
        result[key] = value
    return result


def load(repo, name):
    p = repo / name
    assert sha(read(p)[0]) == SOURCE_PINS[name]
    # Every loaded public module has a guarded main; this never calls it.
    return SimpleNamespace(**runpy.run_path(str(p), run_name='fresh_native_support'))


def full_target(compact):
    # The native consumers require ledger::target's complete serialization.
    # This finite corpus supports only the exact layout already used by its
    # fixed canonical XSAVE and capture-size checks; no inferred fallback.
    assert type(compact) is bytes
    expected = b'target xsave64 743 4:576:256 32:832:64 64:896:512 128:1408:1024 512:2432:8\n'
    assert compact == expected, 'unsupported native target layout'
    prefix = (b'LI2TARGET\t1\nos\tlinux\nisa\tx86-64-legacy-evex\ncet\tunqualified\n'
              b'page_bytes\t4096\nbias_domain\t1\nformat\txsave64-standard\n'
              b'allocation_bytes\t2496\nimage_bytes\t2440\nxcr0_mask\t743\nqualification_complete\tfalse\n')
    return prefix + b''.join(b'component\t' + row.replace(b':',b'\t') + b'\n' for row in compact.split()[3:])


def selected_product(messages, name, kind, source, manifest, profile):
    selected = [r for r in messages if r.get('reason') == 'compiler-artifact'
                and r['target']['name'] == name and r.get('executable')]
    assert len(selected) == 1
    r = selected[0]
    assert r['target']['kind'] == [kind] and r['target']['crate_types'] == ['bin']
    assert r['target']['src_path'] == str(source) and r['target']['edition'] == '2024'
    assert r['manifest_path'] == str(manifest) and r['profile'] == profile and r['features'] == []
    assert all(type(r['profile'][k]) is type(v) for k, v in profile.items())
    assert r['filenames'] == [r['executable']]
    return Path(r['executable'])


def stage_plan():
    plan = ['prepare-gcc-version', 'prepare-strip-version', 'prepare-compile', 'prepare-strip']
    for v in ORIGINALS:
        plan += ['prepare-' + v + '-' + n for n in ('readelf', 'nm') + DATASETS + ('refuse-usage', 'refuse-dataset', 'refuse-overwrite')]
    assert len(plan) == 30
    plan += ['required', 'build-native', 'build-common-sites', 'build-verifier', 'target']
    plan += ['inventory-' + '-'.join(c) for c in CELLS]
    plan += ['observe-' + v + '-' + d for v in ORIGINALS for d in DATASETS]
    production = []
    for h, s, v in CELLS:
        key = '-'.join((h, s, v))
        if key == 'journal-jump-site-unstripped':
            production += ['hook-compile', 'hook-link']
        production += [key + '-core']
        production += [key + '-' + lane + '-' + phase for lane in LANES[1:] for phase in ('transport', 'producer', 'adapter', 'compare')]
    assert len(production) == 74
    plan += production
    plan += ['ordinary-' + '-'.join(c) + '-' + lane + '-' + d for c in CELLS for lane in LANES for d in DATASETS]
    native = [('core', key) for key in CORE_ORDER]
    native += [(lane, key) for key in CORE_ORDER if key.startswith('journal-') for lane in LANES[1:]]
    assert len(native) == 16
    plan += ['native-' + lane + '-' + key + '-' + part for lane, key in native for part in ('witness', 'replay')]
    assert len(plan) == len(set(plan)) == 357
    return plan, native


def native_complete(capture, lane, recording, expanded):
    core = lane == 'core'
    header = 'LI2COMMONCORE' if core else 'LI2COMMONE9'
    header += 'RECORDINGPAIRS' if recording else 'PAIRS'
    expected = dict(heads='87', normal_pairs='174', fault_pairs='2', children='352', comparisons='528')
    if not core:
        expected.update(call_intermediate_checks=str(len(expanded)), snapshots=str(880 + len(expanded)))
    expected['files'] = str(8636 if core else 8637 + 9 * len(expanded))
    if recording:
        expected['recording_profile'] = 'bounded-journal-v1'
    else:
        expected.update(E9='UNIMPLEMENTED_UNRUN', recording_hooks='UNIMPLEMENTED_UNRUN')
    expected.update(normal_loader_validation='false', qualification_complete='false')
    assert fields(read(capture / 'complete.tsv')[0], header + '\t1') == expected
    for i in range(176):
        directory = capture / ('case-%03d' % i)
        expected_pair = dict(case=str(i), comparisons='3', children='2')
        expected_pair.update({'E9': 'UNIMPLEMENTED_UNRUN'} if core else {'call_intermediate_checks': str(int(i in expanded))})
        expected_pair.update(normal_loader_validation='false', qualification_complete='false')
        assert fields(read(directory / 'pair.tsv')[0], ('LI2COREPAIR' if core else 'LI2E9PAIR') + '\t1') == expected_pair
        child = fields(read(directory / 'candidate/complete.tsv')[0], ('LI2COREPAIRCHILD' if core else 'LI2E9PAIRCHILD') + '\t1')
        assert set(child) == {'case', 'steps', 'physical_completion', 'logical_completion', 'fault', 'comparisons', 'reaped_echild', 'qualification_complete'} | (set() if core else {'call_intermediate_checks'})
        assert child['case'] == str(i) and child['comparisons'] == '3' and child['reaped_echild'] == 'true'
        assert 0 < int(child['steps']) <= 20000 and child['qualification_complete'] == 'false'
        if not core: assert child['call_intermediate_checks'] == str(int(i in expanded))
    return dict(pairs=176, children=352, comparisons=528)


def capture_inventory(repo, source, expected):
    """Whole regular-file bytes and metadata; directory owners are retained too."""
    assert source.is_relative_to(repo / 'ignored') and source.resolve(strict=True) == source
    result = {}
    actual = {}
    for root, dirs, files in os.walk(source, followlinks=False):
        for name in dirs:
            assert not (Path(root) / name).is_symlink()
        for p in [Path(root)] + [Path(root) / n for n in files]:
            assert p.resolve(strict=True) == p
            s = p.lstat()
            assert stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)
            item = dict(stat=[s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns],
                        uid=s.st_uid, gid=s.st_gid, nlink=s.st_nlink)
            name = str(p.relative_to(repo))
            assert re.fullmatch(r'[A-Za-z0-9_./-]+', name) and '\n' not in name
            if stat.S_ISREG(s.st_mode):
                assert s.st_nlink == 1
                owner = read(p)[1]
                assert owner['stat'] == item['stat']
                actual[str(p.relative_to(source))] = owner
                item.update(sha256=owner['sha256'], bytes=owner['bytes'])
            result[name] = item
    assert actual == expected and result
    return dict(sorted(result.items()))


def archive_owner(path, limit):
    """Stream the complete archive while retaining the same six-owner guards."""
    assert path.is_absolute() and path.parent.resolve(strict=True) == path.parent
    six = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit
        digest = hashlib.sha256(); total = 0
        while True:
            data = f.read(MIB)
            if not data: break
            total += len(data); assert total <= before.st_size
            digest.update(data)
        assert total == before.st_size and six(before) == six(os.fstat(f.fileno())) == six(path.lstat())
    return dict(sha256=digest.hexdigest(), bytes=total, stat=six(before))


def retention_limit(logical):
    assert type(logical) is int and logical > 0
    return min(logical + 64 * MIB, 256 * MIB)


def retention_request(repo, directory, argv, cap):
    assert type(cap) is int and 0 < cap <= 256 * MIB
    return dict(argv=list(map(str, argv)), cwd=str(repo), env=dict(ENV, TMPDIR=str(directory / 'tmp')),
                cpu_seconds=60, wall_seconds=90, file_bytes=cap,
                stdout=str(directory / 'stdout.txt'), stderr=str(directory / 'stderr.txt'))


class Campaign:
    def __init__(self, args):
        self.repo = args.repo.resolve(strict=True)
        self.raw = args.raw
        assert self.repo == args.repo and self.raw.is_absolute() and self.raw.parent.resolve(strict=True) == self.raw.parent
        assert self.raw.is_relative_to(self.repo / 'ignored') and not self.raw.exists()
        assert not sys.flags.optimize and platform.machine() == 'x86_64'
        self.tools_input = args.tools
        self.tools = js(args.tools)
        assert Path(sys.executable).resolve(strict=True) == Path(self.tools['python']), 'use the selected Python for this wrapper'
        assert self.tools.keys() == {'toolchain', 'cargo_home', 'user_home', 'gcc', 'strip', 'nm', 'readelf', 'python', 'timeout', 'git', 'du', 'tar', 'zstd', 'e9', 'runtime_libraries'}
        for k, v in self.tools.items():
            if k not in ('e9', 'runtime_libraries'):
                p = Path(v); assert p.is_absolute() and p.resolve(strict=True) == p
        assert Path(self.tools['git']) == Path('/usr/bin/git').resolve(strict=True), 'public source readers use /usr/bin/git'
        self.p = load(self.repo, 'evaluation/e9-common-app/produce.py')
        self.b = load(self.repo, 'evaluation/e9-common-app/build_inventory.py')
        self.o = load(self.repo, 'evaluation/e9-common-app/observe_originals.py')
        self.rc = load(self.repo, 'evaluation/e9-common-app/run_core_pairs.py')
        self.re = load(self.repo, 'evaluation/e9-common-app/run_e9_pairs.py')
        self.supervisor = load(self.repo, 'evaluation/admission/processes.py')
        assert self.supervisor.ROOT == self.repo
        self.before = self.p.source(self.repo)
        assert self.before['revision'] == REVISION
        assert all(self.before['files'][n]['sha256'] == h for n, h in SOURCE_PINS.items())
        assert self.tools['e9'].keys() == self.p.PRODUCTS.keys()
        assert 1 <= len(self.tools['runtime_libraries']) <= 14
        for k, v in self.tools['e9'].items():
            assert sha(read(Path(v).resolve(strict=True))[0]) == self.p.PRODUCTS[k]
            assert Path(v).resolve(strict=True) == Path(v)
        self.affinity = sorted(os.sched_getaffinity(0))[:4]
        assert len(self.affinity) == 4
        os.sched_setaffinity(0, self.affinity)
        self.raw.mkdir(mode=0o700)
        for d in ('commands', 'products', 'originals', 'policies', 'inventories', 'observations', 'production', 'ordinary', 'native', 'retention', 'public'):
            (self.raw / d).mkdir(mode=0o700)
        self.logs = self.repo / 'target/evaluation' / ('common-native-' + self.raw.name)
        self.logs.mkdir(parents=True, exist_ok=False)
        self.helper = self.repo / 'tools/unwind-oracle/bounded_command.py'
        assert sha(read(self.helper)[0]) == self.p.HELPER_SHA
        self.plan, self.native_order = stage_plan()
        self.results = {n: dict(stage=n, status='UNRUN', reason='not reached') for n in self.plan}
        self.active = None
        self.native_results = [dict(cell=k, lane=l, status='UNRUN', pairs=None, children=None, comparisons=None) for l, k in self.native_order]
        self.retention_results = [dict(cell=k, lane=l, status='UNRUN') for l, k in self.native_order]
        self.ordinary_results = [dict(cell='-'.join(c), lane=l, dataset=d, status='UNRUN') for c in CELLS for l in LANES for d in DATASETS]
        self.product_owners = {}; self.streams = {}; self.candidates = {}; self.inventories = {}; self.envelopes = {}
        self.archive_owners = {}
        self.selected = [Path(self.tools[k]) for k in ('gcc', 'strip', 'nm', 'readelf', 'python', 'timeout', 'git', 'du', 'tar', 'zstd')]
        self.selected += [Path(self.tools['toolchain']) / k for k in ('cargo', 'rustc', 'rustdoc', 'rustfmt', 'clippy-driver')]
        self.selected += [Path(v) for v in self.tools['e9'].values()] + [Path(v) for v in self.tools['runtime_libraries']]
        self.selected += [self.helper, Path(__file__).resolve(strict=True), args.tools]
        assert all(p.resolve(strict=True) == p for p in self.selected), 'canonical tool and runtime paths required'
        self.owners = {str(p.resolve(strict=True)): read(p.resolve(strict=True))[1] for p in self.selected}
        self.configs = self.config_snapshot()
        self.build_env = dict(ENV, CARGO_BUILD_JOBS='4', CARGO_INCREMENTAL='0', CARGO_NET_OFFLINE='true',
            CARGO_TARGET_DIR=str(self.repo / 'target'), CARGO_HOME=self.tools['cargo_home'], HOME=self.tools['user_home'],
            RUSTC=str(Path(self.tools['toolchain']) / 'rustc'), RUSTDOC=str(Path(self.tools['toolchain']) / 'rustdoc'),
            RUSTC_WORKSPACE_WRAPPER='', RUSTC_WRAPPER='', RUST_TEST_THREADS='4',
            PATH=self.tools['toolchain'] + ':/usr/bin:/bin', **self.b.DEBUG0_ENV)
        cpu = next(s.split(':', 1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name'))
        assert 'AMD EPYC' in cpu
        self.hardware = dict(host_label='AMD EPYC Zen 5 dev host', host_label_scope='Owner-specified reporting label; cpu_model is freshly observed, and Zen 5 or historical same-host identity is not inferred', cpu_model=cpu, architecture=platform.machine(), kernel_release=platform.release(), libc=list(platform.libc_ver()), cpu_count=len(self.affinity))
        self.aliases = {str(self.repo): '$REPO', str(self.raw): '$RAW', str(self.logs): '$LOGS',
            self.tools['toolchain']: '$TOOLCHAIN', self.tools['cargo_home']: '$CARGO_HOME', self.tools['user_home']: '$USER_HOME'}
        self.aliases.update({self.tools[k]: '$' + k.upper() for k in ('gcc', 'strip', 'nm', 'readelf', 'python', 'timeout', 'git', 'du', 'tar', 'zstd')})
        self.aliases.update({p: '$E9_' + k.upper() for k, p in self.tools['e9'].items()})
        self.aliases.update({p: '$RUNTIME_' + str(i) for i, p in enumerate(self.tools['runtime_libraries'])})
        self.aliases[str(Path(__file__).resolve())] = '$REPRODUCER'
        self.aliases[str(self.tools_input)] = '$TOOLS_JSON'
        self.contexts = []
        write(self.raw / 'source-before.json', self.before); write(self.raw / 'tools-before.json', self.owners)
        write(self.raw / 'config-before.json', self.configs); write(self.raw / 'hardware.json', self.hardware)
        write(self.raw / 'config-scope.json', dict(invocation_cwd=str(self.repo), lookup='cwd and ancestors plus explicit CARGO_HOME; no changed compiler cwd', denied_lookup_is_absent=False, consumed_configuration_attested=False, scope='Classified lookup observations under three-consecutive-negative-v1, not identical raw syscall outcomes; denied content remains unknown and existing-entry resolution/read/owner errors fail without retry.'))
        write(self.raw / 'stage-plan.json', self.plan)
        self.datasets = js(self.repo / 'evaluation/e9-common-app/datasets.json')['datasets']
        assert tuple(d['name'] for d in self.datasets) == DATASETS
        for i, d in enumerate(self.datasets):
            assert d['id'] == i and d['expected'] == sorted(d['input']) and len(d['input']) <= 64
            assert (self.repo / 'evaluation/e9-common-app/expected' / (d['name'] + '.stdout')).read_bytes() == d['expected_stdout'].encode()

    def config_snapshot(self):
        paths = [p / '.cargo' / n for p in (self.repo, *self.repo.parents) for n in ('config', 'config.toml')]
        paths += [Path(self.tools['cargo_home']) / n for n in ('config', 'config.toml')]
        result = {}
        six = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
        for p in sorted(set(paths)):
            link_before = None
            for attempt in range(3):
                try:
                    link_before = p.lstat()
                    break
                except (FileNotFoundError, NotADirectoryError) as error:
                    assert error.errno in (errno.ENOENT, errno.ENOTDIR)
                    if attempt == 2:
                        result[str(p)] = dict(exists=False)
                except PermissionError as error:
                    assert error.errno in (errno.EPERM, errno.EACCES)
                    result[str(p)] = dict(observation='READ_DENIED', operation='metadata_lookup', errno=error.errno, exists=None, content_sha256=None)
                    break
            if link_before is None:
                continue
            resolved = p.resolve(strict=True)
            data, owner = read(resolved)
            link_after = p.lstat()
            assert six(link_before) == six(link_after)
            result[str(p)] = dict(exists=True, resolved=str(resolved), sha256=sha(data), stat=owner['stat'], lstat=six(link_after))
        return result

    def stable(self, source=False):
        assert {p: read(Path(p))[1] for p in self.owners} == self.owners
        observed_configs = self.config_snapshot()
        if observed_configs != self.configs:
            count = getattr(self, 'config_mismatches', 0)
            self.config_mismatches = count + 1
            if count < 2:
                write(self.raw / ('config-mismatch-%d.json' % (count + 1)),
                      dict(expected=self.configs, observed=observed_configs, stage=self.active,
                           policy='three-consecutive-negative-v1'))
        assert observed_configs == self.configs
        assert {p: read(Path(p))[1] for p in self.product_owners} == self.product_owners
        if source:
            assert self.p.source(self.repo) == self.before
        return observed_configs

    def keep(self, p):
        key = str(p); owner = read(p)[1]
        if key in self.product_owners:
            assert self.product_owners[key] == owner
        self.product_owners[key] = owner

    def capacity(self, disk, memory=0):
        used = int(subprocess.check_output([self.tools['du'], '-s', '-B1', str(self.repo)], env=ENV, timeout=60).split()[0])
        fs = os.statvfs(self.raw)
        available = {k.rstrip(':'): int(v.split()[0]) * 1024 for k, v in (s.split(None, 1) for s in Path('/proc/meminfo').read_text().splitlines())}
        assert used + disk <= 20000000000 and fs.f_bavail * fs.f_frsize >= disk
        assert available['MemAvailable'] >= memory
        return dict(slot_used=used, required_growth=disk, memory_allowance=memory, slot_cap=20000000000)

    def normalized(self, value):
        if isinstance(value, str):
            for p, role in sorted(self.aliases.items(), key=lambda item: -len(item[0])):
                value = value.replace(p, role)
            assert not any(p in value for p in self.aliases)
            return value
        if isinstance(value, list): return [self.normalized(x) for x in value]
        if isinstance(value, dict): return {k: self.normalized(v) for k, v in value.items()}
        return value

    def run(self, name, argv, kind='small', expected=0, environment=None, tmp=None):
        self.active = name
        assert name == self.plan[sum(r['status'] != 'UNRUN' for r in self.results.values())]
        d = self.raw / 'commands' / name; d.mkdir(); (d / 'tmp').mkdir()
        row = self.results[name]; row.update(status='FAILED', reason='launch or postcheck incomplete')
        cpu, wall, cap, outer, wait = {'small': (20, 30, 16 * MIB, 40, 55),
            'compile': (60, 90, 128 * MIB, 100, 115), 'native': (60, 90, 64 * MIB, 100, 115)}[kind]
        env = dict(environment or ENV, TMPDIR=str(tmp or (d / 'tmp')))
        request = dict(argv=list(map(str, argv)), cwd=str(self.repo), env=env, cpu_seconds=cpu, wall_seconds=wall,
                       file_bytes=cap, stdout=str(d / 'stdout.txt'), stderr=str(d / 'stderr.txt'))
        write(d / 'request.json', request)
        launch = [self.tools['timeout'], '--signal=TERM', '--kill-after=10s', str(outer) + 's', self.tools['python'], '-B', str(self.helper), '--request', str(d / 'request.json'), '--receipt', str(d / 'receipt.json')]
        context = dict(stage=name, request=request, outer_argv=launch, outer_env=ENV, direct_wall_seconds=wait, cleanup_seconds=3)
        write(d / 'command.json', context); self.contexts.append(context)
        self.stable()
        closed = self.supervisor.run_command(launch, ENV, self.logs / (name + '.log'), wait, 2 * MIB)
        write(d / 'closed.json', closed)
        log = read(self.logs / (name + '.log'))[0]; write(d / 'helper.log', log)
        assert sha(log) == closed['private_log_sha256']
        self.stable()
        assert closed['exit_code'] == (0 if expected == 0 else 1) and closed['termination'] is None
        assert closed['cleanup_complete'] and closed['reaped_descendants'] == 0
        receipt = self.p.receipt(d, request)
        assert receipt['exit'] == expected
        terminal = dict(exit=expected, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=expected == 0)
        assert log == (json.dumps(terminal) + '\n').encode()
        row.update(status='PASS', reason='', child_exit=expected, seconds=receipt['elapsed_seconds'], request_sha256=sha(read(d / 'request.json')[0]), receipt_sha256=sha(read(d / 'receipt.json')[0]))
        return d

    def quiet(self, d):
        assert not read(d / 'stdout.txt')[0] and not read(d / 'stderr.txt')[0]

    def retention_command(self, directory, name, argv, cap):
        # Separate retention receipts do not alter the 357 workload stages.
        d = directory / name; d.mkdir(); (d / 'tmp').mkdir()
        request = retention_request(self.repo, d, argv, cap)
        write(d / 'request.json', request)
        launch = [self.tools['timeout'], '--signal=TERM', '--kill-after=10s', '100s', self.tools['python'], '-B', str(self.helper), '--request', str(d / 'request.json'), '--receipt', str(d / 'receipt.json')]
        label = 'retain-' + directory.name + '-' + name
        context = dict(stage=label, scope='lossless-retention-only', request=request, outer_argv=launch,
                       outer_env=ENV, direct_wall_seconds=115, cleanup_seconds=3)
        write(d / 'command.json', context); self.contexts.append(context)
        self.stable()
        closed = self.supervisor.run_command(launch, ENV, self.logs / (label + '.log'), 115, 2 * MIB)
        write(d / 'closed.json', closed)
        log = read(self.logs / (label + '.log'))[0]; write(d / 'helper.log', log)
        assert sha(log) == closed['private_log_sha256']
        self.stable()
        assert closed['exit_code'] == 0 and closed['termination'] is None
        assert closed['cleanup_complete'] and closed['reaped_descendants'] == 0
        receipt = self.p.receipt(d, request); assert receipt['exit'] == 0
        assert log == (json.dumps(dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)) + '\n').encode()
        return d

    def retain_captures(self, lane, key, source, expected):
        # Native PASS precedes retention. These bytes are closed child outputs;
        # the existing full checks above are not replaced by archive checks.
        assert source == self.raw / 'native' / (key + '-' + lane) / 'captures'
        row = next(r for r in self.retention_results if (r['cell'], r['lane']) == (key, lane))
        assert row['status'] == 'UNRUN'; row.update(status='FAILED', reason='retention incomplete')
        d = self.raw / 'retention' / (key + '-' + lane); d.mkdir()
        before = capture_inventory(self.repo, source, expected)
        assert all(os.access(self.repo / p, os.W_OK | os.X_OK) for p, owner in before.items() if stat.S_ISDIR(owner['stat'][2]))
        write(d / 'capture-files.json', expected); write(d / 'tree-before.json', before)
        logical = sum(v['bytes'] for v in before.values() if 'bytes' in v)
        # An enforced output ceiling, not an assumed compression ratio. A tar
        # exceeding it fails with every source file retained.
        limit = retention_limit(logical)
        # Create can write archive/stdout/stderr, each bounded by limit. The
        # two read-only commands have four 16MiB streams; 32MiB covers receipts.
        write(d / 'resource.json', self.capacity(3 * limit + 96 * MIB))
        archive = d / 'captures.tar.zst'; assert not archive.exists()
        compressor = shlex.quote(self.tools['zstd']) + ' -3 -T1'
        decoder = shlex.quote(self.tools['zstd']) + ' -d -T1'
        create = [self.tools['tar'], '--sort=name', '--format=pax', '--atime-preserve=system', '--acls', '--xattrs', '--selinux',
                  '--use-compress-program=' + compressor, '-cf', archive, str(source.relative_to(self.repo))]
        compare = [self.tools['tar'], '--acls', '--xattrs', '--selinux', '--use-compress-program=' + decoder, '-df', archive]
        listing = [self.tools['tar'], '--quoting-style=literal', '--use-compress-program=' + decoder, '-tf', archive]
        self.quiet(self.retention_command(d, 'create', create, limit))
        owner = archive_owner(archive, limit)
        self.quiet(self.retention_command(d, 'compare', compare, 16 * MIB))
        listed = self.retention_command(d, 'list', listing, 16 * MIB)
        assert not read(listed / 'stderr.txt')[0]
        members = [n.rstrip('/') for n in read(listed / 'stdout.txt')[0].decode().splitlines()]
        assert len(members) == len(before) and set(members) == set(before)
        assert archive_owner(archive, limit) == owner and capture_inventory(self.repo, source, expected) == before
        self.stable(source=True)
        write(d / 'verified.json', dict(schema=1, source=str(source.relative_to(self.repo)), archive=str(archive.relative_to(self.repo)),
              archive_owner=owner, original_file_bytes=logical, files=len(expected), entries=len(before),
              full_tar_content_metadata_comparison=True, exact_members=True, source_hashes_and_owners_unchanged=True,
              capture_index_sha256=sha(read(d / 'capture-files.json')[0]), tree_sha256=sha(read(d / 'tree-before.json')[0]),
              scope='Lossless retention only; no new native or independent content-audit credit. Restoration changes inode/ctime and grants no historical owner authority.'))
        assert archive_owner(archive, limit) == owner and capture_inventory(self.repo, source, expected) == before
        removed = []
        try:
            # Sole-writer scope is essential: POSIX unlink is not inode-conditional.
            for name, info in before.items():
                if 'bytes' not in info: continue
                p = self.repo / name; s = p.lstat()
                assert [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns] == info['stat']
                assert s.st_nlink == 1 and p.resolve(strict=True) == p
                p.unlink(); removed.append(name)
            for name, info in sorted(before.items(), key=lambda pair: len(Path(pair[0]).parts), reverse=True):
                if 'bytes' in info: continue
                p = self.repo / name; s = p.lstat()
                assert [s.st_dev, s.st_ino, s.st_mode] == info['stat'][:3] and p.resolve(strict=True) == p
                p.rmdir()
        finally:
            write(d / 'prune.json', dict(archive_sha256=owner['sha256'], removed_files=removed,
                  complete=not source.exists(), restoration_preserves_old_inode_ctime=False))
        assert not source.exists() and len(removed) == len(expected)
        assert archive_owner(archive, limit) == owner
        self.archive_owners[str(archive)] = dict(owner=owner, limit=limit)
        row.update(status='PASS', reason='', original_bytes=logical, archive_bytes=owner['bytes'],
                   archive_sha256=owner['sha256'], files=len(expected), entries=len(before))

    def prepare(self):
        self.originals = {v: self.raw / 'originals' / v for v in ORIGINALS}
        for tool in ('gcc', 'strip'):
            d = self.run('prepare-' + tool + '-version', [self.tools[tool], '--version'])
            assert read(d / 'stdout.txt')[0] and not read(d / 'stderr.txt')[0]
        source = self.repo / 'evaluation/e9-common-app'
        argv = [self.tools['gcc'], '-std=c11', '-O2', '-fomit-frame-pointer', '-fno-optimize-sibling-calls', '-fno-pie', '-no-pie', '-fno-lto', '-fno-toplevel-reorder', '-fno-reorder-blocks-and-partition', '-fno-stack-protector', '-fcf-protection=none', '-Wall', '-Wextra', '-Werror', '-MD', '-MF', self.raw / 'originals/compile.d', '-Wl,-Map,' + str(self.raw / 'originals/link.map'), source / 'heap_sort.c', '-o', self.originals['unstripped']]
        self.quiet(self.run('prepare-compile', argv, 'compile'))
        self.quiet(self.run('prepare-strip', [self.tools['strip'], '--strip-all', '-o', self.originals['stripped'], self.originals['unstripped']]))
        for v, p in self.originals.items():
            assert sha(read(p)[0]) == ORIGINALS[v], 'unknown compiled original; no seed regeneration'
            self.keep(p)
        self.images = {v: read(p)[0] for v, p in self.originals.items()}
        self.geometry = self.b.original_geometry(self.images['unstripped'], self.images['stripped'])
        self.original_headers, self.symbols, self.journal_symbol = self.p.original_pair(self.images['unstripped'], self.images['stripped'])
        for v, p in self.originals.items():
            d = self.run('prepare-' + v + '-readelf', [self.tools['readelf'], '--wide', '--headers', '--program-headers', '--sections', '--symbols', p])
            assert not read(d / 'stderr.txt')[0]
            d = self.run('prepare-' + v + '-nm', [self.tools['nm'], '-S', '--defined-only', '--format=posix', p])
            if v == 'stripped':
                assert not read(d / 'stdout.txt')[0] and read(d / 'stderr.txt')[0] == (self.tools['nm'] + ': ' + str(p) + ': no symbols\n').encode()
            else: assert not read(d / 'stderr.txt')[0]
            for dataset in self.datasets:
                path = self.raw / 'originals' / (v + '-' + dataset['name'] + '.journal')
                d = self.run('prepare-' + v + '-' + dataset['name'], [p, dataset['name'], path])
                assert read(d / 'stdout.txt')[0] == dataset['expected_stdout'].encode() and not read(d / 'stderr.txt')[0]
                assert read(path)[0] == journal(b'') and len(read(path)[0]) == 131144
            for name, code, error in [('usage', 64, b'usage: heap-sort DATASET NEW_JOURNAL_FILE\n'), ('dataset', 65, b'dataset or page-size refusal\n'), ('overwrite', 67, b'journal output failure\n')]:
                path = self.raw / 'originals' / (v + '-refuse-' + name + '.journal')
                if name == 'overwrite': write(path, b'preserve existing journal\n')
                argv = [p] if name == 'usage' else [p, 'not-a-dataset' if name == 'dataset' else 'mixed-64', path]
                d = self.run('prepare-' + v + '-refuse-' + name, argv, expected=code)
                assert not read(d / 'stdout.txt')[0] and read(d / 'stderr.txt')[0] == error
                if name == 'overwrite': assert read(path)[0] == b'preserve existing journal\n'
                else: assert not path.exists()

    def build(self):
        self.active = 'required'; self.results['required'].update(status='FAILED', reason='required gates pending')
        directory = self.raw / 'commands/required'; directory.mkdir()
        argv = [self.tools['python'], '-B', str(self.repo / 'evaluation/required-gates.py'), '--repo', str(self.repo), '--output', str(directory / 'gates')]
        context = dict(stage='required', argv=argv, env=self.build_env, direct_wall_seconds=1000, cleanup_seconds=3)
        write(directory / 'command.json', context); self.contexts.append(context)
        closed = self.supervisor.run_command(argv, self.build_env, self.logs / 'required.log', 1000, 16 * MIB)
        write(directory / 'closed.json', closed); write(directory / 'command.log', read(self.logs / 'required.log')[0])
        assert closed['exit_code'] == 0 and closed['termination'] is None and closed['cleanup_complete'] and closed['reaped_descendants'] == 0
        gates = js(directory / 'gates/commands.json')
        assert gates['head'] == REVISION and gates['source_sha256'] == {n: r['sha256'] for n, r in self.before['files'].items()}
        for row in gates['records']:
            assert sha(read(self.repo / row['log'])[0]) == row['sha256']
        assert [(r['name'], r['exit']) for r in gates['records']] == [('fmt', 0), ('clippy', 0), ('test', 0), ('check', 0)]
        assert [r['timeout_seconds'] for r in gates['records']] == [180, 180, 360, 180]
        self.results['required'].update(status='PASS', reason='', seconds=closed['seconds'])
        cargo = Path(self.tools['toolchain']) / 'cargo'; self.products = {}
        specs = [('build-native', ['-p', 'liteinst2', '-p', 'liteinst-rewrite', '--bin', 'elf-exec-oracle', '--bin', 'liteinst-rewrite'], [('elf-exec-oracle', 'bin', 'tests/support/elf_exec_driver.rs', 'Cargo.toml'), ('liteinst-rewrite', 'bin', 'tools/elf-rewrite/src/main.rs', 'tools/elf-rewrite/Cargo.toml')]),
                 ('build-common-sites', ['-p', 'liteinst-rewrite', '--example', 'common_sites'], [('common_sites', 'example', 'tools/elf-rewrite/examples/common_sites.rs', 'tools/elf-rewrite/Cargo.toml')]),
                 ('build-verifier', ['-p', 'liteinst-rewrite', '--example', 'verify_common_core'], [('verify_common_core', 'example', 'tools/elf-rewrite/examples/verify_common_core.rs', 'tools/elf-rewrite/Cargo.toml')])]
        for name, flags, products in specs:
            d = self.run(name, [cargo, 'build', *flags, '--offline', '--locked', '--message-format=json'], 'compile', environment=self.build_env)
            messages = [json.loads(line) for line in read(d / 'stdout.txt')[0].splitlines()]
            assert messages and messages[-1] == {'reason': 'build-finished', 'success': True}
            assert all(r['reason'] in ('compiler-artifact', 'build-script-executed', 'build-finished') for r in messages)
            for product, kind, source, manifest in products:
                p = selected_product(messages, product, kind, self.repo / source, self.repo / manifest, self.b.DEBUG0_PROFILE)
                assert p == self.repo / 'target/debug' / (('examples/' if kind == 'example' else '') + product)
                data, owner = read(p); assert owner['stat'][2] & 0o111
                copied = self.raw / 'products' / product; write(copied, data); os.chmod(copied, 0o500)
                assert read(p)[1] == owner and read(copied)[0] == data
                self.products[product] = copied; self.keep(copied)
        self.stable(source=True)

    def inventory(self):
        d = self.run('target', [self.products['elf-exec-oracle'], 'target'])
        target = read(d / 'stdout.txt')[0]
        assert re.fullmatch(rb'target xsave64 [0-9]+(?: [0-9]+:[0-9]+:[0-9]+)*\n', target) and len(target) <= 4096
        assert not read(d / 'stderr.txt')[0]
        self.compact_target = self.raw / 'target.txt'; write(self.compact_target, target); self.keep(self.compact_target)
        self.target = self.raw / 'target.tsv'; write(self.target, full_target(target)); self.keep(self.target)
        symbols, text = self.geometry['symbols'], self.geometry['text']
        layout = ['LI2COMMONOBSERVER\t1']
        for tag, names in [('function', self.b.FUNCTIONS + ['main']), ('marker', ['li2_before_sort', 'li2_after_sort']), ('object', ['li2_run', 'li2_journal'])]:
            for name in names:
                s = symbols[name]; layout.append(f"{tag}\t{name}\t0x{s['address']:x}\t{s['bytes']}")
        self.layout = self.raw / 'observer-layout.tsv'; write(self.layout, ('\n'.join(layout + ['END']) + '\n').encode()); self.keep(self.layout)
        policies = {}
        for v in ORIGINALS:
            provenance = self.raw / 'policies' / (v + '-provenance.json')
            write(provenance, dict(scope='FRESH_NATIVE_GEOMETRY_ONLY_NO_CALLER_ADMISSION', revision=REVISION, original_sha256=ORIGINALS[v], target_sha256=sha(target), geometry=self.geometry, allocation_profile='original-derived-v1'))
            lines = ['LI2COMMON 2', 'original ' + ORIGINALS[v], 'target ' + sha(target), 'provenance ' + sha(read(provenance)[0]), f"text 0x{text['address']:x} {text['file_offset']} {text['bytes']} {text['sha256']}"]
            for name in self.b.FUNCTIONS:
                s = symbols[name]; lines.append(f"function {name} 0x{s['address']:x} {s['bytes']} {s['sha256']}")
            for ident, name in [(2, 'li2_null_hook'), (3, 'li2_record_hook')]:
                s = symbols[name]; lines.append(f"hook {ident} 0x{s['address']:x} {s['bytes']} {s['sha256']}")
            lines += ['carrier 0x20000000', f'placement original-derived-v1 {self.b.DERIVED_DOMAIN[0]} {self.b.DERIVED_DOMAIN[1]}', 'arena selected 65536 65536', 'arena victim 65536 65536', 'limits ' + ' '.join(map(str, self.b.LIMITS)), 'search ' + ' '.join(map(str, self.b.SEARCH)), 'END']
            p = self.raw / 'policies' / (v + '.txt'); write(p, ('\n'.join(lines) + '\n').encode()); policies[v] = p
            self.keep(p); self.keep(provenance)
        for h, s, v in CELLS:
            key = '-'.join((h, s, v)); output = self.raw / 'inventories' / key
            d = self.run('inventory-' + key, [self.products['common_sites'], self.originals[v], policies[v], self.compact_target, s, h, output])
            inv = self.p.inventory(output, self.images[v], self.symbols, s, h, lambda p: read(Path(p))[0])
            assert inv['data']['instructions.tsv'] == read(self.repo / 'tests/support/e9_common_seed.instructions.tsv')[0]
            assert len(self.p.tsv(inv['data']['instructions.tsv'])) == 87
            assert read(d / 'stdout.txt')[0] == f"common sites: heads=87 selected={len(inv['sites'])} style={s} hook={h} complete_static_policy=true qualification_complete=false\n".encode() and not read(d / 'stderr.txt')[0]
            inv['directory'] = output; inv['instructions'] = self.p.tsv(inv['data']['instructions.tsv']); self.inventories[key] = inv
            for p in output.iterdir(): self.keep(p)

    def observe(self):
        for v in ORIGINALS:
            interp = Path(self.o.interpreter(self.images[v])).resolve(strict=True)
            owner_paths = [self.originals[v], interp] + [Path(p) for p in self.tools['runtime_libraries']]
            assert len(owner_paths) == len(set(owner_paths)) <= 16
            owners = [self.o.runtime_owner(str(p))[0] for p in owner_paths]
            for p in owner_paths: self.keep(p)
            owner_file = self.raw / 'observations' / (v + '-owners.tsv')
            write(owner_file, ('LI2COMMONOWNERS\t1\n' + ''.join(str(p) + '\n' for p in owner_paths)).encode()); self.keep(owner_file)
            jump, heap = (self.inventories['null-' + s + '-' + v] for s in ('jump-site', 'heap-write'))
            for dataset in self.datasets:
                name = 'observe-' + v + '-' + dataset['name']; captures = self.raw / 'observations' / (v + '-' + dataset['name'])
                d = self.run(name, [self.products['elf-exec-oracle'], 'observe-common-app', self.originals[v], self.layout, jump['directory'] / 'instructions.tsv', jump['directory'] / 'sites.tsv', heap['directory'] / 'sites.tsv', owner_file, dataset['name'], captures], 'native')
                assert read(d / 'stdout.txt')[0] == f"PASS original common-app dataset={dataset['name']} complete static inventory and ordered jump/store observations\n".encode() and not read(d / 'stderr.txt')[0]
                self.o.capture_schema(captures, dataset, jump, owners)
                pcs = read(captures / 'all-pcs.bin')[0]; assert len(pcs) % 8 == 0
                pcs = [p[0] for p in struct.iter_unpack('<Q', pcs)]
                for style, inv, fname in [('jump-site', jump, 'jump-pcs.bin'), ('heap-write', heap, 'heap-pcs.bin')]:
                    selected = {int(r['pc'], 0) for r in inv['sites']}
                    expected = b''.join(struct.pack('<Q', pc) for pc in pcs if pc in selected)
                    assert read(captures / fname)[0] == expected and len(expected) <= 16384 * 8
                    self.streams[(v, dataset['name'], style)] = expected
                    self.keep(captures / fname)
                assert [self.o.runtime_owner(str(p))[0] for p in owner_paths] == owners

    def produce(self):
        hook = None
        for h, s, v in CELLS:
            key = '-'.join((h, s, v)); directory = self.raw / 'production' / key; directory.mkdir()
            if key == 'journal-jump-site-unstripped':
                obj, image = self.raw / 'production/e9_hook.o', self.raw / 'production/e9_hook'
                d = self.run('hook-compile', [self.tools['gcc'], '-fno-stack-protector', '-fpie', '-O2', '-c', '-Wall', '-DLI2_JOURNAL_ADDRESS=' + hex(self.journal_symbol['value']) + 'ULL', self.repo / 'evaluation/e9-common-app/e9_hook.c', '-o', obj], 'compile'); self.quiet(d)
                d = self.run('hook-link', [self.tools['gcc'], obj, '-o', image, '-pie', '-nostdlib', '-Wl,-z', '-Wl,max-page-size=4096', '-Wl,--export-dynamic', '-Wl,--entry=0x0', '-Wl,--strip-all'], 'compile'); self.quiet(d)
                hook, evidence = self.p.hook_elf(read(image)[0], self.original_headers); self.keep(image)
                write(self.raw / 'production/hook-validated.json', dict(hook=hook, elf=evidence))
            inv = self.inventories[key]; selection = inv['directory'] / 'selection.txt'; core = directory / 'core'
            policy = dict(schema=1, original_sha256=ORIGINALS[v], selection_sha256=sha(inv['data']['selection.txt']), e9_revision=self.p.REFERENCE['reference_commit'], instrumentation='null' if h == 'null' else 'real-hook', selection_style=s)
            policy_path = directory / 'comparison-policy.json'; write(policy_path, policy)
            d = self.run(key + '-core', [self.products['liteinst-rewrite'], 'prepare-owned-neighbors', self.originals[v], selection, core])
            assert self.p.profiled_core_product(core, inv, self.images[v], PROFILE)
            assert read(core / 'target.tsv')[0] == read(self.target)[0]
            assert read(d / 'stdout.txt')[0] == f"candidate_complete=true qualification_complete=false sites={len(inv['sites'])}\n".encode() and not read(d / 'stderr.txt')[0]
            self.candidates[(key, 'core')] = core / 'candidate.elf'
            for p in core.iterdir(): self.keep(p)
            for lane in LANES[1:]:
                lane_dir = directory / lane; lane_dir.mkdir(); (lane_dir / 'tmp').mkdir(); candidate = lane_dir / 'candidate.elf'
                match = 'asm=j.*' if s == 'jump-site' else 'addr=^(' + '|'.join(hex(int(r['pc'], 0)) for r in inv['sites']) + ')$'
                instrumentation = 'passthru' if h == 'null' else 'call[clean,before]li2_e9_record(instrAddr)@' + str(self.raw / 'production/e9_hook')
                common = ['--action=' + match + ':' + instrumentation, '--executable', '--compression=9', '--start=' + hex(min(r[0] for r in inv['ranges'])), '--end=' + hex(max(r[1] for r in inv['ranges']))]
                e9 = self.tools['e9']; stock = lane == 'stock-algorithm'
                frontend, backend, loader = (e9['stock_frontend' if stock else 'transport_frontend'], e9['stock_backend' if stock else 'abi_backend'], e9['stock_loader' if stock else 'abi_loader'])
                prefix = key + '-' + lane
                transport = self.run(prefix + '-transport', [e9['transport_frontend'], *common, '--format=json', '--output=-', self.originals[v]], tmp=lane_dir / 'tmp')
                assert not read(transport / 'stderr.txt')[0]
                producer = self.run(prefix + '-producer', [frontend, *common, '--format=binary', '--output=' + str(candidate), '--backend=' + backend, '--option=--debug', self.originals[v]], tmp=lane_dir / 'tmp')
                roles = dict(original=self.originals[v], selection=selection, policy=policy_path, candidate=candidate, frontend=Path(frontend), backend=Path(backend), loader=Path(loader), transport_frontend=Path(e9['transport_frontend']), helper=self.helper)
                for phase, run in [('transport', transport), ('producer', producer)]:
                    for role, file in [('request', 'request.json'), ('receipt', 'receipt.json'), ('stdout', 'stdout.txt'), ('stderr', 'stderr.txt')]: roles[phase + '_' + role] = run / file
                if h == 'journal': roles['hook_elf'] = self.raw / 'production/e9_hook'
                envelope = dict(schema=1, lane=lane, common_argv=common, hook=hook if h == 'journal' else None, files={k: descriptor(p) for k, p in roles.items()}, **self.p.REFERENCE)
                envelope_path = lane_dir / 'envelope.json'; write(envelope_path, envelope)
                inventory = lane_dir / 'inventory'
                d = self.run(prefix + '-adapter', [self.tools['python'], '-B', self.repo / 'tools/elf-rewrite/e9-sites.py', envelope_path, inventory, '--envelope-sha256', sha(read(envelope_path)[0])])
                assert read(d / 'stdout.txt')[0] == f"E9 actual-site inventory: {len(inv['sites'])} requested sites; structural scope only\n".encode() and not read(d / 'stderr.txt')[0]
                binding = js(inventory / 'producer-binding.json')
                assert binding['selected_sites'] == len(inv['sites']) and binding['candidate_sha256'] == sha(read(candidate)[0])
                assert binding['site_inventory_sha256'] == sha(read(inventory / 'sites.tsv')[0]) and not binding['qualification_complete'] and not binding['architectural_equivalence_proved']
                comparison = lane_dir / 'comparison.json'
                d = self.run(prefix + '-compare', [self.tools['python'], '-B', self.repo / 'tools/elf-rewrite/compare-sites.py', selection, core / 'report.tsv', inventory / 'sites.tsv', policy_path, comparison, '--policy-sha256', sha(read(policy_path)[0])]); self.quiet(d)
                result = js(comparison)
                assert result['selected_sites'] == len(inv['sites']) and result['comparison_policy'] == policy and not result['lost_e9_trampoline_sites']
                assert result['qualification_complete'] is False and result['scope'] == 'STRUCTURAL_CANDIDATE_SITE_INVENTORY_ONLY'
                self.candidates[(key, lane)] = candidate; self.envelopes[(key, lane)] = envelope_path
                for p in [candidate, envelope_path, policy_path, comparison, *inventory.iterdir()]: self.keep(p)
        assert len(self.candidates) == 24

    def ordinary(self):
        copies = {}
        for h, s, v in CELLS:
            key = '-'.join((h, s, v))
            for lane in LANES:
                source = self.candidates[(key, lane)]; copied = self.raw / 'ordinary' / (key + '-' + lane + '.elf')
                data = read(source)[0]; write(copied, data); os.chmod(copied, 0o500)
                assert read(copied)[0] == data; self.keep(copied); copies[(key, lane)] = copied
                for dataset in self.datasets:
                    name = 'ordinary-' + key + '-' + lane + '-' + dataset['name']
                    output = self.raw / 'ordinary' / (name + '.journal')
                    pcs = self.streams[(v, dataset['name'], s)] if h == 'journal' else b''
                    row = next(r for r in self.ordinary_results if (r['cell'], r['lane'], r['dataset']) == (key, lane, dataset['name']))
                    row['status'] = 'FAILED'
                    d = self.run(name, [copied, dataset['name'], output])
                    assert read(d / 'stdout.txt')[0] == dataset['expected_stdout'].encode() and not read(d / 'stderr.txt')[0]
                    actual = read(output)[0]; assert len(actual) == 131144 and actual == journal(pcs)
                    row.update(status='PASS', records=len(pcs) // 8, journal_sha256=sha(actual), stdout_sha256=sha(read(d / 'stdout.txt')[0]))
        assert len(self.ordinary_results) == 192

    def native(self):
        for lane, key in self.native_order:
            row = next(r for r in self.native_results if (r['cell'], r['lane']) == (key, lane)); row['status'] = 'FAILED'
            record = key.startswith('journal-'); v = key.rsplit('-', 1)[-1]
            directory = self.raw / 'native' / (key + '-' + lane); directory.mkdir()
            inv = self.inventories[key]; instructions = inv['directory'] / 'instructions.tsv'
            candidate = self.candidates[(key, lane)]; captures = directory / 'captures'
            prefix = 'native-' + lane + '-' + key
            if lane == 'core':
                bundle = candidate.parent; witness = directory / 'core-witness.tsv'
                extra = CORE_ARGS + ([RECORDING] if record else [])
                d = self.run(prefix + '-witness', [self.products['verify_common_core'], self.originals[v], instructions, self.target, inv['directory'], bundle, witness, *extra])
                label = 'recording' if record else 'null'
                assert read(d / 'stdout.txt')[0] == f'core {label} witness complete: heads=87 normal=174 faults=2 execution=false qualification_complete=false\n'.encode() and not read(d / 'stderr.txt')[0]
                wr = [line.split('\t') for line in read(witness)[0].decode().splitlines()]
                assert wr[:2] == [['LI2COMMONCORE', '1'], ['scope', 'STRUCTURAL_CORE_' + ('RECORDING' if record else 'NULL') + '_WITNESSES_ONLY']]
                assert wr[2:8] == [[k, val] for k, val in [('original_sha256', ORIGINALS[v]), ('instructions_sha256', sha(read(instructions)[0])), ('target_sha256', sha(read(self.target)[0])), ('selection_sha256', sha(inv['data']['selection.txt'])), ('candidate_sha256', sha(read(candidate)[0])), ('qualification_complete', 'false')]]
                files = [r for r in wr if r[0] == 'file']; assert {r[1] for r in files} == {p.name for p in bundle.iterdir()} and len(files) == len(list(bundle.iterdir()))
                for _, name, length, digest in files:
                    b = read(bundle / name)[0]; assert len(b) == int(length) and sha(b) == digest
                assert len([r for r in wr if r[0] == 'head']) == 87 and wr[-1] == ['complete', '87', '174', '2', 'E9_UNIMPLEMENTED_UNRUN']
                expanded = []; expected_names = self.rc.capture_names()
                command = [self.products['elf-exec-oracle'], 'replay-common-core', self.originals[v], instructions, self.target, bundle, witness, captures, *extra]
                expected_stdout = (f'core {label} pairs complete: heads=87 normal=174 faults=2 comparisons=528' + ('' if record else ' E9=UNIMPLEMENTED_UNRUN') + ' qualification_complete=false\n').encode()
                pages = set()
                for load_row in self.rc.elf_rows(read(candidate)[0]):
                    if load_row[0] == 1: pages.update(range(load_row[3] & ~4095, (load_row[3] + load_row[6] + 4095) & ~4095, 4096))
                assert 37 <= len(pages) <= 2048 and set(range(0x400000, 0x425000, 4096)) <= pages
                g = (len(pages) - 37) * 4096
                members = [len(read(p)[0]) for p in bundle.iterdir()]; b, f, w = sum(members), max(members), len(read(witness)[0])
                disk = 880 * (256575 + 65536) + 880 * MIB + 529 * g + 64 * MIB + 512 * MIB + 176 * MIB
                memory = 2 * (b + max(f, w, len(self.images[v])) + w + 4 * g + 32 * MIB + 237568 + g) + 2 * (143360 + MIB)
            else:
                assert record
                witness = directory / 'witness'; wi = directory / 'witness-inputs.json'
                write(wi, dict(schema=1, structural_envelope=descriptor(self.envelopes[(key, lane)]), instructions=descriptor(instructions), target=descriptor(self.target), recording_profile='bounded-journal-v1'))
                d = self.run(prefix + '-witness', [self.tools['python'], '-B', self.repo / 'tools/elf-rewrite/e9-null-witness.py', wi, witness, '--inputs-sha256', sha(read(wi)[0]), '--structural-reader', self.repo / 'tools/elf-rewrite/e9-sites.py', RECORDING])
                report = js(witness / 'witness.json')
                assert report['witness_complete'] is True and report['status'] == 'COMPLETE_BYTE_WITNESSES'
                assert not report['unresolved_heads'] and not report['global_issues'] and report['required_heads'] == 87 and report['required_cases'] == 176
                assert len(report['cases']) == 176 and [r['case'] for r in report['cases']] == list(range(176))
                assert all(r['required'] and r['status'] == 'BYTE_WITNESS_COMPLETE' and len(r['operation']) in (1, 2) for r in report['cases'])
                expanded = [r['case'] for r in report['cases'] if len(r['operation']) == 2]
                assert len(expanded) <= 12 and {i ^ 1 for i in expanded} == set(expanded)
                assert all(i < 174 and report['heads'][i // 2]['flow'] == 'Call' for i in expanded)
                assert read(d / 'stdout.txt')[0] == b'E9 recording witnesses: 87 required heads; 176 required cases; COMPLETE_BYTE_WITNESSES\n' and not read(d / 'stderr.txt')[0]
                assert read(witness / 'sites.tsv')[0] == read(self.envelopes[(key, lane)].parent / 'inventory/sites.tsv')[0]
                expected_names = self.re.capture_names(expanded)
                command = [self.products['elf-exec-oracle'], 'replay-common-e9', self.originals[v], instructions, self.target, witness / 'witness.json', witness / 'native.tsv', captures, RECORDING]
                expected_stdout = f'E9 recording pairs complete: heads=87 normal=174 faults=2 comparisons=528 call_intermediates={len(expanded)} files={len(expected_names)} qualification_complete=false\n'.encode()
                pages = report['final_pages']; assert [p['va'] for p in pages] == sorted({p['va'] for p in pages}) and 37 <= len(pages) <= 2048
                assert set(range(0x400000, 0x425000, 4096)) <= {p['va'] for p in pages}
                g = (len(pages) - 37) * 4096; w = sum(len(read(p)[0]) for p in witness.iterdir())
                payload = sum(len(read(p)[0]) for p in [self.originals[v], instructions, self.target, candidate])
                metadata = 16 * MIB + 9000 * (len(str(directory)) + 256) + 12 * (65536 + sum(len(read(p)[0]) for p in (wi, self.envelopes[(key, lane)])))
                disk = (880 + len(expanded)) * (254288 + 2287 + 65536 + MIB) + (529 + len(expanded)) * g + 2 * w + 64 * MIB + metadata + 512 * MIB
                memory = 2 * (payload + w + 4 * g + 32 * MIB + 237568)
            if record:
                disk += 176 * (20000 * 128 + 16384); memory += 2 * (20000 * 128 + 16384)
            write(directory / 'resource.json', self.capacity(disk, memory))
            d = self.run(prefix + '-replay', command, 'native')
            assert read(d / 'stdout.txt')[0] == expected_stdout and not read(d / 'stderr.txt')[0]
            counts = native_complete(captures, lane, record, expanded)
            actual = {}
            for root, dirs, files in os.walk(captures, followlinks=False):
                assert all(not (Path(root) / n).is_symlink() for n in dirs + files)
                for n in files:
                    p = Path(root) / n; actual[str(p.relative_to(captures))] = read(p)[1]
            assert set(actual) == set(expected_names)
            assert read(captures / 'capture-inventory.tsv')[0] == ('\n'.join(expected_names) + '\n').encode()
            sizes = dict(regs=216, xstate=2287, data=4096, stack=32888, **{'stack-owned': 65536, 'loads': 151552, 'generated': g})
            for n, info in actual.items():
                suffix = n.rsplit('.', 1)[-1]
                if suffix in sizes: assert info['bytes'] == sizes[suffix]
                elif suffix == 'maps': assert 0 < info['bytes'] <= MIB
                elif suffix == 'xstate-raw': assert 576 <= info['bytes'] <= 65536
            assert actual['original-pages.bin']['bytes'] == 151552 and actual['candidate-pages.bin']['bytes'] == 151552 + g
            assert read(captures / 'original.elf')[0] == self.images[v] and read(captures / 'instructions.tsv')[0] == read(instructions)[0] and read(captures / 'runtime-target.tsv')[0] == read(self.target)[0]
            row.update(status='PASS', capture_files=len(actual), capture_hashes_sha256=sha(json.dumps({n: {k: v[k] for k in ('sha256', 'bytes')} for n, v in actual.items()}, sort_keys=True).encode()), **counts)
            self.active = None  # A retention failure must not relabel successful replay.
            self.retain_captures(lane, key, captures, actual)

    def finish(self, failure, failure_traceback=None):
        stable = False
        continuity_traceback = None
        try:
            final_configs = self.stable(source=True); stable = True
            assert all(archive_owner(Path(p), row['limit']) == row['owner'] for p, row in self.archive_owners.items())
            write(self.raw / 'source-after.json', self.p.source(self.repo))
            write(self.raw / 'tools-after.json', {p: read(Path(p))[1] for p in self.owners})
            write(self.raw / 'config-after.json', final_configs)
        except BaseException as error:
            continuity_traceback = traceback.format_exc()
            failure = (failure or '') + '; final continuity: ' + type(error).__name__ + ': ' + str(error)
        if failure:
            if self.active: self.results[self.active].update(status='FAILED', reason='see private failure.json')
            write(self.raw / 'failure.json', dict(error=failure, stage=self.active, traceback=failure_traceback, continuity_traceback=continuity_traceback, config_mismatches=getattr(self, 'config_mismatches', 0)))
        passed = not failure and stable and all(r['status'] == 'PASS' for r in self.results.values())
        passed = passed and all(r['status'] == 'PASS' for r in self.retention_results)
        if passed:
            assert len(self.ordinary_results) == 192 and len(self.native_results) == 16
            assert all(r['status'] == 'PASS' for r in self.ordinary_results + self.native_results)
            assert sum(r['pairs'] for r in self.native_results) == 2816
        write(self.raw / 'results.json', list(self.results.values()))
        public = self.raw / 'public'
        write(self.raw / 'command-contexts.json', self.contexts)
        write(public / 'invocation.json', self.normalized(dict(argv=[self.tools['python'], '-B', str(Path(__file__).resolve()), '--repo', str(self.repo), '--tools', str(self.tools_input), '--raw', str(self.raw)], tools=self.tools, build_environment=self.build_env, cpu_count=4, subject_limits=dict(structural=[20,30,16*MIB],compile=[60,90,128*MIB],native=[60,90,64*MIB],required_wall_seconds=[180,180,360,180]), command_contexts_sha256=sha(read(self.raw / 'command-contexts.json')[0]))))
        source_digest = sha(json.dumps(self.before['files'], sort_keys=True).encode())
        denied_configs = sum(v.get('observation') == 'READ_DENIED' for v in self.configs.values())
        receipt = dict(schema=1, status='PASS' if passed else 'FAILED', revision=REVISION, script_sha256=self.owners[str(Path(__file__).resolve())]['sha256'], source_files_sha256=source_digest, hardware=self.hardware,
            build_profile='dev-debug0-v1', planning_profile=PROFILE, recording_profile='bounded-journal-v1',
            planned=dict(stages=357, original_observations=16, ordinary_cases=192, core_null_pairs=704, recording_pairs=2112, native_pairs=2816, native_children=5632, native_comparisons=8448),
            observed=dict(passed_stages=sum(r['status'] == 'PASS' for r in self.results.values()), failed_stages=sum(r['status'] == 'FAILED' for r in self.results.values()), unrun_stages=sum(r['status'] == 'UNRUN' for r in self.results.values()), ordinary_passes=sum(r['status'] == 'PASS' for r in self.ordinary_results), ordinary_failed=sum(r['status'] == 'FAILED' for r in self.ordinary_results), ordinary_unrun=sum(r['status'] == 'UNRUN' for r in self.ordinary_results), complete_native_cells=sum(r['status'] == 'PASS' for r in self.native_results), failed_native_cells=sum(r['status'] == 'FAILED' for r in self.native_results), unrun_native_cells=sum(r['status'] == 'UNRUN' for r in self.native_results), complete_native_pairs=sum(r['pairs'] for r in self.native_results if r['status'] == 'PASS'), complete_native_children=sum(r['children'] for r in self.native_results if r['status'] == 'PASS'), live_rust_comparisons=sum(r['comparisons'] for r in self.native_results if r['status'] == 'PASS')),
            source_tools_configs_products_unchanged=stable and denied_configs == 0, external_e9_sha256=self.p.PRODUCTS,
            source_tools_products_unchanged=stable, configuration_observations_unchanged=stable,
            configuration_scope='Classified lookup observations under three-consecutive-negative-v1, not identical raw syscall outcomes; READ_DENIED content remains unknown, not absent or content-verified',
            configuration_denied_lookups=denied_configs,
            retention=dict(planned_cells=16, passed=sum(r['status'] == 'PASS' for r in self.retention_results), failed=sum(r['status'] == 'FAILED' for r in self.retention_results), unrun=sum(r['status'] == 'UNRUN' for r in self.retention_results), native_credit_added=False),
            product_sha256={k: self.product_owners[str(p)]['sha256'] for k, p in getattr(self, 'products', {}).items() if str(p) in self.product_owners},
            tool_sha256={self.normalized(p): row['sha256'] for p, row in self.owners.items() if p != str(Path(__file__).resolve()) and p != str(self.tools_input)},
            native_comparison_scope='Existing Rust live GPR/flags/XSAVE/stack/data/generated/journal comparisons; saved schema/hash corroboration only',
            historical_custody_reconstruction=False, independent_saved_content_audit=False, full_a3=False,
            E9_null_native_pairs='UNRUN: separate obligation, not part of this reproduction', performance_claim=False,
            operational_timings_not_performance=True)
        write(public / 'receipt.json', receipt)
        for filename, data, columns in [('stages.csv', list(self.results.values()), ['stage', 'status', 'reason', 'child_exit', 'seconds']),
                                       ('ordinary.csv', self.ordinary_results, ['cell', 'lane', 'dataset', 'status', 'records', 'journal_sha256', 'stdout_sha256']),
                                       ('retention.csv', self.retention_results, ['cell', 'lane', 'status', 'reason', 'original_bytes', 'archive_bytes', 'archive_sha256', 'files', 'entries']),
                                       ('native.csv', self.native_results, ['cell', 'lane', 'status', 'pairs', 'children', 'comparisons', 'capture_files', 'capture_hashes_sha256'])]:
            with (public / filename).open('x', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore', lineterminator='\n'); writer.writeheader(); writer.writerows(data)
        return 0 if passed else 1


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo', type=Path, required=True); ap.add_argument('--raw', type=Path, required=True)
    ap.add_argument('--tools', type=Path, required=True)
    args = ap.parse_args()
    args.tools = args.tools.resolve(strict=True)
    os.chdir(args.repo)
    assert not args.raw.exists() and not args.raw.is_symlink(), 'fresh output required'
    campaign = None
    error = None
    error_traceback = None
    try:
        campaign = Campaign(args)
        campaign.capacity(2 * 1024 * MIB)
        campaign.prepare(); campaign.build(); campaign.inventory(); campaign.observe(); campaign.produce(); campaign.ordinary(); campaign.native()
    except BaseException as exc:
        error = type(exc).__name__ + ': ' + str(exc)
        error_traceback = traceback.format_exc()
    if campaign is None:
        if args.raw.is_dir():
            write(args.raw / 'setup-failure.json', dict(status='FAILED', error=error, traceback=error_traceback, native_cases='UNRUN', historical_custody_reconstruction=False))
        raise SystemExit(error)
    raise SystemExit(campaign.finish(error, error_traceback))
