#!/usr/bin/env python3
"""One owned GNU cat 9.5 build; never execute the resulting program."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE_SHA = 'cd328edeac92f6a665de9f323c93b712af1858bc2e0d88f3f7100469470a1b8a'
OWNER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
CEILINGS = (19_994_091_520, 19_061_190_371)
SCRATCH, MIB = 250_000_000, 1024**2
CATALOG_SHA = '2b89602488e2b1854e0df68ecdf49243d4c952a2f393fad4a56785db4a539bde'
MAKEFILE = '.PHONY: cat-only\ncat-only: $(BUILT_SOURCES)\n\t$(MAKE) -j1 -f Makefile src/cat\n'
METADATA = r'''import json, pathlib, subprocess
def run(argv):
    return subprocess.check_output(argv, stderr=subprocess.STDOUT, timeout=15).decode()
names = ['gcc', 'as', 'ld', 'ar', 'ranlib', 'make', 'tar', 'xz', 'rpm']
data = {name: run(['/usr/bin/' + name, '--version']) for name in names}
data['perl'] = run(['/usr/bin/perl', '-e', 'print $^V, chr(10)'])
data['os_release'] = pathlib.Path('/etc/os-release').read_text()
format = '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n'
data['packages'] = run(['/usr/bin/rpm', '-q', '--qf', format, 'gcc', 'binutils', 'glibc-devel', 'kernel-headers'])
paths = ['/usr/bin/gcc', '/usr/bin/as', '/usr/bin/ld', '/usr/include/stdio.h']
version_header = pathlib.Path('/usr/include/linux/version.h')
try: version_header.stat(); paths.append(str(version_header))
except FileNotFoundError: data['linux_version_header'] = 'ABSENT'
data['package_owners'] = {path: dict(actual=str(pathlib.Path(path).resolve(strict=True)), owner=run(['/usr/bin/rpm', '-qf', '--qf', format, str(pathlib.Path(path).resolve(strict=True))])) for path in paths}
print(json.dumps(data, sort_keys=True))
'''


def durable(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def pin(path):
    actual = path.resolve(strict=True); before = actual.stat(); digest = hashlib.sha256()
    assert stat.S_ISREG(before.st_mode)
    with actual.open('rb') as stream:
        for chunk in iter(lambda: stream.read(MIB), b''):
            digest.update(chunk)
    stamp = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert stamp(before) == stamp(actual.stat())
    return dict(path=str(actual), bytes=before.st_size, sha256=digest.hexdigest(), stat=stamp(before))


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--build-profile', choices=('cat-only-v1', 'cat-head-wc-v1'), default='cat-only-v1')
    args = parser.parse_args()
    catalog_path = Path(__file__).with_name('program_catalog.json').resolve(strict=True)
    catalog_bytes = catalog_path.read_bytes()
    assert hashlib.sha256(catalog_bytes).hexdigest() == CATALOG_SHA
    catalog = json.loads(catalog_bytes)
    programs = catalog['build_profiles'][args.build_profile]
    corpus = args.build_profile == 'cat-head-wc-v1'
    make_name = 'corpus-only' if corpus else 'cat-only'
    makefile = ('.PHONY: corpus-only\ncorpus-only: $(BUILT_SOURCES)\n\t$(MAKE) -j1 -f Makefile '
                + ' '.join('src/'+name for name in programs) + '\n') if corpus else MAKEFILE
    assert re.fullmatch('[0-9a-f]{40}', args.revision) and Path.cwd().resolve() == ROOT
    work = args.work.absolute(); archive = args.archive.resolve(strict=True)
    assert work == work.resolve() and work.is_relative_to(ROOT / 'ignored') and work != ROOT / 'ignored'
    assert work.parent.is_dir() and not work.exists()
    cpus = sorted(os.sched_getaffinity(0)); assert len(cpus) == 1
    env = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', TZ='UTC', TMPDIR=str(work / 'tmp'),
               CONFIG_SITE='/dev/null', CC='/usr/bin/gcc', AR='/usr/bin/ar', RANLIB='/usr/bin/ranlib',
               CFLAGS='-O2 -g0 -fno-pie', LDFLAGS='-no-pie', PYTHONDONTWRITEBYTECODE='1')
    def git(*argv):
        return subprocess.check_output(['/usr/bin/git', '-c', 'index.threads=1', '-c', 'core.preloadIndex=false', *argv], env=env, timeout=15)
    helper = ROOT / 'evaluation/admission/processes.py'
    adapter = Path(__file__).with_name('configure_join.py').resolve(strict=True)
    tools = ['gcc', 'as', 'ld', 'ar', 'ranlib', 'make', 'tar', 'xz', 'perl', 'rpm', 'prlimit', 'env', 'du', 'git', 'sh']
    frozen = {str(p): pin(p) for p in [Path(__file__).resolve(), catalog_path, helper, adapter, archive, Path(sys.executable), *[Path('/usr/bin') / n for n in tools]]}
    assert frozen[str(catalog_path)]['sha256'] == CATALOG_SHA
    assert git('ls-files', '--error-unmatch', str(catalog_path.relative_to(ROOT))).strip()
    assert frozen[str(helper)]['sha256'] == OWNER_SHA
    assert frozen[str(adapter)]['sha256'] == 'd78402d45355a733250e8e8bbef88a7f4c335de9e02bc067d0c7f37c490b33a9'
    assert git('ls-files', '--error-unmatch', str(adapter.relative_to(ROOT))).strip()
    assert (frozen[str(archive)]['bytes'], frozen[str(archive)]['sha256']) == (6007136, ARCHIVE_SHA)
    assert git('ls-files', '--error-unmatch', str(Path(__file__).resolve().relative_to(ROOT))).strip()
    def unchanged():
        assert git('rev-parse', 'HEAD').decode().strip() == args.revision and not git('diff', '--binary', 'HEAD', '--')
        assert sorted(os.sched_getaffinity(0)) == cpus
        assert all(pin(Path(path)) == expected for path, expected in frozen.items())
    unchanged()
    spec = importlib.util.spec_from_file_location('cat_build_owner', helper)
    owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
    logs = ROOT / ('target/evaluation/direct-program-coreutils-corpus' if corpus else 'target/evaluation/direct-program-cat') / work.name
    assert not logs.exists(); work.mkdir(); logs.mkdir(parents=True)
    (work / 'tmp').mkdir(); (work / 'build').mkdir()
    (work / (make_name+'.mk')).write_text(makefile)
    frozen[str(work / (make_name+'.mk'))] = pin(work / (make_name+'.mk'))
    receipt = dict(status='FAILED', revision=args.revision, tree=git('rev-parse', 'HEAD^{tree}').decode().strip(),
                   inputs=frozen, cpus=cpus, environment=env, slot_ceilings=CEILINGS,
                   scratch_admission_bytes=SCRATCH, scratch_is_quota=False, subject_executions=0,
                   python=sys.version, load_before=os.getloadavg(), results=[], outcomes={n: 'UNOBSERVED' for n in ('metadata', 'extract', 'configure', 'make')},
                   prior_failed_attempt=dict(path='ignored/direct-program-v1/cat-build-v1/closed.json', bytes=22533, sha256='100d807e4d74750acd61d71ef4138559ebc1f46d8dea0dc14f3b6cc2e716d4f2', status='FAILED', configure_leader=0, outer_termination='descendants_after_exit', reaped=2, make='UNOBSERVED', child_exit_statuses='not retained; no claim both were zombies'))
    if corpus:
        receipt.update(build_profile=args.build_profile, programs=programs, artifacts={name: None for name in programs}, artifact_outcomes={name: 'UNOBSERVED' for name in programs})
    durable(work / 'planned.json', receipt)
    safe, before_done = True, False
    def run(name, argv, cpu, wall, cwd=ROOT, address_space=2 * 1024**3, file_bytes=64 * MIB):
        nonlocal safe
        unchanged()
        command = ['/usr/bin/prlimit', '--cpu=' + str(cpu), '--as=' + str(address_space), '--fsize=' + str(file_bytes), '--core=0', '--', '/usr/bin/env', '--chdir=' + str(cwd), '--', *argv]
        row = dict(name=name, command=command, wall_seconds=wall, log_limit_bytes=MIB, status='DISPATCHED_UNKNOWN')
        receipt['results'].append(row); durable(work / (name + '-intent.json'), row)
        safe = False
        result = owner.run_command(command, env, logs / (name + '.log'), wall, MIB)
        durable(work / (name + '-owner.json'), result); row['owner'] = result
        safe = result['cleanup_complete'] is True
        assert safe, 'incomplete cleanup: no capture reads or further subprocesses'
        raw = (logs / (name + '.log')).read_bytes()
        assert len(raw) <= MIB and hashlib.sha256(raw).hexdigest() == result['private_log_sha256']
        with (work / (name + '.log')).open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        row['capture'] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        row['status'] = 'PASS' if result['exit_code'] == 0 and result['termination'] is None and result['reaped_descendants'] == 0 else 'FAILED'
        unchanged()
        if name == 'configure':
            joined = work / 'configure-join.json'
            if joined.exists():
                joined_pin = pin(joined); assert joined_pin['bytes'] <= MIB
                value = json.loads(joined.read_bytes()); assert pin(joined) == joined_pin
                row['join'] = dict(receipt=joined_pin, result=value)
                assert value['initial_echild'] is True and value['joined_echild'] is True and value['command'] == argv[7:]
                children = [value['leader'], *value['adopted']]
                assert all(child['exit_code'] == os.waitstatus_to_exitcode(child['wait_status']) for child in children)
                joined_passed = all(child['exit_code'] == 0 for child in children)
                assert value['status'] == ('PASS' if joined_passed else 'FAILED')
            if row['status'] == 'PASS': assert 'join' in row and row['join']['result']['status'] == 'PASS'
        assert row['status'] == 'PASS', name + ' failed'
        return raw
    def capacity(tag):
        totals, scratch = [], []
        for apparent in (False, True):
            name = tag + ('-apparent' if apparent else '-allocated')
            argv = ['/usr/bin/du', '--block-size=1', '--count-links', '--max-depth=1'] + (['--apparent-size'] if apparent else [])
            raw = run(name, argv + [str(ROOT), str(work), str(logs)], 30, 180, address_space=256 * MIB, file_bytes=65536)
            pairs = [line.split('\t') for line in raw.decode().splitlines()]
            assert all(len(p) == 2 and p[0].isdigit() for p in pairs) and len({p[1] for p in pairs}) == len(pairs)
            values = {p: int(n) for n, p in pairs}; totals.append(values[str(ROOT)]); scratch.append(values[str(work)] + values[str(logs)])
        receipt[tag + '_capacity'] = dict(slot=totals, scratch=scratch)
        assert all(v < cap for v, cap in zip(totals, CEILINGS)) and max(scratch) <= SCRATCH
        return totals
    def source_inventory():
        source = work / 'coreutils-9.5'; rows = []
        for path in sorted(source.rglob('*')):
            assert not path.is_symlink()
            if path.is_file():
                value = pin(path); rows.append([str(path.relative_to(source)), value['bytes'], value['sha256']])
        assert len(rows) == 3300 and sum(row[1] for row in rows) == 25535023
        return hashlib.sha256((json.dumps(rows, separators=(',', ':')) + '\n').encode()).hexdigest()
    try:
        before = capacity('before'); before_done = True
        assert all(v + SCRATCH < cap for v, cap in zip(before, CEILINGS)), '250 MB scratch reserve unavailable'
        commands = [('metadata', [sys.executable, '-I', '-B', '-c', METADATA], 30, 60, ROOT),
                    ('extract', ['/usr/bin/tar', '-xJf', str(archive), '-C', str(work), '--no-same-owner', '--exclude=coreutils-9.5/po/*.po', '--exclude=coreutils-9.5/po/*.gmo'], 30, 60, ROOT),
                    ('configure', [sys.executable, '-I', '-B', str(adapter), '--receipt', str(work / 'configure-join.json'), '--', str(work / 'coreutils-9.5/configure'), '--disable-nls', '--disable-dependency-tracking', '--disable-acl', '--disable-xattr', '--disable-libcap', '--without-libgmp', '--without-selinux'], 180, 300, work / 'build'),
                    ('make', ['/usr/bin/make', '-j1', '-f', 'Makefile', '-f', str(work / (make_name+'.mk')), make_name], 300, 600, work / 'build')]
        for name, argv, cpu, wall, cwd in commands:
            receipt['outcomes'][name] = 'DISPATCHED_UNKNOWN'
            raw = run(name, argv, cpu, wall, cwd)
            if name == 'metadata': receipt['tool_versions_and_packages'] = json.loads(raw)
            if name == 'extract': receipt['extracted_source_sha256'] = source_inventory()
            receipt['outcomes'][name] = 'PASS'
        assert source_inventory() == receipt['extracted_source_sha256']
        receipt['configuration'] = {name: pin(work / 'build' / name) for name in ('config.log', 'config.status', 'Makefile', 'lib/config.h')}
        for name in programs:
            if corpus: receipt['artifact_outcomes'][name] = 'FAILED'
            product = work / ('build/src/'+name); artifact = pin(product)
            if corpus: receipt['artifacts'][name] = artifact
            else: receipt['artifact'] = artifact
            with product.open('rb') as stream: header = stream.read(64)
            artifact['header_hex'] = header.hex()
            assert len(header) == 64 and header[:7] == b'\x7fELF\x02\x01\x01' and int.from_bytes(header[16:18], 'little') == 2 and int.from_bytes(header[18:20], 'little') == 62
            assert int.from_bytes(header[20:24], 'little') == 1 and int.from_bytes(header[52:54], 'little') == 64 and product.stat().st_mode & 0o111
            if corpus: receipt['artifact_outcomes'][name] = 'PASS'
        receipt['build_passed'] = True
    except BaseException as error:
        receipt['error'] = type(error).__name__ + ': ' + str(error)
        for name, value in receipt['outcomes'].items():
            if value == 'DISPATCHED_UNKNOWN' and safe: receipt['outcomes'][name] = 'FAILED'
    finally:
        if safe and before_done:
            try:
                capacity('after'); unchanged(); receipt['postflight_passed'] = True
            except BaseException as error:
                receipt['postflight_error'] = type(error).__name__ + ': ' + str(error)
        if receipt.get('build_passed') and receipt.get('postflight_passed') and 'error' not in receipt: receipt['status'] = 'READY_BUILT_UNEXECUTED'
        receipt.update(cleanup_complete=safe, load_after=os.getloadavg())
        durable(work / 'closed.json', receipt)
    return int(receipt['status'] != 'READY_BUILT_UNEXECUTED')


if __name__ == '__main__':
    if not (__debug__ and sys.flags.isolated and sys.dont_write_bytecode): raise SystemExit('use Python -I -B with assertions enabled')
    raise SystemExit(main())
