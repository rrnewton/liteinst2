"""Bounded committed-product build and immediate private artifact retention."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import sys
import tarfile
import tomllib

from checks import admission
from page_selected import ENV, bridge_check, fact, need

REPO = Path(__file__).resolve().parents[2]
PRODUCT = REPO/'tools/page-entry/selected'
BUILD = REPO/'target/page-entry/selected'
PROFILES = {'build': [120, 2 << 30, 128 << 20, 150],
            'metadata': [30, 512 << 20, 64 << 20, 60],
            'inspect': [10, 256 << 20, 4 << 20, 20]}
ARTIFACTS = ('decoder.a', 'decoder.d', 'decoder-rustc.txt', 'decoder-cargo.txt',
             'cc-version.txt', 'bridge-selected.so', 'observe')


def package_check(package):
    root = Path(package['root'])
    need(root.name == package['name']+'-'+package['version'], 'registry package directory')
    archive = root.parents[2]/'cache'/root.parent.name/(root.name+'.crate')
    archive_before = fact(archive)
    need(archive_before['sha256'] == package['checksum'], 'locked registry archive checksum')
    members = {}
    with tarfile.open(archive, 'r:gz') as bundle:
        for entry in bundle.getmembers():
            path = PurePosixPath(entry.name)
            need(entry.isfile() and not path.is_absolute() and len(path.parts) >= 2 and
                 path.parts[0] == root.name and all(x not in ('', '.', '..') for x in path.parts),
                 'closed regular archive member')
            name = str(PurePosixPath(*path.parts[1:]))
            need(name not in members and name != '.cargo-ok', 'unique registry archive member')
            target = root/name
            need(target.resolve().is_relative_to(root) and not target.is_symlink(), 'registry member path')
            data = bundle.extractfile(entry).read()
            expected = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            need(entry.size == len(data) and fact(target) == expected, 'actual registry source differs from locked archive')
            members[name] = expected
    # Cargo generates this extraction marker. It is not compiler source and
    # is the only permitted file beyond the authenticated archive members.
    marker = root/'.cargo-ok'
    need(marker.read_bytes() == b'{"v":1}', 'exact Cargo extraction marker')
    paths = list(root.rglob('*'))
    need(not any(p.is_symlink() for p in paths), 'no registry source symlinks')
    actual = {str(p.relative_to(root)) for p in paths if p.is_file()}
    need(actual == set(members) | {'.cargo-ok'}, 'exact extracted registry file set')
    need(fact(archive) == archive_before, 'registry archive changed during inspection')
    manifest = json.dumps(members, sort_keys=True, separators=(',', ':')).encode()
    return dict(name=package['name'], version=package['version'], root=str(root),
                checksum=package['checksum'], archive=archive_before, marker=fact(marker),
                files_checked=len(members), member_manifest_sha256=hashlib.sha256(manifest).hexdigest())


class Build:
    """Caller retains commands/first errors and checks source() before and after."""
    def __init__(self, record, private, pin, binary, run):
        self.record = record.setdefault('build', {'status': 'failed', 'artifacts': {}, 'artifact_prefix': [],
            'output_before': {}, 'started': False, 'command_completed': False, 'final_errors': []})
        self.private, self.pin, self.binary, self.invoke = private, pin, binary, run
        self.retained = private/'artifacts'
        self.tools, self.environment, self.packages = {}, dict(ENV), []
        self.configuration = None
        self.observer = private/'generic-observe'
        self.paths = {}

    def run(self, label, argv, profile='metadata'):
        _, out, err = self.invoke(label, argv, profile=profile, env=self.environment)
        return out, err

    def retain(self, name, source):
        if name in self.record['artifacts']:
            return Path(self.record['artifacts'][name]['path'])
        row = dict(name=name, source=str(source), copied=False)
        self.record['artifact_prefix'].append(row)
        before = fact(source)
        row['source_before'] = before
        dest = self.retained/name
        with source.open('rb') as src, dest.open('xb') as dst:
            shutil.copyfileobj(src, dst)
        dest.chmod(source.stat().st_mode & 0o777)
        need(fact(source) == fact(dest) == before, 'exact retained build bytes')
        row.update(copied=True, mode=dest.stat().st_mode & 0o777, result=before)
        self.binary(dest)
        self.record['artifacts'][name] = dict(path=str(dest), mode=row['mode'], **before)
        return dest

    def prepare(self):
        self.retained.mkdir()
        for key in ('HOME', 'CARGO_HOME', 'RUSTUP_HOME'):
            if key in os.environ:
                need(Path(os.environ[key]).is_absolute(), 'absolute tool/cache location')
                self.environment[key] = os.environ[key]
        self.configuration = admission.cargo_configuration(self.environment)
        self.record['cargo_configuration'] = self.configuration
        self.tools = {name: self.pin(shutil.which(name, path=ENV['PATH']))
                      for name in ('cc', 'sh', 'nm', 'readelf', 'git', 'cp', 'mkdir')}
        self.tools['python'] = self.pin(sys.executable)
        self.tools['rustup'] = self.pin(shutil.which('rustup'))
        for name in ('cargo', 'rustc'):
            out, err = self.run('resolve-'+name, [self.tools['rustup'], 'which', name])
            need(not err and Path(out.decode().strip()).is_absolute(), 'actual installed Rust tool')
            self.tools[name] = self.pin(out.decode().strip())
        self.environment.update(LI2_CC=str(self.tools['cc']), LI2_CARGO=str(self.tools['cargo']),
            LI2_PYTHON=str(self.tools['python']), RUSTC=str(self.tools['rustc']),
            CARGO_TARGET_DIR=str(REPO/'target'), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1',
            CARGO_NET_OFFLINE='true', RUSTFLAGS='-C relocation-model=pic -C panic=abort -C force-unwind-tables=no')
        for name in ('cc1', 'collect2', 'as', 'ld'):
            out, err = self.run('resolve-'+name, [self.tools['cc'], '-print-prog-name='+name])
            need(not err and out.strip(), 'actual C subtool')
            value = out.decode().strip()
            self.tools[name] = self.pin(value if Path(value).is_absolute() else shutil.which(value, path=ENV['PATH']))
        self.record['tools'] = {n: dict(path=str(p), **fact(p)) for n, p in self.tools.items()}
        self.record['environment'] = self.environment
        versions = self.record['versions'] = {}
        numeric = self.record['numeric_versions'] = {}
        for name in ('cc', 'cargo', 'rustc', 'python'):
            out, err = self.run('version-'+name, [self.tools[name], '-vV' if name == 'rustc' else '--version'])
            need(not err, 'version stderr')
            versions[name] = out.decode().strip()
            value = re.search(r'\b([0-9]+)\.([0-9]+)\.([0-9]+)\b', versions[name])
            need(value is not None, 'numeric actual tool version')
            numeric[name] = [int(value[i]) for i in (1, 2, 3)]
        decoder = PRODUCT/'decoder'
        out, err = self.run('cargo-metadata', [self.tools['cargo'], 'metadata', '--manifest-path',
            decoder/'Cargo.toml', '--format-version', '1', '--locked', '--offline'])
        need(not err, 'metadata stderr')
        metadata = json.loads(out)
        need(Path(metadata['target_directory']).resolve() == REPO/'target', 'one repository Cargo target')
        locked = tomllib.loads((decoder/'Cargo.lock').read_text())['package']
        expected = {(x['name'], x['version']): x for x in locked}
        need({(x['name'], x['version']) for x in metadata['packages']} == set(expected), 'exact locked package closure')
        for package in metadata['packages']:
            lock = expected[(package['name'], package['version'])]
            path = self.pin(package['manifest_path'])
            if 'checksum' not in lock:
                need(path == decoder/'Cargo.toml' and package['source'] is None, 'actual local decoder manifest')
                continue
            need(package['source'] == lock['source'], 'exact registry identity')
            self.packages.append(dict(name=package['name'], version=package['version'],
                                      root=str(path.parent), checksum=lock['checksum']))
            self.pin(path.parent/'.cargo-ok')
            self.pin(path.parent.parents[2]/'cache'/path.parent.parent.name/(path.parent.name+'.crate'))
        self.record['registry_before'] = [package_check(p) for p in self.packages]
        # Existing shared outputs may predate this attempt. Retain that fact;
        # only a completed build supplies qualified artifacts for the cohort.
        self.record['output_before'] = {n: fact(BUILD/n) for n in ARTIFACTS if (BUILD/n).is_file()}
        self.record['started'] = True
        self.run('selected-build', [self.tools['sh'], PRODUCT/'build.sh'], 'build')
        self.record['command_completed'] = True
        # Preserve all seven immediately, before another build/link command.
        for name in ARTIFACTS:
            self.retain(name, BUILD/name)
        archive, bridge = self.retained/'decoder.a', self.retained/'bridge-selected.so'
        for name, version in (('decoder-rustc.txt', 'rustc'), ('decoder-cargo.txt', 'cargo'), ('cc-version.txt', 'cc')):
            need((self.retained/name).read_text().strip() == versions[version], 'actual build tool identity')
        dep = (self.retained/'decoder.d').read_text().strip()
        target = str(REPO/'target/release/libli2_page_selected_decoder.a')+': '
        need(dep.startswith(target) and '\n' not in dep, 'archive dep-info target')
        dependencies = shlex.split(dep[len(target):])
        expected = {str(decoder/'src'/name) for name in ('lib.rs', 'abi.rs', 'arena.rs', 'decode.rs', 'scan.rs', 'tf.rs')}
        need(set(dependencies) == expected and len(dependencies) == len(expected), 'exact six decoder sources')
        self.record['dep_info'] = {str(Path(p).relative_to(REPO)): fact(self.pin(p)) for p in dependencies}
        out, err = self.run('archive-text-exports', [self.tools['nm'], '-g', '--defined-only', archive], 'inspect')
        need(not err, 'archive symbol inspection stderr')
        self.record['archive_text_exports'] = {}
        for symbol in ('rust_eh_personality', 'li2_decoder_tf_classify'):
            rows = [line.split() for line in out.splitlines() if line.split()[-1:] == [symbol.encode()]]
            need(len(rows) == 1 and rows[0][-2:] == [b'T', symbol.encode()], 'one real text definition')
            self.record['archive_text_exports'][symbol] = 1
        out, err = self.run('bridge-undefined', [self.tools['nm'], '-u', bridge], 'inspect')
        need(out == err == b'', 'no unresolved bridge imports')
        _, err = self.run('bridge-elf', [self.tools['readelf'], '-h', '-l', '-d', '-r', '-W', bridge], 'inspect')
        need(not err, 'ELF inspection stderr')
        self.record['bridge_elf'] = bridge_check(bridge)
        self.run('generic-observer-link', [self.tools['cc'], '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
            '-I'+str(PRODUCT), '-Wl,--gc-sections,--exclude-libs,ALL,-z,noexecstack,--build-id=none',
            PRODUCT/'tests/generic/observe.c', archive, '-o', self.observer])
        observe = self.retain('generic-observe', self.observer)
        need(bridge.stat().st_mode & 0o111 and observe.stat().st_mode & 0o111, 'retained executable modes')
        self.paths = dict(archive=archive, bridge=bridge, observe=observe, old_observe=self.retained/'observe')
        self.record['status'] = 'passed'
        return self.paths

    def finish(self):
        # Failure prefixes can contain old shared-output bytes; never label
        # them freshly built when command_completed is false.
        if self.record['started']:
            for name, path in [(n, BUILD/n) for n in ARTIFACTS]+[('generic-observe', self.observer)]:
                try:
                    if path.is_file() and name not in self.record['artifacts']:
                        self.retain(name, path)
                except BaseException as exc:
                    self.record['final_errors'].append('retain '+name+': '+repr(exc))
        try:
            after = self.record['registry_after'] = [package_check(p) for p in self.packages]
            need(after == self.record.get('registry_before', []), 'registry source closure changed')
        except BaseException as exc:
            self.record['final_errors'].append('registry closure: '+repr(exc))
        if self.configuration is not None:
            try:
                need(admission.cargo_configuration(self.environment) == self.configuration, 'Cargo configuration changed')
                self.record['configuration_unchanged'] = True
            except BaseException as exc:
                self.record['configuration_unchanged'] = False
                self.record['final_errors'].append('Cargo configuration: '+repr(exc))
        if self.record['final_errors']:
            self.record['status'] = 'failed'
        return self.record['final_errors']
