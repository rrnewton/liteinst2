"""Custody and source checks for the finite freestanding facts campaign.

Process ownership stays in the existing admission and bounded-command helpers.
This module is not a new process supervisor or an admission implementation.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CAP = 8 << 20
RESERVE = 320 << 20
CEILINGS = (19_994_091_520, 19_061_190_371)
BOUNDS = dict(build=(120, 150, 2 << 30, 128 << 20),
              metadata=(30, 60, 512 << 20, 64 << 20),
              inspect=(10, 20, 256 << 20, 4 << 20),
              decoder=(3, 10, 256 << 20, 1 << 20),
              finite=(5, 15, 512 << 20, 16 << 20))


def fact(path):
    data = Path(path).read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Context:
    def __init__(self, args, subjects):
        self.revision, self.out = args.revision, args.output.resolve()
        assert re.fullmatch('[0-9a-f]{40}', self.revision)
        assert Path.cwd().resolve() == ROOT
        assert self.out.is_relative_to(ROOT / 'ignored') and not self.out.exists()
        self.cpus = sorted(os.sched_getaffinity(0))
        assert len(self.cpus) == 1, 'reserve one CPU externally before dispatch'
        toolchain = args.toolchain.resolve(strict=True)
        self.environment = dict(HOME=os.environ['HOME'], LANG='C', LC_ALL='C', TZ='UTC',
            PATH=str(toolchain / 'bin') + ':/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1',
            CARGO_TARGET_DIR=str(ROOT / 'target'), CARGO_NET_OFFLINE='true',
            CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1',
            RUSTFLAGS='-C relocation-model=pic -C panic=abort -C force-unwind-tables=no',
            RUSTC=str(toolchain / 'bin/rustc'), RUSTDOC=str(toolchain / 'bin/rustdoc'))
        for key in ('CARGO_HOME', 'RUSTUP_HOME'):
            if key in os.environ:
                assert Path(os.environ[key]).is_absolute()
                self.environment[key] = os.environ[key]
        self.pins, self.aliases, self.artifacts = {}, {}, {}
        self.safe, self.admitted = True, False
        self.unchanged()
        self.shared = load('facts_shared_validator', self.pin(ROOT / 'evaluation/shared-x86/validate.py'))
        self.durable = self.shared.durable
        helper = self.pin(ROOT / 'evaluation/admission/processes.py')
        assert fact(helper)['sha256'] == '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
        self.owner = load('facts_existing_owner', helper)
        self.child_helper = self.pin(ROOT / 'tools/unwind-oracle/bounded_command.py')
        assert fact(self.child_helper)['sha256'] == 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
        self.out.mkdir(parents=True)
        self.logs = ROOT / 'target/evaluation/shared-freestanding-facts' / self.out.name
        self.logs.mkdir(parents=True, exist_ok=False)
        self.receipt = dict(profile='shared-freestanding-facts-v1', revision=self.revision,
            tree=self.git('rev-parse', 'HEAD^{tree}').decode().strip(), cpus=self.cpus,
            hardware='AMD EPYC Zen 5 dev host', status='FAILED', qualification='NONE',
            scope='15 decoder/descriptor/model processes; no generated instruction execution, native owner, complete CFG, exemption or performance qualification.',
            bounds=BOUNDS, capacity_ceilings=CEILINGS, copy_link_reserve=RESERVE,
            environment=self.environment, load_before=os.getloadavg(), commands=[],
            subjects={name: dict(status='UNOBSERVED') for name in subjects})
        self.durable(self.out / 'planned.json', self.receipt)
        self.tools = {n: self.pin(shutil.which(n, path=self.environment['PATH']))
                      for n in ('cc', 'sh', 'nm', 'readelf', 'git', 'cp', 'mkdir', 'dirname',
                                'realpath', 'taskset', 'prlimit', 'du')}
        self.tools.update(python=self.pin(sys.executable), cargo=self.pin(toolchain / 'bin/cargo'),
                          rustc=self.pin(toolchain / 'bin/rustc'))
        self.environment.update(LI2_CC=str(self.tools['cc']), LI2_CARGO=str(self.tools['cargo']),
                                LI2_PYTHON=str(self.tools['python']))

    def git(self, *argv):
        return subprocess.check_output(['/usr/bin/git', '-c', 'index.threads=1',
            '-c', 'core.preloadIndex=false', *argv], env=self.environment, timeout=15)

    def unchanged(self):
        assert self.git('rev-parse', 'HEAD').decode().strip() == self.revision
        assert not self.git('diff', '--binary', 'HEAD', '--')
        assert sorted(os.sched_getaffinity(0)) == self.cpus
        for path, wanted in self.pins.items():
            assert fact(path) == wanted, 'changed input: ' + path
        for path, resolved in self.aliases.items():
            assert str(Path(path).resolve(strict=True)) == resolved, 'changed input alias'

    def pin(self, path):
        path = Path(path).absolute()
        resolved = path.resolve(strict=True)
        value = fact(resolved)
        assert str(path) not in self.aliases or self.aliases[str(path)] == str(resolved)
        assert str(resolved) not in self.pins or self.pins[str(resolved)] == value
        self.aliases[str(path)] = str(resolved)
        self.pins[str(resolved)] = value
        return resolved

    def loaded_sources(self):
        for module in tuple(sys.modules.values()):
            path = getattr(module, '__file__', None)
            if path and Path(path).resolve().is_relative_to(ROOT):
                resolved = self.pin(path)
                assert self.git('ls-files', '--error-unmatch', '--', str(resolved.relative_to(ROOT)))

    def raw(self, name, command, wall, env, expected=0):
        assert self.safe and re.fullmatch('[a-z0-9-]+', name)
        assert name not in {r['name'] for r in self.receipt['commands']}
        self.unchanged()
        command = list(map(str, command))
        row = dict(name=name, command=command, wall_seconds=wall, expected_exit=expected,
                   load_before=os.getloadavg(), status='DISPATCHED_UNKNOWN')
        self.receipt['commands'].append(row)
        self.durable(self.out / (name + '-intent.json'), row)
        self.safe = False
        result = self.owner.run_command(command, env, self.logs / (name + '.log'), wall, CAP)
        self.durable(self.out / (name + '-owner.json'), result)
        row['owner'] = result
        self.safe = result['cleanup_complete'] is True
        assert self.safe, 'incomplete cleanup: no captures or later dispatch'
        raw = (self.logs / (name + '.log')).read_bytes()
        assert len(raw) <= CAP and hashlib.sha256(raw).hexdigest() == result['private_log_sha256']
        with (self.out / (name + '.log')).open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        row['load_after'] = os.getloadavg()
        self.unchanged()
        assert result['exit_code'] == expected and result['termination'] is None and result['reaped_descendants'] == 0, name + ' failed'
        row['status'] = 'PASS'
        return raw

    def run(self, name, argv, *, profile='metadata', env=None, expected=0):
        cpu, wall, address_space, file_bytes = BOUNDS[profile]
        dest = self.out / ('command-' + name)
        dest.mkdir()
        request = dict(argv=['/usr/bin/taskset', '-c', str(self.cpus[0]), '/usr/bin/prlimit',
            '--as=' + str(address_space), '--', *map(str, argv)], cwd=str(ROOT),
            env=self.environment if env is None else env, stdout=str(dest / 'stdout'),
            stderr=str(dest / 'stderr'), cpu_seconds=cpu, wall_seconds=wall, file_bytes=file_bytes)
        self.durable(dest / 'request.json', request)
        # Decoder rows retain the old 10s child / 20s owner envelope. Other
        # commands keep their existing wall ceiling for the whole owner call.
        outer_wall = 20 if profile == 'decoder' else wall
        self.raw(name, [self.tools['python'], '-I', '-B', self.child_helper, '--request',
            dest / 'request.json', '--receipt', dest / 'child.json'], outer_wall, request['env'],
            expected=0 if expected == 0 else 1)
        child = json.loads((dest / 'child.json').read_text())
        self.durable(dest / 'closed-child.json', child)
        self.receipt['commands'][-1]['child'] = child
        assert child['request_sha256'] == fact(dest / 'request.json')['sha256']
        assert child['helper_sha256'] == fact(self.child_helper)['sha256']
        assert child['exit'] == expected and child['absence_proof'] == 'ECHILD'
        assert not child['wall_timeout'] and not child['unexpected_descendants']
        assert not child['cleanup_events'] and child['cleanup_error'] is None
        assert child['aborted'] is None and child['inputs_unchanged']
        output = []
        for kind in ('stdout', 'stderr'):
            path = dest / kind
            assert path.stat().st_size <= CAP
            data = path.read_bytes()
            assert hashlib.sha256(data).hexdigest() == child[kind + '_sha256']
            output.append(data)
        return child, *output

    def capacity(self, name, *, reserve=True):
        values = []
        for apparent in (False, True):
            argv = ['/usr/bin/prlimit', '--cpu=30', '--as=268435456', '--fsize=65536', '--core=0',
                    '--', '/usr/bin/du', '--block-size=1', '--count-links', '--max-depth=1']
            if apparent:
                argv.append('--apparent-size')
            raw = self.raw(name + ('-apparent' if apparent else '-allocated'), argv + [str(ROOT)], 180, self.environment)
            rows = [line.split('\t') for line in raw.decode().splitlines()]
            assert all(len(row) == 2 and row[0].isdigit() for row in rows)
            assert len({row[1] for row in rows}) == len(rows)
            measured = {path: int(size) for size, path in rows}
            values.append(measured[str(ROOT)])
        self.receipt.setdefault('capacity', {})[name] = values
        assert all(v < ceiling for v, ceiling in zip(values, CEILINGS))
        if reserve:
            assert all(v + RESERVE < ceiling for v, ceiling in zip(values, CEILINGS)), '320 MiB copy/link reserve unavailable'

    def retain(self, source, dest):
        wanted = fact(source)
        assert wanted['bytes'] <= 128 << 20
        with Path(source).open('rb') as src, Path(dest).open('xb') as dst:
            shutil.copyfileobj(src, dst)
        Path(dest).chmod(Path(source).stat().st_mode & 0o777)
        assert fact(source) == fact(dest) == wanted
        self.artifacts[str(dest)] = wanted
        return Path(dest)

    def finish(self):
        if self.admitted and self.safe:
            try:
                self.capacity('after')
                self.unchanged()
                for path, wanted in self.artifacts.items():
                    assert fact(path) == wanted, 'changed retained product'
                self.receipt['postflight_passed'] = True
            except BaseException as error:
                self.receipt['postflight_error'] = type(error).__name__ + ': ' + str(error)
        if self.receipt.get('subjects_passed') and self.receipt.get('postflight_passed') and 'error' not in self.receipt:
            self.receipt['status'] = 'PASS'
        self.receipt.update(cleanup_complete=self.safe, inputs=self.pins, input_aliases=self.aliases,
                            retained_artifacts=self.artifacts, load_after=os.getloadavg())
        self.durable(self.out / 'closed.json', self.receipt)
        return int(self.receipt['status'] != 'PASS')
