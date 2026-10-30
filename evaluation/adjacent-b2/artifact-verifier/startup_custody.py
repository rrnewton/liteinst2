"""Bounded saved-startup custody. No build, producer, or candidate invocation."""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time

MIB = 1048576
PROGRAMS = ('checksum', 'rle-roundtrip')
PROFILE = 'elf-disassembly-null-jumps-static-exec-router-bootstrap-v1'
CRATE = 'evaluation/adjacent-b2/artifact-verifier'
CONTROL = ('request.json', 'command.json', 'parent-closed.json', 'receipt.json',
           'stdout.txt', 'stderr.txt', 'helper.stdout', 'helper.stderr')
INPUTS = ('original', 'ledger', 'policy', 'startup')
SOURCE_ROOTS = ('Cargo.toml','Cargo.lock','build.rs','.cargo','src','crates',
    'tools/elf-rewrite','tests','examples',CRATE,
    'evaluation/offline-corpus/checksum.S','evaluation/offline-corpus/rle-roundtrip.S',
    'evaluation/offline-corpus/layout.ld','tools/unwind-oracle/bounded_command.py')
SOURCE_FILE_BYTES = 16 * MIB
SOURCE_BYTES = 512 * MIB  # The existing outer source-custody budget, not per blob.
SOURCE_REQUEST_BYTES = MIB  # The externally frozen source-profile JSON has this cap.
GIT_SECONDS = 15
GIT_CLEANUP_SECONDS = 5


def need(value, detail):
    if not value:
        raise ValueError(detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, 'canonical digest')
    return value


def json_value(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns]


def absolute(value):
    need(type(value) is str and 1 < len(value) <= 4095 and value.startswith('/') and
         all(33 <= ord(c) <= 126 for c in value) and
         all(p not in ('', '.', '..') for p in value.split('/')[1:]), 'canonical absolute path')
    return Path(value)


def leaf(value):
    return type(value) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}', value) is not None and value not in ('.', '..')


class Store:
    """Read each regular file once, cache bytes, and recheck every identity.

    Every pathname component is opened without following symlinks. Directory
    descriptors stay anchored until close; both paths and descriptors are
    checked again. Separate namespace counters are enforced by callers before
    product/dependency allocation, not replaced by this outer storage budget.
    """
    def __init__(self, maximum=512 * MIB):
        self.maximum = maximum
        self.used = 0
        self.files = {}
        self.directories = {}

    def directory(self, path):
        path = absolute(str(path))
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        current = Path('/')
        try:
            for component in path.parts[1:]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                current = current / component
                observed = stamp(os.fstat(fd))
                key = str(current)
                if key not in self.directories:
                    self.directories[key] = (os.dup(fd), observed[:3])
                need(self.directories[key][1] == observed[:3], 'directory identity changed')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(self, path, cap, pin=None):
        path = absolute(str(path))
        parent = self.directory(path.parent)
        fd = None
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap, 'regular file size/type')
            identity = stamp(before)
            need(identity == stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'open path changed')
            key = str(path)
            if key in self.files:
                record, raw = self.files[key]
                need(record['stat'] == identity, 'cached file changed')
            else:
                need(before.st_size <= self.maximum - self.used, 'outer custody byte bound')
                data = bytearray()
                while len(data) < before.st_size:
                    block = os.read(fd, min(65536, before.st_size - len(data)))
                    need(bool(block), 'short custody read')
                    data.extend(block)
                    self.used += len(block)
                raw = bytes(data)
                record = dict(path=key, bytes=len(raw), sha256=sha(raw), stat=identity)
                need(identity == stamp(os.fstat(fd)) == stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'file changed during read')
                self.files[key] = (record, raw)
            if pin is not None:
                need(record == pin, 'frozen file content/identity')
            return raw
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def pin(self, path, cap):
        self.read(path, cap)
        return dict(self.files[str(path)][0])

    def members(self, path, count=513):
        fd = self.directory(path)
        try:
            before = stamp(os.fstat(fd))
            names = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    need(len(names) < count and leaf(entry.name), 'flat publication member/name bound')
                    names.append(entry.name)
            need(before == stamp(os.fstat(fd)), 'directory changed during listing')
            return dict(stat=before, members=sorted(names))
        finally:
            os.close(fd)

    def verify(self):
        for path, (fd, identity) in self.directories.items():
            need(stamp(os.fstat(fd))[:3] == identity == stamp(os.lstat(path))[:3], 'retained directory replaced')
        for path, (pin, _) in self.files.items():
            self.read(path, pin['bytes'], pin)

    def close(self):
        errors = []
        for fd, _ in self.directories.values():
            try:
                os.close(fd)
            except OSError as error:
                errors.append(str(error))
        self.directories.clear()
        need(not errors, 'custody descriptor close failure: ' + repr(errors))


def closed(store, directory, request, command, helper_sha):
    directory = absolute(str(directory))
    raw_request = store.read(directory / 'request.json', MIB)
    need(json_value(raw_request) == request, 'exact bounded request')
    need(json_value(store.read(directory / 'command.json', MIB)) == command, 'exact bounded supervisor')
    parent = json_value(store.read(directory / 'parent-closed.json', MIB))
    receipt = json_value(store.read(directory / 'receipt.json', MIB))
    need(parent['wait_returned'] is True and parent['error'] is None and
         receipt['absence_proof'] == 'ECHILD' and receipt['cleanup_error'] is None and
         receipt['helper_sha256'] == helper_sha and receipt['request_sha256'] == sha(raw_request) and
         receipt['inputs_unchanged'] is True, 'raw parent/helper/input closure')
    need(type(receipt['exit']) is int and type(parent['exit']) is int and
         parent['exit'] == (0 if receipt['exit'] == 0 else 1) and receipt['wall_timeout'] is False and
         receipt['aborted'] is None and receipt['cleanup_events'] == receipt['unexpected_descendants'] == [], 'raw exit/cleanup closure')
    streams = {name: store.read(directory / (name + '.txt'), request['file_bytes']) for name in ('stdout', 'stderr')}
    need(all(sha(raw) == receipt[name + '_sha256'] for name, raw in streams.items()), 'raw stream identity')
    need(store.read(directory / 'helper.stderr', MIB) == b'', 'helper stderr')
    terminal = dict(exit=receipt['exit'],wall_timeout=False,absence_proof='ECHILD',descendants=0,success=receipt['exit']==0)
    need(store.read(directory / 'helper.stdout', request['file_bytes']) == (json.dumps(terminal)+'\n').encode('ascii'), 'exact bounded helper terminal')
    need(type(receipt['elapsed_seconds']) in (int,float) and 0 <= receipt['elapsed_seconds'] <= request['wall_seconds'], 'strict raw helper deadline')
    return receipt['exit'], streams


def environment(ctx, env, tools):
    need(set(tools) == {'python', 'helper', 'as', 'ld', 'objdump', 'timeout', 'cargo', 'rustc'}, 'exact startup tool population')
    bin_dir = Path(tools['cargo']['path']).parent
    expected = dict(HOME=env['HOME'], CARGO_HOME=env['CARGO_HOME'], PATH=str(bin_dir) + ':/usr/bin:/bin',
        RUSTC=str(bin_dir / 'rustc'), RUSTDOC=str(bin_dir / 'rustdoc'), CARGO_TARGET_DIR=str(ctx.ROOT / 'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never',
        CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        LC_ALL='C', LANG='C', PYTHONDONTWRITEBYTECODE='1')
    need(env == expected and tools['rustc']['path'] == env['RUSTC'], 'exact startup environment')
    absolute(env['HOME']); absolute(env['CARGO_HOME'])
    for pin in tools.values():
        ctx.read(Path(pin['path']), pin)
    need(tools['helper']['sha256'] == ctx.B.HELPER_SHA and
         tools['helper']['path'] == str(ctx.ROOT / 'tools/unwind-oracle/bounded_command.py') and
         ctx.B.identity(sys.executable) == tools['python'], 'exact helper and Python')


class SourceBatch:
    """Strict ordered cat-file records; retain hashes and at most one header.

    Expected content digests come from the external source profile. Git's object
    ID is checked separately against the full blob framing and contents. A batch
    is a fresh read on every call, never a cache or a substitute for live reads.
    """
    def __init__(self, expected):
        self.expected = tuple(expected)
        need(bool(self.expected), 'nonempty source batch')
        for value in self.expected:
            digest(value)
        self.index = 0
        self.total = 0
        self.header = bytearray()
        self.state = 'header'
        self.remaining = 0

    def feed(self, raw):
        need(type(raw) is bytes, 'source batch bytes')
        at = 0
        while at < len(raw):
            need(self.index < len(self.expected), 'source batch trailing output')
            if self.state == 'header':
                end = raw.find(b'\n', at)
                stop = len(raw) if end < 0 else end
                need(len(self.header) + stop - at <= 96, 'source batch header bound')
                self.header.extend(raw[at:stop]); at = stop
                if end < 0:
                    return
                at += 1
                match = re.fullmatch(rb'([0-9a-f]{40}) blob (0|[1-9][0-9]{0,7})', self.header)
                need(match is not None, 'source batch exact blob header')
                size = int(match[2])
                need(size <= SOURCE_FILE_BYTES and size <= SOURCE_BYTES - self.total,
                     'source batch file/aggregate bound')
                self.total += size
                self.oid = match[1].decode('ascii')
                self.content_hash = hashlib.sha256()
                self.object_hash = hashlib.sha1(b'blob ' + str(size).encode('ascii') + b'\0')
                self.remaining = size
                self.header.clear()
                self.state = 'body' if size else 'newline'
            elif self.state == 'body':
                take = min(self.remaining, len(raw) - at)
                block = memoryview(raw)[at:at + take]
                self.content_hash.update(block); self.object_hash.update(block)
                self.remaining -= take; at += take
                if not self.remaining:
                    self.state = 'newline'
            else:
                need(raw[at:at + 1] == b'\n', 'source batch exact blob terminator')
                need(self.content_hash.hexdigest() == self.expected[self.index]
                     and self.object_hash.hexdigest() == self.oid, 'reviewed committed source bytes')
                at += 1; self.index += 1; self.state = 'header'

    def finish(self):
        need(self.index == len(self.expected) and self.state == 'header' and not self.header,
             'source batch missing/truncated record')


def source_batch(root, revision, ordered, env):
    """One bounded Git process and one strict 15-second command deadline."""
    need(type(revision) is str and re.fullmatch('[0-9a-f]{40}', revision) is not None,
         'source batch exact revision')
    request = bytearray()
    for relative, expected in ordered:
        need(type(relative) is str and bool(relative) and not relative.startswith('/')
             and all(part not in ('', '.', '..') for part in relative.split('/'))
             and not any(c in relative for c in '\0\r\n'), 'reviewed source path')
        digest(expected)
        row = (revision + ':' + relative + '\n').encode('utf-8')
        need(len(row) <= SOURCE_REQUEST_BYTES - len(request), 'source batch request bound')
        request.extend(row)
    decoder = SourceBatch([expected for _, expected in ordered])
    argv = ['/usr/bin/git', '-C', str(root), 'cat-file', '--batch']
    deadline = time.monotonic() + GIT_SECONDS
    child = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, bufsize=0)
    try:
        input_fd = child.stdin.fileno()
        output_fd = child.stdout.fileno()
        error_fd = child.stderr.fileno()
        for fd in (input_fd, output_fd, error_fd):
            os.set_blocking(fd, False)
        reading = {output_fd, error_fd}; sent = 0
        while reading or sent < len(request):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, GIT_SECONDS)
            ready, writable, _ = select.select(list(reading),
                [input_fd] if sent < len(request) else [], [], remaining)
            if not ready and not writable:
                raise subprocess.TimeoutExpired(argv, GIT_SECONDS)
            if writable:
                count = os.write(input_fd, memoryview(request)[sent:sent + 65536])
                need(count > 0, 'source batch short request write')
                sent += count
                if sent == len(request):
                    child.stdin.close()
            for fd in ready:
                block = os.read(fd, 65536)
                if not block:
                    reading.remove(fd)
                elif fd == error_fd:
                    raise ValueError('source batch Git stderr')
                else:
                    decoder.feed(block)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, GIT_SECONDS)
        need(child.wait(timeout=remaining) == 0, 'source batch Git exit')
        decoder.finish()
        if time.monotonic() > deadline:
            raise subprocess.TimeoutExpired(argv, GIT_SECONDS)
    finally:
        # Cleanup cannot turn a deadline or parser failure into acceptance. Its
        # separate finite wait is only for reaping the killed read-only child.
        try:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=GIT_CLEANUP_SECONDS)
        finally:
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()


def source_profile(ctx, pins, env):
    revision = pins.SOURCE_REVISION
    need(type(revision) is str and re.fullmatch('[0-9a-f]{40}', revision) is not None and
         bool(pins.SOURCE_PINS), 'startup source profile UNBOUND')
    git = lambda *args: subprocess.check_output(['/usr/bin/git', '-C', str(ctx.ROOT), *args], env=env, timeout=15)
    current = git('rev-parse', 'HEAD').decode('ascii').strip()
    need(not git('diff', '--binary', 'HEAD', '--'), 'clean tracked startup source')
    names = git('ls-tree','-r','--name-only',revision,'--',*SOURCE_ROOTS).decode('utf-8').splitlines()
    need(set(pins.SOURCE_PINS) == set(names), 'complete reviewed startup source inventory')
    # The pinned map is reviewed independently, never accepted from a build's
    # self-reported files. Exact Git and live bytes must both match every pin.
    ordered = sorted(pins.SOURCE_PINS.items())
    source_batch(ctx.ROOT, revision, ordered, env)
    total = 0
    for relative, expected in ordered:
        need(not relative.startswith('/') and '..' not in relative.split('/'), 'reviewed source path')
        digest(expected)
        raw = ctx.read(ctx.ROOT / relative, cap=SOURCE_FILE_BYTES)
        need(len(raw) <= SOURCE_FILE_BYTES and len(raw) <= SOURCE_BYTES - total,
             'live source file/aggregate bound')
        total += len(raw)
        need(sha(raw) == expected, 'reviewed startup source bytes')
    return current


def build(ctx, a, legacy, pins, store, role, reference, captured):
    need(role in ('producer', 'verifier'), 'explicit startup build role')
    directory = absolute(reference['directory'])
    raw = store.read(directory / 'closed.json', MIB)
    need(sha(raw) == digest(reference['sha256']), 'frozen startup build closure')
    value = json_value(raw)
    need(set(value) == {'schema', 'role', 'source_revision', 'files', 'configurations',
         'configuration_profile', 'cargo_cwd', 'lock_sha256'} and
         value['schema'] == 'LI2STARTUP-BUILD-1' and value['role'] == role and
         value['source_revision'] == pins.SOURCE_REVISION and value['cargo_cwd'] == '/', 'new startup build profile')
    module = legacy.rooted_module(ctx)
    configurations = module.configurations(ctx, captured, profile=module.COMMENT_PROFILE)
    need(value['configuration_profile'] == module.COMMENT_PROFILE and value['configurations'] == configurations,
         'complete observed rooted startup build configuration')
    lock_relative = 'Cargo.lock' if role == 'producer' else CRATE + '/Cargo.lock'
    lock_sha = pins.PRODUCER_LOCK_SHA256 if role == 'producer' else pins.VERIFIER_LOCK_SHA256
    need(value['lock_sha256'] == digest(lock_sha), 'separate startup lock pin')
    binary = ctx.ROOT / ('target/release/examples/offline_router_sites' if role == 'producer' else 'target/release/adjacent-b2-artifact-verifier')
    launcher = ctx.ROOT / CRATE / 'startup_cargo_from_root.py'
    argv = [captured['tools']['python']['path'], '-B', str(launcher), captured['tools']['cargo']['path'], str(ctx.ROOT), role]
    request, command = legacy.request_and_command(ctx, captured, directory, argv, (120, 180, 128))
    required = {str(ctx.ROOT / relative): h for relative, h in pins.SOURCE_PINS.items()}
    required[str(ctx.ROOT / lock_relative)] = lock_sha
    required[str(launcher)] = legacy.STARTUP_MODULES['startup_cargo_from_root.py']
    for name, h in legacy.ROOTED_BUILD_SOURCES.items():
        required[str(ctx.ROOT / CRATE / name)] = h
    controls = {str(directory / name) for name in CONTROL}
    need(set(value['files']) == set(required) | controls | {str(binary)}, 'complete startup build file roster')
    for path, pin in value['files'].items():
        observed = ctx.read(Path(path), pin, 128*MIB)
        if path in required:
            need(sha(observed) == required[path], 'startup build reviewed source/lock identity')
    code, streams = closed(store, directory, request, command, ctx.B.HELPER_SHA)
    need(code == 0, 'startup build failed raw closure')
    builder = ctx.load(a.ROUTED.builder, a.ROUTED.builder_sha)
    builder.check_artifact(streams['stdout'], dict(product_name='offline_router_sites' if role == 'producer' else 'adjacent-b2-artifact-verifier',
        product_kind='example' if role == 'producer' else 'bin', product=str(binary)))
    return binary, configurations


def producer_argv(binary, plan):
    need(tuple(plan['inputs']) == PROGRAMS, 'both ordered producer input groups')
    argv = [str(binary)]
    for program in PROGRAMS:
        group = plan['inputs'][program]
        need(tuple(group) == INPUTS, 'exact four input snapshots')
        argv.append(group['original']['path'])
        for key in INPUTS[1:]:
            argv.extend((group[key]['path'], digest(group[key]['sha256'])))
    argv.append(plan['output'])
    return argv


def frozen_inputs(store, plan):
    need(tuple(plan['inputs']) == PROGRAMS, 'full frozen input roster')
    output = {}
    paths = []
    inodes = []
    for program in PROGRAMS:
        group = plan['inputs'][program]
        need(tuple(group) == INPUTS, 'exact four frozen inputs')
        output[program] = {}
        for key in INPUTS:
            pin = group[key]; path = absolute(pin['path']); paths.append(str(path))
            need(stat.S_IMODE(pin['stat'][2]) == 0o400, 'read-only frozen input copy')
            inodes.append(tuple(pin['stat'][:2]))
            output[program][key] = store.read(path, 65536 if key == 'startup' else MIB, pin)
    need(len(set(paths)) == len(set(inodes)) == 8, 'eight distinct frozen input copies')
    return output


def copy_inputs(sources, destination):
    """Owner's pre-attempt helper: real immutable copies, no command dispatch.

    Return eight observed copy pins for the prospective plan. The owner freezes
    that plan before dispatch, then closes the sole command with close_binding.
    """
    need(tuple(sources) == PROGRAMS, 'copy full program roster')
    destination = absolute(str(destination)); destination.mkdir(mode=0o700)
    store = Store(16*MIB)
    try:
        result = {}
        for program in PROGRAMS:
            need(tuple(sources[program]) == INPUTS, 'copy four source inputs')
            result[program] = {}
            for key in INPUTS:
                cap = 65536 if key == 'startup' else MIB
                raw = store.read(absolute(str(sources[program][key])), cap)
                path = destination / (program + '-' + key)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
                try:
                    with os.fdopen(fd, 'wb', closefd=False) as stream:
                        need(stream.write(raw) == len(raw), 'complete frozen input copy')
                        stream.flush(); os.fsync(stream.fileno())
                finally:
                    os.close(fd)
                result[program][key] = store.pin(path, cap)
        store.verify()
        return result
    finally:
        store.close()


def close_binding(plan_path, plan_sha256, producer_directory, output, history, destination):
    """Owner's post-attempt collector; records failure bytes too, never retries.

    This does not assert acceptance. The consumer independently reconstructs the
    expected request/command and checks the raw closure, all snapshots and output.
    """
    store = Store(512*MIB)
    try:
        raw = store.read(plan_path, MIB)
        need(sha(raw) == digest(plan_sha256), 'externally frozen prospective plan')
        plan = json_value(raw)
        need(plan['schema'] == 'LI2STARTUP-SAVED-PLAN-1' and plan['profile'] == PROFILE, 'startup prospective plan only')
        # Observe actual after-identities even when an input changed. The
        # consumer refuses inequality without erasing the raw failed attempt.
        need(tuple(plan['inputs']) == PROGRAMS, 'closed input roster')
        for group in plan['inputs'].values():
            need(tuple(group) == INPUTS, 'closed four-input roster')
            for key,pin in group.items():
                store.read(pin['path'],65536 if key=='startup' else MIB)
        need(str(producer_directory) == plan['producer_directory'] and str(output) == plan['output'], 'fixed attempt/output paths')
        files = {name: store.pin(Path(producer_directory) / name, 16*MIB if name.endswith(('.txt', '.stdout', '.stderr')) else MIB) for name in CONTROL}
        # A missing/partial output is recorded, not hidden by a successful-looking
        # marker. The consumer will retain the original raw exit/refusal label.
        publication = None
        if os.path.lexists(output):
            membership = store.members(output)
            member_pins = {name: store.pin(Path(output)/name, MIB if name == 'COMPLETE' else 16*MIB) for name in membership['members']}
            need(sum(p['bytes'] for name,p in member_pins.items() if name != 'COMPLETE') <= 256*MIB, 'outer publication byte cap')
            publication = dict(path=str(output), directory=membership, files=member_pins)
        retained = [store.pin(absolute(str(path)), 16*MIB) for path in history]
        store.verify()
        if publication is not None:
            need(store.members(output) == publication['directory'], 'publication changed at closure')
        value = dict(schema='LI2STARTUP-SAVED-BINDING-1', profile=PROFILE,
            plan=store.pin(plan_path,MIB), producer_controls=files, publication=publication,
            failure_history=retained, input_after={p:{k:store.pin(v['path'],65536 if k=='startup' else MIB) for k,v in group.items()} for p,group in plan['inputs'].items()})
        path = absolute(str(destination))
        with path.open('xb') as stream:
            raw = (json.dumps(value,indent=2) + '\n').encode('utf-8')
            need(stream.write(raw) == len(raw), 'complete binding write')
            stream.flush(); os.fsync(stream.fileno())
        return sha(raw)
    finally:
        store.close()
