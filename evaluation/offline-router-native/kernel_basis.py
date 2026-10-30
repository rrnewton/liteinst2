"""Explicit unsafe live-kernel configuration basis; never inferred from errno.

The checked caller separately accepts the exact basis SHA. Its kernel semantics
are an unsafe premise, not a compiler/source-to-binary proof. Existing profiles
do not import or use this new mode. No command or native child is dispatched here.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import zlib

PROFILE = 'linux-x86_64-live-config-user-shstk-disabled-v1'
SCHEMA = 'LI2-KERNEL-SHSTK-CONFIG-OFF-1'
GZIP_CAP = 65536
DECODED_CAP = 524288
HEADER_CAP = 262144
PROC_MAGIC = 0x9fa0
FILES = ('config_gzip', 'shstk_header', 'processor_header', 'prctl_header')
OBLIGATION = (
    'I accept the actual running Linux x86-64 kernel and its live /proc/config.gz as trusted kernel evidence. '
    'The pinned release and complete configuration truthfully describe this running kernel: '
    'CONFIG_X86_USER_SHADOW_STACK is disabled and CONFIG_X86_DISABLED_FEATURE_USER_SHSTK is enabled. '
    'Under this exact kernel configuration there is no user SHSTK or WRSS enable or lock path, including '
    'legacy or vendor CET interfaces, across fork, exec and the complete child lifetime. The retained '
    'kernel headers document this accepted basis but are not a compiler or source-to-running-binary proof. '
    'No actor may replace the running kernel, procfs view, basis files or observed configuration during '
    'admission through child cleanup. Missing proc fields or an EINVAL syscall result alone grant no authority. '
    'All original platform, signal, custody, first-instruction, exact-state, population and deadline obligations remain.'
)


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'exact kernel digest')
    return value


def decode(raw):
    need(type(raw) is bytes and len(raw) <= 1048576, 'bounded kernel basis record')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate kernel basis key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('nonfinite kernel basis')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def config_bytes(raw):
    """One complete bounded gzip member; concatenation and surplus are invalid."""
    need(type(raw) is bytes and 0 < len(raw) <= GZIP_CAP, 'bounded compressed kernel configuration')
    reader = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        decoded = reader.decompress(raw, DECODED_CAP + 1)
    except zlib.error as error:
        raise ValueError('invalid kernel gzip member') from error
    need(0 < len(decoded) <= DECODED_CAP and reader.eof and
         not reader.unused_data and not reader.unconsumed_tail, 'exact one whole bounded gzip member')
    need(decoded.endswith(b'\n') and all(byte in (9, 10) or 32 <= byte <= 126 for byte in decoded),
         'canonical ASCII kernel configuration')
    text = decoded.decode('ascii').splitlines()
    for key, expected in (
        ('CONFIG_X86_USER_SHADOW_STACK', '# CONFIG_X86_USER_SHADOW_STACK is not set'),
        ('CONFIG_X86_DISABLED_FEATURE_USER_SHSTK', 'CONFIG_X86_DISABLED_FEATURE_USER_SHSTK=y')):
        rows = [line for line in text if key in line]
        need(rows == [expected], 'exact unique disabled-user-SHSTK configuration')
    return decoded


def capsule(value):
    fields = {'profile', 'basis_sha256', 'release', 'config_gzip_bytes', 'config_gzip_sha256',
              'config_decoded_bytes', 'config_decoded_sha256'}
    need(type(value) is dict and set(value) == fields and value['profile'] == PROFILE,
         'exact named kernel capability capsule')
    release = value['release']
    need(type(release) is str and 1 <= len(release) <= 128 and
         all(33 <= ord(char) <= 126 for char in release), 'bounded exact kernel release')
    for key in ('basis_sha256', 'config_gzip_sha256', 'config_decoded_sha256'):
        digest(value[key])
    for key, cap in (('config_gzip_bytes', GZIP_CAP), ('config_decoded_bytes', DECODED_CAP)):
        need(type(value[key]) is int and 0 < value[key] <= cap, 'exact kernel byte length')
    return dict(value)


def inspect(raw, accepted_sha256, retain):
    """Inspect all FOUR frozen files; the caller owns their lifetime custody."""
    need(sha(raw) == digest(accepted_sha256), 'explicitly accepted kernel basis bytes')
    value = decode(raw)
    need(type(value) is dict and set(value) == {'schema', 'profile', 'platform', 'release', 'files', 'decoded', 'obligation'} and
         value['schema'] == SCHEMA and value['profile'] == PROFILE and
         value['platform'] == 'linux-x86_64' and value['obligation'] == OBLIGATION,
         'complete explicit unsafe kernel premise')
    need(type(value['files']) is dict and set(value['files']) == set(FILES), 'exact four bounded kernel files')
    pins = value['files']
    need(len({p['path'] for p in pins.values()}) == 4 and
         len({tuple(p['stat'][:2]) for p in pins.values()}) == 4, 'four distinct kernel evidence files')
    contents = {name: retain(pins[name], GZIP_CAP if name == 'config_gzip' else HEADER_CAP) for name in FILES}
    need(all(contents[name] for name in FILES), 'nonempty complete kernel evidence files')
    decoded = config_bytes(contents['config_gzip'])
    metadata = value['decoded']
    need(type(metadata) is dict and set(metadata) == {'bytes', 'sha256'} and
         type(metadata['bytes']) is int and metadata['bytes'] == len(decoded) and
         digest(metadata['sha256']) == sha(decoded), 'whole decoded kernel configuration join')
    result = capsule(dict(profile=PROFILE, basis_sha256=accepted_sha256, release=value['release'],
        config_gzip_bytes=len(contents['config_gzip']), config_gzip_sha256=sha(contents['config_gzip']),
        config_decoded_bytes=len(decoded), config_decoded_sha256=sha(decoded)))
    return result


def live_config():
    """The fixed procfs file, never a caller-selected substitute or a stat size."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    directory = os.open('/proc', flags | os.O_DIRECTORY)
    try:
        fd = os.open('config.gz', flags, dir_fd=directory)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode), 'actual proc configuration file')
            # x86-64 statfs starts with a native signed long filesystem type.
            libc = ctypes.CDLL(None, use_errno=True)
            buffer = ctypes.create_string_buffer(256)
            need(libc.fstatfs(ctypes.c_int(fd), ctypes.byref(buffer)) == 0 and
                 ctypes.c_long.from_buffer(buffer).value == PROC_MAGIC, 'actual procfs configuration owner')
            chunks = []
            count = 0
            while count <= GZIP_CAP:
                part = os.read(fd, min(65536, GZIP_CAP + 1 - count))
                if not part:
                    break
                chunks.append(part)
                count += len(part)
            need(0 < count <= GZIP_CAP, 'bounded live compressed kernel configuration')
            identity = lambda s: (s.st_dev, s.st_ino, s.st_mode)
            need(identity(before) == identity(os.fstat(fd)) ==
                 identity(os.stat('config.gz', dir_fd=directory, follow_symlinks=False)),
                 'stable live proc configuration identity')
            return b''.join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def check_live(expected):
    expected = capsule(expected)
    before = os.uname()
    need(before.sysname == 'Linux' and before.machine == 'x86_64' and
         before.release == expected['release'], 'same accepted live kernel/platform')
    raw = live_config()
    need(len(raw) == expected['config_gzip_bytes'] and sha(raw) == expected['config_gzip_sha256'],
         'same whole live compressed kernel configuration')
    decoded = config_bytes(raw)
    need(len(decoded) == expected['config_decoded_bytes'] and sha(decoded) == expected['config_decoded_sha256'],
         'same whole live decoded kernel configuration')
    after = os.uname()
    need((after.sysname, after.machine, after.release) == (before.sysname, before.machine, before.release),
         'live kernel identity remains fixed')


HEADER_PATHS = {
    'shstk_header': 'arch/x86/include/asm/shstk.h',
    'processor_header': 'arch/x86/include/asm/processor.h',
    'prctl_header': 'arch/x86/include/uapi/asm/prctl.h',
}


def file_bytes(path, cap):
    """Whole bounded ordinary evidence file, no symlink in any component."""
    path = Path(path)
    need(path.is_absolute() and str(path) == os.path.normpath(str(path)), 'canonical evidence path')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            stamp = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= cap, 'bounded nonempty whole evidence file')
            chunks = []; remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 65536)); need(chunk, 'short evidence read')
                chunks.append(chunk); remaining -= len(chunk)
            need(not os.read(fd, 1) and stamp(before) == stamp(os.fstat(fd)) ==
                 stamp(os.stat(path.name, dir_fd=directory, follow_symlinks=False)), 'stable whole evidence identity')
            raw = b''.join(chunks)
            return raw, dict(path=str(path), bytes=len(raw), sha256=sha(raw), stat=stamp(before))
        finally: os.close(fd)
    finally: os.close(directory)


def write_new(path, raw, cap):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        os.fchmod(fd, 0o400)
        with os.fdopen(fd, 'wb', closefd=False) as output:
            need(output.write(raw) == len(raw), 'whole capture write')
            output.flush(); os.fsync(output.fileno())
    finally: os.close(fd)
    actual, pin = file_bytes(path, cap)
    need(actual == raw, 'whole capture readback')
    return pin


def capture(args):
    """Capture a draft premise, not acceptance or a source-to-kernel proof."""
    root, headers, output = args.root, args.headers, args.output
    need(root.is_absolute() and root.resolve(strict=True) == root and
         Path(__file__).resolve(strict=True) == root/'evaluation/offline-router-native/kernel_basis.py',
         'actual tracked capture entrypoint')
    need(headers.is_absolute() and headers.resolve(strict=True) == headers and headers.name == args.release,
         'explicit matching-release installed header directory')
    need(output.is_absolute() and output.is_relative_to(root/'ignored') and
         output.parent.resolve(strict=True) == output.parent and not os.path.lexists(output), 'new private kernel basis directory')
    uname = os.uname()
    need(uname.sysname == 'Linux' and uname.machine == 'x86_64' and uname.release == args.release,
         'explicit release equals actual live kernel')
    raw = live_config(); decoded = config_bytes(raw)
    originals = {name: file_bytes(headers/relative, HEADER_CAP) for name, relative in HEADER_PATHS.items()}
    output.mkdir(mode=0o700)
    files = {'config_gzip': write_new(output/'config.gz', raw, GZIP_CAP)}
    for name, (contents, _) in originals.items():
        files[name] = write_new(output/(name+'.h'), contents, HEADER_CAP)
    value = dict(schema=SCHEMA, profile=PROFILE, platform='linux-x86_64', release=args.release,
        files=files, decoded=dict(bytes=len(decoded), sha256=sha(decoded)), obligation=OBLIGATION)
    data = (json.dumps(value, indent=2, sort_keys=True)+'\n').encode()
    def retain(pin, cap):
        contents, actual = file_bytes(pin['path'], cap)
        need(actual == pin, 'same captured evidence pin')
        return contents
    expected = inspect(data, sha(data), retain)
    check_live(expected)
    for name, original in originals.items():
        need(file_bytes(headers/HEADER_PATHS[name], HEADER_CAP) == original, 'matching header source identity remains fixed')
    for name in FILES: retain(files[name], GZIP_CAP if name == 'config_gzip' else HEADER_CAP)
    check_live(expected)
    record = write_new(output/'basis.json', data, 1048576)
    return dict(status='DRAFT_KERNEL_BASIS_REQUIRES_EXPLICIT_REVIEW', basis=record, evidence_files=4,
        execution_authorized=False, native_dispatches=0, qualification_complete=False, performance_eligible=False)


def main():
    import argparse
    import sys
    need(not sys.flags.optimize, 'assertions required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('mode', choices=('capture',))
    for name in ('root', 'headers', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--release', required=True)
    print(json.dumps(capture(parser.parse_args()), sort_keys=True))


if __name__ == '__main__': main()
