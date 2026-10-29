#!/usr/bin/env python3
"""Freeze a source-only native protocol. Never launch or accept a qualification."""
import sys
if sys.flags.optimize or not sys.flags.isolated:
    raise SystemExit('use Python -I -B with assertions enabled')
sys.dont_write_bytecode = True
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import types

MIB = 1048576
PUBLIC = 'evaluation/ordinary-call-pair-native/'
LAUNCHER_SHA = '5665c1dd0b98ff0884fd3132ed807b33e814463d226158f532ea4605ea90b7e5'
OWNER = 'evaluation/admission/processes.py'
OWNER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
ALLOCATOR_REVISION = 'd0c2867be75b495eb64239e664c6306af9747783'
ALLOCATOR_MAP_SHA = '5f47ef0ee344f8e28bdb200e2ae21bab2c4a276d2746d73c204410a2a798d212'
PROFILE = 'call-pair-original-native'
ALLOCATOR_SOURCES = {'py/dagrun/__init__.py': '6fa42195184b1ed623c4e245f9415e474faf17e8611539b4d04ffc3231ac2493', 'py/dagrun/__main__.py': 'efd0c8b9a289ab0ebc702b65d048e7fce178dd031301cf4430810a587c85adc7', 'py/dagrun/admission.py': 'c0805887a3f31205b8f38e02148c4b455fbb62ef256f58e70b51ee3e34eb1a52', 'py/dagrun/ambient.py': '288795b6a2e403fb50fe2a408019c34e60622d78e2d4a1678adda30a89fad7c1', 'py/dagrun/analyze.py': '04bd070ebe9eb693f56f878f1fb9a8d3754aba69d8b7f0fd58640374053c032a', 'py/dagrun/attribution.py': 'ccc64b3acdfcc6b0aef1ec8b05990d62e1199716cdac8596e8ee1397994cae90', 'py/dagrun/capabilities.py': '9680774e6e370a1eed85f691bfd8cf1431155e08f11a2bc94d1012df0edfaece', 'py/dagrun/cgroup.py': '916aa030a03abf4a1709afbc46196a4147577471ef1a97d39501603e63d69d76', 'py/dagrun/cli.py': 'e5a255167f4192fcb8c225ed7bb6602f7233eca09d160be196282da474b992d8', 'py/dagrun/cpuset_allocator.py': '61715797fca6a3c3ba17668eb5f3a820ac0b42b4bf092b6fb815b58c1ed800da', 'py/dagrun/envcheck.py': 'cdd97ad08d50cea716f6c89b0725fa90b3f0daf8ff4cf08693ff74a397c0c495', 'py/dagrun/estimates.py': 'ff9879ec94effe5dbda85c3b5f9eea16951f27b69e60c4a51919e5b973f14203', 'py/dagrun/gh_resolve.py': '03c6dc80d902c51ff163b629b0b44106d2ada6d772cd1c618ecc25923b04a438', 'py/dagrun/io.py': 'd1ef3241ffa133948e51446be58be046843e6d627f3c12f7d6acaa89327e82d2', 'py/dagrun/memory_feedback.py': '31d9126ffbb96e8ea7e7295ef17ff4e3098fda317e0d3a784952f0ca56693939', 'py/dagrun/model.py': 'a4aea0dc8391eedc176cfd1e5d60920984445828a0879ba0093cd1526701bf2c', 'py/dagrun/perflog.py': 'ab48263730e226e11f377671d4c2ebc91a88aac222f840c82632f7dae1de13ac', 'py/dagrun/proccpu.py': '23d03ba34acd9020eef23b399dcef04a3ccee93562583165d7e9a421b43d9a62', 'py/dagrun/procstat.py': 'f4a05f8d37d90a37eb3f4ec37206791742df7c61b2f20608c38461f9e6002a6f', 'py/dagrun/profile_capture.py': '095ced03d5d035e4729ac7eb262cbcb13d4d352d4b1fcf57b767f86ea57c08cc', 'py/dagrun/profile_enrich.py': '8f2a073a1a32de112aa0486debceb75c2ce038c0594810c3fafe963fd20a01b8', 'py/dagrun/profile_report.py': 'a8da24d411c42387ef784d26ba8ed5b48d00b991bf4dbb22299c32a1973a51dc', 'py/dagrun/protocols.py': '112cc489c3ce34db323aaf8c2cb5e7696bd45b71e9e1571a15d0ab76f1b7dfa5', 'py/dagrun/reservation.py': 'df55f994921fcca2250dc0b19646ede2ecc90875de8bfc6bca977310546dcd88', 'py/dagrun/scheduler.py': '8b3270b45a81f11961e3b3fec5bcfcc1e1adddb594ffa66fc1a90e42363d8855', 'py/dagrun/sizing.py': '8ff630b5eeaae9a2a0820b73eaaa4726d734caea4661c1798608e2dfeb7d6866', 'py/dagrun/summary.py': 'eb44f99d0690f8c2f4d9aa9a0a6a82f111f614e9648d18d874524097b9b00f46', 'py/dagrun/sweep.py': 'e8d2c38e3a1814e5b372813641916fcab1926bdf21d6812979dbdc2fb0ec9aee', 'py/dagrun/sync.py': 'f03feabf3ee2de3d5ed877f9e6481bd41d41cc049f9cbc8818defd48a1705c1b', 'py/dagrun/teardown.py': '7fd0bbcbc5758e0968441460c2c73be880043339e88d418a612772adad945909', 'py/dagrun/viz.py': '03dce1fb1bc44f9dcbe5dc86803512475b267eb2f236103ff5edf34cb84e498a'}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')


def pin(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def read(path, cap):
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap
        data = stream.read(cap+1)
        assert len(data) == before.st_size
        assert identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat())
        return data


def existing(value, directory=True):
    assert type(value) is str and value and '\0' not in value and '\n' not in value and '\r' not in value
    path = Path(value)
    assert path.is_absolute() and str(path) == value and '..' not in path.parts
    assert path.resolve(strict=True) == path
    if directory:
        assert path.is_dir()
    return path


def session_values(xdg, bus):
    values = {}
    if xdg is not None:
        values['XDG_RUNTIME_DIR'] = str(existing(xdg))
    if bus is not None:
        # One explicitly supplied filesystem Unix socket; no inherited address,
        # abstract transport, alternate address, UID or bus/ledger inference.
        match = re.fullmatch(r'unix:path=([^,;\x00\r\n]+)(?:,guid=([0-9a-f]{32}))?', bus)
        assert match
        socket = existing(match[1], directory=False)
        assert stat.S_ISSOCK(socket.stat().st_mode)
        values['DBUS_SESSION_BUS_ADDRESS'] = bus
    return values


def absent(paths):
    assert all(not os.path.lexists(p) for p in paths)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    for name in ('toolchain', 'cargo-home', 'user-home', 'allocator-root'):
        ap.add_argument('--'+name, required=True)
    ap.add_argument('--xdg-runtime-dir')
    ap.add_argument('--dbus-session-bus-address')
    a = ap.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    script = Path(__file__).absolute()
    assert script.resolve(strict=True) == script
    root = script.parents[2]
    assert script == root/PUBLIC/'freeze.py' and root.resolve(strict=True) == root
    paths = {name: existing(getattr(a, name)) for name in ('toolchain', 'cargo_home', 'user_home', 'allocator_root')}
    session_env = session_values(a.xdg_runtime_dir, a.dbus_session_bus_address)
    env = dict(HOME=str(paths['user_home']), PATH=str(paths['toolchain'])+'/bin:/usr/bin:/bin',
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1',
        LANG='C.UTF-8', LC_ALL='C.UTF-8', **session_env)
    first = {}
    def remember(path, data):
        key = str(path); value = pin(data)
        if key in first:
            assert first[key] == value
        else:
            first[key] = value
        return first[key]
    def held(path, cap):
        assert path.resolve(strict=True) == path
        data = read(path, cap); remember(path, data); return data
    git_path = Path('/usr/bin/git').resolve(strict=True)
    assert os.access(git_path, os.X_OK)
    held(git_path, 512*MIB)
    def git(directory, *args):
        # Fixed argv and explicit environment even before any project import.
        assert pin(read(git_path, 512*MIB)) == first[str(git_path)]
        value = subprocess.check_output([str(git_path), '-C', str(directory), *args], env=env, timeout=15)
        assert len(value) <= 32*MIB
        return value
    def clean():
        assert git(root, 'rev-parse', '--show-toplevel').decode().strip() == str(root)
        assert git(root, 'rev-parse', 'HEAD').decode().strip() == a.revision
        assert git(root, 'status', '--porcelain', '--untracked-files=no') == b''
    clean()
    bootstrap = {}
    for name in (PUBLIC+'freeze.py', PUBLIC+'launch.py', PUBLIC+'ROOT_PROTOCOL.md', OWNER):
        data = held(root/name, MIB)
        assert data == git(root, 'show', a.revision+':'+name)
        bootstrap[name] = data
    assert pin(bootstrap[PUBLIC+'launch.py'])['sha256'] == LAUNCHER_SHA
    assert pin(bootstrap[OWNER])['sha256'] == OWNER_SHA
    assert pin(canonical(ALLOCATOR_SOURCES))['sha256'] == ALLOCATOR_MAP_SHA
    assert len(ALLOCATOR_SOURCES) == 31
    # Execute exactly the authenticated held owner bytes. Its main is not run;
    # top-level imports are standard library only, with no process-owner import.
    launcher = types.ModuleType('_public_call_pair_launcher')
    launcher.__file__ = str(root/PUBLIC/'launch.py')
    exec(compile(bootstrap[PUBLIC+'launch.py'], launcher.__file__, 'exec'), launcher.__dict__)
    assert launcher.OWNER_SHA == OWNER_SHA and launcher.ALLOCATOR_MAP_SHA == ALLOCATOR_MAP_SHA
    tools = {}
    for name in launcher.TOOLS:
        path = (Path(sys.executable) if name == 'python' else paths['toolchain']/'bin'/name
                if name in ('cargo', 'rustc', 'rustdoc') else Path('/usr/bin')/name).resolve(strict=True)
        assert os.access(path, os.X_OK)
        tools[name] = dict(path=str(path), **pin(held(path, 512*MIB)))
    assert len(tools) == 13 and tools['git']['path'] == str(git_path)
    selectors = ('src', 'crates', 'tests/support', 'tools/rapid-profiler', 'Cargo.toml', 'Cargo.lock',
        'README.md', 'build.rs', '.cargo', ':(glob)**/Cargo.toml', *launcher.COMMON, *launcher.EXTRA[PROFILE])
    def source_names():
        data = git(root, 'ls-files', '-z', '--', *selectors)
        assert data.endswith(b'\0')
        names = data[:-1].decode().split('\0')
        assert all(names) and len(names) == len(set(names))
        assert set(launcher.COMMON+launcher.EXTRA[PROFILE]) <= set(names)
        for name in names:
            q = Path(name)
            assert not q.is_absolute() and str(q) == name and '..' not in q.parts
        return sorted(names)
    sources = {}
    for name in source_names():
        data = held(root/name, 512*MIB)
        assert data == git(root, 'show', a.revision+':'+name)
        sources[name] = pin(data)
    allocator = paths['allocator_root']
    def allocator_check():
        assert git(allocator, 'rev-parse', 'HEAD').decode().strip() == ALLOCATOR_REVISION
        assert git(allocator, 'status', '--porcelain', '--untracked-files=no') == b''
        actual = {str(q.relative_to(allocator)) for q in (allocator/'py/dagrun').rglob('*.py')}
        assert actual == set(ALLOCATOR_SOURCES)
        for name, digest in ALLOCATOR_SOURCES.items():
            data = held(allocator/name, MIB)
            assert pin(data)['sha256'] == digest
            assert data == git(allocator, 'show', ALLOCATOR_REVISION+':'+name)
    allocator_check()
    # Create only fixed common parent directories. The per-revision attempt is
    # always exclusive; a failed freeze or qualification must not be reset.
    for parent in (root/'ignored', root/'ignored/a5', root/'target', root/'target/evaluation'):
        if not os.path.lexists(parent):
            parent.mkdir(mode=0o700)
        assert parent.resolve(strict=True) == parent and parent.is_dir()
    destination = root/'ignored/a5'/('call-pair-public-'+a.revision)
    raw = destination/('call-pair-native-'+a.revision)
    capture = destination/'owner'
    logs = root/'target/evaluation'/('call-pair-owner-'+a.revision)
    inner_logs = root/'target/evaluation'/raw.name
    absent((destination, raw, capture, logs, inner_logs))
    protocol = dict(CLOSED=True, execution='UNRUN', version=1, profile=PROFILE,
        qualification=dict(launcher.PROFILES[PROFILE]), revision=a.revision,
        tag='call-pair-original-native-'+a.revision,
        paths=dict(root=str(root), raw=str(raw), capture=str(capture), log_dir=str(logs),
                   **{key:str(value) for key,value in paths.items()}),
        launcher=dict(path=launcher.__file__, **pin(bootstrap[PUBLIC+'launch.py'])),
        source_pins=sources, tools=tools, allocator_revision=ALLOCATOR_REVISION,
        allocator_sources=dict(ALLOCATOR_SOURCES), session_env=session_env,
        limits=dict(outer_seconds=1200, outer_log_bytes=8*MIB, evidence_bytes=2*1024**3,
                    build_reserve_bytes=1024**3, wrapper_bytes=24*MIB, slot_limit_bytes=20000000000))
    launcher.validate_protocol(protocol)
    argv, selected_env = launcher.command_environment(protocol)
    assert selected_env == env
    resolved = launcher.execution_paths(protocol, selected_env)
    destination.mkdir(mode=0o700)
    def save(name, value, cap):
        data = canonical(value); assert len(data) <= cap
        path = destination/name
        with path.open('xb') as stream: stream.write(data)
        remember(path, data)
        assert read(path, cap) == data
        return dict(path=str(path), **pin(data))
    save('freeze-attempt.json', dict(status='FAILED_UNLESS_SOURCE_FROZEN_MARKER', execution='UNRUN',
        revision=a.revision, attempts=1, retries=0), MIB)
    try:
        # Existing receipt controls intentionally use this exact compatibility
        # path. Never overwrite or normalize a different owner at that path.
        compat_dir = root/'ignored/a5/normal-call-pair-launch-source-v1'
        if not os.path.lexists(compat_dir): compat_dir.mkdir(mode=0o700)
        assert compat_dir.resolve(strict=True) == compat_dir and compat_dir.is_dir()
        compat = compat_dir/'launch.py'
        if not os.path.lexists(compat):
            with compat.open('xb') as stream: stream.write(bootstrap[PUBLIC+'launch.py'])
        assert held(compat, MIB) == bootstrap[PUBLIC+'launch.py']
        protocol_pin = save('protocol.json', protocol, 2*MIB)
        # All comparisons retain the first pin; final observations never refresh it.
        clean()
        assert source_names() == sorted(sources)
        for name, expected in sources.items():
            data = held(root/name, 512*MIB)
            assert pin(data) == expected and data == git(root, 'show', a.revision+':'+name)
        for name, original in bootstrap.items():
            assert held(root/name, MIB) == original == git(root, 'show', a.revision+':'+name)
        for name, expected in tools.items():
            path = Path(expected['path'])
            assert os.access(path, os.X_OK) and dict(path=str(path), **pin(held(path, 512*MIB))) == expected
            selected = (Path(sys.executable) if name == 'python' else paths['toolchain']/'bin'/name
                        if name in ('cargo', 'rustc', 'rustdoc') else Path('/usr/bin')/name)
            assert selected.resolve(strict=True) == path
        allocator_check()
        assert session_values(a.xdg_runtime_dir, a.dbus_session_bus_address) == session_env
        assert launcher.execution_paths(protocol, selected_env) == resolved
        launcher.validate_protocol(protocol)
        absent((raw, capture, logs, inner_logs))
        for name, expected in first.items():
            path = Path(name); assert path.resolve(strict=True) == path
            assert pin(read(path, max(MIB, expected['bytes']))) == expected
        clean()
        marker = dict(status='SOURCE_FROZEN_UNRUN', execution='UNRUN', revision=a.revision,
            profile=PROFILE, protocol=protocol_pin, launcher=protocol['launcher'],
            bootstrap={name:pin(data) for name,data in bootstrap.items()},
            compatibility_launcher=dict(path=str(compat), **first[str(compat)]),
            source_count=len(sources), tools=13, allocator_sources=31,
            allocator_execution_paths=resolved, command=argv, environment=selected_env,
            first_pins=first.copy(), qualification_attempts=0,
            scope='Source freeze only. No reservation, process closure, native acceptance or runtime result.')
        marker_pin = save('source-frozen.json', marker, 2*MIB)
    except BaseException as error:
        save('freeze-failure.json', dict(status='FAILED', execution='UNRUN', error=type(error).__name__,
            revision=a.revision, first_pins=first.copy()), 2*MIB)
        raise
    print(json.dumps(dict(status='SOURCE_FROZEN_UNRUN', protocol=protocol_pin, marker=marker_pin)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
