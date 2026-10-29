#!/usr/bin/env python3
"""Fixed explicit whole-policy scalar campaign; no native-state or timing credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SHARED = ROOT / 'evaluation/ordinary-leaf-set-session/reproduce.py'


def authenticate(a):
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    assert HERE == ROOT / 'evaluation/ordinary-leaf-set-whole-session'
    for path in (ROOT, a.toolchain, a.user_home, a.cargo_home):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home),
               PATH=str(a.toolchain / 'bin') + ':/usr/bin:/bin', LC_ALL='C',
               PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    def git(*args):
        data = subprocess.check_output(['/usr/bin/git', '-C', ROOT, *args], env=env, timeout=15)
        assert len(data) <= 32 * 1048576
        return data
    assert git('rev-parse', '--show-toplevel').decode().strip() == str(ROOT)
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    paths = tuple(HERE / name for name in (
        'reproduce.py', 'produce.py', 'profile.py', 'catalog.py', 'profile_controls.py', 'README.md')) + tuple(
        SHARED.with_name(name) for name in ('reproduce.py', 'produce.py', 'catalog.py', 'output.py'))
    pins = {}
    for path in paths:
        assert path.resolve(strict=True) == path and not path.is_symlink() and path.is_file()
        assert path.stat().st_size <= 1048576
        data = path.read_bytes()
        assert data == git('show', a.revision + ':' + str(path.relative_to(ROOT)))
        pins[str(path)] = hashlib.sha256(data).hexdigest()
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    return pins


def load(name, path, pins):
    assert path.resolve(strict=True) == path
    assert hashlib.sha256(path.read_bytes()).hexdigest() == pins[str(path)]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    started = time.monotonic()  # Includes bootstrap; the shared runner must not reset it.
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True); ap.add_argument('--reservation-tag', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args()
    pins = authenticate(a)
    profile = load('_leaf_whole_profile', HERE / 'profile.py', pins)
    binding = profile.whole_binding()
    binding.check_sources(ROOT, pins)
    shared = load('_leaf_whole_shared_runner', SHARED, pins)
    return shared._main(started, binding=binding)


if __name__ == '__main__':
    raise SystemExit(main())
