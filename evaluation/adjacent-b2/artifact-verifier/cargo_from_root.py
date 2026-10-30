#!/usr/bin/env python3
"""Fixed verifier build launcher: explicit toolchain, manifest and Cargo cwd."""
import os
from pathlib import Path
import sys


def command(root, env, cargo, manifest):
    assert not sys.flags.optimize, 'assertions required'
    root = root.resolve(strict=True)
    expected = root / 'evaluation/adjacent-b2/artifact-verifier/Cargo.toml'
    compiler = Path(env['RUSTC'])
    assert compiler.is_absolute() and compiler.name == 'rustc'
    assert cargo == str(compiler.with_name('cargo')) and manifest == str(expected)
    assert Path(cargo).is_absolute() and expected.is_file()
    assert env['CARGO_TARGET_DIR'] == str(root / 'target')
    assert Path(env['CARGO_HOME']).is_absolute()
    return [cargo, 'build', '--release', '--locked', '--offline', '--manifest-path',
            manifest, '--bin', 'adjacent-b2-artifact-verifier', '--message-format=json']


def main():
    assert len(sys.argv) == 3, 'fixed Cargo and manifest arguments'
    root = Path(__file__).resolve().parents[3]
    argv = command(root, os.environ, *sys.argv[1:])
    os.chdir('/')
    os.execve(argv[0], argv, dict(os.environ))


if __name__ == '__main__':
    main()
