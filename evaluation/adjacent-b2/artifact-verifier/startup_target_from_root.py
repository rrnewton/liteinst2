#!/usr/bin/env python3
"""Fixed target-query build from /. No candidate or bootstrap build/exec."""
import os
from pathlib import Path
import sys


def command(values, env):
    if len(values)!=3:
        raise ValueError('fixed target Cargo launcher arity')
    _,cargo,root=values
    root=Path(root); compiler=Path(env['RUSTC'])
    if not root.is_absolute() or root.resolve(strict=True)!=root or not compiler.is_absolute():
        raise ValueError('canonical exact root/compiler')
    if cargo!=str(compiler.with_name('cargo')) or env['CARGO_TARGET_DIR']!=str(root/'target'):
        raise ValueError('exact target toolchain/target directory')
    return [cargo,'build','--release','--locked','--offline','--manifest-path',str(root/'Cargo.toml'),
            '--package','liteinst2','--bin','elf-exec-oracle','--message-format=json']


def main():
    argv=command(sys.argv,os.environ)
    os.chdir('/')
    os.execve(argv[0],argv,dict(os.environ))


if __name__=='__main__':
    main()
