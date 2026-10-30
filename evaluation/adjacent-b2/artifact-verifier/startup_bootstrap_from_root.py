#!/usr/bin/env python3
"""Fixed standalone per-catalog DSO build; never invoke a candidate or planner."""
import os
from pathlib import Path
import sys


def command(argv, env):
    if len(argv)!=3:
        raise ValueError('fixed bootstrap Cargo launcher arity')
    _,cargo,root=argv
    root=Path(root);compiler=Path(env['RUSTC']);catalog=Path(env['LITEINST_BOOTSTRAP_CATALOG'])
    if (not root.is_absolute() or root.resolve(strict=True)!=root or
            not compiler.is_absolute() or cargo!=str(compiler.with_name('cargo')) or
            env['CARGO_TARGET_DIR']!=str(root/'target') or not catalog.is_absolute() or
            catalog.resolve(strict=True)!=catalog or not catalog.is_relative_to(root/'ignored')):
        raise ValueError('canonical exact root/compiler/target/catalog')
    return [cargo,'build','--release','--locked','--offline','--manifest-path',
        str(root/'crates/liteinst-bootstrap/Cargo.toml'),'--lib','--message-format=json']


def main():
    argv=command(sys.argv,os.environ)
    os.chdir('/')
    os.execve(argv[0],argv,dict(os.environ))


if __name__=='__main__':
    main()
