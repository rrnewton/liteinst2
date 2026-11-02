#!/usr/bin/env python3
"""Explicit ABI5 exec path; ordinary carrier creation and ABI2 remain unchanged."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
sys.dont_write_bytecode=True
from carrier import FOOT, META, PH, MAX_FILE


def counter_descriptor(counter_fd, counter_nonce, parent):
    if (type(counter_fd) is not int or counter_fd <= 2 or type(counter_nonce) is not int or
            not 0 < counter_nonce < 1 << 64 or type(parent) is not int or parent<=0):
        raise ValueError("single-process explicit counter descriptor/nonce")
    cs = os.fstat(counter_fd)
    ch = os.pread(counter_fd, 4096, 0)
    if (not stat.S_ISREG(cs.st_mode) or cs.st_mode & 0o7777 != 0o600 or cs.st_nlink != 0 or
            cs.st_size != 4096 or not os.get_inheritable(counter_fd) or
            fcntl.fcntl(counter_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDWR or
            fcntl.fcntl(counter_fd, fcntl.F_GET_SEALS) != 6 or len(ch) != 4096 or
            struct.unpack_from('<8Q', ch) != (0x31434f554e544750, 5, 1696, 4096, counter_nonce,
                                            parent, cs.st_dev, cs.st_ino) or any(ch[64:])):
        raise ValueError("exact initial diagnostic memfd identity/seals/header")
    return dict(version=5,bytes=4096,logical_bytes=1696,nonce=counter_nonce,parent=parent,
                device=cs.st_dev,inode=cs.st_ino,initial_seals=6,child_fd=counter_fd)

def _execute_loader(carrier, original, roots, directory, argv, fork_fds=None, child_failure=0, disable_rseq=False, provider_policy=None, *, late_sonames=(), counter_fd=None, counter_nonce=None, descriptor, environment_prefix, identity_name):
    # This separate command intentionally supplies a private namespace and a
    # closed environment. The original fixture's make/exec path is unchanged.
    if provider_policy not in (None, "mask-random-v1", "deterministic-builtins-v1"):
        raise ValueError("unknown selected provider policy")
    if (counter_fd is None) != (counter_nonce is None):
        raise ValueError("both explicit counter descriptor and nonce required")
    if counter_fd is not None:
        if fork_fds is not None:
            raise ValueError("counter carrier forbids fork profile")
        descriptor(counter_fd, counter_nonce, os.getppid())
    if (counter_fd is None or counter_nonce is None or fork_fds is not None or child_failure or
            disable_rseq or provider_policy is not None or late_sonames):
        raise ValueError("ABI5 requires one default-rseq release process and one explicit counter channel")
    counter_identity=descriptor(counter_fd,counter_nonce,os.getppid())
    import namespace
    with carrier.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    if not FOOT.size + META.size <= len(data) <= MAX_FILE:
        raise ValueError("loader carrier size")
    magic, offset, size = FOOT.unpack_from(data, len(data) - FOOT.size)
    if magic != b"LI2END01" or offset + size != len(data) - FOOT.size or size < META.size:
        raise ValueError("loader carrier footer")
    meta = META.unpack_from(data, offset)
    if meta[0] != b"LI2BOOT1" or meta[1] != 1 or meta[9] != 0 or not 1 <= meta[4] <= 32:
        raise ValueError("loader carrier metadata")
    if size != META.size + meta[4] * PH.size + meta[6]:
        raise ValueError("loader carrier metadata extent")
    fds, directory = namespace.prepare(original, roots, directory, meta[10], meta[11], late_sonames=late_sonames)
    fd = None
    try:
        fd = namespace.sealed_bytes("li2-private-loader-carrier", data, False)
        argv = argv[1:] if argv[:1] == ["--"] else argv
        argv = argv or [str(original)]
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
               "LD_LIBRARY_PATH": str(directory), "LD_BIND_NOW": "1",
               "LI2_DEPENDENCY_FDS": ",".join(str(item) for item in fds)}
        if counter_fd is not None:
            if counter_fd in fds or counter_fd == fd:
                raise ValueError("counter descriptor is separate from carrier/dependencies")
            env[environment_prefix+"_FD"] = str(counter_fd)
            env[environment_prefix+"_NONCE"] = str(counter_nonce)
        carrier_identity=os.fstat(fd)
        for item in (*fds,fd):
            identity=os.fstat(item)
            if (identity.st_dev,identity.st_ino)==(counter_identity['device'],counter_identity['inode']):
                raise ValueError("ABI5 backing aliases actual carrier or dependency")
        carrier_record=dict(fd=fd,device=carrier_identity.st_dev,inode=carrier_identity.st_ino,
                            seals=fcntl.fcntl(fd,fcntl.F_GET_SEALS))
        if carrier_record['seals']!=namespace.SEALS:
            raise ValueError("exact sealed carrier identity")
        if provider_policy is not None:
            env["LI2_SELECTED_PROVIDER"] = provider_policy
        if disable_rseq:
            # Explicit named workload only; never inherit arbitrary caller tunables.
            env["GLIBC_TUNABLES"] = "glibc.pthread.rseq=0"
        if fork_fds is not None:
            if len(fork_fds) != 2 or fork_fds[0] == fork_fds[1] or any(item <= 2 for item in fork_fds):
                raise ValueError("distinct fork report descriptors")
            for item in fork_fds:
                if not stat.S_ISFIFO(os.fstat(item).st_mode):
                    raise ValueError("fork report descriptor is not a pipe")
            env["LI2_RAW_FORK"] = "1"
            env["LI2_FORK_REPORT_FDS"] = ",".join(str(item) for item in fork_fds)
            if child_failure:
                if child_failure not in (1, 2, 3, 4):
                    raise ValueError("child failure step")
                env["LI2_FORK_CHILD_FAILURE"] = str(child_failure)
        # Preparation is reproducible and retained even if exec fails. This is
        # not an execution receipt and cannot claim the linker used these files.
        (directory / "launch.json").write_text(json.dumps({
            "schema_version": 1, "scope": "first_entry_loader_candidate", "status": "prepared_not_executed",
            "carrier_sha256": hashlib.sha256(data).hexdigest(), "carrier_size": len(data),
            "argv": argv, "environment": env, "dependency_fds": fds,
            identity_name: counter_identity, "carrier_fd": carrier_record,
        }, indent=2, sort_keys=True) + "\n")
        os.execve(fd, argv, env)
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(fds):
            os.close(item)


def _main(execute):
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='mode',required=True)
    loader=sub.add_parser('exec-loader')
    loader.add_argument('--library-root',action='append',type=Path,required=True)
    loader.add_argument('--namespace',type=Path,required=True)
    loader.add_argument('--counter-fd',type=int,required=True)
    loader.add_argument('--counter-nonce',type=int,required=True)
    loader.add_argument('carrier',type=Path)
    loader.add_argument('original',type=Path)
    loader.add_argument('argv',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    execute(args.carrier,args.original,args.library_root,args.namespace,args.argv,
                   counter_fd=args.counter_fd,counter_nonce=args.counter_nonce)


def execute_loader(carrier, original, roots, directory, argv, fork_fds=None, child_failure=0, disable_rseq=False, provider_policy=None, *, late_sonames=(), counter_fd=None, counter_nonce=None):
    return _execute_loader(carrier,original,roots,directory,argv,fork_fds,child_failure,disable_rseq,provider_policy,
        late_sonames=late_sonames,counter_fd=counter_fd,counter_nonce=counter_nonce,
        descriptor=counter_descriptor,environment_prefix="LI2_LOOP_RO_REASON",identity_name="loop_ro_reason_counter")

def main():
    _main(execute_loader)


if __name__=='__main__':main()
