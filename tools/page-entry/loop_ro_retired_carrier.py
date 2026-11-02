#!/usr/bin/env python3
"""Strict ABI6 descriptor with shared source-owned namespace/exec custody."""
import fcntl,os,stat,struct
from loop_ro_reason_carrier import _execute_loader,_main

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
            struct.unpack_from('<8Q', ch) != (0x31434f554e544750, 6, 2016, 4096, counter_nonce,
                                            parent, cs.st_dev, cs.st_ino) or any(ch[64:])):
        raise ValueError("exact initial diagnostic memfd identity/seals/header")
    return dict(version=6,bytes=4096,logical_bytes=2016,nonce=counter_nonce,parent=parent,
                device=cs.st_dev,inode=cs.st_ino,initial_seals=6,child_fd=counter_fd)

def execute_loader(carrier,original,roots,directory,argv,fork_fds=None,child_failure=0,disable_rseq=False,provider_policy=None,*,late_sonames=(),counter_fd=None,counter_nonce=None):
    return _execute_loader(carrier,original,roots,directory,argv,fork_fds,child_failure,disable_rseq,provider_policy,
        late_sonames=late_sonames,counter_fd=counter_fd,counter_nonce=counter_nonce,
        descriptor=counter_descriptor,environment_prefix="LI2_LOOP_RO_RETIRED",identity_name="loop_ro_retired_counter")

if __name__=='__main__':_main(execute_loader)
