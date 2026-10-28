"""Actual parent normal exclusive-open FD, then the original Popen dup/exec route."""
import ctypes
import fcntl
import os
import platform
import stat
import struct

def need(ok, message):
    if not ok: raise ValueError(message)

def observe(fd):
    need(platform.machine() == 'x86_64' and ctypes.sizeof(ctypes.c_long) == 8 and
         type(fd) is int and fd > 2, 'actual x86-64 parent capture descriptor')
    s = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    need(stat.S_ISREG(s.st_mode) and not flags & os.O_PATH and
         flags & os.O_ACCMODE == os.O_WRONLY, 'normal writable regular capture open')
    raw = ctypes.create_string_buffer(256)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = libc.syscall(ctypes.c_long(332), ctypes.c_int(fd), ctypes.c_char_p(b''),
        ctypes.c_int(0x1000), ctypes.c_uint(0x1103), ctypes.byref(raw))
    need(result == 0, 'actual parent AT_EMPTY_PATH statx')
    b = raw.raw
    mask, = struct.unpack_from('<I', b)
    mode, = struct.unpack_from('<H', b, 28)
    inode, = struct.unpack_from('<Q', b, 32)
    major, minor, mount = struct.unpack_from('<IIQ', b, 136)
    need(mask & 0x1103 == 0x1103 and not mask & 0x4000 and mount > 0 and
         (mode, inode, major, minor) == (s.st_mode, s.st_ino, os.major(s.st_dev), os.minor(s.st_dev)),
         'ordinary mount ID and complete actual fstat/statx identity')
    return dict(parent_fd=fd, open_route='exclusive-normal-open/Popen-stdout-dup2-exec',
        identity=[s.st_dev,s.st_ino,mount,major,minor,mode,flags], statx_hex=b.hex())

def same(before, after):
    need(before['parent_fd'] == after['parent_fd'] and before['identity'] == after['identity'] and
         before['open_route'] == after['open_route'], 'same held parent capture descriptor before/after child')
    # The complete raw statx snapshots remain retained; size and timestamps may
    # change when the real child writes. They are not descriptor identity.
