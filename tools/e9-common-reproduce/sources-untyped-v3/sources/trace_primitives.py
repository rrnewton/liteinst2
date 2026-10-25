"""Literal ABI witness primitives; no trace or application runs at import."""
import sys
if sys.flags.optimize: raise SystemExit("optimized Python forbidden")
sys.dont_write_bytecode = True
import ctypes as C
import os
from pathlib import Path
import signal
import time
from bootstrap_validate import Invalid, PAGE, need, sha
from mapping_identity import backing_identity, require_mapping_identity
LIB=C.CDLL(None,use_errno=True)
LIB.ptrace.restype=C.c_long
LIB.ptrace.argtypes=[C.c_uint,C.c_uint,C.c_void_p,C.c_void_p]
R=1;W=2;X=4
REG_NAMES=('r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs')
class Registers(C.Structure):_fields_=[(n,C.c_ulonglong) for n in REG_NAMES]


def ptrace(op,pid,addr=0,data=0):
    C.set_errno(0)
    p=C.cast(data,C.c_void_p) if not isinstance(data,int) else C.c_void_p(data)
    out=LIB.ptrace(op,pid,C.c_void_p(addr),p)
    if out==-1 and C.get_errno():raise OSError(C.get_errno(),'ptrace')
    return out


def registers(pid):
    r=Registers();ptrace(12,pid,data=C.byref(r));return r


def readmem(pid,address,size):
    need(0<size<=16*PAGE and address>0,'bounded memory read')
    fd=os.open(f'/proc/{pid}/mem',os.O_RDONLY)
    try:b=os.pread(fd,size,address)
    finally:os.close(fd)
    need(len(b)==size,'complete memory read');return b


def cstring(pid,address,limit=4096):
    # Read one page fragment at a time; never cross into an unowned mapping
    # merely to find a terminator. These strings originate in the exact loader.
    out=b''
    while len(out)<limit:
        n=min(limit-len(out),PAGE-(address+len(out))%PAGE)
        b=readmem(pid,address+len(out),n)
        if b'\0' in b:return (out+b.split(b'\0',1)[0]).decode('ascii')
        out+=b
    raise Invalid('unterminated syscall path')


def file_fd_identity(pid,fd,path,blob):
    root=Path(f'/proc/{pid}')
    fp=root/'fd'/str(fd);st=fp.stat();link=os.readlink(fp)
    fi=(root/'fdinfo'/str(fd)).read_text()
    mounts=(root/'mountinfo').read_text().splitlines()
    ids=[x.split(':',1)[1].strip() for x in fi.splitlines() if x.startswith('mnt_id:')]
    need(len(ids)==1,'one fd mount ID')
    selected=[x for x in mounts if x.split()[0]==ids[0]]
    need(len(selected)==1,'one exact fd mount record')
    record=dict(fd=fd,stat_dev=st.st_dev,stat_ino=st.st_ino,stat_size=st.st_size,sha256=sha(blob))
    local=Path(path).stat();need((st.st_dev,st.st_ino,st.st_size)==(local.st_dev,local.st_ino,len(blob)),'live fd file identity')
    backing=backing_identity(record,fi,selected[0]+'\n',link,path,local.st_dev,local.st_ino,len(blob),sha(blob))
    return dict(record=record,fdinfo=fi,mountinfo=selected[0]+'\n',path=link,backing=list(backing))


def map_rows(pid):
    raw=Path(f'/proc/{pid}/maps').read_text();rows=[]
    for line in raw.splitlines():
        f=line.split(maxsplit=5);need(len(f)>=5,'maps field count')
        a,b=[int(v,16) for v in f[0].split('-')]
        major,minor=[int(v,16) for v in f[3].split(':')]
        rows.append(dict(lo=a,hi=b,perms=f[1],offset=int(f[2],16),major=major,minor=minor,inode=int(f[4]),path=f[5] if len(f)==6 else ''))
    return raw,rows


def authenticate_page(pid,address,offset,prot,path,blob,identity):
    raw,rows=map_rows(pid);owners=[r for r in rows if r['lo']<=address and address+PAGE<=r['hi']]
    need(len(owners)==1,'full page has one VMA')
    m=owners[0];need(m['perms']=={R:'r--p',R|W:'rw-p',R|X:'r-xp'}[prot],'exact file protection')
    need(m['offset']+address-m['lo']==offset and m['path']==path,'exact file offset/path')
    require_mapping_identity(tuple(identity['backing']),m['major'],m['minor'],m['inode'])
    expected=blob[offset:offset+PAGE].ljust(PAGE,b'\0')
    actual=readmem(pid,address,PAGE);need(actual==expected,'complete mapped file page')
    return dict(address=address,offset=offset,sha256=sha(actual),bytes_hex=actual.hex(),vma=m)


def wait_owned(pid,deadline):
    while time.monotonic()<deadline:
        got,status=os.waitpid(pid,os.WNOHANG)
        if got:return status
        time.sleep(0.0001)
    raise TimeoutError('15-second trace deadline')


def stopped(status,sig):need(os.WIFSTOPPED(status) and os.WSTOPSIG(status)==sig,'exact ptrace stop')

