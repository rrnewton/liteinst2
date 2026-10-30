"""Closed Request wire schema. Sealing proves immutability, never authority."""
import fcntl
import hashlib
import os
import re

MAGIC=b'LI2-OBSERVER-REQUEST\0\x01'
MAGIC_V2=b'LI2-OBSERVER-REQUEST\0\x02'
KERNEL_PROFILE='linux-x86_64-live-config-user-shstk-disabled-v1'
CAP=260*1048576
PAGE_CAP=65536
SEALS=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE


def need(ok,why):
    if not ok:raise ValueError(why)


def keys(value,names):
    need(type(value) is dict and set(value)==set(names),'exact wire schema keys')


def uint(value,maximum):
    need(type(value) is int and 0<=value<=maximum,'wire integer type/bound')
    return value


def raw_hex(value,maximum):
    need(type(value) is str and len(value)%2==0 and len(value)<=2*maximum
         and re.fullmatch('[0-9a-f]*',value) is not None,'canonical bounded wire hex')
    return bytes.fromhex(value)


def encode(request):
    fields=('main','loader','bootstrap','dependencies','dataset','entry','entry_bytes',
            'completion_relative','completion_file_offset','xstate_bytes')
    extended=type(request) is dict and 'kernel_basis' in request
    keys(request,fields+(('kernel_basis',) if extended else ()))
    out=bytearray(MAGIC_V2 if extended else MAGIC);pages=0
    def put(raw):
        need(len(raw)<=CAP-len(out),'bounded wire bytes');out.extend(raw)
    def integer(value,width):put(uint(value,(1<<(8*width))-1).to_bytes(width,'little'))
    def pin(value):
        keys(value,('path','bytes','sha256','stat'))
        path=value['path']
        need(type(path) is str and 1<len(path)<=4095 and path.startswith('/')
             and all(33<=ord(c)<=126 for c in path)
             and all(p not in ('','.','..') for p in path.split('/')[1:]),'canonical wire pathname')
        raw=path.encode('ascii');integer(len(raw),4);put(raw)
        digest=raw_hex(value['sha256'],32);need(len(digest)==32,'full SHA256');put(digest)
        need(type(value['stat']) is list and len(value['stat'])==6,'full stat tuple')
        dev,ino,mode,size,mtime,ctime=value['stat']
        need(uint(value['bytes'],16*1048576)==size,'file bytes equal stat size')
        need(type(mode) is int and mode&0o170000==0o100000,'regular file pin')
        for item,width in ((dev,8),(ino,8),(mode,4),(size,8),(mtime,16),(ctime,16)):integer(item,width)
        need(mtime<1<<127 and ctime<1<<127,'signed timestamp range')
    def permissions(value):
        need(type(value) is str and re.fullmatch('[r-][w-][x-]p',value) is not None
             and value[1:3]!='wx','private non-WX permissions')
        put(value.encode('ascii'))
    def image(value):
        if value is None:integer(0,1)
        else:
            raw=raw_hex(value,4096);need(len(raw)==4096,'whole page comparator')
            integer(1,1);put(raw)
    def obj(value):
        nonlocal pages
        keys(value,('file','pages'));pin(value['file'])
        rows=value['pages'];need(type(rows) is list and 0<len(rows)<=PAGE_CAP,'page population')
        pages+=len(rows);need(pages<=PAGE_CAP,'aggregate page population');integer(len(rows),4)
        prior=-1
        for row in rows:
            keys(row,('relative','file_offset','permissions_at_exec','permissions_at_entry','file_backed','bytes'))
            address=uint(row['relative'],(1<<47)-4097);offset=uint(row['file_offset'],16*1048576)
            need(address%4096==offset%4096==0 and address>prior,'ordered aligned page');prior=address
            integer(address,8);integer(offset,8)
            permissions(row['permissions_at_exec']);permissions(row['permissions_at_entry'])
            need(type(row['file_backed']) is bool,'exact backing flag');integer(int(row['file_backed']),1)
            image(row['bytes'])
    for role in ('main','loader','bootstrap'):obj(request[role])
    deps=request['dependencies'];need(type(deps) is list and len(deps)<=16,'finite dependency population')
    integer(len(deps),4)
    for dependency in deps:obj(dependency)
    pin(request['dataset']);need(request['dataset']['bytes']<=65536,'fixed dataset bound')
    integer(uint(request['entry'],(1<<47)-1),8)
    entry=raw_hex(request['entry_bytes'],15);need(entry,'nonempty exact entry bytes')
    integer(len(entry),4);put(entry)
    completion=uint(request['completion_relative'],(1<<47)-9)
    need(completion%8==0,'aligned completion object');integer(completion,8)
    offset=request['completion_file_offset'];integer(int(offset is not None),1)
    if offset is not None:integer(uint(offset,16*1048576-8),8)
    need(type(request['xstate_bytes']) is int and 576<=request['xstate_bytes']<=16384,'exact xstate bound')
    integer(request['xstate_bytes'],4)
    if extended:
        basis=request['kernel_basis']
        keys(basis,('profile','basis_sha256','release','config_gzip_bytes','config_gzip_sha256',
                    'config_decoded_bytes','config_decoded_sha256'))
        need(basis['profile']==KERNEL_PROFILE,'explicit named kernel mode')
        release=basis['release']
        need(type(release) is str and 1<=len(release)<=128 and all(33<=ord(c)<=126 for c in release),
             'bounded exact kernel release')
        integer(1,1)
        digest=raw_hex(basis['basis_sha256'],32);need(len(digest)==32,'whole kernel basis digest');put(digest)
        integer(len(release),4);put(release.encode('ascii'))
        for kind,cap in (('gzip',65536),('decoded',524288)):
            size=uint(basis['config_'+kind+'_bytes'],cap);need(size>0,'nonempty kernel configuration')
            integer(size,4)
            digest=raw_hex(basis['config_'+kind+'_sha256'],32)
            need(len(digest)==32,'whole kernel configuration digest');put(digest)
    return bytes(out)


def sealed(raw):
    """Caller owns returned FD and must pass only it to the checked observer.

    The caller must already have reconstructed final package/platform authority.
    No token, digest, memfd name or seal authenticates that caller's semantics.
    """
    need(type(raw) is bytes and len(MAGIC)<len(raw)<=CAP and raw[:len(MAGIC)] in (MAGIC,MAGIC_V2),'bounded wire envelope')
    fd=os.memfd_create('li2-observer-request-v1',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
    try:
        need(3<=fd<=1024,'bounded inherited request descriptor')
        at=0
        while at<len(raw):
            written=os.write(fd,raw[at:at+65536]);need(written>0,'complete memfd write');at+=written
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,SEALS)
        need(fcntl.fcntl(fd,fcntl.F_GET_SEALS)&SEALS==SEALS,'all four immutable seals')
        need(os.fstat(fd).st_size==len(raw) and os.pread(fd,len(raw),0)==raw,'sealed whole request readback')
        return fd,hashlib.sha256(raw).hexdigest()
    except BaseException:
        os.close(fd);raise
