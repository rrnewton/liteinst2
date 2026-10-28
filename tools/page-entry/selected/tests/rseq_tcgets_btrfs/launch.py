"""Fresh real native/carrier exec with a retained signal and FD3 preparation."""
import argparse,ctypes,fcntl,json,os,stat,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[5]
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from page_selected_process import Action


def prepare_capture(route,path,layout_path,retained):
    """Trusted pre-exec normal-open construction, not application assertions.

    The actual binary layout file is produced by the enclosing qualified GDB
    inspection and pinned before this bounded launcher executes. Raw query
    buffers remain in the private preparation record for later replay.
    """
    layout=json.loads(layout_path.read_bytes());types=layout['types']
    if types['statfs']['bytes']!=120 or types['statx']['bytes']!=256:raise ValueError('actual x86-64 query layouts')
    fields=types['statx']['fields'];f=types['statfs']['fields']
    expected={'stx_mask':(0,4),'stx_mode':(28,2),'stx_ino':(32,8),'stx_dev_major':(136,4),'stx_dev_minor':(140,4),'stx_mnt_id':(144,8)}
    if any(fields[k]!=dict(offset=o,bytes=n)for k,(o,n)in expected.items())or f['f_type']!=dict(offset=0,bytes=8):raise ValueError('complete actual typed query fields')
    libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
    calls=[];owned=[];state=dict(route=route,path=str(path),calls=calls,status="failed",error=None)
    def note(name,**values):calls.append(dict(name=name,**values))
    def owned_fd(fd):
        if type(fd)is not int or fd<=3:raise ValueError('owned capture descriptors stay above inherited FD3')
        owned.append(fd);return fd
    def info(fd):
        s=os.fstat(fd);flags=fcntl.fcntl(fd,fcntl.F_GETFL);offset=os.lseek(fd,0,os.SEEK_CUR)if stat.S_ISREG(s.st_mode)and not flags&os.O_PATH else None
        return dict(device=s.st_dev,inode=s.st_ino,mode=s.st_mode,flags=flags,size=s.st_size,offset=offset)
    def query(n,fd,size):
        b=ctypes.create_string_buffer(size);ctypes.set_errno(0)
        if n==138:r=libc.syscall(ctypes.c_long(n),ctypes.c_long(fd),ctypes.byref(b))
        else:r=libc.syscall(ctypes.c_long(n),ctypes.c_long(fd),ctypes.c_char_p(b''),ctypes.c_long(0x1000),ctypes.c_long(0x1103),ctypes.byref(b))
        e=ctypes.get_errno()if r==-1 else 0;note('query',number=n,fd=fd,result=int(r),errno=e,bytes=size,raw=bytes(b).hex())
        if r:raise OSError(e,'actual FD query')
        return bytes(b)
    try:
        if route in ('normal','subvolume','dup','opath'):
            fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600);owned_fd(fd)
            note('open',fd=fd,flags=os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,identity=info(fd))
            if route=='opath':
                os.close(fd);owned.remove(fd);note('close',fd=fd,result=0)
                fd=os.open(path,os.O_PATH|os.O_CLOEXEC|os.O_NOFOLLOW);owned_fd(fd);note('open_path',fd=fd,identity=info(fd))
        elif route=='directory':
            path.mkdir();fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW);owned_fd(fd);note('open_directory',fd=fd,identity=info(fd))
        elif route=='pipe':
            readfd,fd=os.pipe2(os.O_CLOEXEC);owned_fd(readfd);owned_fd(fd);note('pipe',read_fd=readfd,write_fd=fd,identity=info(fd))
        else:
            fd=os.memfd_create('li2-tcgets-wrong-fs',os.MFD_CLOEXEC);owned_fd(fd);note('memfd',fd=fd,identity=info(fd))
        before=info(fd);fs=query(138,fd,120);sx=query(332,fd,256)
        val=lambda k:int.from_bytes(sx[fields[k]['offset']:fields[k]['offset']+fields[k]['bytes']],'little')
        if val('stx_mask')&0x1103!=0x1103 or val('stx_mask')&0x4000 or not val('stx_mnt_id')or val('stx_mode')!=before['mode']or val('stx_ino')!=before['inode']or (val('stx_dev_major'),val('stx_dev_minor'))!=(os.major(before['device']),os.minor(before['device'])):raise ValueError('actual FD stat/statx identity')
        subvolume=None
        if route=='subvolume':
            # Actual future ELF DWARF and the pinned native UAPI both own
            # this complete result; pathname/device heuristics are not used.
            t=types['btrfs_ioctl_get_subvol_info_args'];bf=t['fields']
            if t['bytes']!=504 or bf['treeid']!=dict(offset=0,bytes=8)or bf['uuid']!=dict(offset=296,bytes=16)or bf['reserved']!=dict(offset=440,bytes=64):raise ValueError('actual complete subvolume ABI')
            command=layout['subvolume_command']
            if type(command)is not int or command!=0x81f8943c:raise ValueError('actual typed subvolume ioctl command')
            buf=bytearray(t['bytes']);result=fcntl.ioctl(fd,command,buf,True)
            note('get_subvol_info',fd=fd,command=command,result=result,bytes=len(buf),raw=bytes(buf).hex(),before=before,after=info(fd))
            treeid=struct.unpack_from('<Q',buf,bf['treeid']['offset'])[0]
            if result!=0 or treeid<256 or not any(buf[296:312])or any(buf[440:]):raise ValueError('actual non-top-level subvolume capture')
            subvolume=dict(treeid=treeid,raw=bytes(buf).hex())
        if info(fd)!=before:raise ValueError('capture FD changed during identity observations')
        if route=='dup':
            duplicate=fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,16);owned_fd(duplicate)
            note('same_ofd_dup',source_fd=fd,result_fd=duplicate,command=fcntl.F_DUPFD_CLOEXEC,identity=info(duplicate))
            if info(duplicate)!=before:raise ValueError('actual duplicate identity')
            fd=duplicate
        os.dup2(fd,1,inheritable=True);note('dup2',source_fd=fd,result_fd=1,identity=info(1))
        if info(1)!=before or not os.get_inheritable(1):raise ValueError('actual inherited FD1 identity')
        state.update(identity=before,major=os.major(before['device']),minor=os.minor(before['device']),mount_id=val('stx_mnt_id'),filesystem_type=int.from_bytes(fs[:8],'little'),subvolume=subvolume,status='passed')
        return state
    except BaseException as exc:
        state['error']=type(exc).__name__+': '+str(exc);raise
    finally:
        errors=[]
        for fd in reversed(owned):
            try:os.close(fd);note('close',fd=fd,result=0)
            except BaseException as exc:errors.append(type(exc).__name__+': '+str(exc));note('close',fd=fd,error=errors[-1])
        state['cleanup_errors']=errors
        if errors:state['status']='failed'
        with retained.open('x')as stream:json.dump(state,stream,sort_keys=True)
        if errors and state['error']is None:raise ValueError('capture descriptor cleanup failed')

def main():
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=('native','gated'),required=True)
    p.add_argument('--original',type=Path,required=True);p.add_argument('--carrier',type=Path);p.add_argument('--namespace',type=Path)
    p.add_argument('--library-root',type=Path,required=True);p.add_argument('--preparation',type=Path,required=True);p.add_argument('--record-fd',type=int,required=True)
    p.add_argument('--capture-route',choices=('normal','subvolume','dup','opath','directory','pipe','memfd'),required=True)
    p.add_argument('--capture-object',type=Path,required=True)
    p.add_argument('--layout',type=Path,required=True)
    a=p.parse_args();sys.path.insert(0,str(ROOT/'tools/page-entry'));import carrier
    if a.record_fd!=3:raise ValueError('actual invoke observer descriptor is literal FD3')
    capture=prepare_capture(a.capture_route,a.capture_object,a.layout,a.preparation.with_name('capture-preparation.json'))
    prior=os.fstat(a.record_fd)
    if not stat.S_ISREG(prior.st_mode)or prior.st_size or os.lseek(a.record_fd,0,os.SEEK_CUR):raise ValueError('fresh regular record')
    os.dup2(a.record_fd,3,inheritable=True)
    if a.record_fd!=3:os.close(a.record_fd)
    observer=os.fstat(3)
    if(observer.st_dev,observer.st_ino)!=(prior.st_dev,prior.st_ino)or not os.get_inheritable(3):raise ValueError('real observer fd identity')
    libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
    previous=ctypes.c_uint64();empty=ctypes.c_uint64();actual=ctypes.c_uint64(1)
    if libc.syscall(14,2,ctypes.byref(empty),ctypes.byref(previous),8):raise OSError('signal mask reset')
    observations=[]
    for number in range(1,65):
        if number in(9,19):continue
        before,zero,after=Action(),Action(),Action()
        if libc.syscall(13,number,None,ctypes.byref(before),8)or libc.syscall(13,number,ctypes.byref(zero),None,8)or libc.syscall(13,number,None,ctypes.byref(after),8)or after.handler:raise OSError('signal action reset')
        observations.append(dict(signal=number,before=int(before.handler or 0),after=int(after.handler or 0)))
    if libc.syscall(14,2,None,ctypes.byref(actual),8)or actual.value:raise OSError('actual empty mask')
    argv=[str(a.original)]+(['native']if a.mode=='native'else[])
    env={k:v for k,v in os.environ.items()if k!='PYTHONDONTWRITEBYTECODE'}
    with a.preparation.open('x')as f:json.dump(dict(previous_mask=previous.value,mask=actual.value,dispositions=observations,argv=argv,environment=env,
        observer=dict(fd=3,device=observer.st_dev,inode=observer.st_ino),capture=capture,mode=a.mode,affinity=sorted(os.sched_getaffinity(0))),f,sort_keys=True)
    if a.mode=='native':os.execve(a.original,argv,env)
    if a.carrier is None or a.namespace is None:raise ValueError('genuine gated inputs')
    carrier.execute_loader(a.carrier,a.original,[a.library_root],a.namespace,argv,disable_rseq=False)
if __name__=='__main__':main()
