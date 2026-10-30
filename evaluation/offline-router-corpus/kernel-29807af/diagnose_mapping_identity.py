import ctypes,hashlib,json,os,stat
from pathlib import Path
libc=ctypes.CDLL(None,use_errno=True);libc.mmap.restype=ctypes.c_void_p
rows=[]
for path in (Path.cwd()/'ignored/a3/kernel-config-off-v1/observe/checksum/candidate',Path('/usr/lib64/ld-linux-x86-64.so.2')):
 fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW);address=None
 try:
  info=os.fstat(fd);address=libc.mmap(None,4096,1,2,fd,0)
  if address==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_errno(),'mmap')
  rows_for_address=[]
  for line in Path('/proc/self/maps').read_text().splitlines():
   fields=line.split();start,end=(int(x,16) for x in fields[0].split('-'))
   if start<=address and address+4096<=end:rows_for_address.append((line,start,end))
  assert len(rows_for_address)==1
  line,start,end=rows_for_address[0];mapping=Path('/proc/self/map_files')/('%x-%x'%(start,end))
  row=dict(file_bytes=info.st_size,stat_device=info.st_dev,stat_inode=info.st_ino,maps_line=line,attempts={})
  operations={'readlink':lambda:os.readlink(mapping),'stat':lambda:list(os.stat(mapping)[:3]),'open_path':lambda:os.open(mapping,os.O_PATH|os.O_CLOEXEC),'open_read':lambda:os.open(mapping,os.O_RDONLY|os.O_CLOEXEC)}
  for name,fn in operations.items():
   try:
    value=fn()
    if name.startswith('open_'):
     try:
      got=os.fstat(value);value_out=dict(device=got.st_dev,inode=got.st_ino,mode=got.st_mode)
     finally:os.close(value)
     value=value_out
    row['attempts'][name]=dict(result=value)
   except OSError as error:row['attempts'][name]=dict(errno=error.errno)
  assert (info.st_dev,info.st_ino,info.st_size)==(os.fstat(fd).st_dev,os.fstat(fd).st_ino,os.fstat(fd).st_size)
  rows.append(row)
 finally:
  if address not in (None,ctypes.c_void_p(-1).value):assert libc.munmap(ctypes.c_void_p(address),ctypes.c_size_t(4096))==0
  os.close(fd)
result=dict(rows=rows,native_dispatches=0,mappings_unmapped=True)
data=json.dumps(result,sort_keys=True)+'\n'
Path(__file__).with_name('result.json').write_text(data)
print(data,end='')
