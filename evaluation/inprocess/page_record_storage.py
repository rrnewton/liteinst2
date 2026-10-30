"""Lossless storage for fully accepted native records; every fact streams original bytes."""
import gzip,hashlib,json,os,stat
from pathlib import Path

def need(ok,label):
    if not ok:raise ValueError(label)

def fact(path):
    h=hashlib.sha256();n=0
    with Path(path).open('rb')as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b);n+=len(b)
    return dict(bytes=n,sha256=h.hexdigest())

def stable(path):
    s=Path(path).lstat()
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid,s.st_nlink]

class RecordStorage:
    def __init__(self,private,receipt):
        self.private=Path(private).resolve(strict=True);self.entries={};self.log=None
        self.path=self.private/'record-storage.jsonl'
        self.receipt=receipt['record_storage']=dict(schema=1,scope='Lossless storage only; original capture facts and full reader results are unchanged.',records=[],journal=None)

    def contains(self,path):return str(Path(path).absolute())in self.entries

    def path_for(self,path):
        p=Path(path).absolute()
        need(str(p)in self.entries and p.parent==self.private and p.suffix=='.record','registered direct native record')
        return p

    def original(self,path):
        """Rehash compressed storage and bounded decompression on every call."""
        p=self.path_for(path);row=self.entries[str(p)];gz=self.private/row['compressed_file']
        need(not p.exists()and not p.is_symlink(),'archived raw path remains absent')
        s=gz.lstat();before=stable(gz)
        need(gz==gz.resolve(strict=True)and stat.S_ISREG(s.st_mode)and s.st_nlink==1 and before==row['compressed_stat'],'exact compressed storage identity')
        need(fact(gz)==row['compressed'],'whole compressed bytes')
        h=hashlib.sha256();n=0
        with gzip.open(gz,'rb')as source:
            for b in iter(lambda:source.read(1<<20),b''):
                n+=len(b);need(n<=row['raw']['bytes'],'bounded original record extent');h.update(b)
        value=dict(bytes=n,sha256=h.hexdigest())
        need(value==row['raw']and stable(gz)==before,'whole original record bytes and stable storage')
        return dict(value,mode=before[5])

    def emit(self,value):
        if self.log is None:self.log=self.path.open('x')
        self.log.write(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n');self.log.flush();os.fsync(self.log.fileno())

    def archive(self,path,command,accepted):
        p=Path(path).resolve(strict=True);cap=command['captures']['record'];want={k:cap[k]for k in('bytes','sha256')}
        need(p.parent==self.private and p.name==cap['file']==command['name']+'.record'and p.suffix=='.record','only owning direct record capture')
        need(command['profile']=='native'and command['bounds']==[5,536870912,16777216,15]and command['capture_limit']==65536 and
             command['exit']==command['expected_exit']and command['exit']in(0,125)and command['reaped']is True and
             not command['timed_out']and not command['error']and not command['cleanup_errors']and
             all(d['closed']is True for d in command['descriptors']),'unchanged closed native process')
        need(accepted['name']==command['name']and accepted['status']=='accepted_observation'and accepted['actual_exit']==command['exit']and
             accepted['record']==want and accepted['outcome']['operation']==('completed'if command['exit']==0 else'failed_memory_read'),
             'full reader accepted this exact original operation')
        s=p.lstat();before=stable(p);gz=Path(str(p)+'.gz')
        need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<want['bytes']<16<<20 and str(p)not in self.entries and
             not gz.exists()and not gz.is_symlink(),'unique raw record and absent archive')
        need(fact(p)==want and stable(p)==before,'whole original capture before archive')
        row=dict(raw_file=p.name,raw=want,raw_stat=before,compressed_file=gz.name,command=command['name'],actual_exit=command['exit'],status='started')
        self.receipt['records'].append(row);self.emit(dict(event='begin',**row))
        with gz.open('xb')as destination:
            os.fchmod(destination.fileno(),before[5])
            with gzip.GzipFile(filename='',mode='wb',compresslevel=9,fileobj=destination,mtime=0)as output:
                with p.open('rb')as source:
                    for b in iter(lambda:source.read(1<<20),b''):output.write(b)
            destination.flush();os.fsync(destination.fileno())
        need(stable(p)==before,'raw stable through compression');h=hashlib.sha256();n=0
        with gzip.open(gz,'rb')as restored,p.open('rb')as original:
            while True:
                a=restored.read(1<<20);b=original.read(1<<20)
                need(a==b,'whole roundtrip byte comparison')
                if not a:break
                n+=len(a);need(n<=want['bytes'],'bounded roundtrip extent');h.update(a)
        need(dict(bytes=n,sha256=h.hexdigest())==want,'roundtrip original capture fact')
        with gz.open('rb')as f:header=f.read(10)
        need(header[:8]==bytes((31,139,8,0,0,0,0,0)),'fixed gzip header without paths/time')
        g=stable(gz);need(g[5:8]==before[5:8]and g[8]==1,'preserved mode and owner')
        row.update(compressed=fact(gz),compressed_stat=g,status='verified')
        need(stable(p)==before and fact(p)==want and stable(gz)==g,'stable exact files before replacement')
        fd=os.open(self.private,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
        self.emit(dict(event='verified_before_raw_unlink',**row))
        p.unlink();self.entries[str(p)]=row;row['status']='archived'
        fd=os.open(self.private,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
        need(self.original(p)==dict(want,mode=before[5]),'post-replacement original byte closure')
        self.emit(dict(event='raw_storage_replaced',**row))

    def finish(self):
        try:
            for path in self.entries:self.original(path)
            need(len(self.entries)==len(self.receipt['records'])and all(x['status']=='archived'for x in self.receipt['records']),'all archive attempts completed')
        finally:
            if self.log is not None:
                log=self.log;self.log=None
                try:log.flush();os.fsync(log.fileno())
                finally:log.close()
                self.receipt['journal']=dict(file=self.path.name,**fact(self.path))
