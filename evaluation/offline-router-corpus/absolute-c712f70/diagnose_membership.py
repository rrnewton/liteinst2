from pathlib import Path
import hashlib,json,os,types
root=Path.cwd();out=root/'ignored/a3/membership-transition-v1'
source=root/'evaluation/adjacent-b2/artifact-verifier/startup_custody.py'
raw=source.read_bytes();assert hashlib.sha256(raw).hexdigest()=='6c236204101fb5950f955eb0540a51756bcf27d0a09860a9feab5f041d51f8c5'
m=types.ModuleType('custody');m.__file__=str(source);exec(compile(raw,str(source),'exec'),m.__dict__)
p=out/'fixture';p.mkdir()
for name in ['command.json','request.json']:(p/name).write_bytes(b'{}')
s=m.Store(1048576); rows=[]
try:
 rows.append(dict(stage='initial',record=s.members(p)))
 for name in ['parent-closed.json','receipt.json','stdout.txt','stderr.txt','helper.stdout','helper.stderr']:(p/name).write_bytes(b'')
 rows.append(dict(stage='same-retained-store-after-synchronous-add',record=s.members(p)))
 held=s.directory(p)
 try:
  os.lseek(held,0,os.SEEK_SET)
  rows.append(dict(stage='same-description-after-explicit-seek',names=sorted(os.listdir(held))))
  fresh=os.open('.',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=held)
  try:rows.append(dict(stage='fresh-open-relative-to-retained-anchor',same_inode=os.fstat(held).st_ino==os.fstat(fresh).st_ino,names=sorted(os.listdir(fresh))))
  finally:os.close(fresh)
 finally:os.close(held)
 fresh_store=m.Store(1048576)
 try:rows.append(dict(stage='fresh-store',record=fresh_store.members(p)))
 finally:fresh_store.close()
 s.verify()
finally:s.close()
result=dict(source_sha256=hashlib.sha256(raw).hexdigest(),rows=rows)
(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
