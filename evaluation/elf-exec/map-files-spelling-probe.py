#!/usr/bin/python3.9
"""One authorized self-only procfs name-spelling observation; no child or mapping."""
import hashlib, json, os, sys, time
from pathlib import Path
out=Path(__file__).resolve().parent
exe=os.readlink('/proc/self/exe')
lines=Path('/proc/self/maps').read_text().splitlines()
rows=[line for line in lines if len(line.split(None,5))==6 and line.split(None,5)[5]==exe]
assert rows
row=rows[0]
start,end=(int(x,16) for x in row.split()[0].split('-'))
assert 0 < start < end
names=[format(start,'x')+'-'+format(end,'x'),'0'+format(start,'x')+'-0'+format(end,'x')]
observed=[]
for name in names:
    path='/proc/self/map_files/'+name
    try:
        value=os.readlink(path)
        observed.append({'name':name,'link':value,'errno':None})
    except OSError as error:
        observed.append({'name':name,'link':None,'errno':error.errno,'error':str(error)})
assert row in Path('/proc/self/maps').read_text().splitlines()
record={'schema':1,'scope':'self-existing-interpreter-VMA spelling only; no fixture execution','pid':os.getpid(),'time_ns':time.time_ns(),'executable':exe,'maps_row':row,'start':start,'end':end,'observed':observed,'maps_row_unchanged':True,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
with (out/'result.json').open('x') as f:
    json.dump(record,f,indent=2,sort_keys=True);f.write('\n')
print(json.dumps(record,sort_keys=True))
