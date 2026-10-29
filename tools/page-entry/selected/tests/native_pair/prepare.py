"""Exact private observation/control views; every whole donor is recoverable."""
from pathlib import Path
import json
from page_selected import fact,need

def prepare(root,out,pin):
    root,out=Path(root),Path(out)
    selected=root/'tools/page-entry/selected'
    fixture=selected/'tests/native_pair'
    catalogue=pin(fixture/'ADAPTERS.json')
    document=json.loads(catalogue.read_bytes())
    need(document['version']==1,'fixed pair adapter version')
    need(not out.exists(),'unique pair observer source view');out.mkdir(parents=True)
    changes=[]
    for row in document['views']:
        source=pin(selected/row['name']);before=source.read_bytes()
        need(fact(source)==row['before'],'exact complete pair source '+row['name'])
        data=before
        for operation in row['operations']:
            old,new=operation['old'].encode(),operation['new'].encode()
            if operation['kind']=='replace':
                need(old and data.count(old)==1,'unique pair observation seam '+row['name'])
                data=data.replace(old,new)
            else:
                need(operation['kind']=='append' and not old and new not in data,'exact pair suffix')
                data+=new
        inverse=data
        for operation in reversed(row['operations']):
            old,new=operation['old'].encode(),operation['new'].encode()
            if operation['kind']=='replace':
                need(inverse.count(new)==1,'unique pair inverse '+row['name'])
                inverse=inverse.replace(new,old)
            else:
                need(inverse.endswith(new),'exact pair inverse suffix');inverse=inverse[:-len(new)]
        need(inverse==before,'complete original pair source recovered '+row['name'])
        output=out/row['name'];output.write_bytes(data)
        need(fact(output)==row['after'],'exact generated pair source '+row['name']);pin(output)
        changes.append(dict(name=row['name'],before=fact(source),after=fact(output)))
    for original,name in (('observe.inc','native_pair_observe.inc'),('record.h','native_pair_record.h'),
                          ('runtime_record.h','native_pair_runtime_record.h'),('hooks.h','native_pair_hooks.h')):
        source=pin(fixture/original);output=out/name
        output.write_bytes(source.read_bytes());pin(output)
        changes.append(dict(name=name,before=fact(source),after=fact(output)))
    return changes
