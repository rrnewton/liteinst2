#!/usr/bin/env python3
"""Create current inputs for a fresh cohort, without historical private evidence."""
import argparse,hashlib,json,os,struct,subprocess,sys
from pathlib import Path
from types import SimpleNamespace
if sys.flags.optimize:raise SystemExit('assertions required')
REVISION='4fe20da702222651894501f297123e367312544c'
OBSERVER='0d3697eaaf433fc76d22f4ec7b6bc8047d0260f90bf9227072ad8dee2f4662ba'
def sha(b):return hashlib.sha256(b).hexdigest()
def put(path,value):
    data=value if isinstance(value,bytes)else(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    with path.open('xb')as stream:stream.write(data)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--cohort',type=Path,required=True);args=ap.parse_args()
    repo=Path.cwd().resolve();packet=Path(__file__).resolve().parent;cohort=args.cohort
    assert packet.is_relative_to(repo/'ignored') and packet.resolve(strict=True)==packet
    assert cohort.is_absolute() and cohort.parent==repo/'ignored' and cohort.resolve(strict=True)==cohort
    assert not packet.is_relative_to(cohort) and not cohort.is_relative_to(packet)
    pins=json.loads((packet/'pins.json').read_text());assert set(pins)=={'schema','revision','files'} and pins['schema']==1 and pins['revision']==REVISION
    assert set(pins['files'])=={'build.py','run.py','prepare.py','launch.py','CASES.json','source-members.json'}
    for name,pin in pins['files'].items():
        data=(packet/name).read_bytes();assert pin==dict(sha256=sha(data),bytes=len(data))
    env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
    assert subprocess.check_output(['/usr/bin/git','rev-parse','HEAD'],env=env,timeout=30).decode().strip()==REVISION
    assert not subprocess.check_output(['/usr/bin/git','diff','--binary','HEAD','--'],env=env,timeout=30)
    build=cohort/(cohort.name+'-native-build');parent=cohort/'build-parent';here=cohort/'activation';raw=cohort/'native'
    assert not here.exists() and not raw.exists() and not (cohort/'run-parent').exists()
    observer=repo/'evaluation/trampoline-parallel.py';source=observer.read_bytes();assert sha(source)==OBSERVER
    namespace=dict(__name__='_fresh_point_observer',__file__=str(observer));exec(compile(source,str(observer),'exec'),namespace);observe=SimpleNamespace(**namespace)
    before_bytes=(build/'inputs-before.json').read_bytes();assert before_bytes==(build/'inputs-after.json').read_bytes()
    before=json.loads(before_bytes);assert observe.source(repo,'/usr/bin/git',env)==before['source']
    assert before['source']['revision']==REVISION and len(before['source']['files'])==2189
    members=json.loads((packet/'source-members.json').read_text());assert len(members)==4
    assert members=={name:{k:before['source']['files'][name][k]for k in('sha256','bytes')}for name in members}
    summary=json.loads((build/'summary.json').read_text());command=json.loads((build/'command.json').read_text());result=json.loads((build/'process-result.json').read_text())
    assert summary['revision']==command['source_revision']==REVISION and summary['phase']=='native-build'
    assert summary['status']=='PASS' and summary['source_tools_configs_equal']is True and summary['command']==result
    assert result['exit_code']==0 and result['cleanup_complete']is True and result['reaped_descendants']==0 and result['termination']is None
    assert command['argv']==['cargo','build','-p','rapid-profiler','--bin','frontend-native-point','--message-format=json']
    assert command['caller_sha256']==pins['files']['build.py']['sha256'] and command['timeout_seconds']==180 and command['max_log_bytes']==8*1048576 and command['affinity']==[0,1,2,3]
    closed=json.loads((parent/'closed.json').read_text());started=json.loads((parent/'started.json').read_text());outer=json.loads((parent/'command.json').read_text())
    assert closed['exit']==0 and closed['parent_error']is None and closed['parent_wait_returned']is True and closed['pid']==started['pid']
    assert outer['source_revision']==REVISION and outer['source_sha256']==pins['files']['build.py']['sha256'] and outer['parent_source_sha256']==pins['files']['launch.py']['sha256']
    for stream in('stdout','stderr'):assert sha((parent/(stream+'.txt')).read_bytes())==closed[stream+'_sha256']
    assert (parent/'stderr.txt').read_bytes()==b'' and json.loads((parent/'stdout.txt').read_bytes())==summary
    assert observe.configuration(repo,Path(command['env']['CARGO_HOME']))==before['configurations']
    assert {name:observe.tool(Path(row['path']))for name,row in before['tools'].items()}==before['tools']
    log=(build/'command.log').read_bytes();assert sha(log)==result['private_log_sha256']
    records=[]
    for line in log.splitlines():
        if line.startswith(b'{'):records.append(json.loads(line))
    assert [x for x in records if x.get('reason')=='build-finished']==[dict(reason='build-finished',success=True)]
    artifacts=[x for x in records if x.get('reason')=='compiler-artifact'and x['target']['name']=='frontend-native-point'];assert len(artifacts)==1
    artifact=artifacts[0];binary=repo/'target/debug/frontend-native-point'
    assert artifact['executable']==str(binary)and artifact['filenames']==[str(binary)]
    assert artifact['target']['kind']==artifact['target']['crate_types']==['bin']and artifact['target']['src_path']==str(repo/'tools/rapid-profiler/native-point/main.rs')
    assert artifact['features']==[]and artifact['target']['edition']=='2024'and artifact['manifest_path']==str(repo/'tools/rapid-profiler/Cargo.toml')
    assert artifact['package_id']=='path+'+(repo/'tools/rapid-profiler').as_uri()+'#0.1.0'
    assert artifact['profile']==dict(debug_assertions=True,debuginfo=0,opt_level='0',overflow_checks=True,test=False)
    actual=observe.tool(binary);s=binary.stat();six=[s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
    assert actual['stat']==actual['lookup_stat']==six and actual['resolved']==str(binary)and s.st_mode&0o111
    here.mkdir()
    product=dict(revision=REVISION,build_summary_sha256=sha((build/'summary.json').read_bytes()),build_log_sha256=sha(log),artifact=artifact,product=dict(path=str(binary),sha256=actual['sha256'],bytes=actual['bytes'],dev=s.st_dev,ino=s.st_ino,mode=s.st_mode,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns,uid=s.st_uid,gid=s.st_gid))
    put(build/'product.json',product)
    def interpreter(path):
        data,owner=observe.read(path.resolve(strict=True))
        assert data[:7]==b'\x7fELF\x02\x01\x01'and len(data)>=64
        off,count=struct.unpack_from('<Q',data,32)[0],struct.unpack_from('<H',data,56)[0]
        assert 1<=count<=128 and struct.unpack_from('<H',data,54)[0]==56 and off+count*56<=len(data)
        selected=[row for row in(struct.unpack_from('<IIQQQQQQ',data,off+i*56)for i in range(count))if row[0]==3];assert len(selected)==1
        row=selected[0];assert 1<row[5]<=4096 and row[2]+row[5]<=len(data)
        value=data[row[2]:row[2]+row[5]];assert value.endswith(b'\0')and b'\0'not in value[:-1]
        return value[:-1].decode()
    tools={name:observe.tool(Path(path))for name,path in dict(python='/usr/bin/python3.9',timeout='/usr/bin/timeout',git='/usr/bin/git',helper=str(repo/'tools/unwind-oracle/bounded_command.py'),du='/usr/bin/du').items()}
    runtime=dict(schema=1,authority='ROOT_REVIEWED_BYTE_POINT_SELECTED_RUNTIME',scope='selected-host-owners-only',revision=REVISION,driver_sha256=actual['sha256'],python_sha256=tools['python']['sha256'],owners=dict(driver_interpreter=observe.tool(Path(interpreter(binary))),python_interpreter=observe.tool(Path(interpreter(Path('/usr/bin/python3.9')))),libc=observe.tool(Path('/lib64/libc.so.6')),loader_cache=observe.tool(Path('/etc/ld.so.cache'))))
    put(here/'runtime.json',runtime)
    put(here/'capacity.json',dict(schema=1,authority='ROOT_REVIEWED_BYTE_POINT_CAPACITY',revision=REVISION,raw=str(raw),max_slot_bytes=20000000000,reserved_growth_bytes=1073741824,minimum_available_memory_bytes=536870912,sole_writer_required=True))
    binding=dict(schema=1,authority='ROOT_REVIEWED_BYTE_POINT_NATIVE_INPUTS',repo=str(repo),revision=REVISION,caller_sha256=pins['files']['run.py']['sha256'],source_manifest=str(packet/'source-members.json'),build=str(build),build_launch=str(parent),build_parent_source=str(packet/'launch.py'),tools=tools,files={},cases=str(packet/'CASES.json'),runtime=str(here/'runtime.json'),capacity=str(here/'capacity.json'))
    selected=[packet/n for n in('run.py','source-members.json','CASES.json','launch.py','build.py','prepare.py','pins.json')]+[here/'runtime.json',here/'capacity.json']
    selected += [build/n for n in('inputs-before.json','inputs-after.json','summary.json','command.json','command.log','process-result.json','hardware.json','product.json')]
    selected += [parent/n for n in('closed.json','started.json','command.json','stdout.txt','stderr.txt')]
    assert len(selected)==22 and len(set(selected))==22 and len(selected)<=64
    for path in selected:
        data,owner=observe.read(path);binding['files'][str(path)]=dict(sha256=sha(data),bytes=len(data),stat=owner)
    put(here/'binding.json',binding)
    assert observe.tool(binary)==actual and observe.source(repo,'/usr/bin/git',env)==before['source']
    print(json.dumps(dict(revision=REVISION,binding_sha256=sha((here/'binding.json').read_bytes()),selected_files=22,cohort='fresh-independent-repetition',historical_result_transfer=False,native_cases='UNRUN',qualification_complete=False),sort_keys=True))
if __name__=='__main__':main()
