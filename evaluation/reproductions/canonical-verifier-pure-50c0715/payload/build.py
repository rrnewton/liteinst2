#!/usr/bin/env python3
"""Fresh direct-rustc verifier producer proposal. Never runs the verifier."""
import sys
if sys.flags.optimize:raise SystemExit('assertions required')
import argparse,errno,hashlib,json,os,runpy,signal,stat,subprocess,time
from pathlib import Path
R=Path(__file__).resolve().parents[4];P=Path(__file__).resolve().parent;E=None
# Activation is a separate reviewed literal edit after the final build epoch.
REV=None;SOURCE_FILES=None;BUILD_RELATIVE=None;BUILD_REVIEW_RELATIVE=None;EPOCH_RELATIVE=None
SUPPORT=None
CAP=128*1024*1024
BUILD_SUPPORT='31545ba44b5cb3b055a96269c689b9235957ec3dab0cfd3e65ba86efbdde71ed'
HELPER='c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
REWRITES=((b'#[path = "../../../tests/support/e9_common_seed.rs"]', b'#[path = "e9_common_seed.rs"]'), (b'#[path = "support/common_core_foreign.rs"]', b'#[path = "common_core_foreign.rs"]'), (b'#[path = "../../../tests/support/e9_common_planning_profile.rs"]', b'#[path = "e9_common_planning_profile.rs"]'), (b'#[path = "support/common_core_router.rs"]', b'#[path = "common_core_router.rs"]'), (b'#[path = "../../../tests/support/e9_common_router_contract.rs"]', b'#[path = "e9_common_router_contract.rs"]'))
SOURCE='tools/elf-rewrite/examples/verify_common_core.rs'
MEMBERS={'src/common_core_foreign.rs': 'tools/elf-rewrite/examples/support/common_core_foreign.rs', 'src/common_core_router.rs': 'tools/elf-rewrite/examples/support/common_core_router.rs', 'src/e9_common_planning_profile.rs': 'tests/support/e9_common_planning_profile.rs', 'src/e9_common_router_contract.rs': 'tests/support/e9_common_router_contract.rs', 'src/e9_common_seed.instructions.tsv': 'tests/support/e9_common_seed.instructions.tsv', 'src/e9_common_seed.rs': 'tests/support/e9_common_seed.rs', 'src/verify_common_core.rs': 'tools/elf-rewrite/examples/verify_common_core.rs'}
ENV=dict(PATH='/usr/bin:/bin',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1')
def sha(b):return hashlib.sha256(b).hexdigest()
def six(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def loads(b):
    def unique(pairs):
        out={}
        for key,value in pairs:assert key not in out;out[key]=value
        return out
    def invalid(value):raise AssertionError('invalid JSON constant '+value)
    return json.loads(b,object_pairs_hook=unique,parse_constant=invalid)
def load(p):return loads(read(p)[0])
def read(p):
    p=Path(p);assert p.is_absolute() and p.parent.resolve(strict=True)==p.parent
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
        s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode) and s.st_size<=CAP
        b=f.read(CAP+1);assert len(b)==s.st_size and six(s)==six(os.fstat(f.fileno()))==six(p.lstat())
    return b,dict(sha256=sha(b),bytes=len(b),stat=six(s))
def write(p,x):
    b=x if isinstance(x,bytes) else (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    with p.open('xb') as f:f.write(b)
def pinned(p,pin):
    b,row=read(p);assert all(row[k]==v for k,v in pin.items()),str(p);return b,row

def tool_snapshot():
    result={}
    for p in tool_paths:
        resolved=p.resolve(strict=True);data,owner=read(resolved);assert owner['stat'][2]&0o111
        result[str(p)]=dict(resolved=str(resolved),sha256=sha(data),stat=owner['stat'])
    return result

def config_snapshot():
    result={}
    for p in config_paths:
        try:exists=p.exists()
        except PermissionError as error:
            assert error.errno in (errno.EPERM,errno.EACCES)
            result[str(p)]=dict(observation='READ_DENIED',operation='metadata_lookup',errno=error.errno,exists=None,content_sha256=None);continue
        if not exists and not p.is_symlink():result[str(p)]=dict(exists=False)
        else:
            resolved=p.resolve(strict=True);data,owner=read(resolved)
            result[str(p)]=dict(exists=True,resolved=str(resolved),sha256=sha(data),stat=owner['stat'],lstat=six(p.lstat()))
    return result

def canonical_epoch(repo, relative):
    assert type(relative) is str
    rel = Path(relative)
    assert not rel.is_absolute() and str(rel) == relative and '..' not in rel.parts
    epoch = repo / rel
    assert epoch.parent == repo / 'ignored/a3'
    assert epoch.name != 'common-native-epoch-v1'
    return epoch


def canonical_epoch_member(epoch, value):
    path = Path(value)
    assert path.is_absolute() and str(path) == os.fspath(value) and '..' not in path.parts
    assert path != epoch and path.is_relative_to(epoch)
    return path


def canonical_source(data):
    original=data
    for old,new in REWRITES:
        assert data.count(old)==1 and new not in data
        data=data.replace(old,new)
        assert data.count(new)==1
    inverse=data
    for old,new in reversed(REWRITES):inverse=inverse.replace(new,old)
    assert inverse==original
    return data

owned_raw=None
held_fds=[]
def main():
    global tool_paths,config_paths,owned_raw,E
    if None in (REV,SOURCE_FILES,SUPPORT,BUILD_RELATIVE,BUILD_REVIEW_RELATIVE,EPOCH_RELATIVE):
        raise SystemExit('canonical producer activation is pending final reviewed source/build pins')
    assert type(REV) is str and len(REV)==40 and all(x in '0123456789abcdef' for x in REV)
    assert type(SOURCE_FILES) is int and SOURCE_FILES>0
    assert type(SUPPORT) is str and len(SUPPORT)==64 and all(x in '0123456789abcdef' for x in SUPPORT)
    for name in (BUILD_RELATIVE,BUILD_REVIEW_RELATIVE):
        p=Path(name);assert not p.is_absolute() and '..' not in p.parts and str(p)==name and p.is_relative_to(Path('ignored/a3'))
    E=canonical_epoch(R,EPOCH_RELATIVE);assert E.resolve(strict=True)==E
    ap=argparse.ArgumentParser();ap.add_argument('--caller',type=Path,required=True);ap.add_argument('--caller-sha256',required=True);a=ap.parse_args()
    cb,caller_owner=read(a.caller);assert sha(cb)==a.caller_sha256;caller=loads(cb)
    assert set(caller)=={'schema','authority','revision','raw','producer_sha256','entry_sha256','references_sha256','linker','capacity_record'}
    assert caller['schema']==1 and caller['authority']=='ROOT_AUTHORIZED_DIRECT_RUSTC_VERIFIER_PRODUCTION' and caller['revision']==REV
    self_before=read(Path(__file__).resolve());assert sha(self_before[0])==caller['producer_sha256']
    entry_source=P/'compiler_entry.py';entry_before=read(entry_source);assert sha(entry_before[0])==caller['entry_sha256']
    reference_bytes,reference_owner=read(P/'references.json');assert sha(reference_bytes)==caller['references_sha256'];reference_pins=loads(reference_bytes)
    for name,pin in reference_pins.items():pinned(R/name,pin)
    for name,digest in [('evaluation/e9-common-app/run_candidates.py',SUPPORT),('evaluation/e9-common-app/build_inventory.py',BUILD_SUPPORT),('tools/unwind-oracle/bounded_command.py',HELPER)]:assert sha(read(R/name)[0])==digest
    c=runpy.run_path(str(R/'evaluation/e9-common-app/run_candidates.py'),run_name='_pinned_source_receipt_definitions_')
    n=runpy.run_path(str(R/'evaluation/e9-common-app/build_inventory.py'),run_name='_pinned_depfile_definitions_')
    build=canonical_epoch_member(E,R/BUILD_RELATIVE);review=load(canonical_epoch_member(E,R/BUILD_REVIEW_RELATIVE));assert review['findings']==[]
    assert review['revision']==REV
    required=set(MEMBERS.values())|{'evaluation/e9-common-app/run_candidates.py','evaluation/e9-common-app/build_inventory.py','tools/unwind-oracle/bounded_command.py',BUILD_REVIEW_RELATIVE}
    assert required<=set(reference_pins)
    raw=canonical_epoch_member(E,caller['raw']);assert raw.is_absolute() and raw.is_relative_to(E) and raw!=E and '..' not in raw.parts and raw.parent.resolve(strict=True)==raw.parent and not raw.exists() and not raw.is_symlink()
    assert set(caller['capacity_record'])==set(caller['linker'])=={'path','sha256','bytes','stat'}
    capacity_path=Path(caller['capacity_record']['path']);pinned(capacity_path,{k:v for k,v in caller['capacity_record'].items() if k!='path'})
    assert not capacity_path.is_relative_to(raw)
    before=c['source'](R);saved=load(build/'source.json')
    assert before['revision']==saved['revision']==REV and len(before['files'])==SOURCE_FILES
    assert before['files']==saved['files'] and {p:v['stat'] for p,v in before['owners'].items()}==saved['owners']
    assert read(build/'source.json')[0]==read(build/'source-after.json')[0]
    tool_paths=[Path(p) for p in load(build/'tools.json')];config_paths=[Path(p) for p in load(build/'configs.json')]
    tools=tool_snapshot();configs=config_snapshot();assert tools==load(build/'tools.json') and configs==load(build/'configs.json')
    linker=Path(caller['linker']['path']);assert linker.is_absolute() and linker.resolve(strict=True)==linker
    linker_before=pinned(linker,{k:v for k,v in caller['linker'].items() if k!='path'});assert linker_before[1]['stat'][2]&0o111
    base_request=load(build/'common-sites-compile/request.json');rustc=Path(base_request['env']['RUSTC']);assert str(rustc) in tools
    assert (base_request['cpu_seconds'],base_request['wall_seconds'],base_request['file_bytes'])==(60,90,CAP)
    archive=load(build/'common-sites-compile/artifact-archive.json');cargo=[loads(line) for line in read(build/'common-sites-compile/stdout.txt')[0].splitlines()]
    assert 1<=len(cargo)<=512 and cargo[-1]==dict(reason='build-finished',success=True) and archive['source_revision']==REV
    assert sum(x.get('reason')=='build-finished' for x in cargo)==1
    assert all(x.get('reason') in ('compiler-artifact','build-script-executed','build-finished') for x in cargo)
    assert all(type(x['fresh']) is bool and x['filenames'] for x in cargo if x['reason']=='compiler-artifact')
    assert archive['source_files_sha256']==sha(c['encode'](before['files']))
    assert archive['cargo_stdout_sha256']==sha(read(build/'common-sites-compile/stdout.txt')[0])
    assert archive['command_result_sha256']==sha(read(build/'common-sites-compile/result.json')[0])
    assert len(archive['selected'])==1 and set(archive['selected'])=={'common_sites'}
    selected=archive['selected']['common_sites'];assert cargo.count(selected['cargo'])==1
    reported={p for row in cargo if row['reason']=='compiler-artifact' for p in row['filenames']}
    assert set(archive['artifacts'])==reported|{str(Path(selected['cargo']['executable']).with_suffix('.d'))}
    for name,pin in selected['source_bindings'].items():assert before['files'][name]==pin
    raw.mkdir(mode=0o700);owned_raw=raw
    for name in ('inputs','output','tmp','compile','archive'):(raw/name).mkdir(mode=0o700)
    for name in ('src','deps'):(raw/'inputs'/name).mkdir(mode=0o700)
    for name,value in [('caller.json',cb),('source.json',before),('tools.json',tools),('configs.json',configs),('linker.json',caller['linker']),('original-build-archive.json',archive)]:write(raw/name,value)
    originals={};copies={};source_map={}
    for relative,member in MEMBERS.items():
        data,fact=pinned(R/member,dict(sha256=before['files'][member]['sha256'],bytes=before['files'][member]['bytes'],stat=before['owners'][member]['stat']))
        transformed=data
        if member==SOURCE:
            transformed=canonical_source(data)
        dest=raw/'inputs'/relative;write(dest,transformed);os.chmod(dest,0o444)
        source_map[relative]=dict(original_member=member,original_owner=fact,original_mode=before['files'][member]['mode'],compiled=read(dest)[1],transformation='five-path-literals' if member==SOURCE else 'byte-identical')
    for spelling,row in archive['artifacts'].items():
        p=Path(row['path']);assert p.is_relative_to(build/'artifacts/common-sites-compile') and not p.is_relative_to(R/'target')
        data,fact=pinned(p,dict(sha256=row['sha256'],bytes=row['bytes'],stat=row['archive_owner']));originals[str(p)]=fact
        base=Path(spelling).name
        if base.endswith(('.rlib','.rmeta')):
            assert base.startswith('lib') and '/' not in base and base not in copies
            dest=raw/'inputs/deps'/base;write(dest,data);os.chmod(dest,0o444)
            copies[base]=dict(source=str(p),original=fact,copy=read(dest)[1])
    assert copies and len({tuple(v['copy']['stat'][:2]) for v in copies.values()})==len(copies)
    externs={}
    for alias,name in [('formats','liteinst_artifact'),('li2core','liteinst2'),('liteinst_rewrite','liteinst_rewrite'),('iced_x86','iced_x86')]:
        rows=[x for x in cargo if x['reason']=='compiler-artifact' and x['target']['name']==name and x['target']['kind']==['lib']]
        assert len(rows)==1
        libs=[Path(x).name for x in rows[0]['filenames'] if x.endswith('.rlib')];assert len(libs)==1 and libs[0] in copies
        externs[alias]='deps/'+libs[0]
    for d in (raw/'inputs/src',raw/'inputs/deps',raw/'inputs'):os.chmod(d,0o555)
    # Freeze only the fully populated compiler input tree. Output/temp never live here.
    directory_fds={};leaf_fds={};private={};dirs={}
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK
    rootfd=os.open(raw/'inputs',flags);held_fds.append(rootfd);directory_fds['']=rootfd
    for name in ('src','deps'):
        directory_fds[name]=os.open(name,flags,dir_fd=rootfd);held_fds.append(directory_fds[name])
    for name,fd in directory_fds.items():dirs[name]=six(os.fstat(fd));assert dirs[name]==six((raw/'inputs'/name).lstat())
    for name in list(MEMBERS)+['deps/'+n for n in sorted(copies)]:
        parent,base=name.split('/');fd=os.open(base,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory_fds[parent]);leaf_fds[name]=fd;held_fds.append(fd)
        private[name]=read(raw/'inputs'/name)[1];assert six(os.fstat(fd))==private[name]['stat']
    def private_snapshot():
        # Record actual observations; compare only after the saved after-map exists.
        actual_dirs={name:six(os.fstat(fd)) for name,fd in directory_fds.items()}
        path_dirs={name:six((raw/'inputs'/name).lstat()) for name in directory_fds}
        entries={name:sorted(os.listdir(fd)) for name,fd in directory_fds.items()}
        path_files={};opened_files={}
        for name,fd in leaf_fds.items():
            st=os.fstat(fd);assert stat.S_ISREG(st.st_mode) and st.st_size<=CAP
            data=os.pread(fd,st.st_size+1,0);assert len(data)==st.st_size and six(st)==six(os.fstat(fd))
            opened_files[name]=dict(sha256=sha(data),bytes=len(data),stat=six(st))
            path_files[name]=read(raw/'inputs'/name)[1]
        return dict(directories=actual_dirs,path_directories=path_dirs,entries=entries,files=path_files,opened_files=opened_files)
    private_expected=dict(directories=dirs,path_directories=dirs,entries={'':['deps','src'],**{name:sorted(p.split('/')[1] for p in private if p.startswith(name+'/')) for name in ('src','deps')}},files=private,opened_files=private)
    assert len({tuple(x['stat'][:2]) for x in private.values()})==len(private)
    private_before=private_snapshot();assert private_before==private_expected;write(raw/'private-before.json',private_before);write(raw/'source-transform.json',source_map);write(raw/'dependencies.json',dict(originals=originals,copies=copies,externs=externs))
    compiler=raw/'compile';exe=raw/'output/verify_common_core';dep=raw/'output/verify_common_core.d'
    argv=[tools[str(rustc)]['resolved'],'--crate-name','verify_common_core','--edition=2024','--crate-type=bin','-C','opt-level=0','-C','debuginfo=2','-C','debug-assertions=yes','-C','overflow-checks=yes','-C','codegen-units=4','-C','linker='+str(linker),'--emit=link='+str(exe)+',dep-info='+str(dep),'--out-dir',str(raw/'output'),'-L','dependency=deps']
    for name,path in sorted(externs.items()):argv+=['--extern',name+'='+path]
    argv+=['src/verify_common_core.rs']
    env=dict(base_request['env']);del env['CARGO_TARGET_DIR'];env['TMPDIR']=str(raw/'tmp')
    job=dict(schema=1,scope='DIRECT_RUSTC_CANONICAL_PRIVATE_INPUTS',input_root=str(raw/'inputs'),directories=dirs,files=private,rustc=tools[str(rustc)],argv=argv,env=env,entry=str(raw/'compiler-entry.json'))
    write(raw/'compiler-job.json',job)
    q=dict(argv=['/usr/bin/python3.9','-B',str(entry_source),'--job',str(raw/'compiler-job.json'),'--job-sha256',sha(read(raw/'compiler-job.json')[0])],cwd=str(R),env=ENV,stdout=str(compiler/'stdout.txt'),stderr=str(compiler/'stderr.txt'),cpu_seconds=60,wall_seconds=90,file_bytes=CAP)
    write(compiler/'request.json',q)
    outer=['/usr/bin/timeout','--signal=TERM','--kill-after=10s','100s','/usr/bin/python3.9','-B',str(R/'tools/unwind-oracle/bounded_command.py'),'--request',str(compiler/'request.json'),'--receipt',str(compiler/'receipt.json')]
    command=dict(request=q,argv=outer,cwd=str(R),env=ENV,parent_timeout_seconds=115)
    write(compiler/'command.json',command);start=time.monotonic();timedout=False
    with (compiler/'helper.stdout').open('xb') as out,(compiler/'helper.stderr').open('xb') as err:
        child=subprocess.Popen(outer,cwd=R,env=ENV,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
        try:
            write(compiler/'started.json',dict(pid=child.pid,source=caller['producer_sha256'],command_sha256=sha(read(compiler/'command.json')[0])))
            child.wait(timeout=115)
        except BaseException as error:
            timedout=isinstance(error,subprocess.TimeoutExpired)
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.wait();write(compiler/'result.json',dict(command,pid=child.pid,exit=child.returncode,parent_wait_returned=True,parent_timeout=timedout,aborted_by=type(error).__name__,elapsed_seconds=time.monotonic()-start));raise
    write(compiler/'result.json',dict(command,pid=child.pid,exit=child.returncode,parent_wait_returned=True,parent_timeout=False,elapsed_seconds=time.monotonic()-start))
    # Write all actual after observations before their equalities, retaining failures.
    after=c['source'](R);tools_after=tool_snapshot();configs_after=config_snapshot()
    originals_after={p:read(Path(p))[1] for p in originals};private_after=private_snapshot();linker_after=read(linker)
    for name,value in [('source-after.json',after),('tools-after.json',tools_after),('configs-after.json',configs_after),('dependencies-after.json',originals_after),('private-after.json',private_after),('linker-after.json',linker_after[1])]:write(raw/name,value)
    assert after==before and tools_after==tools and configs_after==configs and originals_after==originals and private_after==private_before and linker_after==linker_before
    assert child.returncode==c['receipt'](compiler,q)['exit']==0
    assert 0<=load(compiler/'result.json')['elapsed_seconds']<=115
    assert read(compiler/'stdout.txt')[0]==read(compiler/'stderr.txt')[0]==read(compiler/'helper.stderr')[0]==b''
    assert read(compiler/'helper.stdout')[0]==(json.dumps(dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True))+'\n').encode()
    entry=load(raw/'compiler-entry.json');assert entry['cwd']==str(raw/'inputs') and type(entry['pid']) is int and entry['pid']>0;assert entry['job_sha256']==sha(read(raw/'compiler-job.json')[0]) and entry['cwd_owner']==dirs[''] and entry['files']==private and entry['directories']==dirs and entry['argv']==argv and entry['env']==env and entry['rustc']==tools[str(rustc)]
    assert {p.name for p in (raw/'output').iterdir()}=={'verify_common_core','verify_common_core.d'}
    rules=n['depfile_rules'](read(dep)[0].decode());nonempty=[(t,v) for t,v in rules if v];empty=[t for t,v in rules if not v]
    assert len(nonempty)==2 and {t for t,v in nonempty}=={str(exe),str(dep)}
    for target,dependencies in nonempty:assert len(dependencies)==len(set(dependencies))==7 and set(dependencies)==set(MEMBERS)
    assert len(empty)==len(set(empty))==7 and set(empty)==set(MEMBERS)
    products={}
    for p in (exe,dep):
        data,fact=read(p);assert p!=exe or fact['stat'][2]&0o111
        dest=raw/'archive'/p.name;write(dest,data);os.chmod(dest,stat.S_IMODE(fact['stat'][2]));copy=read(dest)[1]
        assert read(p)==(data,fact) and read(dest)[0]==data
        products[p.name]=dict(original_path=str(p),original=fact,path=str(dest),archive=copy)
    assert private_snapshot()==private_before
    assert read(Path(__file__).resolve())==self_before and read(entry_source)==entry_before and read(a.caller)==(cb,caller_owner) and read(P/'references.json')==(reference_bytes,reference_owner)
    write(raw/'complete.json',dict(schema=1,revision=REV,status='DIRECT_RUSTC_VERIFIER_PRODUCED_REVIEW_REQUIRED',compiler_status='PASS_STRICT_RECEIPT',archive_status='PASS_FRESH_DIRECT_ARCHIVE',dependency_archive_records=len(originals),dependency_copies=len(copies),direct_source_dependencies=7,source_transform=source_map,products=products,application_or_verifier_executions=0,prior_four_archive_attempts='FAILED_UNCHANGED',existing_cargo_admission_compatible=False,qualification_complete=False))
    print(json.dumps(dict(status='DIRECT_RUSTC_VERIFIER_PRODUCED_REVIEW_REQUIRED',products=products,qualification_complete=False),sort_keys=True))

def index_saved_raw():
    rows={}
    for parent,dirs,names in os.walk(owned_raw,followlinks=False):
        for name in dirs:assert stat.S_ISDIR((Path(parent)/name).lstat().st_mode)
        for name in names:
            p=Path(parent)/name
            assert p.name!='raw-files.json'
            _,fact=read(p);rows[str(p)]=fact
    write(owned_raw/'raw-files.json',rows)

if __name__=='__main__':
    try:main()
    except BaseException as error:
        if owned_raw is not None:
            write(owned_raw/'failure.json',dict(schema=1,status='FAILED',error_type=type(error).__name__,message=str(error),qualification_complete=False))
        raise
    finally:
        for fd in reversed(held_fds):os.close(fd)
        if owned_raw is not None:index_saved_raw()
