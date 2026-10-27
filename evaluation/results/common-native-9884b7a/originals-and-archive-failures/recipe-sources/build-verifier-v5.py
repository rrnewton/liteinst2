#!/usr/bin/env python3
"""Fresh verifier compilation/archive at one fixed source and owner epoch.
No application/verifier execution. Caller records actual parent closure separately.
"""
import errno, hashlib, json, os, runpy, stat, subprocess, sys, time
from pathlib import Path
if sys.flags.optimize: raise SystemExit('assertions required')
repo=Path(__file__).resolve().parents[4]
raw=repo/'ignored/a3/common-native-epoch-v1/verifier-build-v4'
build=repo/'ignored/a3/common-native-epoch-v1/build-v1'
revision='9884b7a259b4e0ea80d2cca6d726abab4594807a'
pins={
'evaluation/e9-common-app/build_inventory.py':'31545ba44b5cb3b055a96269c689b9235957ec3dab0cfd3e65ba86efbdde71ed',
'evaluation/e9-common-app/run_candidates.py':'523ce6007068c5764be6bf007d67f8093aaedf4054b1beb3b7465bed95f1196f',
'ignored/a3/e9-common-verifier-archive-admission-proposal-v1/successor-v2/admit.py':'133690b51ec1cba4f887d79bf4303c00f263817b36c1ac0d3c41034cff5896a5'}
for name,digest in pins.items(): assert hashlib.sha256((repo/name).read_bytes()).hexdigest()==digest
n=runpy.run_path(str(repo/'evaluation/e9-common-app/build_inventory.py'),run_name='_build_archive_support_')
c=runpy.run_path(str(repo/'evaluation/e9-common-app/run_candidates.py'),run_name='_source_support_')
for name in ('read','write','path','sha','encode','loads','git','depfile_rules','CAP','PROFILE','RUNTIME','HELPER_SHA'): globals()[name]=n[name]

def fields(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]

def source_alias(repo, spelling, expected, git_bytes):
    """Walk actual lexical directories, never normalize past an unchecked owner."""
    prefix = str(repo) + '/'
    assert spelling.startswith(prefix), 'exact repository prefix required'
    parts = spelling[len(prefix):].split('/')
    assert parts and all(p not in ('', '.') for p in parts) and parts[-1] != '..'
    descriptors, stack, proofs = [], [], []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    def hold(path, name=None, parent=None):
        fd = os.open(path if name is None else name, flags, dir_fd=parent)
        descriptors.append(fd)
        st = os.fstat(fd); assert stat.S_ISDIR(st.st_mode)
        assert fields(st) == fields(os.stat(path, follow_symlinks=False))
        proofs.append((str(path), fd, fields(st)))
        return fd
    def stable():
        for path, fd, owner in proofs:
            assert fields(os.fstat(fd)) == fields(os.stat(path, follow_symlinks=False)) == owner, 'directory drift'
    try:
        current = Path('/'); fd = hold(current)
        for part in repo.parts[1:]:
            current = current / part; fd = hold(current, part, fd)
        stack = [(repo, fd)]
        for part in parts[:-1]:
            if part == '..':
                assert len(stack) > 1, 'lexical escape, even if later returning'
                parent = stack[-2]
                up = hold(parent[0], '..', stack[-1][1])
                assert fields(os.fstat(up)) == fields(os.fstat(parent[1]))
                stack.pop()
            else:
                parent_path, parent_fd = stack[-1]
                child_path = parent_path / part
                stack.append((child_path, hold(child_path, part, parent_fd)))
        canonical = stack[-1][0] / parts[-1]
        member = canonical.relative_to(repo).as_posix()
        assert member == expected['canonical_member']
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=stack[-1][1])
        with os.fdopen(fd, 'rb') as f:
            before = os.fstat(f.fileno())
            assert stat.S_ISREG(before.st_mode) and before.st_size == expected['bytes'] <= CAP
            data = f.read(CAP + 1)
            assert fields(before) == fields(os.fstat(f.fileno())) == fields(canonical.lstat())
            assert data == git_bytes and sha(data) == expected['sha256'] and len(data) == expected['bytes']
            assert bool(before.st_mode & 0o111) == (expected['mode'] == '100755')
            stable()
            # Read the original, unnormalized spelling as well. All intermediates
            # were held above; compare the resulting leaf's whole bytes and owner.
            with os.fdopen(os.open(spelling, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as alias:
                alias_owner = fields(os.fstat(alias.fileno()))
                assert alias_owner == fields(before)
                alias_data = alias.read(CAP + 1)
                assert alias_data == data
                assert fields(os.fstat(alias.fileno())) == fields(before)
            stable()
            assert fields(canonical.lstat()) == fields(before)
            return dict(spelling=spelling, canonical_member=member, sha256=sha(data), bytes=len(data),
                        mode=expected['mode'], fresh_owner=fields(before),
                        alias_owner=alias_owner, alias_sha256=sha(alias_data), alias_bytes=len(alias_data),
                        directory_observations=[dict(path=p, owner=s) for p, _, s in proofs])
    finally:
        for fd in reversed(descriptors): os.close(fd)

def unique_bindings(rows):
    assert len({r['canonical_member'] for r in rows}) == len(rows)
    assert len({tuple(r['fresh_owner'][:2]) for r in rows}) == len(rows), 'duplicate physical source alias'

def tool_snapshot():
    result = {}
    for p in tool_paths:
        resolved = p.resolve(strict=True)
        data, owner = read(resolved)
        assert owner[2] & 0o111
        result[str(p)] = dict(resolved=str(resolved), sha256=sha(data), stat=owner)
    return result

def config_snapshot():
    result = {}
    for p in config_paths:
        try:
            exists = p.exists()
        except PermissionError as error:
            assert error.errno in (errno.EPERM, errno.EACCES)
            result[str(p)] = dict(observation='READ_DENIED', operation='metadata_lookup', errno=error.errno, exists=None, content_sha256=None)
            continue
        if not exists and not p.is_symlink():
            result[str(p)] = dict(exists=False)
        else:
            resolved = p.resolve(strict=True)
            data, owner = read(resolved)
            link = p.lstat()
            result[str(p)] = dict(exists=True, resolved=str(resolved), sha256=sha(data), stat=owner, lstat=[link.st_dev, link.st_ino, link.st_mode, link.st_size, link.st_mtime_ns, link.st_ctime_ns])
    return result

def archive(compilation, selected):
    messages = [loads(line) for line in read(compilation / 'stdout.txt')[0].splitlines()]
    assert 1 <= len(messages) <= 512 and messages[-1] == dict(reason='build-finished', success=True)
    assert sum(r.get('reason') == 'build-finished' for r in messages) == 1
    assert all(r.get('reason') in ('compiler-artifact', 'build-script-executed', 'build-finished') for r in messages)
    assert not any(line.startswith(('warning:', 'error:')) for line in read(compilation / 'stderr.txt')[0].decode().splitlines())
    dest = raw / 'artifacts' / compilation.name
    dest.mkdir()
    copied = {}
    def copy(p):
        p = path(str(p))
        assert p.is_relative_to(repo / 'target')
        data, owner = read(p)
        if str(p) not in copied:
            to = dest / ('product-' + str(len(copied)))
            write(to, data)
            os.chmod(to, stat.S_IMODE(owner[2]))
            assert read(p) == (data, owner) and read(to)[0] == data
            copied[str(p)] = dict(path=str(to), sha256=sha(data), bytes=len(data), original_owner=owner, archive_owner=read(to)[1])
        else:
            assert owner == copied[str(p)]['original_owner'] and sha(data) == copied[str(p)]['sha256']
        return copied[str(p)]
    for row in messages:
        if row['reason'] == 'compiler-artifact':
            assert type(row['fresh']) is bool and row['filenames']
            for p in row['filenames']:
                copy(p)
    chosen = {}
    for name, package, kind, relative_source in selected:
        rows = [r for r in messages if r['reason'] == 'compiler-artifact' and r['target']['name'] == name and r.get('executable')]
        assert len(rows) == 1
        row = rows[0]
        expected = repo / 'target/debug' / ('examples/' + name if kind == 'example' else name)
        assert row['manifest_path'] == str(repo / package / 'Cargo.toml')
        package_name = 'liteinst2' if not package else 'liteinst-rewrite'
        assert row['package_id'] == 'path+' + (repo / package).as_uri() + '#' + package_name + '@0.1.0'
        assert row['target']['kind'] == [kind] and row['target']['crate_types'] == ['bin']
        assert row['target']['edition'] == '2024'
        assert row['target']['src_path'] == str(repo / relative_source)
        assert row['profile'] == PROFILE and row['features'] == []
        assert row['filenames'] == [str(expected)] and row['executable'] == str(expected)
        product = copy(expected)
        assert product['original_owner'][2] & 0o111
        dep = expected.with_suffix('.d')
        saved_dep = copy(dep)
        rules = depfile_rules(read(dep)[0].decode())
        assert len(rules) == 1 and rules[0][0] == str(expected) and rules[0][1]
        bindings = {}
        for spelling in rules[0][1]:
            alias_row = observe_alias(spelling)
            member = alias_row['canonical_member']
            assert member not in bindings
            bindings[member] = before['files'][member]
            aliases.append(alias_row)
        unique_bindings(aliases)
        assert relative_source in bindings
        chosen[name] = dict(cargo=row, product=product, depfile=saved_dep, source_bindings=bindings)
        products[name] = product['path']
    report = dict(schema=1, source_revision=revision, source_files_sha256=sha(encode(before['files'])), command_result_sha256=sha(read(compilation / 'result.json')[0]), cargo_stdout_sha256=sha(read(compilation / 'stdout.txt')[0]), artifacts=copied, selected=chosen,
                  scope='Complete Cargo-reported products and exact selected Cargo alias depfiles/source members; not a whole target, system-header, configuration or loader closure.')
    write(compilation / 'artifact-archive.json', report)
    archives[compilation.name] = report


def observe_alias(spelling):
    prefix=str(repo)+'/'
    assert spelling.startswith(prefix)
    parts=spelling[len(prefix):].split('/')
    assert parts and all(p not in ('','.') for p in parts) and parts[-1]!='..'
    stack=[]
    for part in parts:
        if part=='..':
            assert stack, 'no lexical escape, including leave-and-return'
            stack.pop()
        else: stack.append(part)
    member='/'.join(stack)
    assert member in before['files']
    expected=dict(before['files'][member],canonical_member=member)
    data=git(repo,'show',revision+':'+member)
    row=source_alias(repo,spelling,expected,data)
    assert row['fresh_owner']==before['owners'][member]['stat']
    return row

def target_snapshot():
    result={}
    for path,row in archives['verifier-compile']['artifacts'].items():
        data,owner=read(path)
        assert owner==row['original_owner'] and sha(data)==row['sha256'] and len(data)==row['bytes']
        copy,copy_owner=read(row['path'])
        assert copy==data and copy_owner==row['archive_owner']
        result[path]=dict(sha256=sha(data),bytes=len(data),stat=owner)
    return result

assert not raw.exists() and not raw.is_symlink()
raw.mkdir(); (raw/'artifacts').mkdir(); compilation=raw/'verifier-compile'; compilation.mkdir(); (compilation/'tmp').mkdir()
self_before=read(Path(__file__).resolve())
before=c['source'](repo)
assert before['revision']==revision
saved=loads(read(build/'source.json')[0])
assert before['files']==saved['files'] and saved['revision']==revision
assert {p:x['stat'] for p,x in before['owners'].items()}==saved['owners']
assert read(build/'source.json')[0]==read(build/'source-after.json')[0]
tool_paths=[Path(p) for p in loads(read(build/'tools.json')[0])]
config_paths=[Path(p) for p in loads(read(build/'configs.json')[0])]
tools=tool_snapshot(); configs=config_snapshot()
assert tools==loads(read(build/'tools.json')[0]) and configs==loads(read(build/'configs.json')[0])
for name,value in [('source.json',before),('tools.json',tools),('configs.json',configs)]:write(raw/name,value)
archives={}; products={}; aliases=[]
request=loads(read(build/'common-sites-compile/request.json')[0])
assert request['argv'][1:]==['build','-p','liteinst-rewrite','--example','common_sites','--offline','--locked','--message-format=json']
request['argv'][5]='verify_common_core'
for name in ('stdout','stderr'):request[name]=str(compilation/(name+'.txt'))
request['env']['TMPDIR']=str(compilation/'tmp')
assert (request['cpu_seconds'],request['wall_seconds'],request['file_bytes'])==(60,90,128*1024*1024)
write(compilation/'request.json',request)
outer=['/usr/bin/timeout','--signal=TERM','--kill-after=10s','100s','/usr/bin/python3.9','-B',str(repo/'tools/unwind-oracle/bounded_command.py'),'--request',str(compilation/'request.json'),'--receipt',str(compilation/'receipt.json')]
command=dict(argv=request['argv'],cwd=str(repo),env=request['env'],request=request,outer_argv=outer,outer_env=RUNTIME,parent_timeout_seconds=115)
write(compilation/'command.json',command); start=time.monotonic()
with (compilation/'helper.stdout').open('xb') as out,(compilation/'helper.stderr').open('xb') as err:
    child=subprocess.run(outer,cwd=repo,env=RUNTIME,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=115)
result=dict(command,exit=child.returncode,elapsed_seconds=time.monotonic()-start,parent_timeout=False)
write(compilation/'result.json',result)
assert child.returncode==c['receipt'](compilation,request)['exit']==0
assert not read(compilation/'helper.stderr')[0]
assert read(compilation/'helper.stdout')[0]==(json.dumps(dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True))+'\n').encode()
archive(compilation,[('verify_common_core','tools/elf-rewrite','example','tools/elf-rewrite/examples/verify_common_core.rs')])
target_before=target_snapshot()
write(raw/'target-owners-before.json',target_before)
write(raw/'source-aliases-before.json',aliases)
after=c['source'](repo)
aliases_after=[observe_alias(x['spelling']) for x in aliases]
target_after=target_snapshot()
tools_after=tool_snapshot(); configs_after=config_snapshot()
for name,value in [('source-after.json',after),('tools-after.json',tools_after),('configs-after.json',configs_after),('target-owners-after.json',target_after),('source-aliases-after.json',aliases_after),('artifacts.json',archives)]:write(raw/name,value)
assert after==before and tools_after==tools and configs_after==configs
assert aliases_after==aliases and target_after==target_before
assert read(Path(__file__).resolve())==self_before
for name,digest in pins.items(): assert sha(read(repo/name)[0])==digest
write(raw/'complete.json',dict(schema=1,revision=revision,compiler_status='PASS_STRICT_RECEIPT',archive_status='PASS_FRESH_ARCHIVE',artifacts=len(target_before),source_dependencies=len(aliases),source_tools_configs_unchanged=True,application_or_verifier_executions=0,qualification_complete=False,products=products))
print(json.dumps(dict(status='FRESH_COMPILER_ARCHIVE_CLOSED_INSIDE_RECIPE',artifacts=len(target_before),source_dependencies=len(aliases),products=products)),flush=True)
