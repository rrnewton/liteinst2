"""Fixed four-action disk accounting. No subject imports or native dispatch."""
import json
import os
from pathlib import Path
import stat

M = 1024**2
DATA, META, SLOT = 2048*M, 64*M, 20_000_000_000
PROFILE = 'stock-matrix-disk-v1'


def layout(root, path, document):
    root, path = Path(root), Path(path)
    assert path == path.resolve() and path.name == 'matrix.json'
    assert path.parent.parent == root/'ignored/a3'
    assert document['schema'] == 1 and document['profile'] == PROFILE
    assert document['data_bytes'] == DATA and document['metadata_bytes'] == META
    assert document['slot_bytes'] == SLOT
    assert [r['action_index'] for r in document['actions']] == [1,2,3,4]
    roots = []
    for row in document['actions']:
        assert set(row) == {'action_index','run','logs','owner','owner_logs'}
        assert all(isinstance(row[k],str) and not Path(row[k]).is_absolute()
                   and str(Path(row[k])) == row[k] and '..' not in Path(row[k]).parts
                   for k in ('run','logs','owner','owner_logs'))
        run = root/row['run']; logs = root/row['logs']
        owner = root/row['owner']; owner_logs = root/row['owner_logs']
        assert run == run.resolve() and run.parent == root/'ignored/a3'
        assert logs == root/'target/evaluation'/run.name
        assert owner == run.with_name(run.name+'-owner')
        assert owner_logs == root/'target/evaluation'/owner.name
        for p in (run,logs,owner,owner_logs):
            assert p == p.resolve() and p != path.parent
        roots += [run,logs,owner,owner_logs]
    assert len(roots) == len(set(roots)) == 16
    assert all(a not in b.parents and b not in a.parents for i,a in enumerate(roots) for b in roots[i+1:])
    assert all(path.parent not in p.parents and p not in path.parent.parents for p in roots)
    return dict(data=[root/r[k] for r in document['actions'] for k in ('run','logs')],
                metadata=[root/r[k] for r in document['actions'] for k in ('owner','owner_logs')]+[path.parent],
                roots=roots)


def initial_absence(paths):
    assert all(not os.path.lexists(p) for p in paths['roots'])
    return dict(absent=[str(p) for p in paths['roots']])


def charge(roots):
    apparent = allocated = 0
    for base in roots:
        if not os.path.lexists(base):
            continue
        assert base == base.resolve() and stat.S_ISDIR(base.lstat().st_mode)
        for directory,dirs,files in os.walk(base,followlinks=False):
            for path in [Path(directory),*(Path(directory)/n for n in files)]:
                s = path.lstat()
                assert stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode)
                apparent += s.st_size; allocated += s.st_blocks*512
            assert all(not (Path(directory)/n).is_symlink() for n in dirs)
    return dict(apparent=apparent,allocated=allocated,charged=max(apparent,allocated))


def measure(paths, expected=None):
    if expected is not None:
        for path,identity in expected.items():
            s = Path(path).lstat()
            assert stat.S_ISDIR(s.st_mode) and [s.st_dev,s.st_ino] == identity
    return {k:charge(paths[k]) for k in ('data','metadata')}


def admit(slot, before, after, data_allowance=0, metadata_allowance=0, initial=False):
    assert type(initial) is bool
    assert type(data_allowance) is int and data_allowance >= 0
    assert type(metadata_allowance) is int and metadata_allowance >= 0
    result = {}
    for dimension in ('allocated','apparent'):
        values = [slot[dimension],before['data'][dimension],after['data'][dimension],
                  before['metadata'][dimension],after['metadata'][dimension]]
        assert all(type(n) is int and n >= 0 for n in values)
        used_data = max(before['data'][dimension],after['data'][dimension])
        used_meta = max(before['metadata'][dimension],after['metadata'][dimension])
        assert used_data+data_allowance+M <= DATA, 'Shared data envelope exhausted'
        assert used_meta+metadata_allowance+M <= META, 'Shared metadata envelope exhausted'
        credit_data = 0 if initial else min(before['data'][dimension],after['data'][dimension])
        credit_meta = 0 if initial else min(before['metadata'][dimension],after['metadata'][dimension])
        unused = (DATA-credit_data)+(META-credit_meta)
        assert slot[dimension]+unused <= SLOT, 'Current slot plus unused matrix envelope exceeds20GB'
        result[dimension] = dict(slot=slot[dimension],used_data=used_data,used_metadata=used_meta,
                                credit_data=credit_data,credit_metadata=credit_meta,unused=unused)
    return result


def local_admit(current, data_allowance, metadata_allowance):
    assert type(data_allowance) is int and data_allowance >= 0
    assert type(metadata_allowance) is int and metadata_allowance >= 0
    for dimension in ('allocated','apparent'):
        assert current['data'][dimension]+data_allowance+M <= DATA, 'Shared data envelope exhausted'
        assert current['metadata'][dimension]+metadata_allowance+M <= META, 'Shared metadata envelope exhausted'
    return current


def capture_remaining(root, row):
    # Both the current target outer log and its retained copy consume metadata.
    # Credit only the smaller dimension, never an allocation in another dimension.
    totals = [0,0]
    for path in (root/row['owner_logs']/'outer.log',root/row['owner']/'outer.log'):
        if os.path.lexists(path):
            s = path.lstat(); assert stat.S_ISREG(s.st_mode) and s.st_size <= 8*M
            totals[0] += s.st_size; totals[1] += s.st_blocks*512
    return max(0,16*M-min(totals))


def identities(paths):
    result = {}
    for p in paths['roots']:
        if os.path.lexists(p):
            s = p.lstat(); assert stat.S_ISDIR(s.st_mode) and p == p.resolve()
            result[str(p)] = [s.st_dev,s.st_ino]
    return result


def released(live):
    pid = live['pid']; assert type(pid) is int and pid > 0
    old = live['stat'].rsplit(')',1)[1].split()[19]
    path = Path('/proc')/str(pid)/'stat'
    try:
        current = path.read_text().rsplit(')',1)[1].split()[19]
    except FileNotFoundError:
        current = None
    assert current != old, 'Prior process identity still live'
    lines = live['cgroup'].splitlines(); assert len(lines) == 1 and lines[0].startswith('0::/')
    group = Path('/sys/fs/cgroup')/lines[0][4:]
    assert not group.exists(), 'Prior scope not released'


def predecessors(root, document, index, pin, matrix_pin, matrix_path, previous_sha):
    retained = {}
    assert index in (2,3,4) and len(previous_sha) == 64
    def read(p):
        q = pin(p); value = json.loads(p.read_text()); assert pin(p) == q
        retained[str(p)] = q; return value
    previous_path = root/document['actions'][index-2]['owner']/'closed.json'
    assert pin(previous_path)['sha256'] == previous_sha
    previous = read(previous_path)
    for row in document['actions'][:index-1]:
        meta,run = root/row['owner'],root/row['run']
        if row['action_index'] < index-1:
            assert pin(meta/'closed.json') == previous['prior_closed'][str(meta/'closed.json')]
        closed = read(meta/'closed.json'); live = read(meta/'live.json')
        owned = read(meta/'owner-closed.json'); receipt = read(run/'receipt.json')
        assert pin(meta/'live.json') == closed['live']
        assert pin(meta/'owner-closed.json') == closed['owner_closed']
        assert closed['action_index'] == row['action_index'] and closed['matrix_continue'] is True
        assert closed['source_unchanged'] is True and closed['normal'] is True
        assert all(closed['matrix'][k] == matrix_pin[k] for k in ('bytes','sha256'))
        assert closed['result'] == owned['result']
        assert closed['result']['exit_code'] in (0,1) and closed['result']['termination'] is None
        assert closed['result']['cleanup_complete'] and closed['result']['reaped_descendants'] == 0
        assert pin(run/'receipt.json') == closed['receipt']
        assert pin(matrix_path.with_name('initial.json')) == closed['initial']
        assert receipt['source_unchanged'] is True and receipt['action_index'] == row['action_index']
        assert receipt['matrix_final_admission'] and len(receipt['dispatch_attempts']) == len(receipt['chains']) == 6
        pairs = [(r,s) for r in ('original','li2','e9') for s in ('e9tool','e9patch')]
        assert receipt['dispatch_attempts'] == [r+'-'+s for r,s in pairs]
        assert [(r['role'],r['source']) for r in receipt['chains']] == pairs
        assert all(r['owner']['cleanup_complete'] and r['owner']['reaped_descendants'] == 0 for r in receipt['chains'])
        for p,identity in closed['matrix_root_identities'].items():
            s = Path(p).lstat(); assert stat.S_ISDIR(s.st_mode) and [s.st_dev,s.st_ino] == identity
        released(live); released(receipt['before'])
        # Do not replay the preceding action's frozen external inode identities.
        # Its exact CLOSED record remains pinned; this action freezes current ones.
    return retained
