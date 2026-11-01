"""Pure arithmetic/path controls; no product, request or subject-running import."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import resource
import sys
import tempfile

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit('Use assertions-enabled Python -I -B')
for key,value in ((resource.RLIMIT_CPU,30),(resource.RLIMIT_AS,268435456),
                  (resource.RLIMIT_FSIZE,1048576),(resource.RLIMIT_CORE,0)):
    resource.setrlimit(key,(value,value))
path = Path(__file__).resolve().with_name('matrix_disk.py')
data = path.read_bytes()
assert hashlib.sha256(data).hexdigest() == 'd0202e52f4aaccc1c700e3043c497b0e7a140d8bc1f517445ed1d2a3a7882ac1'
spec = importlib.util.spec_from_file_location('pure_matrix_disk',path)
md = importlib.util.module_from_spec(spec); spec.loader.exec_module(md)
assert path.read_bytes() == data


def refuses(fn):
    try:
        fn()
    except AssertionError:
        return
    raise AssertionError('expected refusal')


def sample(data=0,meta=0):
    return dict(data=dict(allocated=data,apparent=data),metadata=dict(allocated=meta,apparent=meta))


reserve = 2_214_592_512
assert reserve == md.DATA+md.META
slot = dict(allocated=20_000_000_000-reserve,apparent=20_000_000_000-reserve)
zero = sample()
accepted = md.admit(slot,zero,zero,initial=True)
assert all(q['unused'] == reserve and q['credit_data'] == q['credit_metadata'] == 0 for q in accepted.values())
refuses(lambda:md.admit({k:v+1 for k,v in slot.items()},zero,zero,initial=True))
print('PASS initial_full_reservation')

used = sample(1000,200)
s = {k:v+1200 for k,v in slot.items()}
accepted = md.admit(s,used,used)
assert all(q['unused'] == reserve-1200 for q in accepted.values())
refuses(lambda:md.admit({k:v+1 for k,v in s.items()},used,used))
print('PASS prior_failed_retention_and_outside_growth')

after = sample(1200,400)
accepted = md.admit(s,used,after)
assert all(q['credit_data'] == 1000 and q['credit_metadata'] == 200 and
           q['used_data'] == 1200 and q['used_metadata'] == 400 for q in accepted.values())
refuses(lambda:md.admit({k:v+1 for k,v in s.items()},used,after))
print('PASS lower_credit_higher_cap')

asymmetric = sample(); asymmetric['data']['apparent'] = 2000
refuses(lambda:md.admit(dict(allocated=slot['allocated']+1000,apparent=slot['apparent']),asymmetric,asymmetric))
refuses(lambda:md.admit(slot,sample(md.DATA+1),sample(md.DATA+1)))
refuses(lambda:md.admit(slot,sample(meta=md.META+1),sample(meta=md.META+1)))
print('PASS no_cross_dimension_or_negative_unused_credit')

allowance = 512*md.M+2*32*md.M
at_boundary = sample(md.DATA-allowance-md.M,md.META-16*md.M-md.M)
md.local_admit(at_boundary,allowance,16*md.M)
refuses(lambda:md.local_admit(at_boundary,allowance+1,16*md.M))
refuses(lambda:md.local_admit(at_boundary,allowance,16*md.M+1))
print('PASS exact_immediate_product_and_capture_admission')

with tempfile.TemporaryDirectory(prefix='stock-matrix-pure-') as tmp:
    root = Path(tmp).resolve(); (root/'ignored/a3/matrix').mkdir(parents=True)
    (root/'target/evaluation').mkdir(parents=True)
    rows = [dict(action_index=i,run='ignored/a3/stock-'+str(i),logs='target/evaluation/stock-'+str(i),
                 owner='ignored/a3/stock-'+str(i)+'-owner',owner_logs='target/evaluation/stock-'+str(i)+'-owner') for i in (1,2,3,4)]
    doc = dict(schema=1,profile=md.PROFILE,data_bytes=md.DATA,metadata_bytes=md.META,slot_bytes=md.SLOT,actions=rows)
    paths = md.layout(root,root/'ignored/a3/matrix/matrix.json',doc)
    assert len(md.initial_absence(paths)['absent']) == 16
    alias = copy.deepcopy(doc); alias['actions'][1]['run'] = alias['actions'][0]['run']
    refuses(lambda:md.layout(root,root/'ignored/a3/matrix/matrix.json',alias))
    duplicate = copy.deepcopy(doc); duplicate['actions'][1]['action_index'] = 1
    refuses(lambda:md.layout(root,root/'ignored/a3/matrix/matrix.json',duplicate))
    base = paths['data'][0]; base.mkdir(); refuses(lambda:md.initial_absence(paths))
    (base/'one').write_bytes(b'abc'); os.link(base/'one',base/'two')
    q = md.charge([base]); st = base.stat(); file = (base/'one').stat()
    assert q['apparent'] == st.st_size+6 and q['allocated'] == st.st_blocks*512+2*file.st_blocks*512
    (base/'bad').symlink_to(base/'one'); refuses(lambda:md.charge([base]))
print('PASS fixed_paths_absence_alias_and_hardlink_counts')
