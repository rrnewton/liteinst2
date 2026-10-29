"""One additive gate report; unchanged boundary completion still owns success."""
import importlib.util
import json
from pathlib import Path

SCALARS = {'version','status','failure_code','detail_abs','detail_negative'}
ARRAYS = dict(prefix=15,launch=7,current=7,query=7,mount=12,commands=3)
def need(ok, message):
    if not ok: raise ValueError(message)
def unique(pairs):
    row = {}
    for k,v in pairs:
        need(k not in row, 'duplicate report field');row[k] = v
    return row
def old_reader(root):
    p = Path(root)/'tools/page-entry/selected/tests/rseq_native_boundary/reports.py'
    s = importlib.util.spec_from_file_location('tcgets_original_boundary_reports',p)
    m = importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def split(stderr):
    need(type(stderr) is bytes and stderr.endswith(b'\n'), 'complete stderr')
    lines = stderr[:-1].split(b'\n')
    ix = [i for i,x in enumerate(lines) if x.startswith(b'LI2_RSEQ_BTRFS_TTY_QUERY ')]
    need(len(ix) == 1, 'one actual gate row')
    at = ix[0]
    need(at > 0 and at+1 < len(lines) and lines[at-1].startswith(b'LI2_RSEQ_BOUNDARY ') and
         lines[at+1].startswith(b'LI2_CHAIN ') and len(lines[at])+1 <= 4096,
         'bounded extension at exact production report position')
    row = json.loads(lines[at][len(b'LI2_RSEQ_BTRFS_TTY_QUERY '):],object_pairs_hook=unique)
    need(type(row) is dict and set(row) == SCALARS|set(ARRAYS)|{'scope'} and
         row['scope'] == 'trusted_parent_capture_btrfs_tcgets_tiocgwinsz_v1', 'exact gate report contract')
    for k in SCALARS:
        need(type(row[k]) is int and 0 <= row[k] < 1<<64, 'typed unsigned scalar')
    for k,n in ARRAYS.items():
        need(type(row[k]) is list and len(row[k]) == n and
             all(type(x) is int and 0 <= x < 1<<64 for x in row[k]), 'complete typed gate array')
    return row,b'\n'.join(lines[:at]+lines[at+1:])+b'\n'
def check(stderr,pid,exit_code,parent,old):
    o,terminal = split(stderr);p = old.reports(terminal)
    need(type(pid) is int and pid > 0 and type(exit_code) is int and exit_code in (0,125),
         'actual report-bearing terminal process')
    need(o['version'] == 1 and o['status'] == exit_code and
         all(o[k] == p['loader'][k] for k in ('status','failure_code','detail_abs','detail_negative')),
         'same terminal outcome, never a failed operation relabel')
    x,q,m = o['prefix'],o['query'],o['mount']
    need(x[0] == 1 and o['launch'] == parent['identity'] and
         all(v in (0,1) for v in (x[1],x[5],*q[:2],q[4],q[6],*m[:5],m[6],m[8],o['detail_negative'])) and
         x[2] <= 8 and x[11] <= x[10] <= x[9] <= x[8] <= x[7] and q[1] <= q[0] and
         m[9] <= 256<<10 and m[10] <= 2048 and m[11] <= 1,
         'actual normal-open launch identity and bounded truthful gate prefixes')
    need((x[1] == 0 and x[6] == 0) or (x[1] == 1 and x[6] == 3),
         'permanent invalidation records attempted close(1)')
    if x[8] and x[7] == x[8]:
        need(o['current'][:5] == o['launch'][:5] and
             o['current'][5] & 0o170000 == o['launch'][5] & 0o170000 == 0o100000 and
             not o['current'][6] & 0o10000000 and x[13] > 0 and x[14] > 0,
             'actual admitted descriptor identity and registration/check prefix')
    if x[11] and x[7] == x[11]:
        need(x[7] == x[8] == x[9] == x[10] == x[11] and q[5:] == [25,1] and
             q[:2] == [1,1] and m[:5] == [1]*5 and m[7:9] == [0,0] and
             m[9] > 0 and m[10] > 0 and m[11] == 1,
             'actual last completed result is -ENOTTY with full unique mount closure')
    commands=o['commands']
    need(commands[0]+commands[1]==x[11] and commands[2]in(0,0x5401,0x5413) and
         (commands[2]==0)==(x[7]==0),'exact per-command actual validated-return accounting')
    if x[11] and x[7]==x[11]:
        need(commands[0 if commands[2]==0x5401 else 1]>0,
             'actual last completed command belongs to its nonempty counter')
    completed = False
    if exit_code == 0:
        old.completed(p,pid)  # Every original report, epoch, rseq, native and owner guard.
        need(o['failure_code'] == o['detail_abs'] == o['detail_negative'] == x[3] == x[4] == x[5] == 0 and
             x[2] in (2,7) and x[7] == x[8] == x[9] == x[10] == x[11],
             'no pending or failed gate at application completion')
        if x[11]:
            need(x[2] == 7 and q[5:] == [25,1] and q[:2] == [1,1] and
                 m[:5] == [1]*5 and m[7:9] == [0,0] and m[9] > 0 and m[10] > 0 and m[11] == 1,
                 'actual last -ENOTTY and complete unique mount proof before commit')
        need(commands[0]>0 and commands[1]>0,
             'successful two-query diagnostic must actually validate both exact commands')
        completed = True
    else:
        refused = False
        try: old.completed(p,pid)
        except ValueError: refused = True
        need(refused, 'unchanged completed rejects failed operation')
    return o,p,dict(application_completed=completed,gate_result_validations=x[11],
        attempts=x[7],permitted=x[8],issued=x[9],returned=x[10],invalidated=x[1],
        tcgets_result_validations=commands[0],tiocgwinsz_result_validations=commands[1],last_command=commands[2],
        gate_phase=x[2],gate_first_error=x[3],gate_first_detail_abs=x[4],
        last_result_abs=q[5],last_result_negative=q[6],failure_code=o['failure_code'],
        detail_abs=o['detail_abs'],detail_negative=o['detail_negative'],
        original_completed_rejected=not completed)
