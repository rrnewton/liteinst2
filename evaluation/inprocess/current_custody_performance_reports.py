"""Current-custody production counters plus every unchanged terminal check."""
import hashlib,json
from page_selected import need
import current_custody_reports as current
import unrolled_hash_reports as old
H=lambda b:hashlib.sha256(b).hexdigest()
KEYS=current.CURRENT_KEYS


def completed(row):
    need(row['version']==1 and all(row[k]==0 for k in
         ('status','failure_code','first_error','first_detail_abs','first_detail_negative')),
         'complete successful current-custody counter outcome')
    a,s,n,f,r,c,k,x=(row[key]for key in
        ('attempts','current_stages','current_seeds','physical_fallbacks','retained_stages','retained_checks','commits','cancels'))
    need(a==s+f and s>=n>0 and r>0 and s+r==k+x and n<=k<=n+r and c==r+k-n,
         'all completed current seed, retained-stage, commit, cancellation and physical-fallback counts close')


def check(stdout,stderr,args,kind,lane):
    need(lane in('current','differential'),'explicit current-custody production lane')
    row,suffix=current.split_current(stderr);completed(row)
    parsed,summary,view,owner,unused=old.check(stdout,suffix,args,kind,
        'differential'if lane=='differential'else'unrolled')
    need(row['status']==parsed['loader']['status']and row['failure_code']==parsed['loader']['failure_code'],
         'new current row and complete original outcome agree')
    return parsed,summary,view,owner,row


def controls(stdout,stderr,args,kind,lane):
    check(stdout,stderr,args,kind,lane)
    row,suffix=current.split_current(stderr)
    retained=old.controls(stdout,suffix,args,kind,'differential'if lane=='differential'else'unrolled')
    first=stderr.split(b'\n',1)[0];trials=[]
    def changed(name,value):
        trials.append((name,current.CURRENT_PREFIX+json.dumps(value,separators=(',',':'),allow_nan=False).encode()+b'\n'+suffix))
    for key in KEYS:
        value=dict(row);value[key]^=1;changed('current_'+key,value)
    for name,value in(('boolean',True),('float',0.5),('negative',-1),('overflow',1<<64)):
        changed_row=dict(row);changed_row['attempts']=value;changed('current_type_'+name,changed_row)
    short=dict(row);del short['first_error'];changed('current_missing_key',short)
    extra=dict(row);extra['extra']=0;changed('current_extra_key',extra)
    changed('current_reordered',dict(reversed(list(row.items()))))
    next_row,remaining=suffix.split(b'\n',1)
    trials.extend([('current_absent',suffix),('current_duplicate',first+b'\n'+stderr),
        ('current_misplaced',next_row+b'\n'+first+b'\n'+remaining),('current_truncated',stderr[:-1]),
        ('current_duplicate_key',first[:-1]+b',"version":1}\n'+suffix)])
    need(len(trials)==len({name for name,_ in trials})==26,'all26 additional production current-row refusals')
    refused=[]
    for name,value in trials:
        caught=False
        try:check(stdout,value,args,kind,lane)
        except ValueError:caught=True
        need(caught,'complete current production reader refuses '+name);refused.append(name)
    return dict(original=retained,current_refusals=refused,native_operations=0,
        original_stderr_sha256=H(stderr),legacy_stderr_sha256=H(suffix))
