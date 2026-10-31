"""Additional actual scalar/reuse rows around the unchanged ls/true reader.

These are release terminal checks. Full frame/plan/retirement qualification is
a separate mandatory same-revision prerequisite, never inferred from counters.
"""
import copy,json
from page_selected import need
import scalar_reuse_reports as reuse
import unrolled_hash_reports as old


def current(row):
    c=row['current']
    if c[0]:
        need(c[0]==1 and c[1]<row['used'] and c[2:5]==[1,1,1] and c[5]<8 and
             c[6:14]==[1]*8 and c[14:20]==[0,0,1,1,0,0] and c[20:24]==[0]*4 and
             c[24:29]==[4096,4096,4096,0,1] and c[29:31]in([0,0],[1,1]) and c[31]==0 and
             c[32]&~0xffff==0 and c[32]&16==0 and c[33]&~0x8d5==0,
             'actual scalar current completed and closed full image/source with bounded union effects')
    else:
        # try() clears current before each candidate. A final source/capacity
        # miss or a returned planner refusal is a complete non-entry prefix.
        expected=[0]*34;expected[16]=1
        if c[29:31]==[1,1]:
            need(c[31]in(1,2402,2403,2404) and
                 row['refusals'][(1,2402,2403,2404).index(c[31])]>0,
                 'actual final returned planner refusal counted in its exact class')
            expected[29:32]=c[29:32]
        else:
            need(row['source_misses']+row['capacity_misses']>0,
                 'actual final non-entry has an observed source or capacity miss')
        need(c==expected,'entire final non-entry prefix is canonical and owns no generated execution')


def check(stdout,stderr,args,kind,lane, *, cache_completed=None, chain_closure=None, true_repeat=None):
    need(lane in('scalar-reuse','differential'),'explicit scalar-reuse release profile')
    scalar,retirement,suffix=reuse.split(stderr)
    parsed,summary,view,unrolled,unused=old.check(stdout,suffix,args,kind,
        'differential'if lane=='differential'else'unrolled',cache_completed=cache_completed,chain_closure=chain_closure,true_repeat=true_repeat)
    reuse.scalar_completed(scalar,retirement);current(scalar)
    need(all(scalar[k]==unrolled[k]==parsed['loader'][k]for k in
         ('status','failure_code','detail_abs','detail_negative')),
         'every actual terminal row agrees on complete successful outcome')
    need(scalar['events']==unrolled['events'] and scalar['signals']==unrolled['signals'],
         'both actual preentry observers saw the same complete handler population')
    return parsed,summary,view,unrolled,scalar,retirement


def controls(stdout,stderr,args,kind,lane, *, cache_completed=None, chain_closure=None, true_repeat=None):
    _,_,_,_,scalar,retirement=check(stdout,stderr,args,kind,lane,cache_completed=cache_completed,chain_closure=chain_closure,true_repeat=true_repeat)
    _,_,suffix=reuse.split(stderr)
    prior=old.controls(stdout,suffix,args,kind,'differential'if lane=='differential'else'unrolled',cache_completed=cache_completed,chain_closure=chain_closure,true_repeat=true_repeat)
    lines=stderr[:-1].split(b'\n');trials=[]
    def changed(name,index,value):
        rows=list(lines);prefix=reuse.PREFIX if index==-2 else reuse.old.PREFIX
        rows[index]=prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        trials.append((name,b'\n'.join(rows)+b'\n'))
    scalar_keys=('version status failure_code detail_abs detail_negative initialized first_error used candidates '
                 'source_misses plan_misses capacity_misses publications hits entries completed unexpected events '
                 'plan_checks rseq_checks active busy decoding').split()
    for key in scalar_keys:
        value=copy.deepcopy(scalar);value[key]+=1;changed('scalar_'+key,-1,value)
    for key in ('signals','refusals','exit_indices'):
        value=copy.deepcopy(scalar);value[key][0]+=1;changed('scalar_'+key,-1,value)
    # Each whole current field has a typed semantic or shape constraint. Use
    # out-of-domain values for unconstrained selected slot/exit/effect masks.
    for i in range(34):
        value=copy.deepcopy(scalar)
        value['current'][i]=2405 if i==31 else 1<<64 if i in(1,5,32,33)else value['current'][i]^1
        changed('scalar_current_'+str(i),-1,value)
    for key in reuse.KEYS:
        value=dict(retirement);value[key]+=1;changed('reuse_'+key,-2,value)
    for name,key,value in [('bool','hits',True),('float','entries',1.0),('negative','events',-1)]:
        row=dict(scalar);row[key]=value;changed(name,-1,row)
    for name,index,row in [('scalar',-1,scalar),('reuse',-2,retirement)]:
        missing=dict(row);missing.pop('version');changed(name+'_missing_key',index,missing)
        changed(name+'_key_order',index,dict(reversed(list(row.items()))))
    trials.extend([('truncated',stderr[:-1]),('missing_scalar',b'\n'.join(lines[:-1])+b'\n'),
        ('missing_reuse',b'\n'.join(lines[:-2]+lines[-1:])+b'\n'),
        ('duplicate_scalar',stderr+lines[-1]+b'\n'),('duplicate_reuse',stderr+lines[-2]+b'\n'),
        ('row_order',b'\n'.join(lines[:-2]+[lines[-1],lines[-2]])+b'\n')])
    need(len(trials)==86 and len({n for n,_ in trials})==86,'all fixed additional scalar/reuse terminal refusals')
    names=[]
    for name,data in trials:
        rejected=False
        try:check(stdout,data,args,kind,lane,cache_completed=cache_completed,chain_closure=chain_closure,true_repeat=true_repeat)
        except ValueError:rejected=True
        need(rejected,'complete release reader refuses supplied '+name);names.append(name)
    return dict(original=prior,scalar_reuse_refusals=names,native_operations=0,
                original_stderr_sha256=reuse.H(stderr))
