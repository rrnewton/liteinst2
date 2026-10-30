"""Exact certificate release counters around unchanged real ls/true gates.

The same-revision full certificate owner prerequisite carries architectural
qualification. Release rows never substitute for frame, payload or fault proof.
"""
import copy,json
from page_selected import need
import scalar_reuse_reports as reuse
import unrolled_hash_reports as old
import scalar_reuse_performance_reports as donor
import scalar_reuse_certificate_reports as certificate_rows
current=donor.current


def check(stdout,stderr,args,kind,lane):
    need(lane in('certificate-reuse','differential'),'explicit certificate/reuse release lane')
    scalar,retirement,certificate,suffix=certificate_rows.split(stderr)
    parsed,summary,view,unrolled,unused=old.check(stdout,suffix,args,kind,
        'differential'if lane=='differential'else'unrolled')
    certificate_rows.scalar_completed(scalar,retirement,certificate);current(scalar)
    need(all(scalar[k]==unrolled[k]==parsed['loader'][k]for k in
         ('status','failure_code','detail_abs','detail_negative')),
         'every actual terminal row agrees on complete successful outcome')
    need(scalar['events']==unrolled['events']and scalar['signals']==unrolled['signals'],
         'both actual preentry observers saw the same complete handler population')
    return parsed,summary,view,unrolled,scalar,retirement,certificate


def controls(stdout,stderr,args,kind,lane):
    _,_,_,_,scalar,retirement,certificate=check(stdout,stderr,args,kind,lane)
    _,_,_,suffix=certificate_rows.split(stderr)
    prior=old.controls(stdout,suffix,args,kind,'differential'if lane=='differential'else'unrolled')
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
        try:check(stdout,data,args,kind,lane)
        except ValueError:rejected=True
        need(rejected,'complete release reader refuses supplied '+name);names.append(name)
    extra=[]
    for key in certificate_rows.CERTIFICATE_KEYS:
        value=dict(certificate);value[key]+=1;rows=list(lines)
        rows[-3]=certificate_rows.CERTIFICATE_PREFIX+json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        extra.append(('certificate_'+key,b'\n'.join(rows)+b'\n'))
    extra.extend([('certificate_missing',b'\n'.join(lines[:-3]+lines[-2:])+b'\n'),
        ('certificate_duplicate',stderr+lines[-3]+b'\n'),
        ('certificate_order',b'\n'.join(lines[:-3]+[lines[-2],lines[-3],lines[-1]])+b'\n')])
    need(len(extra)==15 and len({name for name,_ in extra})==15,'all15 additional certificate terminal refusals')
    certificate_names=[]
    for name,data in extra:
        rejected=False
        try:check(stdout,data,args,kind,lane)
        except ValueError:rejected=True
        need(rejected,'complete certificate release reader refuses '+name);certificate_names.append(name)
    return dict(original=prior,scalar_reuse_refusals=names,certificate_refusals=certificate_names,
                native_operations=0,original_stderr_sha256=reuse.H(stderr))
