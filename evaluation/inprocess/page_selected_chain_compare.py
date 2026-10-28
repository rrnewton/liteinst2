"""Explicit additive LI2_CHAIN parser; old LOADER/REP/RUN parsing stays exact.

Successful completion also requires the unchanged old complete-owner predicate.
The bound report-only successor supplies one actual retained slot for every
rich owner/query/release field; the operational active slot stays unchanged.
"""
import json
import page_selected_register_real as old
from page_selected import need

HEAD=('status failure_code detail_abs detail_negative active pending error event sequence attempts steps '
      'nx_entries trace_entries fallbacks preparations releases unexpected proof_valid').split()
SLOT=('phase origin fallback generation event pc code length prepare prepared retry owner_phase owner_error '
      'open opened revoke revoked trace post_pc borrow held fetch_error validations query queried query_pc '
      'release released unexpected').split()
KEYS={'version','scope',*HEAD,*('s'+str(i)+'_'+x for i in (0,1) for x in SLOT)}


def reports(data):
    lines=data.splitlines()
    need(len(lines) in (3,4) and all(len(x)+1<=4096 for x in lines) and
         lines[0].startswith(b'LI2_LOADER ') and lines[-2].startswith(b'LI2_CHAIN ') and
         lines[-1].startswith(b'LI2_RUN ') and
         (len(lines)==3 or lines[1].startswith(b'LI2_REPEAT ')), 'exact additive report order and bounds')
    loader,repeat,run=old.reports(b'\n'.join(lines[:-2]+lines[-1:])+b'\n')
    c=json.loads(lines[-2][10:],object_pairs_hook=old.finite.generic.unique,
                 parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite chain report')))
    need(type(c)is dict and set(c)==KEYS and c['version']==1 and c['scope']=='opt_in_trace_to_plain' and
         all(type(v)is int and 0<=v<1<<64 for k,v in c.items() if k!='scope'), 'closed unsigned chain schema')
    need(all(c[k]==loader[k]==run[k] for k in old.ZERO) and c['active'] in (0,1) and
         c['pending'] in (0,1) and c['proof_valid'] in (0,1) and
         c['attempts']==loader['generic_tf_attempts'] and c['steps']==loader['generic_tf_steps'],
         'same actual terminal outcome and generic counters')
    for i in (0,1):
        s=slot(c,i)
        need(s['phase']<=7 and s['origin']<=2 and s['fallback']<=6 and s['owner_phase']<=6 and
             all(s[x] in (0,1) for x in ('prepare','prepared','retry','trace','held','query','queried','release','released','unexpected')) and
             all(s[x]<=3 for x in ('open','opened','revoke','revoked')) and s['length']<=15,
             'exact finite slot domains; incomplete prefixes remain incomplete')
    if any(c[k] for k in old.ZERO) or c['pending'] or c['error'] or c['proof_valid'] or loader['step_route']:
        same_slot(loader,slot(c,c['active']))
    return loader,repeat,run,c


def slot(c,index):return {x:c['s'+str(index)+'_'+x] for x in SLOT}


def same_slot(loader,s):
    pairs={'tf_phase':'owner_phase','tf_error':'owner_error','tf_trace':'trace',
           'tf_open_started':'open','tf_opened':'opened','tf_revoke_started':'revoke','tf_revoked':'revoked',
           'tf_query_attempted':'query','tf_query_complete':'queried',
           'tf_release_started':'release','tf_release_complete':'released'}
    need(all(loader[k]==s[v] for k,v in pairs.items()), 'rich actual owner/query/release all bind one retained slot')


def completed(loader,repeat,run,c):
    # This call retains every prior cache/publication/private-brk and generic
    # close/query/flags/error assertion. No reconstruction of an owner is used.
    old.completed(loader,repeat,run)
    need(all(c[k]==0 for k in old.ZERO) and c['pending']==c['error']==c['unexpected']==c['proof_valid']==0 and
         c['attempts']==c['steps']==c['nx_entries']+c['trace_entries']>0 and
         c['nx_entries']==c['fallbacks']>0 and c['sequence']==c['trace_entries']>0 and
         c['preparations']>=c['steps'] and c['releases']==c['preparations']+c['fallbacks'] and
         c['nx_entries']<=loader['nx_faults'], 'complete real segments, actual NX and TRACE entries separately')
    active=slot(c,c['active']);previous=slot(c,c['active']^1)
    need(active['phase']==6 and active['origin']==2 and active['fallback']!=0 and active['prepare']==active['prepared']==1 and
         active['owner_phase']==active['owner_error']==active['open']==active['opened']==active['revoke']==active['revoked']==
         active['trace']==active['post_pc']==active['query']==active['queried']==active['query_pc']==active['unexpected']==0,
         'actual descriptive fallback is retained as unexecuted, not completed')
    for s in (active,previous):
        need(s['generation']>0 and 0<s['event']<=c['event'] and s['borrow']>0 and s['validations']>0 and
             s['held']==s['fetch_error']==0 and s['release']==s['released']==1,
             'each slot retains its own complete source release')
    same_slot(loader,previous)
    p=previous;length=p['length'];pc=p['pc'];mask=1 if pc//4096==(pc+length-1)//4096 else 3
    need(p['phase']==5 and p['origin'] in (1,2) and p['fallback']==0 and 1<=length<=15 and pc>0 and
         p['owner_phase']==5 and p['owner_error']==p['unexpected']==0 and
         p['open']==p['opened']==p['revoke']==p['revoked']==mask and
         p['trace']==p['query']==p['queried']==1 and p['post_pc']==p['query_pc']==active['pc'] and
         p['borrow']<active['borrow'], 'retained completed predecessor, distinct original continuation borrow')
    need(loader['tf_pc']==pc and loader['tf_length']==length and loader['tf_code']==p['code'] and
         loader['tf_phase']==p['owner_phase'] and loader['tf_trace']==p['trace'] and
         loader['tf_query_attempted']==p['query'] and loader['tf_query_complete']==p['queried'] and
         loader['tf_release_started']==p['release'] and loader['tf_release_complete']==p['released'],
         'rich unchanged LOADER completion evidence binds the actual retained predecessor')
