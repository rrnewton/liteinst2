"""Exact actual linked terminal wire schema; no protected-record authority."""
import json
from page_selected import need
import scalar_reuse_reports as reuse
maps_view=reuse.maps_view
PREFIX=b'LI2_LINKED_EPOCH '
REUSE_PREFIX=b'LI2_LINKED_EPOCH_REUSE '
KEYS=('version status failure_code detail_abs detail_negative initialized first_error used offers closed '
      'resumed refaults hash_misses candidates source_misses plan_misses capacity_misses publications hits entries '
      'completed unexpected events plan_checks rseq_checks live_checks proof_checks active busy decoding closing resuming '
      'transfer signals refusals exit_indices current').split()
ARRAYS=dict(transfer=21,signals=5,refusals=4,exit_indices=8,current=37)
OUTCOME=('status','failure_code','detail_abs','detail_negative')


def split(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete TRACE linked terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>2 and lines[-2].startswith(REUSE_PREFIX)and lines[-1].startswith(PREFIX)and
         sum(x.startswith(REUSE_PREFIX)for x in lines)==sum(x.startswith(PREFIX)for x in lines)==1 and
         all(len(x)<=4096 and b'\r'not in x for x in lines[-2:]),
         'one final linked-reuse row followed by one linked row')
    decode=maps_view.pair.pair_reports.rseq.decode
    linked=decode(lines[-1][len(PREFIX):]);retirement=decode(lines[-2][len(REUSE_PREFIX):])
    need(type(linked)is dict and list(linked)==KEYS and
         all(type(linked[k])is int and 0<=linked[k]<1<<64 for k in KEYS if k not in ARRAYS),
         'complete ordered unsigned linked schema without duplicate keys or boolean values')
    for key,size in ARRAYS.items():
        need(type(linked[key])is list and len(linked[key])==size and
             all(type(x)is int and 0<=x<1<<64 for x in linked[key]),'whole unsigned linked '+key)
    need(type(retirement)is dict and list(retirement)==reuse.KEYS and
         all(type(retirement[k])is int and 0<=retirement[k]<1<<64 for k in reuse.KEYS),
         'complete ordered unsigned linked-reuse schema')
    need(linked['version']==retirement['version']==1 and linked['status']in(0,125)and
         all(linked[k]in(0,1)for k in ('detail_negative','initialized','active','busy','decoding','closing','resuming'))and
         all(retirement[k]in(0,1)for k in ('detail_negative','pending','retiring'))and retirement['cursor']<64,
         'exact linked versions, outcome, boolean fields and bounded cursor')
    need(all(linked[k]==retirement[k]for k in OUTCOME),'one actual linked/reuse outcome')
    for row,prefix,line in ((linked,PREFIX,lines[-1]),(retirement,REUSE_PREFIX,lines[-2])):
        need(prefix+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==line,
             'canonical complete linked terminal row')
    return linked,retirement,b'\n'.join(lines[:-2])+b'\n'


REFAULT_FIELD_CONTROL_COUNT=5
REFAULT_CAUSAL_CONTROL_COUNT=2
REFAULT_CLASS_ERROR='every completed NX refault is an actual counted relocation refusal'
REFAULT_FLAGS_ERROR='completed NX refault has exact transfer and current completion flags'


def refault_count(row):
    need(row['refaults']<=row['refusals'][3],REFAULT_CLASS_ERROR)


def refault_completed(row):
    """Successful terminal prefix only; failed prefixes require the raw owner.

    An earlier refault may have been followed by a newer consumed/resumed
    offer. Only a retained phase6 record carries these completion flags.
    No terminal report by itself proves the subsequent hardware NX event.
    """
    refault_count(row)
    t,c=row['transfer'],row['current'];refault=t[0]==6
    need(t[19:]==([1,1]if refault else[0,0])and
         c[34:]==([1,1,0]if refault else[0,0,0]),REFAULT_FLAGS_ERROR)
    if not refault:return
    need(row['refaults']>0 and t[1]==row['offers'] and t[2]>0 and t[3]<2 and
         t[4:6]==[0,0] and t[6]>0 and 0<t[7]<t[8] and
         0x200000000<=t[9]<1<<64 and(t[9]>>47)in(0,0x1ffff)and
         t[9]%4096<=4096-15 and t[10]&0x30100==0 and t[11]==1 and
         t[12:19]==[0]*7,
         'actual closed NX retry retains high PC, one-use released borrow and no successor or consume/resume')
    expected=[0]*37;expected[16]=1;expected[29:32]=[1,1,2404];expected[34:36]=[1,1]
    need(c==expected,
         'actual closed NX retry is exactly a returned relocation miss without generated slot or execution')


def refault_causal_mutations(row):
    """Two supplied mutations of the actual terminal row, never executions."""
    import copy
    count=copy.deepcopy(row);count['refaults']=count['refusals'][3]+1
    phase=copy.deepcopy(row);phase['transfer'][0]=5 if phase['transfer'][0]==6 else 6
    return [('refault_above_relocation',count,REFAULT_CLASS_ERROR),
            ('refault_phase_flags',phase,REFAULT_FLAGS_ERROR)]


def refault_chain_mutation(row):
    """Count a complete extra relocation miss without its already-started ordinary NX segment.

    This counter is not evidence of the subsequent hardware refault event."""
    import copy
    changed=copy.deepcopy(row)
    for key in ('offers','closed','candidates','refaults','plan_misses'):changed[key]+=1
    changed['refusals'][3]+=1
    return changed


def refault_required(row,control):
    """Four actual helper failures after the focal graph completed, never passes."""
    need(type(control)is int and control in(1,2,3,4),'exact required refault selector')
    code={1:3002,2:3002,3:3001,4:3003}[control];done=int(control==2)
    need([row[k]for k in OUTCOME]==[125,3104,code,0]and row['first_error']==3104 and
         [row[k]for k in('active','busy','decoding','closing','resuming')]==[0,1,0,0,0],
         'actual required helper failure retains its exact code and busy nonexecuting owner')
    refault_count(row);tr,cur=row['transfer'],row['current']
    need(tr[0]==(6 if done else 2)and tr[1]==row['offers']and tr[2]>0 and tr[3]<2 and
         tr[4:6]==[0,0]and tr[6]>0 and tr[7]>0 and
         (tr[8]>tr[7]if done else tr[8]==0)and
         0x200000000<=tr[9]<1<<64 and(tr[9]>>47)in(0,0x1ffff)and tr[9]%4096<=4081 and
         tr[10]&0x30100==0 and tr[11:16]==[1,0,0,0,0]and
         tr[16:]==[code,5 if control in(1,2)else 3,0,done,done],
         'exact required stale, double, held-borrow or changed-frame transfer prefix')
    expected=[0]*37;expected[16]=1;expected[27:29]=[int(control==3),1]
    expected[29:32]=[1,1,2404];expected[34:36]=[done,done]
    need(cur==expected,'exact actual required-refault current record without generated execution')


# Explicit native-hint schema. The baseline split and all relocation-only
# predicates above remain unchanged; no v2 stream can satisfy this parser.
HINT_PREFIX=b'LI2_LINKED_NATIVE_HINT '
HINT_LINKED_KEYS=KEYS[:KEYS.index('refaults')+1]+['graph_refaults']+KEYS[KEYS.index('refaults')+1:]
HINT_KEYS=('version status failure_code ready pending outcome_complete publications evictions lookups hits '
    'invalidations next_nx admitted refused errors receipt_sequence receipt_publication selected_publication '
    'selected_serial selected_event selected_pc selected_seeds selected_published outcome_result '
    'current_checked current_hit current_publication').split()
HINT_CLASS_ERROR='every graph retry is an actual counted GRAPH refusal'
HINT_LIFETIME_ERROR='one-use positive native hint lifetime and complete actual outcome'
HINT_CURRENT_ERROR='actual current advisory selection binds its retained publication and serial'


def split_hint(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete explicit native-hint terminal stream')
    lines=stderr[:-1].split(b'\n')
    need(len(lines)>3 and lines[-3].startswith(REUSE_PREFIX)and lines[-2].startswith(PREFIX)and
         lines[-1].startswith(HINT_PREFIX)and
         all(sum(x.startswith(prefix)for x in lines)==1 for prefix in(REUSE_PREFIX,PREFIX,HINT_PREFIX))and
         all(len(x)<=4096 and b'\r'not in x for x in lines[-3:]),
         'one final linked-reuse, linked and native-hint row in actual source order')
    decode=maps_view.pair.pair_reports.rseq.decode
    linked=decode(lines[-2][len(PREFIX):]);retirement=decode(lines[-3][len(REUSE_PREFIX):])
    hint=decode(lines[-1][len(HINT_PREFIX):])
    need(type(linked)is dict and list(linked)==HINT_LINKED_KEYS and
         all(type(linked[k])is int and 0<=linked[k]<1<<64 for k in HINT_LINKED_KEYS if k not in ARRAYS),
         'complete ordered unsigned native-hint linked schema')
    for key,size in ARRAYS.items():
        need(type(linked[key])is list and len(linked[key])==size and
             all(type(x)is int and 0<=x<1<<64 for x in linked[key]),'whole unsigned native-hint linked '+key)
    need(type(retirement)is dict and list(retirement)==reuse.KEYS and
         all(type(retirement[k])is int and 0<=retirement[k]<1<<64 for k in reuse.KEYS),
         'complete ordered unsigned native-hint linked-reuse schema')
    need(type(hint)is dict and list(hint)==HINT_KEYS and
         all(type(hint[k])is int and 0<=hint[k]<1<<64 for k in HINT_KEYS),
         'complete ordered unsigned actual27-field native-hint schema')
    need(linked['version']==retirement['version']==hint['version']==1 and linked['status']in(0,125)and
         all(linked[k]in(0,1)for k in('detail_negative','initialized','active','busy','decoding','closing','resuming'))and
         all(retirement[k]in(0,1)for k in('detail_negative','pending','retiring'))and retirement['cursor']<64 and
         all(hint[k]in(0,1)for k in('ready','pending','outcome_complete','current_checked','current_hit')),
         'exact native-hint versions, actual outcome, literal flags and bounded cursor')
    need(all(linked[k]==retirement[k]for k in OUTCOME)and
         all(linked[k]==hint[k]for k in('status','failure_code')),
         'all native-hint rows retain one actual terminal outcome')
    for row,prefix,line in((linked,PREFIX,lines[-2]),(retirement,REUSE_PREFIX,lines[-3]),(hint,HINT_PREFIX,lines[-1])):
        need(prefix+json.dumps(row,separators=(',',':'),allow_nan=False).encode()==line,
             'canonical complete native-hint terminal row')
    return linked,retirement,hint,b'\n'.join(lines[:-3])+b'\n'


def hint_counts(row,hint):
    """Closed declared outcomes only; no terminal row substitutes for next-NX frames."""
    refault_count(row)
    need(row['graph_refaults']<=row['refusals'][2],HINT_CLASS_ERROR)
    need(hint['ready']+hint['evictions']+hint['hits']+hint['invalidations']==hint['publications']and
         hint['hits']+hint['invalidations']<=hint['lookups']<=row['refusals'][2]and
         hint['pending']==hint['errors']==0 and
         hint['hits']==row['graph_refaults']==hint['next_nx']==hint['admitted']+hint['refused'],
         HINT_LIFETIME_ERROR)
    need(hint['current_hit']<=hint['current_checked']and
         bool(hint['current_publication'])==bool(hint['current_hit']),HINT_CURRENT_ERROR)
    if hint['current_checked']:
        need(row['current'][29:32]==[1,1,2403]and row['transfer'][9]>=0x200000000,
             'actual advisory lookup follows an observed high GRAPH refusal')
    if hint['current_hit']:
        need(hint['current_publication']==hint['selected_publication']and
             row['transfer'][1]==hint['selected_serial'],HINT_CURRENT_ERROR)


def hint_native(row,hint,parsed,*,finite=False):
    """Join actual complete counters to the unchanged native owner reports.

    A native refusal is permitted by the release API but is not exercised by
    the fixed finite subjects. The finite profile requires observed refused0.
    """
    need(type(finite)is bool,'literal finite native-hint report profile')
    hint_counts(row,hint)
    native=parsed['native'];pair=parsed['native_pair'];life=pair['lifecycle'];counts=pair['counts']
    need(hint['publications']==hint['receipt_publication']==native['admissions']==life[12],
         'every actual native publication produces exactly one positive advisory receipt')
    if finite:need(hint['refused']==0,'fixed finite profile observes no native-policy refusal branch')
    if not hint['publications']:
        need(hint['receipt_sequence']==0,'no publication means no retained receipt sequence')
    else:
        need(0<hint['receipt_sequence']<=life[6],
             'retained actual positive receipt precedes current native lifecycle sequence')
    if not hint['hits']:
        need(all(hint[k]==0 for k in('outcome_complete','outcome_result','selected_publication','selected_serial',
             'selected_event','selected_pc','selected_seeds','selected_published')),
             'no actual advisory selection means no invented outcome or selected provenance')
    else:
        need(hint['outcome_complete']==1 and hint['outcome_result']in(0,1)and
             0<hint['selected_publication']<=hint['selected_published']<=hint['receipt_publication']and
             0<hint['selected_serial']<=row['offers']and hint['selected_event']<counts[0]and
             hint['selected_seeds']<=counts[1]and 0x200000000<=hint['selected_pc']<1<<64 and
             (hint['selected_pc']>>47)in(0,0x1ffff)and hint['selected_pc']%4096<=4081,
             'actual completed advisory selection retains its earlier receipt and native event provenance')
        if hint['outcome_result']==1:
            need(hint['admitted']>0 and hint['selected_seeds']<counts[1]and
                 hint['selected_published']<hint['receipt_publication'],
                 'last admitted advisory outcome retains one later native seed and publication')
        else:
            need(hint['refused']>0,'last descriptive advisory outcome belongs to actual refused population')


def hint_refault_completed(row,hint):
    """Retained phase6 distinguishes relocation retries from advisory GRAPH retries."""
    hint_counts(row,hint)
    if not hint['current_hit']:
        refault_completed(row)
        return
    t,c=row['transfer'],row['current']
    need(t[0]==6 and t[19:]==[1,1]and c[34:]==[1,1,0],REFAULT_FLAGS_ERROR)
    need(row['graph_refaults']>0 and t[1]==row['offers']and t[2]>0 and t[3]<2 and
         t[4:6]==[0,0]and t[6]>0 and 0<t[7]<t[8]and
         0x200000000<=t[9]<1<<64 and(t[9]>>47)in(0,0x1ffff)and
         t[9]%4096<=4081 and t[10]&0x30100==0 and t[11]==1 and t[12:19]==[0]*7,
         'actual GRAPH retry retains one-use released borrow and no successor or consume/resume')
    expected=[0]*37;expected[16]=1;expected[29:32]=[1,1,2403];expected[34:36]=[1,1]
    need(c==expected,'actual GRAPH retry is exactly a returned graph refusal without generated execution')


def hint_required(row,hint,control):
    """Three real advisory invalidations followed by an explicit harness stop.

    The zero choose result is not a native-policy refusal or failed retry API.
    The protected reader proves the whole actual before/mutated/after receipt.
    """
    need(type(control)is int and control in(1,2,3),'exact required advisory selector')
    hint_counts(row,hint)
    need([row[k]for k in OUTCOME]==[125,3104,0,0]and row['first_error']==3104 and
         [row[k]for k in('active','busy','decoding','closing','resuming')]==[0,1,0,0,0]and
         hint['ready']==0 and hint['invalidations']>0 and
         [hint[k]for k in('current_checked','current_hit','current_publication')]==[1,0,0],
         'actual advisory invalidation keeps explicit harness-stop outcome without native refusal credit')
    tr,cur=row['transfer'],row['current']
    need(tr[0]==2 and tr[1]==row['offers']and tr[2]>0 and tr[3]<2 and tr[4:6]==[0,0]and
         tr[6]>0 and tr[7]>0 and tr[8]==0 and 0x200000000<=tr[9]<1<<64 and
         (tr[9]>>47)in(0,0x1ffff)and tr[9]%4096<=4081 and tr[10]&0x30100==0 and
         tr[11]==1 and tr[12:]==[0]*9,
         'advisory invalidation retains real unconsumed CLOSED transfer without API failure')
    expected=[0]*37;expected[16]=1;expected[28]=1;expected[29:32]=[1,1,2403]
    need(cur==expected,'advisory invalidation retains complete released fresh source and no generated or retry execution')
