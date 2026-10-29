"""New scope/accounting adapter; every old completion predicate remains called.

Old counters still describe actual arms/closes. Transfers have separate fields
and never satisfy an old CLOSED/released condition by translation.
"""
import importlib.util,json
from pathlib import Path
from page_selected import need
S=importlib.util.spec_from_file_location('lso_winsz_reports',Path(__file__).resolve().parent.parent/'rseq_tcgets_btrfs/winsz.py')
old=importlib.util.module_from_spec(S);S.loader.exec_module(old)
EXTRA=set('lease_phase lease_active lease_candidates lease_misses lease_transfers lease_closed lease_event lease_fetch_phase lease_fetch_before lease_fetch_after'.split())
def reports(stderr,lease=True):
 need(type(lease)is bool and type(stderr)is bytes and stderr.endswith(b'\n'),'complete explicit lease profile report')
 lines=stderr[:-1].split(b'\n');extensions=None;out=[];seen=set()
 for line in lines:
  prefix,sep,raw=line.partition(b' ')
  if prefix in(b'LI2_LOADER',b'LI2_CHAIN'):
   need(prefix not in seen and sep==b' ','unique actual profile row');seen.add(prefix);d=old.base.decode.decode(raw)
   if lease:
    if prefix==b'LI2_LOADER':
     need(d['scope']=='partial_selected_same_page_tf_lease','literal new production scope');d['scope']='partial_selected_native_pages_cpuid_nx'
    else:
     need(d['scope']=='opt_in_same_page_tf_lease'and EXTRA<=set(d),'literal separate transfer fields')
     extensions={k:d.pop(k)for k in EXTRA};need(all(type(v)is int and 0<=v<1<<64 for v in extensions.values()),'typed actual transfer counters')
     d['scope']='opt_in_trace_to_plain'
   else:need(not EXTRA&set(d),'old reference cannot acquire transfer fields')
   out.append(prefix+b' '+json.dumps(d,separators=(',',':'),sort_keys=True).encode())
  else:out.append(line)
 need(seen=={b'LI2_LOADER',b'LI2_CHAIN'}and((extensions is not None)==lease),'actual complete two profile rows')
 parsed=old.reports(b'\n'.join(out)+b'\n');parsed['lease']=extensions;return parsed

def completed(parsed,pid):
 old.base.old.completed(parsed,pid) # Unchanged NX/native/rseq/boundary/CHAIN/REP/RUN predicates.
 t=parsed['tcgets'];p=t['prefix'];need(t['status']==t['failure_code']==0 and p[:7]==[1,0,2,0,0,0,0]and p[7:12]==[0]*5 and
      t['commands']==[0,0,0],'actual initialized gate with no attempted ioctl; no forwarded-call credit')
 l=parsed['lease']
 if l is not None:
  need(l['lease_phase']in(0,4,5)and l['lease_active']==0 and l['lease_transfers']+l['lease_misses']==l['lease_candidates']and
       l['lease_closed']<=l['lease_transfers']and(l['lease_transfers']==0 or l['lease_closed']>0),
       'separate balanced transfer/candidate/real lease-close accounting')

def join(parsed,r,data):
 if parsed['lease']is None:return
 t=r.field(data,r.rt,'terminal_chain');l=r.field(t,'li2_tf_chain','lease');v=r.field(l,'li2_tf_same_page','transfer')
 mapping=dict(lease_phase='phase',lease_active='origin_active',lease_candidates='candidates',lease_misses='misses',lease_transfers='transfers',lease_closed='closed_leases',lease_event='completed_event')
 expected={k:r.integer(l,'li2_tf_same_page',name)for k,name in mapping.items()}
 expected.update({key:r.integer(v,'li2_fetch_rx_view',name)for key,name in dict(lease_fetch_phase='phase',lease_fetch_before='before_sequence',lease_fetch_after='after_sequence').items()})
 need(parsed['lease']==expected,'every new report field joins the complete actual terminal binary state')
