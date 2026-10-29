"""Strict actual sealed-page custody proof; origin maps are never fresh maps.

The original lease/frame readers remain unchanged. This leaf consumes genuine
outer-stage/commit and handler-end observations, without issuing any query.
"""
import hashlib,importlib.util,struct,sys
sys.dont_write_bytecode=True
from pathlib import Path
from page_selected import need

def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path)
 result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
BASE=Path(__file__).resolve().parent.parent
old=module('cso_original_lease',BASE/'tf_same_page/check.py')
interval=module('cso_original_interval',BASE/'tf_interval/check.py')
MAIN,BODY,TAIL,GUARD,DATA,PAGE,AREA,WORD=old.MAIN,old.BODY,old.TAIL,old.GUARD,old.DATA,old.PAGE,old.AREA,old.WORD
q,word,put=old.q,old.word,old.put
MASK=interval.SELECTED_MASK

class Reader(interval.Reader):
 def __init__(self,data,layout):
  need(type(data)is bytes and type(layout)is dict and set(layout)=={'types','record','offsets','siginfo','uc_bytes'}and layout['record']=='cso_stream','explicit complete actual custody stream/layout')
  types=layout['types'];names='cso_stream cso_record cso_row cso_meta cso_snapshot lso_record lso_event lso_native_row rn_frame li2_tf_chain li2_tf_chain_slot li2_tf_trace_entry li2_decoder_stats li2_tf_owner li2_tf_hooks li2_tf_shstk_observation li2_step_owner li2_step_hooks li2_step_session li2_step_request li2_step_page li2_step_frame li2_chain_fetch li2_chain_release li2_tf_continuation li2_tf_same_page li2_fetch_rx_view li2_fetch_ref li2_fetch_progress li2_fetch_page li2_fetch_backing stat li2_fetch_map_progress li2_maps_observation li2_maps_stats li2_page_custody_receipt li2_page_custody_stats li2_rseq_state li2_rseq_transaction li2_rseq_data li2_write_footprint li2_decoded li2_tf_classification'.split()
  need(type(types)is dict and set(types)==set(names),'exact source-defined actual custody type inventory')
  self.page_keys={};self.retained_sequences=set();self.session_bytes=None;self.registration_identity=None;self.fetch_owner=None;self.hook_functions=None
  self.history_anchors={};self.history_views={} # Each observed RX serial keeps its own exact history.
  root=types['cso_stream'];need(set(root['fields'])=={'base','custody'},'exact stream children')
  n=types['lso_record']['bytes'];cn=types['cso_record']['bytes']
  need(root==dict(bytes=n+cn,fields=dict(base=dict(offset=0,bytes=n),custody=dict(offset=n,bytes=cn)))and len(data)==n+cn<16<<20,'complete exact stream without truncation, extra bytes or padding between objects')
  # This is an actual embedded subobject view, not an alternate record or a
  # transformed maps receipt. The original constructor checks its full shape.
  old.Reader.__init__(self,data[:n],dict(layout,record='lso_record'),'lso_record')
  self.data,self.layout,self.rt=data,layout,root
  need(layout['offsets']==dict(greg=40,fp_pointer=224,mask=296,stack_sp=16,stack_flags=24,stack_size=32),'literal actual x86-64 signal offsets')
  z=lambda t:types[t]['bytes']
  forms={
   'cso_meta':dict(present=8,point=8,index=8,result=4,slot=4,chain=8,slot_address=8,owner_address=8,step_address=8,ref_address=8,session_address=8,chain_session_address=8,event=8,generation=8,argument_ref=z('li2_fetch_ref'),published_ref=z('li2_fetch_ref'),custody=z('li2_page_custody_stats'),maps=z('li2_maps_stats'),rx=z('li2_fetch_rx_view'),session=z('li2_step_session')),
   'cso_snapshot':dict(meta=z('cso_meta'),owner=z('li2_tf_owner'),fetch=z('li2_chain_fetch'),rseq=z('li2_rseq_state')),
   'cso_row':dict(entry=z('cso_meta'),returned=z('cso_meta'),handler_before=z('cso_meta'),stage=z('cso_snapshot'),commit=z('cso_snapshot'),ready=z('cso_snapshot'),ready_frame=z('rn_frame')),
   'cso_record':dict(h=256,rows=12*z('cso_row'),stack_endpoints=2*z('lso_native_row'),fault=z('cso_snapshot'),terminal=z('cso_meta')),
   'li2_page_custody_stats':dict(epoch=8,seeds=8,retained_stages=8,retained_checks=8,commits=8,discards=8,phase=4,last_reason=4),
   'li2_maps_stats':dict(fresh_calls=8,acquisitions=8,reuses=8,invalidations=8,handler_id=8,mutation_epoch=8,active=4,valid=4,poisoned=4,reserved=4),
   'li2_step_session':dict(pid=8,tid=8,sync_register=8,sync_query=8,application_mask=8,initialized=4,self_test_complete=4),
   'li2_page_custody_receipt':dict(kind=4,provenance=4,slot=4,checks=4,epoch=8,origin_sequence=8,owner_generation=8,event=8,chain=8,owner=8,session=8,origin=z('li2_fetch_map_progress')),
   'stat':dict(st_dev=8,st_ino=8,st_nlink=8,st_mode=4,st_uid=4,st_gid=4,__pad0=4,st_rdev=8,st_size=8,st_blksize=8,st_blocks=8,st_atim=16,st_mtim=16,st_ctim=16,__glibc_reserved=24),
  }
  for name,fields in forms.items():
   shape=types[name]
   need(list(sorted(shape['fields'],key=lambda k:shape['fields'][k]['offset']))==list(fields)and all(shape['fields'][k]['bytes']==v for k,v in fields.items()),'complete source field inventory and width '+name)
  need(z('stat')==144 and z('li2_step_session')==48 and z('li2_page_custody_stats')==56 and z('li2_maps_stats')==64 and z('li2_page_custody_receipt')==160,'exact fixed core ABI extents')
  self.padding_tree(data,'cso_stream')
 def padding_tree(self,b,t):
  interval.Reader.padding_tree(self,b,t)
  if t=='li2_step_frame':
   n,initialized=self.values(b,t,'fp_bytes initialized')
   need((n==initialized==0 and not any(b))or(512<=n==initialized<=65536 and not any(self.field(b,t,'fp')[n:])),
        'complete initialized retained owner frame and zero unused FP capacity')
  extra={
   'cso_stream':dict(base='lso_record',custody='cso_record'),
   'cso_record':dict(rows='cso_row',stack_endpoints='lso_native_row',fault='cso_snapshot',terminal='cso_meta'),
   'cso_row':dict(entry='cso_meta',returned='cso_meta',handler_before='cso_meta',stage='cso_snapshot',commit='cso_snapshot',ready='cso_snapshot',ready_frame='rn_frame'),
   'cso_snapshot':dict(meta='cso_meta',owner='li2_tf_owner',fetch='li2_chain_fetch',rseq='li2_rseq_state'),
   'cso_meta':dict(argument_ref='li2_fetch_ref',published_ref='li2_fetch_ref',custody='li2_page_custody_stats',maps='li2_maps_stats',rx='li2_fetch_rx_view',session='li2_step_session'),
   'lso_record':dict(endpoints='lso_native_row',events='lso_event',cpuid_before='rn_frame',cpuid_after='rn_frame',terminal_chain='li2_tf_chain',terminal_rseq='li2_rseq_state',fault_view='li2_fetch_rx_view',terminal_maps='li2_fetch_map_progress',nested='rn_frame'),
   'lso_native_row':dict(before='rn_frame',after='rn_frame'),
   'lso_event':dict(before='rn_frame',after='rn_frame',owner_before='li2_tf_owner',owner_after='li2_tf_owner',fetch_before='li2_chain_fetch',fetch_after='li2_chain_fetch',next_fetch='li2_chain_fetch',next_first_fetch='li2_chain_fetch',next_first_decoded='li2_decoded',next_first_release='li2_chain_release',release='li2_chain_release',query='li2_tf_continuation',next_before='li2_step_frame',lease='li2_tf_same_page',rseq_before='li2_rseq_state',rseq='li2_rseq_state'),
   'li2_tf_chain':dict(initial_stats='li2_decoder_stats'),
   'li2_tf_owner':dict(hooks='li2_tf_hooks',rdssp_observation='li2_tf_shstk_observation'),
   'li2_tf_hooks':dict(step='li2_step_hooks'),
   'li2_step_owner':dict(hooks='li2_step_hooks'),
   'li2_fetch_rx_view':dict(custody='li2_page_custody_receipt'),
   'li2_page_custody_receipt':dict(origin='li2_fetch_map_progress'),
  }.get(t,{})
  for key,child in extra.items():
   for raw in self.array(b,t,key,child):self.padding_tree(raw,child)
 # Construction below is specific to the exact emitted cso_stream. These
 # unchanged methods operate only on complete actual typed byte extents.
 def values(self,b,t,names):
  return tuple(self.integer(b,t,k)for k in names.split())
 def array(self,b,t,key,child):
  raw=self.field(b,t,key);n=self.types[child]['bytes']
  need(len(raw)>0 and len(raw)%n==0,'complete typed array '+t+'.'+key)
  return [raw[a:a+n]for a in range(0,len(raw),n)]
 def changed(self,a,b,t,names):
  """Join every byte outside separately validated actual assignment fields."""
  need(len(a)==len(b)==self.types[t]['bytes'],'complete compared typed objects')
  out=bytearray(a)
  for key in names.split():
   f=self.types[t]['fields'][key];at,n=f['offset'],f['bytes'];out[at:at+n]=b[at:at+n]
  need(bytes(out)==b,'all unassigned bytes unchanged in '+t)
 def zero(self,b,label):need(not any(b),'zero unused '+label)
 def maps_fresh(self,b,stats=None):
  # Keep the original strict fresh-map predicate. No kind-2 receipt here.
  self.maps(b);o=self.field(b,'li2_fetch_map_progress','observation')
  acq,handler,epoch,kind,io=self.values(o,'li2_maps_observation','acquisition_id handler_id mutation_epoch kind io_performed')
  need(kind==io==1,'genuine fresh acquisition, never retained origin relabelled')
  if stats is not None:
   need(stats['active']==stats['valid']==1 and stats['poisoned']==0 and
        (acq,handler,epoch)==tuple(stats[k]for k in('acquisitions','handler_id','mutation_epoch')),
        'fresh receipt matches actual current maps state')
  return acq,handler,epoch
 def maps_state(self,b):
  t='li2_maps_stats';self.padding(b,t)
  names='fresh_calls acquisitions reuses invalidations handler_id mutation_epoch active valid poisoned reserved'.split()
  v={k:self.integer(b,t,k)for k in names}
  need(v['fresh_calls']>=v['acquisitions']>0 and v['handler_id']>0 and
       v['invalidations']==v['mutation_epoch']>0 and v['active']in(0,1)and
       v['valid']in(0,1)and v['poisoned']==v['reserved']==0,
       'complete nonpoisoned actual maps counters and flags')
  return v
 def custody_state(self,b):
  t='li2_page_custody_stats';self.padding(b,t)
  names='epoch seeds retained_stages retained_checks commits discards phase last_reason'.split()
  v={k:self.integer(b,t,k)for k in names}
  need(v['epoch']==v['discards']>0 and v['phase']in range(7)and v['last_reason']in range(1,8)and
       v['commits']>=v['seeds']and v['retained_stages']<=v['retained_checks']<=2*v['retained_stages']+1,
       'complete finite custody counters, no overflow or poisoned success')
  return v
 def session(self,b,pid,anchor=None):
  t='li2_step_session';self.padding(b,t)
  need(self.values(b,t,'pid tid sync_register application_mask initialized self_test_complete')==(pid,pid,0,MASK,1,1)and
       self.integer(b,t,'sync_query')&96==96,'real complete initialized singleton session and original mask/selftest')
  if anchor is not None:need(b==anchor,'complete actual session retained byte-for-byte')
  return b
 def receipt(self,v,stats,identity,origin=None,checks=0):
  I,F=self.integer,self.field;t='li2_fetch_rx_view';ct='li2_page_custody_receipt';c=F(v,t,'custody')
  self.padding(v,t);self.padding(c,ct)
  kind=I(c,ct,'kind');need(kind in(1,2),'explicit FRESH or RETAINED custody proof')
  need(self.values(c,ct,'provenance slot epoch owner_generation event chain owner session')==
       (1,identity['slot'],stats['epoch'],identity['generation'],identity['event'],identity['chain'],identity['owner'],identity['session']),
       'exact custody epoch, provenance and actual complete permission owner identity')
  need(I(c,ct,'origin_sequence')>0 and I(c,ct,'checks')==checks,'exact source borrow and actual backing check count')
  original=F(c,ct,'origin');self.maps_fresh(original)
  if kind==1:
   need(checks==0 and I(v,t,'maps_observed')==1 and F(v,t,'maps')==original and
        I(c,ct,'origin_sequence')==I(v,t,'before_sequence'),
        'cold seed retains the actual fresh stage and its original borrow')
   need(origin is None,'new fresh seed has no surviving previous certificate')
  else:
   need(origin is not None and I(v,t,'maps_observed')==0 and not any(F(v,t,'maps')),
        'retained proof has no invented current maps observation')
   # Event/serial/current checks advance; all original authority remains exact.
   need(original==origin['maps']and I(c,ct,'origin_sequence')==origin['sequence']and
        tuple(identity[k]for k in('slot','generation','chain','owner','session'))==origin['identity']and
        stats['epoch']==origin['epoch'],'retained receipt joins complete original acquisition/owner, not just its hash')
  return dict(kind=kind,maps=original,sequence=I(c,ct,'origin_sequence'),
              identity=tuple(identity[k]for k in('slot','generation','chain','owner','session')),epoch=stats['epoch'])
 def view(self,v,image,pid,identity,stats,origin,phase,sequence,pc,checks,anchor=None,page_identity=None):
  I,F=self.integer,self.field;t='li2_fetch_rx_view';n=min(15,4096-(pc&4095))
  need(self.values(v,t,'phase complete result before_sequence after_sequence pc length pid tid')==
       (phase,1,0,sequence,sequence+1 if phase==4 else 0,pc,n,pid,pid)and I(v,t,'serial')>0 and
       F(v,t,'bytes')==bytes.fromhex(image['source_hex'])[pc-MAIN:pc-MAIN+n].ljust(15,b'\0'),
       'complete actual staged/committed singleton, source bytes and exact sequence')
  backing=self.backing(F(v,t,'backing'),image['backing'],anchor)
  key=self.page(F(v,t,'page'),pc&~4095,backing,page_identity)
  proof=self.receipt(v,stats,identity,origin,checks)
  self.remember_backing(v,backing)
  self.history_views[self.integer(v,"li2_fetch_rx_view","serial")]=v
  return proof,backing,key
 def fetch_progress(self,b,ref,n,held,kind,validation_calls,last_observed):
  """The actual current borrow keeps its own origin; never fill missing maps."""
  I,F=self.integer,self.field;t='li2_fetch_progress';self.padding(b,t);self.padding(ref,'li2_fetch_ref')
  seq=I(ref,'li2_fetch_ref','sequence')
  need(I(ref,'li2_fetch_ref','owner')>0 and seq>0 and
       self.values(b,t,'held complete first_error identity_observed first_detail pages_copied bytes_copied sequence validation_calls last_backing_page last_backing_observed')==
       (held,1,0,1,0,1,n,seq,validation_calls,0,last_observed),'complete exact original/retained fetch progress')
  if kind==1:self.maps(F(b,t,'preparation'))
  else:need(kind==2 and not any(F(b,t,'preparation')),'retained preparation has no acquisition receipt')
  if validation_calls:self.maps(F(b,t,'validation'))
  else:self.zero(F(b,t,'validation'),'current unobserved validation')
  return seq
 def original_open(self,owner,request,session,pages):
  I,F=self.integer,self.field;t='li2_step_owner';p=F(owner,'li2_tf_owner','step')
  need(I(p,t,'session')==session and F(p,t,'request')==request and
       self.values(p,t,'first_error self_test trace_seen revoke_sync_started first_detail open_sync')==(0,0,0,0,0,0),
       'original actual opening owner and untouched error/revoke prefix')
  for key in('open_started','opened'):need(F(p,t,key)==struct.pack('<2I',1,int(pages==2)),'exact actual original page opens')
  for key in('open_result','revoke_started','revoked','revoke_result','revoke_sync'):self.zero(F(p,t,key),key)
  for key in('destination','width','immediate','effect','source'):need(I(p,t,key)==0,'unused generic-owner effect remains zero')
  for key in('continuation_started','continuation_complete','unexpected_frame_observed','continuation_result','rdssp_query_attempted','rdssp_query_complete','rdssp_query_result','rdssp_features','bnd_xcr0_attempted','bnd_xcr0_complete','bnd_xcr0'):
   need(I(owner,'li2_tf_owner',key)==0,'unused original generic-owner field '+key)
  self.zero(F(owner,'li2_tf_owner','rdssp_observation'),'RDSSP observation')
  hooks=F(p,t,'hooks');th=F(owner,'li2_tf_owner','hooks')
  need(th[:len(hooks)]==hooks and all(x>0 for x in q(hooks))and word(th,len(hooks))>0,'complete original actual callbacks/context')
  return p
 def meta(self,b,index,point,result,pid,owner=None,expected_ref=None,published=None):
  I,F=self.integer,self.field;t='cso_meta'
  need(self.values(b,t,'present point index result')==(1,point,index,result),'exact actual snapshot point/index/result')
  slot,chain,slot_address,oa,step,ref,session,chain_session,event,generation=self.values(b,t,'slot chain slot_address owner_address step_address ref_address session_address chain_session_address event generation')
  need(slot in(0,1)and min(chain,chain_session,event,generation)>0 and
       slot_address==chain+self.types['li2_tf_chain']['fields']['slots']['offset']+slot*self.types['li2_tf_chain_slot']['bytes']and
       oa==slot_address+self.types['li2_tf_chain_slot']['fields']['owner']['offset']and
       step==oa+self.types['li2_tf_owner']['fields']['step']['offset']and
       ref==slot_address+self.types['li2_tf_chain_slot']['fields']['fetch']['offset']+self.types['li2_chain_fetch']['fields']['ref']['offset'],
       'actual chain/slot/owner/step/ref storage addresses and live generation')
  if owner is not None:
   p=F(owner,'li2_tf_owner','step');need(I(p,'li2_step_owner','session')==session,'actual copied owner/session identity')
  if session:
   need(session==chain_session,'actual initialized owner shares the exact chain session');self.session(F(b,t,'session'),pid,self.session_bytes)
   self.session_bytes=F(b,t,'session')
  else:self.zero(F(b,t,'session'),'absent owner session; no chain substitution')
  if expected_ref is not None:need(F(b,t,'argument_ref')==expected_ref,'actual pre-call argument ref, including commit aliasing')
  if published is None:self.zero(F(b,t,'published_ref'),'unpublished ref')
  else:need(F(b,t,'published_ref')==published,'actual returned successor ref')
  return dict(slot=slot,chain=chain,owner=step,session=session,event=event,generation=generation,
              slot_address=slot_address,chain_session=chain_session,
              custody=self.custody_state(F(b,t,'custody')),maps=self.maps_state(F(b,t,'maps')))
 def page(self,b,address,backing,identity=None):
  # append() assigns each initial-image page its own successive generation.
  # Do not equate two different pages' generations, even within one object.
  key=interval.Reader.page(self,b,address,backing)
  if address in self.page_keys:need(key==self.page_keys[address],'same complete actual page identity at every observation')
  for a,k in self.page_keys.items():
   need(key[0]==k[0]and key[2]==k[2]and key[1]-k[1]==(address-a)//4096,
        'one original main allocation/object and exact append generation for each distinct page')
  self.page_keys[address]=key;return key
 def transfer_map(self,v,index,fault):
  expected=self.accepted_fault if fault else self.accepted_transfers.get(index)
  need(expected is not None and v==expected,'whole original transfer receipt equals independently checked outer API observation')
  kind=self.integer(self.field(v,'li2_fetch_rx_view','custody'),'li2_page_custody_receipt','kind')
  if kind==1:
   self.maps_fresh(self.field(v,'li2_fetch_rx_view','maps'))
  else:
   need(kind==2 and self.integer(v,'li2_fetch_rx_view','maps_observed')==0 and
        not any(self.field(v,'li2_fetch_rx_view','maps')),'retained branch has no current maps receipt')
 def partial_slot(self,observed,slot,*,previous=None,changed=''):
  # The observer uses a fresh zero object. chain_observe writes only the real
  # source prefix in a persistent slot; its untouched suffix is still data.
  t='li2_chain_fetch';n=self.integer(observed,t,'length')
  ob=self.field(observed,t,'bytes');sb=self.field(slot,t,'bytes')
  need(ob[:n]==sb[:n]and not any(ob[n:]),'exact copy-only partial source and zero unused observer capacity')
  if previous is not None:need(sb[n:]==self.field(previous,t,'bytes')[n:],'every unassigned persistent slot source-tail byte retained')
  self.changed(slot,observed,t,('bytes '+changed).strip())
 def registration(self,b,pid):
  I,F=self.integer,self.field;t='li2_rseq_state';d=F(b,t,'data');dt='li2_rseq_data'
  need(self.values(b,t,'initialized registered held phase pid tid address page length signature epoch fs_base gs_base fs_result gs_result tls_attempted tls_complete calls registrations unregistrations kernel_errors')==
       (1,1,1,3,pid,pid,AREA,PAGE,32,0x53053053,1,DATA+2048,DATA+2304,0,0,1,1,1,1,0,0),
       'complete actual singleton registered identity, original TLS and one real registration')
  need(self.values(d,dt,'address page pid tid attempted complete error detail')==(AREA,PAGE,pid,pid,1,1,0,0)and
       I(d,dt,'allocation')>0 and I(d,dt,'generation')>0 and I(d,dt,'offset')%4096==0,'actual complete anonymous rseq data pin')
  self.maps(F(d,dt,'maps'))
  identity=self.values(d,dt,'address page allocation generation offset pid tid')
  if self.registration_identity is None:self.registration_identity=identity
  need(identity==self.registration_identity,'no cached per-instruction rseq answer; same actual allocation identity')
  tx=F(b,t,'transaction');tt='li2_rseq_transaction'
  need(F(tx,tt,'args')==struct.pack('<6q',AREA,32,0,0x53053053,-1,0)and
       self.values(tx,tt,'result attempted issued returned prior_registered input_word_observed input_word')==(0,1,1,1,0,1,0),
       'complete real original registration syscall transaction')
  before,after=(F(tx,tt,k)for k in('before','after'))
  for raw in(before,after):
   need(self.values(raw,dt,'address page allocation generation offset pid tid')==identity and
        self.values(raw,dt,'attempted complete error detail')==(1,1,0,0),'both complete original actual registration pin observations')
   self.maps(F(raw,dt,'maps'))
  need(d==after,'retained registration data is the actual post-syscall pin observation')
  return identity
 def remember_backing(self,v,anchor):
  serial=self.integer(v,'li2_fetch_rx_view','serial')
  need(serial>0,'actual RX serial for a complete historical backing')
  if serial in self.history_anchors:need(anchor==self.history_anchors[serial],'same historical RX serial retains every stat byte and descriptor')
  self.history_anchors[serial]=anchor
 def after_native_copy(self,before,after):
  # Both arguments come from backing(), which independently validates all
  # actual stat fields/timestamps. Only the named callsite can authorize this
  # cross-episode comparison; the inherited backing() remains fully exact.
  at=self.types['stat']['fields']['st_atim'];a,n=at['offset'],at['bytes']
  need(n==16 and before[0]==after[0]and before[1][:a]==after[1][:a]and before[1][a+n:]==after[1][a+n:],
       'source-proven native pread boundary: same descriptor and every stat byte except typed atime')
 def history(self,v,image,pid,meta,anchor=None):
  # An EMPTY certificate can leave diagnostic RX bytes from setup or a real
  # cancellation. They are fully typed/source-bound, never current authority.
  if not any(v):return anchor
  I,F=self.integer,self.field;t='li2_fetch_rx_view';c=F(v,t,'custody');ct='li2_page_custody_receipt'
  pc,n=self.values(v,t,'pc length')
  need(I(v,t,'phase')in(2,3,4,5)and I(v,t,'complete')==1 and I(v,t,'result')in(0,302)and
       I(v,t,'serial')>0 and I(v,t,'before_sequence')>0 and
       I(v,t,'after_sequence')==(I(v,t,'before_sequence')+1 if I(v,t,'phase')==4 else 0)and
       self.values(v,t,'pid tid')==(pid,pid)and MAIN<=pc<MAIN+24576 and n==min(15,4096-(pc&4095))and
       F(v,t,'bytes')==bytes.fromhex(image['source_hex'])[pc-MAIN:pc-MAIN+n].ljust(15,b'\0'),
       'entire non-authoritative historical RX source/sequence/process prefix')
  anchor=self.backing(F(v,t,'backing'),image['backing'],self.history_anchors.get(I(v,t,'serial'),anchor));self.page(F(v,t,'page'),pc&~4095,anchor)
  self.remember_backing(v,anchor)
  kind=I(c,ct,'kind');slot=I(c,ct,'slot');owner=meta['chain']+self.types['li2_tf_chain']['fields']['slots']['offset']+slot*self.types['li2_tf_chain_slot']['bytes']+self.types['li2_tf_chain_slot']['fields']['owner']['offset']+self.types['li2_tf_owner']['fields']['step']['offset']
  need(kind in(1,2)and slot in(0,1)and self.values(c,ct,'provenance chain owner session')==(1,meta['chain'],owner,meta['chain_session'])and
       0<I(c,ct,'epoch')<=meta['custody']['epoch']and 0<I(c,ct,'event')<=meta['event']and I(c,ct,'owner_generation')>0 and
       0<I(c,ct,'origin_sequence')<=I(v,t,'before_sequence')and I(c,ct,'checks')in((0,)if kind==1 else(1,2)),
       'complete retained diagnostic custody provenance, with no fresh/current use')
  serial=I(v,t,'serial')
  if serial in self.history_views:need(v==self.history_views[serial],'every byte of previously observed historical RX remains exact')
  self.history_views[serial]=v
  self.maps_fresh(F(c,ct,'origin'))
  if kind==1:need(I(v,t,'maps_observed')==1 and F(v,t,'maps')==F(c,ct,'origin'),'historical FRESH keeps its genuine origin receipt')
  else:need(I(v,t,'maps_observed')==0 and not any(F(v,t,'maps')),'historical RETAINED has no invented maps I/O')
  return anchor
 def raw_fetch(self,b,image,pid,anchor=None,identity=None,*,partial=True,unpublished=False):
  """All actual payload fields, with receipt semantics checked by its point."""
  I,F=self.integer,self.field;t='li2_chain_fetch';ref=F(b,t,'ref');pr=F(b,t,'progress')
  pc,n,pages=self.values(b,t,'pc length page_count')
  need(MAIN<=pc<MAIN+24576 and 0<n<=15 and pc+n<=MAIN+24576 and pages in(1,2)and
       pages==1+int((pc&~4095)!=((pc+n-1)&~4095))and
       self.values(b,t,'pid tid identity_observed')==(pid,pid,1)and
       F(b,t,'bytes')[:n]==bytes.fromhex(image['source_hex'])[pc-MAIN:pc-MAIN+n]and(not partial or not any(F(b,t,'bytes')[n:])),
       'complete actual partial-fetch source/process/extent; no source shortening')
  pg=self.array(b,t,'pages','li2_fetch_page');backs=self.array(b,t,'backing','li2_fetch_backing')
  for i in range(pages):
   anchor=self.backing(backs[i],image['backing'],anchor)
   identity=self.page(pg[i],(pc&~4095)+4096*i,anchor,identity)
  for raw in pg[pages:]+backs[pages:]:self.zero(raw,'unused page/backing')
  last=F(b,t,'last_backing')
  if any(last):self.backing(last,image['backing'],anchor)
  else:need(I(pr,'li2_fetch_progress','last_backing_observed')==0,'zero last-backing requires genuinely absent observation')
  need(I(ref,'li2_fetch_ref','owner')>0 and I(ref,'li2_fetch_ref','sequence')>0,'real singleton ref identity')
  actual_owner=I(ref,'li2_fetch_ref','owner')
  if self.fetch_owner is None:self.fetch_owner=actual_owner
  need(actual_owner==self.fetch_owner,'same actual opaque lifecycle singleton, not the permission-owner pointer')
  seq=I(pr,'li2_fetch_progress','sequence');calls=I(pr,'li2_fetch_progress','validation_calls')
  need(seq==I(ref,'li2_fetch_ref','sequence')+int(unpublished)and self.values(pr,'li2_fetch_progress','complete identity_observed pages_copied bytes_copied')==(1,1,pages,n)and
       I(pr,'li2_fetch_progress','held')in(0,1)and I(pr,'li2_fetch_progress','first_error')in(0,302)and I(pr,'li2_fetch_progress','first_detail')==0 and
       0<=I(pr,'li2_fetch_progress','last_backing_page')<pages and I(pr,'li2_fetch_progress','last_backing_observed')in(0,1),'every actual copied progress field and exact ordinary/pre-publication sequence')
  prep=F(pr,'li2_fetch_progress','preparation');validation=F(pr,'li2_fetch_progress','validation')
  if any(prep):self.maps(prep)
  else:need(seq in self.retained_sequences or unpublished,'only an explicitly authenticated retained candidate has zero preparation')
  if calls:self.maps(validation)
  else:self.zero(validation,'zero current validation without original validation call')
  return anchor,identity

GREG,VECTORS,MASKS,page_ids=old.GREG,old.VECTORS,old.MASKS,old.page_ids
MAGIC=old.MAGIC
program=old.program

def literal_states(image,cpuid,context,overlap=False):
 if overlap:return module('cso_overlap_literals',BASE/'page_custody_overlap/check.py').states(image,cpuid)
 if context is not None:
  return module('cso_stack_literals',BASE/'page_custody_stack/check.py').states(image,context)
 # Cases6–9 use the literal case0 body. Their fixed failure point, not a
 # different instruction model, limits the actually completed prefix below.
 return old.states(dict(image,case=0)if image['case']>=6 else image,cpuid)

def literal_program(image,context,overlap):
 if context is not None:return module('cso_stack_program',BASE/'page_custody_stack/check.py').program()
 if overlap:return module('cso_overlap_program',BASE/'page_custody_overlap/check.py').program()
 return old.program(image['case'])

def literal_memory(image,context,native,page,state,terminal=False,episode=0):
 if context is None:return old.memory(image,native,page,state,terminal)
 stack=module('cso_stack_memory',BASE/'page_custody_stack/check.py')
 return stack.memory(image,native,page,context,3 if terminal else episode*2,terminal)

def literal_endpoint(r,b,st,image,index,components,context):
 return old.endpoint(r,b,st,image,False,index,components)

# BEGIN ORIGINAL FINITE SEMANTIC BODY, WITH EXPLICIT CUSTODY BRANCHES.
def _core(r,image,pid,exit_status,control,stack_context,overlap):
 data=r.field(r.data,'cso_stream','base');base_type=r.types['lso_record'];lease=True
 stack=stack_context is not None;model_case=image['case'];warm=bool(control)
 expected_events=(7 if stack else 2 if warm else old.GENERIC[model_case])
 expected_transfers=(3 if stack else 1 if warm else old.TRANSFERS[model_case] if model_case<5 else 0)
 c=image['case'];need(type(lease)is bool and type(pid)is int and pid>0 and type(exit_status)is int and exit_status==old.EXIT[c],'actual fixed gated outcome')
 I,F=r.integer,r.field;h=q(F(data,base_type,'h'));et=r.types['lso_event'];rows=F(data,base_type,'events')
 need(h[:6]==(MAGIC,2,len(data),c,r.ucn,et['bytes'])and h[6]&0xe7==0xe7 and h[7:11]==(1,0,1,old.EXIT[c])and h[13:15]==(expected_events,1)and
      h[15]>0 and h[16]==512*1024 and h[17]==h[18]>0 and h[19:21]==(pid,pid)and not any(h[22:32]+h[40:41]+h[50:]),'complete actual terminal record, no partial success')
 need(len(rows)==12*et['bytes']and not any(rows[expected_events*et['bytes']:]),'bounded fixed event capacity and zero unused rows')
 hw=struct.unpack('<14I',F(data,base_type,'hardware'));need(hw[:2]==(1,0)and hw[2]>=13 and hw[8]&0x18000000==0x18000000 and hw[11]&0x40010000==0x40010000,'actual pre-arm CPUID capability')
 components=r.components(F(data,base_type,'xstate'));cpuid=None;ch=q(F(data,base_type,'cpuid_h'))
 if c==2:
  need(ch[:3]==(1,1,3)and ch[3]==ch[4]==ch[5]==2 and ch[6:10]==(BODY+36,BODY+38,0,0)and ch[10:14]==ch[14:18]and not any(ch[18:]),'exact interpreter plus one program CPUID; actual raw sample equals committed result')
  cpuid=ch[10:14];cb=r.frame(F(data,base_type,'cpuid_before'),image);ca=r.frame(F(data,base_type,'cpuid_after'),image,'committed')
  changed=bytearray(cb['uc'])
  for reg,value in zip((13,11,14,12),cpuid):put(changed,r.go+8*reg,value)
  put(changed,r.go+16*8,BODY+38);put(changed,r.go+17*8,cb['greg'][17]&~0x10000)
  need(bytes(changed)==ca['uc']and cb['h']==ca['h']and cb['fp']==ca['fp']and cb['data']==ca['data']and cb['page']==ca['page'],'complete exact builtin frame commit and unchanged FP/source/data/mask')
 else:need(not any(F(data,base_type,'cpuid_h')+F(data,base_type,'cpuid_before')+F(data,base_type,'cpuid_after')),'no fabricated program CPUID')
 model=literal_states(image,cpuid,stack_context,overlap);executed=[x for x in model if x['kind']not in('nop','cpuid')]
 if c>=5:executed=executed[:1+int(warm)]
 need(len(executed)==expected_events,'source-fixed generic execution count')
 ep=F(data,base_type,'endpoints');nt=r.types['lso_native_row'];ends=[]
 for i in range(2 if c<5 else 1):
  row=ep[i*nt['bytes']:(i+1)*nt['bytes']];f=literal_endpoint(r,row,nt,image,i,components,stack_context);v=q(F(row,nt,'h'))
  need(not any(v[5:24]+v[28:]),'endpoint has actual native-fetch READY return and no invented permission calls')
  r.envelope(f,h[15],h[16],False);state=model[4]['after']if stack and i else model[-1]['after']if i else model[0]['before'];old.literal(f,state,GUARD if i else model[0]['pc'],0x10000,components)
  need(f['data']==literal_memory(image,stack_context,False,f['page'],state,episode=0),'complete actual endpoint data/stack');ends.append(f)
 if c>=5:need(not any(ep[nt['bytes']:]),'failed operation has no endpoint')
 baseline=ends[0]['fp'];previous=None;active_opening=None;actual_transfers=closed=0;observed_cpus=[page_ids(f['page'])['cpu']for f in ends]
 def sub(b,t,k):return F(b,t,k)
 def step(owner):return F(owner,'li2_tf_owner','step')
 def request(p):return F(p,'li2_step_owner','request')
 def initialized(a,b):
  t='li2_step_frame';n=I(a,t,'fp_bytes');need(n==I(b,t,'fp_bytes')and I(a,t,'initialized')==I(b,t,'initialized')==n and 512<=n<=65536,'same entire initialized frame extent')
  off=r.types[t]['fields']['fp']['offset'];need(a[:off+n]==b[:off+n],'all initialized metadata/FP bytes exact')
 def opening(lr,expected=None):
  t='li2_tf_same_page';actual=(F(lr,t,'opening'),F(lr,t,'opening_frame'),
       *(I(lr,t,k)for k in('slot','owner_generation','origin_event','origin_borrow')))
  if expected is None:
   need(actual[0]==rq and actual[2:]==(v[2],v[3],v[17],seq),'original request/slot/generation/event/borrow from the actual pre-transfer owner')
   initialized(actual[1],saved)
  else:need(actual==expected,'entire original opening proof persists through transfer and actual final close')
  return actual
 def maps_receipt(b,direct=False):
  mt='li2_fetch_map_progress';ot='li2_maps_observation';o=F(b,mt,'observation')
  need(I(b,mt,'fd')>3 and I(b,mt,'last_read')==I(b,mt,'close_result')==0 and
       0<I(b,mt,'bytes')<=256*1024 and 0<I(b,mt,'rows')<=2048 and
       all(I(b,mt,k)==1 for k in('opened','close_started','closed')),'actual complete maps acquisition with EOF and closed descriptor')
  if direct:need(not any(o),'separate direct post-failure observation does not invent a phase receipt')
  else:need(I(o,ot,'acquisition_id')>0 and I(o,ot,'handler_id')>0 and I(o,ot,'mutation_epoch')>0 and
       I(o,ot,'kind')==I(o,ot,'io_performed')==1,'fresh actual RX acquisition in this handler, no inherited validity')
 def borrow(b,pc,pages,held):
  t='li2_chain_fetch';ref=F(b,t,'ref');pr=F(b,t,'progress');seq=I(ref,'li2_fetch_ref','sequence')
  need(I(ref,'li2_fetch_ref','owner')>0 and seq>0 and I(pr,'li2_fetch_progress','sequence')==seq and I(pr,'li2_fetch_progress','held')==held and
       I(pr,'li2_fetch_progress','complete')==I(pr,'li2_fetch_progress','identity_observed')==1 and I(pr,'li2_fetch_progress','first_error')==I(pr,'li2_fetch_progress','first_detail')==0 and
       I(b,t,'pc')==pc and I(b,t,'page_count')==pages and I(b,t,'pid')==I(b,t,'tid')==pid and I(b,t,'identity_observed')==1,'complete live held/released fetch identity')
  n=I(b,t,'length');need(1<=n<=15 and F(b,t,'bytes')[:n]==bytes.fromhex(image['source_hex'])[pc-MAIN:pc-MAIN+n],'every borrowed source byte')
  return seq
 for i,m in enumerate(executed):
  row=rows[i*et['bytes']:(i+1)*et['bytes']];v=q(F(row,et,'h'));bcount=q(F(row,et,'counts_before'));acount=q(F(row,et,'counts_after'))
  need(v[:2]==(1,i)and v[2]in(0,1)and v[3]>0 and 0<v[17]<bcount[0]and v[18]in(1,2)and v[19]==3 and not any(v[20:24]+v[28:]),'actual ordered event and original owner event identity')
  before=r.frame(F(row,et,'before'),image,'trace');r.envelope(before,h[15],h[16],False);r.entry_siginfo(row,et,before,v[4]==1)
  old.literal(before,m['after'],m['next'],0x100,components);need(before['data']==literal_memory(image,stack_context,False,before['page'],m['after'],episode=m.get('episode',0)),'complete per-instruction state and disjoint store')
  expected_fp=bytearray(baseline);expected_fp[160:176]=m['after'][2][:16]
  need(before['fp']==bytes(expected_fp),'entire hardware FP image; only literal PXOR bytes change')
  observed_cpus.append(page_ids(before['page'])['cpu'])
  ob,oa=F(row,et,'owner_before'),F(row,et,'owner_after');pb,pa=step(ob),step(oa);rq=request(pb);d=F(rq,'li2_step_request','decoded')
  pages=1+int((m['pc']&~4095)!=((m['pc']+m['length']-1)&~4095))
  need(I(pb,'li2_step_owner','phase')==3 and I(pb,'li2_step_owner','first_error')==0 and I(pb,'li2_step_owner','in_handler')==I(pb,'li2_step_owner','trace_seen')==0 and
       I(d,'li2_decoded','pc')==m['pc']and I(d,'li2_decoded','next_pc')==m['pc']+m['length']and I(d,'li2_decoded','length')==m['length']and
       I(rq,'li2_step_request','page_count')==pages and I(rq,'li2_step_request','original_flags')==m['before'][1],'actual running instruction and original logical flags')
  for k in('open_started','opened'):need(struct.unpack('<2I',F(pb,'li2_step_owner',k))==(1,int(pages==2)),'only actual original opens')
  for k in('revoke_started','revoked','revoke_result'):need(not any(F(pb,'li2_step_owner',k)),'no invented pre-effect revocation')
  need(not any(F(pb,'li2_step_owner','open_result'))and I(pb,'li2_step_owner','open_sync')==0,'actual successful original opening')
  saved=F(pb,'li2_step_owner','before');sg=q(F(saved,'li2_step_frame','greg'))
  need(tuple(sg[n]for n in GREG)==m['before'][0]and sg[16]==m['pc'],'literal complete saved execution input')
  from_lease=previous is not None and previous['result']==2
  need(sg[17]==(m['before'][1]|(0x100 if from_lease else 0x10000 if sg[20]==14 else 0)),'genuine TF-set transfer before-frame versus actual old NX/TRACE armed frame')
  if i==0:r.step_frame(saved,ends[0])
  if from_lease:need(ob==previous['owner_after']and v[17]==previous['event'],'same actual permission owner and committed event survive application retirement')
  bf,af=F(row,et,'fetch_before'),F(row,et,'fetch_after');seq=borrow(bf,m['pc'],pages,1)
  need(bcount[10:13]==(v[2],1,0)and bcount[15]==301,'one real pending chain and continuously held fetch interlock')
  rb,ra=F(row,et,'rseq_before'),F(row,et,'rseq');rt='li2_rseq_state'
  for state in(rb,ra):
   need(tuple(I(state,rt,k)for k in('initialized','registered','held','phase','pid','tid','address','page','length','signature','epoch'))==
        (1,1,1,3,pid,pid,AREA,PAGE,32,0x53053053,1)and
        tuple(I(state,rt,k)for k in('tls_attempted','tls_complete','fs_result','gs_result','fs_base','gs_base'))==
        (1,1,0,0,DATA+2048,DATA+2304),'same real ACTIVE registration and fresh completed TLS authority at every transfer')
  checked_next=(v[4]==1 and v[5]in(1,2))or(c in(5,7,9)and i==control)
  need(I(ra,rt,'instruction_checks')==I(rb,rt,'instruction_checks')+int(checked_next),'every actual admitted successor performs one fresh instruction guard')
  if checked_next:
   successor=next(x for x in literal_program(image,stack_context,overlap)if x[0]==m['next']);pc,n,kind=successor
   is_store=kind in('store','overlap');first=(stack_context['target']if stack_context is not None else WORD if c==5 else DATA+128)if is_store else 0;end=first+8 if is_store else 0
   footprint=F(ra,rt,'last_footprint');ft='li2_write_footprint'
   need(tuple(I(footprint,ft,k)for k in('pc','next_pc','first','end','abi_version','policy','length'))==
        (pc,pc+n,first,end,1,2 if is_store else 1,n)and I(footprint,ft,'code')==I(ra,rt,'last_code')and
        tuple(I(ra,rt,k)for k in('last_pc','last_first','last_end','last_policy'))==(pc,first,end,2 if is_store else 1)and
        I(ra,rt,'range_checks')==I(rb,rt,'range_checks')+int(is_store),
        'actual fresh typed successor footprint including exact disjoint/publication write range')
  expected_rseq=bytearray(rb)
  changed=('instruction_checks','range_checks','last_pc','last_code','last_first','last_end','last_policy','last_footprint')if checked_next else()
  if c==5 and i==control:changed+=('first_error','first_detail')
  for key in changed:
   f=r.types[rt]['fields'][key];a=f['offset'];expected_rseq[a:a+f['bytes']]=ra[a:a+f['bytes']]
  need(bytes(expected_rseq)==ra and I(rb,rt,'first_error')==0 and I(ra,rt,'first_error')==(1205 if c==5 and i==control else 0)and I(ra,rt,'first_detail')==0,
       'complete registration/pin/TLS state unchanged outside the exact new guard observations')
  if c>=5 and i==control:
   need(v[4:6]==(0,0)and not any(F(row,et,'after')),'terminal prefix never invents a returned trace or state')
   need(I(pa,'li2_step_owner','phase')==6 and I(pa,'li2_step_owner','first_error')>0 and struct.unpack('<2I',F(pa,'li2_step_owner','revoke_started'))==(1,0)and
        struct.unpack('<2Q',F(pa,'li2_step_owner','revoke_result'))==(0,0)and I(pa,'li2_step_owner','revoke_sync_started')==1 and I(pa,'li2_step_owner','revoke_sync')==0 and
        not any(F(row,et,'release'))and I(oa,'li2_tf_owner','continuation_started')==0,'failed operation attempted actual original-page revoke and sync; no close/release claim')
   need(request(pa)==rq and I(pa,'li2_step_owner','session')==I(pb,'li2_step_owner','session')and F(pa,'li2_step_owner','hooks')==F(pb,'li2_step_owner','hooks'),'same original permission cleanup owner through failure')
   need(v[6:10]==(v[2],v[3],7,v[18])and v[10:12]==(0,0), 'failed staged transfer retains its original active slot; no successor publication')
   need(tuple(struct.unpack('<2I',F(pa,'li2_step_owner','revoked')))==(1,0),
        'actual successful mprotect is retained even when subsequent authentication fails; phase remains FAILED')
   lr=F(row,et,'lease');lt='li2_tf_same_page'
   need(I(lr,lt,'origin_active')==int(warm or c in(7,9)),'only the actual commit prefixes install an original opening proof')
   if warm or c in(7,9):
    need(I(lr,lt,'phase')==(2 if c in(7,9)else 1),'failed commit prefix remains TRANSFERRING, never CLOSED')
    active_opening=opening(lr,active_opening)
   continue
  need(v[4]==1 and v[5]in(0,1,2)and(lease or v[5]!=2),'actual completed strict result discriminator')
  after=r.frame(F(row,et,'after'),image,'returned');r.envelope(after,h[15],h[16],False)
  ua=bytearray(before['uc']);put(ua,r.go+17*8,after['greg'][17])
  need(bytes(ua)==after['uc']and before['fp']==after['fp']and before['h']==after['h']and before['data']==after['data']and before['page']==after['page'],
       'every real local byte preserved except exact owner TF transition')
  r.step_frame(F(pa,'li2_step_owner','after'),before)
  if v[5]==2:
   actual_transfers+=1;need(F(row,et,'before')==F(row,et,'after')and after['greg'][17]&0x100,'no transfer frame normalization')
   need(v[6:10]==(v[2],v[3],3,v[18])and v[10:12]==(0,0),'same actual opening slot/generation, no invented retry or fallback')
   need(acount[:2]==bcount[:2]and acount[2:10]==bcount[2:10]and acount[10:13]==bcount[10:13]and acount[15]==301,'no synthetic preparation/open/step/close/release accounting')
   lr=F(row,et,'lease');lt='li2_tf_same_page';vtx=F(lr,lt,'transfer');vt='li2_fetch_rx_view';nextpc=m['next']
   need(I(lr,lt,'phase')==3 and I(lr,lt,'origin_active')==1 and I(lr,lt,'slot')==v[2]and I(lr,lt,'owner_generation')==v[3]and
        I(lr,lt,'completed_event')==bcount[0]and I(vtx,vt,'phase')==4 and I(vtx,vt,'complete')==1 and I(vtx,vt,'result')==0 and
        I(vtx,vt,'before_sequence')==seq and I(vtx,vt,'pc')==nextpc and I(vtx,vt,'pid')==I(vtx,vt,'tid')==pid,'complete same-slot same-generation transfer receipt')
   active_opening=opening(lr,active_opening)
   nextseq=borrow(af,nextpc,1,1);need(nextseq==I(vtx,vt,'after_sequence')==seq+1,'actual singleton replacement followed by exact ref publication')
   n=I(vtx,vt,'length');need(n==min(15,4096-(nextpc&4095))and F(vtx,vt,'bytes')[:n]==bytes.fromhex(image['source_hex'])[nextpc-MAIN:nextpc-MAIN+n],'complete clipped fresh RX source window')
   r.transfer_map(vtx,i,False)
   p=F(vtx,vt,'page');pt='li2_fetch_page';original_page=F(rq,'li2_step_request','pages')[:r.types['li2_step_page']['bytes']]
   need(tuple(I(p,pt,k)for k in('address','allocation','generation','offset'))==
        tuple(I(original_page,'li2_step_page',k)for k in('address','object','generation','offset'))and
        I(p,pt,'logical')==5 and I(p,pt,'closed_prot')==1 and I(p,pt,'backing')==1 and
        I(p,pt,'vma_first')<=I(p,pt,'address')and I(p,pt,'vma_end')>=I(p,pt,'address')+4096,
        'fresh observed mapping retains the exact original opening allocation/generation/page/source offset')
   backing=F(vtx,vt,'backing');bt='li2_fetch_backing'
   need(I(backing,bt,'retained_fd')>3 and I(backing,bt,'seals')&15==15 and I(backing,bt,'stat_result')==0 and
        I(backing,bt,'seals_observed')==I(backing,bt,'stat_observed')==1 and
        F(af,'li2_chain_fetch','backing')[:r.types[bt]['bytes']]==backing,
        'actual sealed backing queries retained in the committed singleton')
   need(F(lr,lt,'previous')==rq and F(lr,lt,'previous_fetch')==F(bf,'li2_chain_fetch','progress'),'exact predecessor request and held fetch')
   initialized(F(lr,lt,'previous_before'),saved);r.step_frame(F(pa,'li2_step_owner','before'),before)
   need(F(request(pa),'li2_step_request','decoded')==F(lr,lt,'next')and F(oa,'li2_tf_owner','classification')==F(lr,lt,'classification')and
        tuple(I(pa,'li2_step_owner',k)for k in('signal_number','signal_code','signal_errno','signal_address'))==(5,2,0,m['next']),
        'new request/classification and actual entry fields match the authenticated transfer')
   need(I(pa,'li2_step_owner','phase')==3 and I(pa,'li2_step_owner','trace_seen')==0 and I(pa,'li2_step_owner','in_handler')==0 and
        F(request(pa),'li2_step_request','pages')==F(rq,'li2_step_request','pages')and I(request(pa),'li2_step_request','page_count')==1 and
        I(pa,'li2_step_owner','session')==I(pb,'li2_step_owner','session')and F(pa,'li2_step_owner','hooks')==F(pb,'li2_step_owner','hooks')and
        not any(F(row,et,'release')+F(row,et,'query'))and I(oa,'li2_tf_owner','continuation_started')==0,'original actual permission owner; no invented CLOSED continuation')
   for k in('open_started','opened','open_result','open_sync','revoke_started','revoked','revoke_result','revoke_sync_started','revoke_sync'):
    need(F(pa,'li2_step_owner',k)==F(pb,'li2_step_owner',k),'all actual permission-call fields unchanged on transfer '+k)
   original=bytearray(ob);sf=r.types['li2_tf_owner']['fields']['step'];pt=r.types['li2_step_owner'];qt=r.types['li2_step_request']
   # These are the only fields assigned by the real completed transfer. Keep
   # every other owner byte, including hooks, opening results and padding.
   for key in('before','after','signal_number','signal_code','signal_errno','signal_address'):
    field=pt['fields'][key];a=sf['offset']+field['offset'];original[a:a+field['bytes']]=oa[a:a+field['bytes']]
   for key in('decoded','original_flags'):
    field=qt['fields'][key];a=sf['offset']+pt['fields']['request']['offset']+field['offset'];original[a:a+field['bytes']]=oa[a:a+field['bytes']]
   for key in('classification','actual_post_pc','actual_post_flags'):
    field=r.types['li2_tf_owner']['fields'][key];a=field['offset'];original[a:a+field['bytes']]=oa[a:a+field['bytes']]
   need(bytes(original)==oa,'complete same permission-owner bytes outside explicit authenticated transfer fields')
  else:
   closed+=1;need(I(pa,'li2_step_owner','phase')==5 and I(pa,'li2_step_owner','first_error')==0 and I(pa,'li2_step_owner','trace_seen')==1 and
        I(pa,'li2_step_owner','revoke_sync_started')==1 and I(pa,'li2_step_owner','revoke_sync')==0 and
        I(oa,'li2_tf_owner','continuation_started')==I(oa,'li2_tf_owner','continuation_complete')==1 and I(oa,'li2_tf_owner','continuation_result')==0,'actual old complete trace/revoke/sync/continuation route')
   for k in('revoke_started','revoked'):need(struct.unpack('<2I',F(pa,'li2_step_owner',k))==(1,int(pages==2)),'all original pages actually revoked')
   need(not any(F(pa,'li2_step_owner','revoke_result'))and F(request(pa),'li2_step_request','pages')==F(rq,'li2_step_request','pages'),'real final revoke keeps original opening page identity')
   need(tuple(I(F(row,et,'release'),'li2_chain_release',k)for k in('started','complete','result'))==(1,1,0),'actual complete release')
   need(borrow(af,m['pc'],pages,0)==seq and acount[3]==bcount[3]+1 and acount[8]>bcount[8]and acount[7]>bcount[7],'one actual old completed step, release and successor preparation')
   if active_opening is not None:
    lr=F(row,et,'lease');opening(lr,active_opening)
    need(I(lr,'li2_tf_same_page','phase')==5 and I(lr,'li2_tf_same_page','origin_active')==0,'original opening proof reaches its actual CLOSED receipt')
    active_opening=None
   nq=F(row,et,'query');need(tuple(I(nq,'li2_tf_continuation',k)for k in('pc','attempted','page_observed','complete','result'))==(m['next'],1,1,1,0),'actual closed continuation at exact next PC')
   nf=F(row,et,'next_fetch');need(I(F(nf,'li2_chain_fetch','ref'),'li2_fetch_ref','sequence')>seq,'strictly new ordinary borrow after final lease close')
   need(v[6]==(v[2]^1)and v[7]>0 and v[8]==(3 if v[5]==1 else 6)and v[9]==2 and v[12:14]==(1,1)and v[16]==m['next'],
        'actual ordinary successor preparation after the original owner closes')
   need(v[11]==(0 if v[5]==1 else 3 if c==2 and m['next']==BODY+36 else 4),'exact selected/old-NOP fallback; no invented domain refusal')
   retry=(c==4 and i==0)
   need(v[10]==int(retry),'only the actual clipped cross-page preparation retries')
   if retry:
    ff=F(row,et,'next_first_fetch');fd=F(row,et,'next_first_decoded');fr=F(row,et,'next_first_release')
    fs=borrow(ff,TAIL-2,1,0)
    need(I(ff,'li2_chain_fetch','length')==2 and I(fd,'li2_decoded','decode_status')==2 and I(fd,'li2_decoded','available')==2 and
         tuple(I(fr,'li2_chain_release',k)for k in('started','complete','result'))==(1,1,0)and
         fs>seq and I(F(nf,'li2_chain_fetch','ref'),'li2_fetch_ref','sequence')==fs+1 and I(nf,'li2_chain_fetch','page_count')==2,
         'real clipped first borrow/release precedes a new two-page borrow; no relaxed coverage')
   else:need(not any(F(row,et,'next_first_fetch')+F(row,et,'next_first_decoded')+F(row,et,'next_first_release')),'no invented cross-page retry')
   if lease and m['kind']not in('jump_branch','jump_guard')and pages==1 and (m['pc']>>12)==(m['next']>>12):
    lr=F(row,et,'lease');tx=F(lr,'li2_tf_same_page','transfer')
    need(I(tx,'li2_fetch_rx_view','phase')==5 and I(tx,'li2_fetch_rx_view','result')==0 and
         I(tx,'li2_fetch_rx_view','before_sequence')==seq and I(tx,'li2_fetch_rx_view','after_sequence')==0,
         'clean classification/domain miss cancels staging before the unchanged actual close')
   if v[5]==1:r.step_frame(F(row,et,'next_before'),after,after['greg'][17]&~0x100)
   need(after['greg'][17]==m['after'][1]|(0x100 if v[5]==1 else 0),'exact real old close/rearm TF transition')
  previous=dict(result=v[5],owner_after=oa,event=bcount[0])
 need(actual_transfers==expected_transfers and closed==(expected_events-actual_transfers if c<5 else 0),'literal transfer versus real old-close counts')
 tc=F(data,base_type,'terminal_chain');rs=F(data,base_type,'terminal_rseq');rt='li2_rseq_state'
 need(I(rs,rt,'initialized')==I(rs,rt,'registered')==I(rs,rt,'held')==1 and I(rs,rt,'pid')==I(rs,rt,'tid')==pid and
      tuple(I(rs,rt,k)for k in('address','page','length','signature'))==(AREA,PAGE,32,0x53053053)and I(rs,rt,'epoch')==1 and
      I(rs,rt,'tls_attempted')==I(rs,rt,'tls_complete')==1 and I(rs,rt,'fs_result')==I(rs,rt,'gs_result')==0 and
      I(rs,rt,'fs_base')==DATA+2048 and I(rs,rt,'gs_base')==DATA+2304 and I(rs,rt,'phase')==3,
      'retained real registration and full actual TLS authority')
 page=F(data,base_type,'terminal_page');page_ids(page);observed_cpus.append(page_ids(page)['cpu'])
 need(F(data,base_type,'terminal_source')==bytes.fromhex(image['source_hex'])and all(f['page']==page for f in ends),'complete unchanged source and slot page')
 sender_uid=None
 if c<5:
  need(active_opening is None,'every observed transfer reaches an observed actual final close')
  need(h[11:13]==(0,0)and h[21]==0 and not any(h[32:50])and I(tc,'li2_tf_chain','pending')==I(tc,'li2_tf_chain','first_error')==0 and
       I(rs,rt,'first_error')==0 and F(data,base_type,'terminal_data')==literal_memory(image,stack_context,False,page,model[-1]['after'],True),'actual successful terminal full data and no pending/failed owner')
  if lease:
   l=F(tc,'li2_tf_chain','lease');need(I(l,'li2_tf_same_page','origin_active')==0 and I(l,'li2_tf_same_page','transfers')>=actual_transfers and I(l,'li2_tf_same_page','closed_leases')>=int(actual_transfers>0),'all leases really closed, no fabricated release')
 else:
  if active_opening is not None:
   l=F(tc,'li2_tf_chain','lease');opening(l,active_opening)
   need(I(l,'li2_tf_same_page','phase')==(2 if c in(7,9)else 1)and I(l,'li2_tf_same_page','origin_active')==1,'terminal failed prefix retains original cleanup authority without verified close')
  expected_error=1205 if c==5 else 903 if c in(6,7)else 7
  detail=302 if c==7 else 5 if c>=8 else 0
  need(h[11:13]==(expected_error,detail)and I(tc,'li2_tf_chain','first_error')==expected_error and I(tc,'li2_tf_chain','first_detail')==detail and
       h[43:47]==(1,0,1,1),'retained exact required operation failure plus independent actual R observation')
  maps_receipt(F(data,base_type,'terminal_maps'),True)
  need(F(data,base_type,'terminal_data')==literal_memory(image,stack_context,False,page,model[control]['after']),'failed effect did not write any application byte')
  need(h[32]==max(0,c-5)and h[33]==(2 if c==9 else 1 if c>=6 else 0),'exact finite failure seam selection')
  slot=F(tc,'li2_tf_chain','slots')[r.types['li2_tf_chain_slot']['bytes']*I(tc,'li2_tf_chain','active'):][:r.types['li2_tf_chain_slot']['bytes']]
  final_fetch=F(slot,'li2_tf_chain_slot','fetch');final_ref=F(final_fetch,'li2_chain_fetch','ref');progress=F(final_fetch,'li2_chain_fetch','progress')
  if c>=6:
   fv=F(data,base_type,'fault_view');vt='li2_fetch_rx_view'
   need(I(fv,vt,'phase')==(3 if c==9 else 2)and I(fv,vt,'complete')==1 and I(fv,vt,'result')==0 and
        I(fv,vt,'before_sequence')==h[34]and I(fv,vt,'after_sequence')==0 and I(fv,vt,'pc')==executed[control]['next'] and I(fv,vt,'length')==15 and
        F(fv,vt,'bytes')==bytes.fromhex(image['source_hex'])[executed[control]['next']-MAIN:executed[control]['next']-MAIN+15],
        'complete actual staged/committing prefix precedes the explicit control')
   r.transfer_map(fv,control,True)
   need(I(progress,'li2_fetch_progress','held')==1 and I(final_ref,'li2_fetch_ref','sequence')==(h[34]+1 if c==6 else h[34])and
        I(progress,'li2_fetch_progress','sequence')==(h[34]+1 if c==9 else h[34])and
        I(progress,'li2_fetch_progress','first_error')==(302 if c==7 else 0),
        'exact occupied singleton/chain-ref prefix distinguishes stale before/after replacement and backing failure')
  if c==5:need(I(rs,rt,'first_error')==1205 and word(page,72)==0 and not any(h[32:43]),'unchanged rseq publication overlap guard')
  if c==6:need(h[36]==h[34]+1 and h[37:43]==(0,0,0,0,0,0),'explicit supplied stale ref, no invented actual syscall')
  if c==7:need(h[36]>3 and h[37:40]==(1,0,1)and h[41:43]==(0,0),'actual retained backing close result precedes authentication refusal')
  if c>=8:
   need(h[37]==1 and h[38]==h[39]==0 and h[41:43]==(1,5),'genuine nested delivery before tgkill returned; no returned-call claim')
   nested=r.frame(F(data,base_type,'nested'),image,'nested');observed_cpus.append(page_ids(nested['page'])['cpu'])
   r.step_frame(F(slot,'li2_tf_chain_slot','unexpected'),nested)
   need(I(slot,'li2_tf_chain_slot','unexpected_frame_observed')==1 and I(slot,'li2_tf_chain_slot','unexpected_signal')==5 and
        I(slot,'li2_tf_chain_slot','unexpected_code')==(1<<32)-6,'actual owner retains the same genuine nested signal/frame')
   offset=h[47]-nested['h'][3];need(h[48:50]==(128,16)and offset==r.layout['offsets']['mask']+8 and offset+128<=r.ucn,'actual nested siginfo pointer/extent/typed sender alias')
   payload=bytearray(128);struct.pack_into('<iii',payload,0,5,0,-6);sender_uid=nested['h'][8]>>32
   struct.pack_into('<II',payload,16,pid,sender_uid)
   need(nested['h'][8]&0xffffffff==pid and nested['uc'][offset:offset+128]==payload,'whole genuine self-tgkill siginfo and actual sender PID, including padding')
  else:need(not any(h[47:50])and not any(F(data,base_type,'nested')),'no fabricated nested signal')
  need(h[35]==301 if c>=6 else True,'original singleton remained held at injected prefix')
 return dict(case=c,exit_status=exit_status,operation_status='passed'if c<5 else'failed',events=expected_events,transfers=actual_transfers,real_closes=closed,
             observed_cpus=observed_cpus,cpuid=cpuid,nested_sender_uid=sender_uid,accepted=True)


# END ORIGINAL FINITE SEMANTIC BODY.

def _equal_except(r,a,b,t,names,label):
 r.changed(a,b,t,names);need(a!=b or not names,'actual '+label)

def _delta(a,b,changes,label):
 need(set(a)==set(b)and all(b[k]==a[k]+changes.get(k,0)for k in a),'exact '+label+' counter/phase transition')

def _typed_model(image,cpuid,context,control,overlap):
 model=literal_states(image,cpuid,context,overlap);events=[m for m in model if m['kind']not in('nop','cpuid')]
 if image['case']>=5:events=events[:control+1]
 return model,events

def _closed_anchor_boundary(r,row,pc):
 # All full old close/frame predicates still run in _core. These explicit
 # prerequisite joins prevent a new stat anchor on a supplied scalar phase.
 I,F=r.integer,r.field;t='lso_event';h=q(F(row,t,'h'));owner=F(row,t,'owner_after');step=F(owner,'li2_tf_owner','step')
 need(h[4:6]==(1,0)and h[8:10]==(6,2)and h[11]==4 and h[16]==pc and
      r.values(step,'li2_step_owner','phase first_error trace_seen revoke_sync_started revoke_sync')==(5,0,1,1,0)and
      r.values(F(row,t,'release'),'li2_chain_release','started complete result')==(1,1,0)and
      I(F(F(row,t,'fetch_after'),'li2_chain_fetch','progress'),'li2_fetch_progress','held')==0 and
      r.values(F(row,t,'query'),'li2_tf_continuation','pc attempted page_observed complete result')==(pc,1,1,1,0),
      'actual old close/release/old-NOP fallback precedes the named native-copy boundary')

def _body_anchor_boundary(r,image,index,rows,events,base,extra,context,overlap):
 # Exactly three fixed ingress shapes. Ordinary same-BODY NOP/CPUID/branch
 # paths are already native_blocked and never authorize an atime change.
 stack=context is not None;c=image['case'];kind=1 if index==0 else 2 if not stack and not overlap and c in(3,4)and index==3 else 3 if stack and index==4 else 0
 if not kind:return 0
 I,F=r.integer,r.field;t='lso_event';row=rows[index];h=q(F(row,t,'h'));counts=q(F(row,t,'counts_before'));m=events[index]
 step=F(F(row,t,'owner_before'),'li2_tf_owner','step');saved=F(step,'li2_step_owner','before');g=q(F(saved,'li2_step_frame','greg'))
 need(h[18]==1 and h[17]+1==counts[0]and r.values(step,'li2_step_owner','phase signal_number signal_code signal_errno signal_address')==(3,11,2,0,m['pc'])and
      g[16:18]==(m['pc'],m['before'][1]|0x10000)and g[19:21]==(21,14)and g[22]==m['pc'],
      'named boundary has the actual original owner event and genuine first-byte NX frame')
 if kind==2:
  nop=TAIL+(4 if c==3 else 6)
  need(events[index-1]['pc']==TAIL+(0 if c==3 else 2)and events[index-1]['next']==nop and m['pc']==nop+1 and m['kind']=='jump_guard'and
       bytes.fromhex(image['source_hex'])[nop-MAIN:nop-MAIN+1]==b'\x90','only literal first-TAIL old NOP before the fixed jump')
  _closed_anchor_boundary(r,rows[index-1],nop)
  prior=q(F(rows[index-1],t,'counts_after'))
  need(counts[4]==prior[4]+1 and h[17]>prior[0],'one new actual NX owner after the TAIL fallback')
  before_rx=F(F(r.array(extra,'cso_record','rows','cso_row')[index-1],'cso_row','ready'),'cso_snapshot','meta')
  current=r.array(extra,'cso_record','rows','cso_row')[index]
  need(F(before_rx,'cso_meta','rx')==F(F(current,'cso_row','entry'),'cso_meta','rx'),'old cancelled TAIL receipt persists exactly across the intervening native attempt')
 else:
  endpoint=r.array(base,'lso_record','endpoints','lso_native_row')[0]if kind==1 else r.array(extra,'cso_record','stack_endpoints','lso_native_row')[0]
  need(m['pc']==events[0]['pc']if kind==1 else m['pc']==BODY+96 and events[index-1]['next']==GUARD,'fixed first or second-episode source entry')
  if kind==3:
   _closed_anchor_boundary(r,rows[index-1],GUARD)
   need(context['query_result']==context['pid']and context['proof_bytes']==152352 and context['new_first']+4096==context['stack_first']and context['target']==context['new_first']+64,
        'independently checked complete stack-growth/getpid proof before the second episode')
  raw=F(endpoint,'lso_native_row','before');eh=q(F(endpoint,'lso_native_row','h'))
  need(raw==F(endpoint,'lso_native_row','after')and eh[:5]==(1,0 if kind==1 else 2,m['pc'],m['pc'],1)and not any(eh[5:24]+eh[28:]),'whole genuine endpoint and actual native-fetch refusal, no invented permission call')
  r.step_frame(saved,r.frame(raw,image))
 return kind

def _terminal_anchor_boundary(r,image,rows,events,base,extra,context,exit_status,meta,view):
 I,F=r.integer,r.field;stack=context is not None;guard=GUARD+128 if stack else GUARD
 need(exit_status==0 and image['case']<5 and events[-1]['kind']in('jump_guard','jump_again')and events[-1]['next']==guard,
      'only successful fixed post-body path can establish a later historical stat')
 _closed_anchor_boundary(r,rows[-1],guard)
 endpoint=r.array(extra,'cso_record','stack_endpoints','lso_native_row')[1]if stack else r.array(base,'lso_record','endpoints','lso_native_row')[1]
 raw=F(endpoint,'lso_native_row','before');h=q(F(endpoint,'lso_native_row','h'));f=r.frame(raw,image)
 need(raw==F(endpoint,'lso_native_row','after')and h[:5]==(1,3 if stack else 1,guard,guard,1)and not any(h[5:24]+h[28:])and
      f['greg'][16]==f['h'][8]==guard and meta['event']>q(F(rows[-1],'lso_event','counts_after'))[0]and
      image['symbols']['rn_finish']<=I(view,'li2_fetch_rx_view','pc')<GUARD+4096,
      'new terminal history is on the exact genuine GUARD/capture/finish path after full body close')

def _audit(r,image,pid,exit_status,cpu,control,context,overlap):
 I,F=r.integer,r.field;bt='lso_record';ct='cso_record';base=F(r.data,'cso_stream','base');extra=F(r.data,'cso_stream','custody')
 h=q(F(base,bt,'h'));ch=q(F(extra,ct,'h'));stack=context is not None;c=image['case']
 need(type(control)is int and control in(0,1)and(not control or c in(6,7,8,9)or overlap)and type(overlap)is bool and(not overlap or c==5 and control==1 and not stack)and
      type(cpu)is int and cpu>=0 and type(pid)is int and pid>0 and type(exit_status)is int,
      'fixed genuine lane, cold/warm fault selector and external process/CPU')
 need(ch[:14]==(0x31564f5453554350,1,len(extra),12,int(stack),0 if overlap else control,int(overlap),1,1,0,exit_status,h[11],h[12],h[13])and not any(ch[14:]),
      'complete actual source-selected custody header/outcome, no failed-prefix completion')
 rows=r.array(base,bt,'events','lso_event');observations=r.array(extra,ct,'rows','cso_row')
 cpuid=q(F(base,bt,'cpuid_h'))[10:14]if c==2 else None
 model,events=_typed_model(image,cpuid,context,control,overlap)
 need(h[13]==len(events)<=12 and all(not any(v)for v in rows[len(events):]+observations[len(events):]),'exact source event count and zero unused whole rows')
 r.accepted_transfers={};r.accepted_fault=None
 origin=None;anchor=None;page_identity=None;last_ready=None;fresh=retained=commits=0
 for index,(row,co,m)in enumerate(zip(rows,observations,events)):
  et='lso_event';ot='cso_row';v=q(F(row,et,'h'));bc=q(F(row,et,'counts_before'))
  ob,oa=F(row,et,'owner_before'),F(row,et,'owner_after');bf,af=F(row,et,'fetch_before'),F(row,et,'fetch_after')
  entry=r.meta(F(co,ot,'entry'),index,1,0,pid,ob,F(bf,'li2_chain_fetch','ref'))
  need((entry['slot'],entry['generation'],entry['event'])==(v[2],v[3],bc[0]),'actual old/new row and current event identity')
  need(entry['maps']['active']==1 and entry['maps']['valid']==0,'global maps facts invalidated before this real handler route')
  if last_ready is not None and origin is not None:
   _delta(last_ready['custody'],entry['custody'],{'phase':1},'READY to next genuine ENTRY')
   _delta(last_ready['maps'],entry['maps'],dict(invalidations=3,mutation_epoch=3,handler_id=1,valid=-last_ready['maps']['valid']),
          'unchanged global maps return/event/begin invalidation')
   need(F(F(co,ot,'entry'),'cso_meta','rx')==last_ready['rx'],'complete previous published custody receipt survives exactly')
  else:need(entry['custody']['phase']==0,'cold entry has no live retained certificate')
  r.registration(F(row,et,'rseq_before'),pid);r.registration(F(row,et,'rseq'),pid)
  boundary=_body_anchor_boundary(r,image,index,rows,events,base,extra,context,overlap)
  historical=F(F(co,ot,'entry'),'cso_meta','rx');known=r.integer(historical,'li2_fetch_rx_view','serial')in r.history_anchors
  prior=r.history(historical,image,pid,entry,None if boundary in(1,3)else anchor)
  if boundary in(1,3)and any(historical)and not known:
   pc=I(historical,'li2_fetch_rx_view','pc')
   need(MAIN<=pc<MAIN+4096 if boundary==1 else image['symbols']['rn_finish']<=pc<GUARD+4096,
        'unseen ingress history belongs only to the fixed setup or between-episode finish path')
   if anchor is not None:r.after_native_copy(anchor,prior)
  previous=anchor
  anchor,page_identity=r.raw_fetch(bf,image,pid,None if boundary else anchor,page_identity,partial=False)
  if boundary and(previous is not None or prior is not None):r.after_native_copy(previous if previous is not None else prior,anchor)
  if last_ready is not None and origin is not None:need(F(last_ready['record'],'cso_snapshot','rseq')==F(row,et,'rseq_before'),'actual per-instruction rseq state persists only as bytes, then new guard still runs')
  before=r.frame(F(row,et,'before'),image,'trace');need(page_ids(before['page'])['cpu']==cpu,'actual TRACE reserved CPU')
  pc=m['next'];pages=1+int((m['pc']&~4095)!=((m['pc']+m['length']-1)&~4095))
  eligible_stage=pages==1 and(m['pc']>>12)==(pc>>12)and not m['kind'].startswith('jump')
  sb=F(co,ot,'stage');cb=F(co,ot,'commit');stage=None;commit=None
  if not eligible_stage:
   r.zero(sb+cb,'unreached outer stage/commit');need(v[5]!=2,'no transfer without actual stage')
  else:
   sm=F(sb,'cso_snapshot','meta');stage=r.meta(sm,index,2,0,pid,F(sb,'cso_snapshot','owner'),F(bf,'li2_chain_fetch','ref'))
   so=F(sb,'cso_snapshot','owner');sp=F(so,'li2_tf_owner','step');bp=F(ob,'li2_tf_owner','step')
   r.changed(ob,so,'li2_tf_owner','step');r.changed(bp,sp,'li2_step_owner','in_handler signal_number signal_code signal_errno signal_address after')
   need(r.values(sp,'li2_step_owner','in_handler signal_number signal_code signal_errno signal_address')==(1,5,2,0,pc),'real enter sets only current TRACE observation fields')
   r.step_frame(F(sp,'li2_step_owner','after'),before)
   r.original_open(ob,F(bp,'li2_step_owner','request'),entry['session'],pages)
   hooks=q(F(bp,'li2_step_owner','hooks'));continuation=I(F(ob,'li2_tf_owner','hooks'),'li2_tf_hooks','continue_closed')
   need(hooks[0]==entry['slot_address'],'real hooks context is the actual permission slot')
   functions=hooks[1:]+(continuation,)
   if r.hook_functions is None:r.hook_functions=functions
   need(functions==r.hook_functions,'same actual fixed authentication/failure/continuation callbacks')
   need(F(sb,'cso_snapshot','rseq')==F(row,et,'rseq_before'),'no per-instruction rseq result invented before actual guard')
   sx=F(sm,'cso_meta','rx');kind=I(F(sx,'li2_fetch_rx_view','custody'),'li2_page_custody_receipt','kind')
   need(I(sx,'li2_fetch_rx_view','serial')==I(F(F(co,ot,'entry'),'cso_meta','rx'),'li2_fetch_rx_view','serial')+1,'exact new stage serial, no stale or replayed receipt')
   checks=int(kind==2);seq=I(F(bf,'li2_chain_fetch','ref'),'li2_fetch_ref','sequence')
   proof,anchor,page_identity=r.view(sx,image,pid,stage,stage['custody'],origin,2,seq,pc,checks,anchor,page_identity)
   if kind==1:
    fresh+=1;need(entry['custody']['phase']==0 and stage['custody']['phase']==4 and stage['custody']['epoch']>entry['custody']['epoch'],'cold stage binds its fresh post-query epoch')
    for key in('seeds','retained_stages','retained_checks','commits'):need(stage['custody'][key]==entry['custody'][key],'cold stage cannot claim a committed seed or retained work')
    r.maps_fresh(F(sx,'li2_fetch_rx_view','maps'),stage['maps'])
    raw_calls=stage['custody']['epoch']-entry['custody']['epoch']
    need(raw_calls>=4,'actual maps open, positive read, EOF and close effect prefixes')
    _delta(entry['custody'],stage['custody'],dict(epoch=raw_calls,discards=raw_calls,phase=4,last_reason=1-entry['custody']['last_reason']),'cold fresh seed effects')
    _delta(entry['maps'],stage['maps'],dict(fresh_calls=1,acquisitions=1,invalidations=2*raw_calls+3,mutation_epoch=2*raw_calls+3,handler_id=1,valid=1),'entire actual fresh acquisition and unchanged global invalidation accounting')
   else:
    retained+=1;need(entry['custody']['phase']==2,'retained stage requires actual prior READY consumption')
    _delta(entry['custody'],stage['custody'],dict(phase=2,retained_stages=1,retained_checks=1),'retained stage')
    _delta(entry['maps'],stage['maps'],dict(invalidations=2,mutation_epoch=2,handler_id=1),'retained stage preserves global invalidation without maps I/O')
   sf=F(sb,'cso_snapshot','fetch');r.raw_fetch(sf,image,pid,anchor,page_identity)
   r.partial_slot(sf,bf,changed='progress last_backing')
   bpr=F(bf,'li2_chain_fetch','progress');spr=F(sf,'li2_chain_fetch','progress')
   r.changed(bpr,spr,'li2_fetch_progress','validation_calls last_backing_page last_backing_observed validation')
   need(I(spr,'li2_fetch_progress','validation_calls')==I(bpr,'li2_fetch_progress','validation_calls')+int(kind==1)and
        r.values(spr,'li2_fetch_progress','last_backing_page last_backing_observed')==(0,1),
        'fresh original validation count versus separately counted retained backing check')
   if kind==1:r.maps_fresh(F(spr,'li2_fetch_progress','validation'))
   else:r.zero(F(spr,'li2_fetch_progress','validation'),'retained current validation receipt')
   r.backing(F(sf,'li2_chain_fetch','last_backing'),image['backing'],anchor)
   if any(cb):
    cm=F(cb,'cso_snapshot','meta');result=302 if c==7 and index==control else 0
    cf=F(cb,'cso_snapshot','fetch');outref=F(cf,'li2_chain_fetch','ref')if result==0 else None
    commit=r.meta(cm,index,3,result,pid,F(cb,'cso_snapshot','owner'),F(bf,'li2_chain_fetch','ref'),outref)
    need(F(cb,'cso_snapshot','owner')==so,'commit cannot mutate the actual permission owner')
    need(F(cb,'cso_snapshot','rseq')==F(row,et,'rseq'),'commit retains the actual fresh successor rseq check')
    if result==0:
     cx=F(cm,'cso_meta','rx');r.view(cx,image,pid,commit,commit['custody'],None if kind==1 else origin,4,seq,pc,2*checks,anchor,page_identity)
     r.changed(sx,cx,'li2_fetch_rx_view','phase after_sequence custody')
     r.changed(F(sx,'li2_fetch_rx_view','custody'),F(cx,'li2_fetch_rx_view','custody'),'li2_page_custody_receipt','checks')
     _delta(stage['custody'],commit['custody'],dict(phase=1,retained_checks=checks),'actual commit before publish')
     _delta(stage['maps'],commit['maps'],dict(reuses=1)if kind==1 else{},'actual commit maps work')
     if kind==2:r.retained_sequences.add(seq+1)
     r.raw_fetch(cf,image,pid,anchor,page_identity)
     need(r.values(cf,'li2_chain_fetch','pc length page_count pid tid identity_observed')==(pc,I(cx,'li2_fetch_rx_view','length'),1,pid,pid,1)and
          I(outref,'li2_fetch_ref','sequence')==seq+1,'real singleton replacement and exact successor ref')
     pr=F(cf,'li2_chain_fetch','progress');r.fetch_progress(pr,outref,I(cx,'li2_fetch_rx_view','length'),1,kind,0,0)
     need(F(pr,'li2_fetch_progress','preparation')==(F(sx,'li2_fetch_rx_view','maps')if kind==1 else bytes(r.types['li2_fetch_map_progress']['bytes'])),
          'candidate preparation is fresh source receipt or exact retained zero')
     need(F(cf,'li2_chain_fetch','pages')[:r.types['li2_fetch_page']['bytes']]==F(cx,'li2_fetch_rx_view','page')and
          F(cf,'li2_chain_fetch','backing')[:r.types['li2_fetch_backing']['bytes']]==F(cx,'li2_fetch_rx_view','backing')and
          F(cf,'li2_chain_fetch','last_backing')==F(sf,'li2_chain_fetch','last_backing'),
          'complete committed page/backing and actual predecessor backing payload')
    else:
     cx=F(cm,'cso_meta','rx');r.changed(sx,cx,'li2_fetch_rx_view','result')
     need(I(cx,'li2_fetch_rx_view','result')==302,'actual close invalidates authority before exact STALE refusal')
     r.history_views[I(cx,'li2_fetch_rx_view','serial')]=cx
     _delta(stage['custody'],commit['custody'],dict(epoch=2,discards=2,phase=-4,last_reason=2-stage['custody']['last_reason']),'raw close then exact custody error before any backing query')
     _delta(stage['maps'],commit['maps'],dict(invalidations=2,mutation_epoch=2,valid=-stage['maps']['valid']),'actual raw close invalidates global maps')
     r.changed(sf,cf,'li2_chain_fetch','progress');r.changed(F(sf,'li2_chain_fetch','progress'),F(cf,'li2_chain_fetch','progress'),'li2_fetch_progress','first_error')
     need(I(F(cf,'li2_chain_fetch','progress'),'li2_fetch_progress','first_error')==302,'only reached exact first fetch error; no inferred later observation')
   if v[4]==1 and v[5]==2:
    need(commit is not None,'published transfer requires a genuine returned outer commit');commits+=1
    ret=r.meta(F(co,ot,'returned'),index,4,2,pid,oa,F(af,'li2_chain_fetch','ref'))
    _delta(commit['custody'],ret['custody'],dict(phase=1,seeds=int(kind==1),commits=1),'actual publish to RETURN')
    need(ret['maps']==commit['maps']and F(F(co,ot,'returned'),'cso_meta','rx')==F(F(cb,'cso_snapshot','meta'),'cso_meta','rx'),
         'no maps or receipt mutation between commit and actual trace return')
    r.partial_slot(F(cb,'cso_snapshot','fetch'),af,previous=bf)
    origin=proof;r.accepted_transfers[index]=F(F(row,et,'lease'),'li2_tf_same_page','transfer')
    need(r.accepted_transfers[index]==F(F(cb,'cso_snapshot','meta'),'cso_meta','rx'),'original lease transfer retains exact actual outer commit')
   elif v[4]==1:
    need(not any(cb),'cancelled stage did not call commit');origin=None
    cancelled=F(F(co,ot,'returned'),'cso_meta','rx')
    r.changed(sx,cancelled,'li2_fetch_rx_view','phase')
    need(I(cancelled,'li2_fetch_rx_view','phase')==5,'actual cancellation changes only its staged RX phase')
    r.history_views[I(cancelled,'li2_fetch_rx_view','serial')]=cancelled
  if v[4]==0:
   r.zero(F(co,ot,'returned')+F(co,ot,'handler_before')+F(co,ot,'ready')+F(co,ot,'ready_frame'),'failed handler never returns or reaches READY')
   need(index==len(events)-1 and exit_status==125,'exact failed terminal operation prefix');last_ready=None
  else:
   after=F(row,et,'after');ready=F(co,ot,'ready');rm=F(ready,'cso_snapshot','meta')
   owner=F(ready,'cso_snapshot','owner');fetch=F(ready,'cso_snapshot','fetch');current_ref=F(F(row,et,'next_fetch'),'li2_chain_fetch','ref')
   ret=r.meta(F(co,ot,'returned'),index,4,v[5],pid,owner,current_ref)
   hb=r.meta(F(co,ot,'handler_before'),index,5,0,pid,owner,current_ref)
   end=r.meta(rm,index,6,0,pid,owner,current_ref)
   r.changed(F(co,ot,'returned'),F(co,ot,'handler_before'),'cso_meta','point result')
   r.changed(F(co,ot,'handler_before'),rm,'cso_meta','point custody')
   need(ret['custody']==hb['custody']and ret['maps']==hb['maps'],'genuine handler-end entry follows return without hidden work')
   _delta(hb['custody'],end['custody'],dict(phase=-5)if v[5]==2 else{},'actual handler-end READY or empty authority')
   need(end['custody']['phase']==(1 if v[5]==2 else 0)and end['maps']==hb['maps'],'handler end changes custody only; global maps invalidation remains later')
   need(F(co,ot,'ready_frame')==after and F(ready,'cso_snapshot','rseq')==F(row,et,'rseq'),
        'entire actual READY frame/FP/source/data/rseq/fetch equals returned state')
   r.partial_slot(fetch,F(row,et,'next_fetch'),previous=bf if v[5]==2 else None)
   if v[5]==2:need(owner==oa,'same actual permission owner survives handler end')
   last_ready=dict(custody=end['custody'],maps=end['maps'],rx=F(rm,'cso_meta','rx'),record=ready)
   if v[5]!=2:origin=None
   r.registration(F(ready,'cso_snapshot','rseq'),pid)
   r.history(F(rm,'cso_meta','rx'),image,pid,end,anchor)
   if v[5]==1:
    need(index+1<len(events)and events[index+1]['pc']==pc and
         owner==F(rows[index+1],et,'owner_before'),'complete freshly armed successor owner equals its next genuine event')
   if v[5]==0:
    # chain_next installs only cleanup hooks before selected/old-step fallback.
    fallback=bytearray(len(owner));stepoff=r.types['li2_tf_owner']['fields']['step']['offset'];hook=r.types['li2_step_owner']['fields']['hooks'];at=stepoff+hook['offset']
    fallback[at:at+hook['bytes']]=F(F(owner,'li2_tf_owner','step'),'li2_step_owner','hooks')
    need(bytes(fallback)==owner and q(fallback[at:at+hook['bytes']])[0]==end['slot_address']and all(q(fallback[at:at+hook['bytes']])),'complete actual fallback owner contains only the installed cleanup hooks')
 # The unchanged core consumes original cleanup/error/terminal payloads. New
 # fault metadata must identify its same actual event, never a supplied frame.
 fault=F(extra,ct,'fault')
 if c>=6:
  fm=F(fault,'cso_snapshot','meta');v=q(F(rows[control],'lso_event','h'));bf=F(rows[control],'lso_event','fetch_before')
  phase=2 if c==9 else 1
  fm_value=r.meta(fm,control,7,phase,pid,F(fault,'cso_snapshot','owner'),F(bf,'li2_chain_fetch','ref'))
  stage=F(observations[control],'cso_row','stage');sm=F(stage,'cso_snapshot','meta')
  need(F(fault,'cso_snapshot','owner')==F(stage,'cso_snapshot','owner'),'whole pre-injection permission owner')
  r.changed(sm,fm,'cso_meta','point result maps rx custody')
  if c!=9:
   need(F(fault,'cso_snapshot','fetch')==F(stage,'cso_snapshot','fetch')and F(fault,'cso_snapshot','rseq')==F(stage,'cso_snapshot','rseq')and
        F(sm,'cso_meta','maps')==F(fm,'cso_meta','maps')and F(sm,'cso_meta','rx')==F(fm,'cso_meta','rx')and F(sm,'cso_meta','custody')==F(fm,'cso_meta','custody'),
        'entire actual stage snapshot precedes the first injected effect without intervening queries')
  else:
   sx,fx=(F(meta,'cso_meta','rx')for meta in(sm,fm));kind=I(F(sx,'li2_fetch_rx_view','custody'),'li2_page_custody_receipt','kind')
   r.changed(sx,fx,'li2_fetch_rx_view','phase custody');need(I(fx,'li2_fetch_rx_view','phase')==3,'actual COMMITTING before out-ref publication')
   r.changed(F(sx,'li2_fetch_rx_view','custody'),F(fx,'li2_fetch_rx_view','custody'),'li2_page_custody_receipt','checks')
   need(I(F(fx,'li2_fetch_rx_view','custody'),'li2_page_custody_receipt','checks')==2*int(kind==2),'actual second backing check before replacement')
   _delta(r.custody_state(F(sm,'cso_meta','custody')),fm_value['custody'],dict(retained_checks=int(kind==2)),'pre-publication commit check')
   _delta(r.maps_state(F(sm,'cso_meta','maps')),fm_value['maps'],dict(reuses=1)if kind==1 else{},'pre-publication original or retained maps work')
   r.history_views[I(fx,'li2_fetch_rx_view','serial')]=fx
   ff=F(fault,'cso_snapshot','fetch');r.raw_fetch(ff,image,pid,anchor,page_identity,unpublished=True)
   need(I(F(ff,'li2_chain_fetch','progress'),'li2_fetch_progress','sequence')==I(F(bf,'li2_chain_fetch','ref'),'li2_fetch_ref','sequence')+1 and
        F(ff,'li2_chain_fetch','ref')==F(bf,'li2_chain_fetch','ref')and F(fault,'cso_snapshot','rseq')==F(rows[control],'lso_event','rseq'),'actual replaced singleton with still-unpublished old ref and genuine successor guard')
  need(F(fm,'cso_meta','rx')==F(base,bt,'fault_view'),'whole actual pre-injection fault view joins unchanged base record')
  r.accepted_fault=F(base,bt,'fault_view')
 else:r.zero(fault,'absent injected fault')
 terminal=F(extra,ct,'terminal');tc=F(base,bt,'terminal_chain');slots=r.array(tc,'li2_tf_chain','slots','li2_tf_chain_slot');active=I(tc,'li2_tf_chain','active')
 need(active in(0,1),'actual terminal active slot');slot=slots[active]
 terminal_meta=r.meta(terminal,control if exit_status else 12,8,exit_status,pid,F(slot,'li2_tf_chain_slot','owner'),F(F(slot,'li2_tf_chain_slot','fetch'),'li2_chain_fetch','ref'))
 need(terminal_meta['custody']['phase']==0,'actual complete disposal before terminal report; no surviving certificate')
 terminal_view=F(terminal,'cso_meta','rx');terminal_anchor=anchor
 if any(terminal_view)and I(terminal_view,'li2_fetch_rx_view','serial')not in r.history_anchors and exit_status==0:
  _terminal_anchor_boundary(r,image,rows,events,base,extra,context,exit_status,terminal_meta,terminal_view)
  terminal_anchor=r.backing(F(terminal_view,'li2_fetch_rx_view','backing'),image['backing'])
  r.after_native_copy(anchor,terminal_anchor)
 r.history(terminal_view,image,pid,terminal_meta,terminal_anchor);r.registration(F(base,bt,'terminal_rseq'),pid)
 if not stack:r.zero(F(extra,ct,'stack_endpoints'),'unselected stack endpoints')
 if stack:_stack_endpoints(r,image,pid,cpu,context)
 return dict(fresh_stages=fresh,retained_stages=retained,retained_checks=retained+sum(I(F(v,'li2_fetch_rx_view','custody'),'li2_page_custody_receipt','kind')==2 for v in r.accepted_transfers.values())+int(c==9 and control==1),commits=commits,events=len(events))

def _stack_endpoints(r,image,pid,cpu,context):
 I,F=r.integer,r.field;base=F(r.data,'cso_stream','base');extra=F(r.data,'cso_stream','custody')
 h=q(F(base,'lso_record','h'));components=r.components(F(base,'lso_record','xstate'))
 stack=module('cso_stack_endpoints',BASE/'page_custody_stack/check.py');model=stack.states(image,context)
 rows=r.array(base,'lso_record','endpoints','lso_native_row')+r.array(extra,'cso_record','stack_endpoints','lso_native_row')
 states=(model[0]['before'],model[4]['after'],model[5]['before'],model[-1]['after']);frames=[]
 for index,(row,pc,state)in enumerate(zip(rows,stack.geometry(),states)):
  v=q(F(row,'lso_native_row','h'));a=F(row,'lso_native_row','before')
  need(a==F(row,'lso_native_row','after')and v[:5]==(1,index,pc,pc,1)and not any(v[5:24]+v[28:]),'complete real stack endpoint; no synthetic permission calls')
  f=r.frame(a,image);r.envelope(f,h[15],h[16],False);r.siginfo_alias(row,'lso_native_row',f)
  need(f['greg'][16]==f['h'][8]==pc and page_ids(f['page'])['cpu']==cpu,'current-PC stack endpoint and reserved CPU')
  old.literal(f,state,pc,0x10000,components)
  need(f['data']==stack.memory(image,False,f['page'],context,index),'entire actual two-episode stack fixture memory')
  if frames:need(f['fp']==frames[0]['fp']and f['page']==frames[0]['page'],'whole native-like reseeded endpoint FP and registered page')
  frames.append(f)
 return frames

def gated(data,layout,image,pid,exit_status,cpu,*,fault_event=0,stack_context=None,overlap=False):
 """Exact current-profile record; callers bind actual ELF/carrier and selectors.

 stack_context must be the result of the fixed stack output reader. Its raw
 proof and source custody remain mandatory in stack_pair/the enclosing helper.
 """
 need(type(image)is dict and type(image.get('case'))is int and image['case']in range(10)and
      type(fault_event)is int and fault_event in(0,1)and type(overlap)is bool and
      (not fault_event or image['case']in(6,7,8,9))and
      (not overlap or image['case']==5 and fault_event==0 and stack_context is None)and
      (stack_context is None or image['case']==0 and fault_event==0 and not overlap),
      'fixed emitted profile selectors, no arbitrary comparator or policy callbacks')
 if stack_context is not None:
  need(type(stack_context)is dict and stack_context.get('pid')==pid and stack_context.get('query_result')==pid and
       stack_context.get('proof_bytes')==152352 and type(stack_context.get('proof_sha256'))is str and len(bytes.fromhex(stack_context['proof_sha256']))==32,
       'actual per-lane validated whole stack proof/PID input')
 r=Reader(data,layout);control=1 if overlap else fault_event
 custody=_audit(r,image,pid,exit_status,cpu,control,stack_context,overlap)
 value=_core(r,image,pid,exit_status,control,stack_context,overlap)
 need(all(c==cpu for c in value['observed_cpus']),'every actual frame/terminal page joins the independent reserved CPU')
 value['custody']=custody;value['fault_event']=fault_event;value['stack']=int(stack_context is not None);value['overlap']=int(overlap)
 return value

def _abi(nr,gr):
 need(nr.layout['offsets']==gr.layout['offsets']and nr.layout['siginfo']==gr.layout['siginfo']and nr.ucn==gr.ucn,'same entire actual signal ABI')

def _endpoint_pair(nr,gr,nf,gf,*,stack=False,ncontext=None,gcontext=None,index=0):
 need(nf['fp']==gf['fp'],'whole native/gated FP bytes; no component/flag exemption')
 nu,gu=bytearray(nf['uc']),bytearray(gf['uc'])
 for key in('stack_sp','stack_size','fp_pointer'):
  put(nu,nr.layout['offsets'][key],0);put(gu,gr.layout['offsets'][key],0)
 if stack:
  # Each value was already proved by the full literal state and same-lane
  # source/stack proof. The two fresh execs have different real stack targets.
  need(nf['greg'][GREG[7]]==ncontext['target']and gf['greg'][GREG[7]]==gcontext['target'],'actual per-lane stack operand')
  put(nu,nr.go+8*GREG[7],0);put(gu,gr.go+8*GREG[7],0)
 need(nu==gu,'all remaining complete raw UC bytes exact after typed actual pointers/operand')
 nd,gd=bytearray(nf['data']),bytearray(gf['data']);put(nd,16,0)
 if stack:
  for b,ctx in((nd,ncontext),(gd,gcontext)):
   need(word(b,80)==ctx['entry_rsp']and word(b,88)==ctx['target']and word(b,104)==ctx['pid']and word(b,96)==(ctx['pid']if index>=2 else 0),'literal source-owned stack/PID fields')
   for at in(80,88,96,104):put(b,at,0)
   if index>=2:need(word(b,6208+7*8)==ctx['target'],'typed captured first-episode target');put(b,6208+7*8,0)
 np,gp=bytearray(nf['page']),bytearray(gf['page']);ni,gi=page_ids(np),page_ids(gp)
 need(ni['cpu']==gi['cpu']and ni['node']==gi['node'],'actual independent singleton CPU/node')
 for b,at in((nd,8192+88),(gd,8192+88),(np,88),(gp,88)):struct.pack_into('<I',b,at,0)
 need(nd==gd and np==gp,'every remaining memory/page byte exact; no broad payload masking')

def pair(nrec,grec,nout,gout,layouts,image,npid,gpid,cpu):
 need(type(cpu)is int and cpu>=0 and type(npid)is type(gpid)is int and npid>0 and gpid>0 and npid!=gpid and image['case']in range(5),'independent fixed ordinary native/gated pair')
 n=old.native(nrec,layouts['native'],image,npid,0);g=gated(grec,layouts['gated'],image,gpid,0,cpu)
 need(n['cpuid']==g['cpuid'],'same-input native/raw/committed CPUID equality')
 no=old.output(nout,image,True,n['cpuid']);go=old.output(gout,image,False,g['cpuid'])
 need(all(x==cpu for x in n['observed_cpus']+g['observed_cpus']+[no['cpu'],go['cpu']]),'every actual native/gated frame/output CPU')
 nr=old.Reader(nrec,layouts['native'],'lso_native_record');gr=Reader(grec,layouts['gated']);_abi(nr,gr)
 ns=nr.types['lso_native_row'];nb=nr.field(nrec,nr.rt,'rows');base=gr.field(grec,'cso_stream','base');gb=gr.array(base,'lso_record','endpoints','lso_native_row')
 for i,row in enumerate(gb):
  nf=nr.frame(nr.field(nb[i*ns['bytes']:(i+1)*ns['bytes']],ns,'before'),image);gf=gr.frame(gr.field(row,'lso_native_row','before'),image)
  _endpoint_pair(nr,gr,nf,gf)
 return dict(case=image['case'],successful_pair=1,native=n,gated=g,native_output=no,gated_output=go)

def stack_pair(nrec,grec,nout,gout,layouts,image,npid,gpid,cpu):
 need(type(cpu)is int and cpu>=0 and type(npid)is type(gpid)is int and npid>0 and gpid>0 and npid!=gpid and image['case']==0,'independent fixed stack-growth pair')
 stack=module('cso_stack_pair',BASE/'page_custody_stack/check.py')
 no=stack.output(nout,layouts['native'],image,npid,True,cpu);go=stack.output(gout,layouts['native'],image,gpid,False,cpu)
 nr,nfs,components=stack.native_frames(nrec,layouts['native'],image,npid,0,no['context'],cpu)
 g=gated(grec,layouts['gated'],image,gpid,0,cpu,stack_context=go['context']);gr=Reader(grec,layouts['gated']);_abi(nr,gr)
 gfs=_stack_endpoints(gr,image,gpid,cpu,go['context'])
 for i,(nf,gf)in enumerate(zip(nfs,gfs)):_endpoint_pair(nr,gr,nf,gf,stack=True,ncontext=no['context'],gcontext=go['context'],index=i)
 need(len(nfs)==len(gfs)==4 and g['events']==7 and g['transfers']==3 and g['real_closes']==4 and
      g['custody']==dict(fresh_stages=2,retained_stages=3,retained_checks=4,commits=3,events=7),
      'actual growth followed by retained proof before fresh query; syscall then new cold episode')
 return dict(case=0,successful_pair=1,episodes=2,grown_pages=1,native=dict(accepted=True,exit_status=0,frames=4,observed_cpus=[cpu]*4),gated=g,native_output=no,gated_output=go)

def reports_join(stderr,data,layout,image,pid,result):
 """Only the new literal loader scope is adapted; all old predicates run."""
 import json
 reports=module('cso_original_reports',BASE/'tf_same_page/reports.py')
 need(type(stderr)is bytes and stderr.endswith(b'\n')and result['accepted']is True,'complete actual report and separately accepted exact record')
 lines=stderr[:-1].split(b'\n');matched=0;out=[]
 for line in lines:
  prefix,sep,raw=line.partition(b' ')
  if prefix==b'LI2_LOADER':
   need(sep==b' ','actual loader row');d=reports.old.base.decode.decode(raw)
   need(d['scope']=='partial_selected_sealed_page_custody','literal explicit new production scope')
   d['scope']='partial_selected_same_page_tf_lease';line=prefix+b' '+json.dumps(d,sort_keys=True,separators=(',',':')).encode();matched+=1
  out.append(line)
 need(matched==1,'one source-bound custody loader row')
 parsed=reports.reports(b'\n'.join(out)+b'\n');r=Reader(data,layout);base=r.field(data,'cso_stream','base')
 # An actual embedded base view retains every byte and the expanded DWARF.
 br=old.Reader(base,dict(layout,record='lso_record'),'lso_record');reports.join(parsed,br,base)
 h=q(r.field(base,'lso_record','h'));loader=parsed['loader'];cpuid=parsed['cpuid_nx']
 need((loader['status'],loader['failure_code'],loader['detail_abs'],loader['detail_negative'])==(result['exit_status'],h[11],h[12],0),'exact failed/successful binary and public terminal outcome')
 need(cpuid['attempts']==cpuid['samples']==cpuid['commits']==loader['cpuid']>0 and cpuid['raw']==cpuid['result']and cpuid['phase']==3 and cpuid['hardware_entered']==cpuid['hardware_returned']==1,'actual genuine CPUID prefix')
 if result['exit_status']==0:
  reports.completed(parsed,pid)
  need(parsed['rseq_native']['admissions']>0 and parsed['rseq_boundary']['counts']==[0]*6,'unchanged native admission and no invented boundary retry')
 else:need(result['operation_status']=='failed'and result['exit_status']==125,'required failed operation stays failed')
 return parsed
