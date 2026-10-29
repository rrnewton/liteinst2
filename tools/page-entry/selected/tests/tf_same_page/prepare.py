"""Finite observation adapters; every product source has a whole-file inverse."""
from pathlib import Path
from page_selected import fact,need
ADAPTERS=(
 ('runtime_loader.c','static void fail(unsigned,long) __attribute__((noreturn));','static void fail(unsigned,long) __attribute__((noreturn));\nstatic void lso_terminal(unsigned,unsigned,long);'),
 ('runtime_loader.c','    reported=1;\n','    reported=1;\n    lso_terminal(status,code,detail);\n'),
 ('runtime_loader.c','#include "selected_controller.inc"','#include "tf_lease_observe.inc"\n#include "selected_controller.inc"'),
 ('runtime_loader.c','    li2_rseq_native_preentry();','    li2_rseq_native_preentry();\n    lso_entry(sig,si,ptr);'),
 ('runtime_loader.c','    checked(!native_error,(unsigned)native_error,0);','    checked(!native_error,(unsigned)native_error,0);\n    lso_initialize();'),
 ('native_controller.inc','static int selected_native_fetch(','static int lso_real_native_fetch('),
 ('selected_chain.inc','enum li2_chain_result result=li2_tf_chain_trace(&selected_chain,sig,si,context);','enum li2_chain_result result=lso_trace(&selected_chain,sig,si,context);'),
 ('selected_controller.inc','    if(p->kind==LI2_CPUID)selected_cpuid_nx_committed(g);',
  '    if(p->kind==LI2_CPUID) {selected_cpuid_nx_committed(g);\n        lso_cpuid_after(context,selected_cpuid_nx.phase,selected_cpuid_nx.attempts,selected_cpuid_nx.samples,selected_cpuid_nx.commits,selected_cpuid_nx.pc,selected_cpuid_nx.next_pc,selected_cpuid_nx.leaf,selected_cpuid_nx.subleaf,selected_cpuid_nx.raw,selected_cpuid_nx.result);\n    }'),
 ('fetch_rx_transfer.inc','#include "tf_same_page.h"','#include "tf_same_page.h"\nextern void lso_fetch_phase(unsigned,const struct li2_fetch_ref *,const struct li2_fetch_rx_view *);'),
 ('fetch_rx_transfer.inc','    *out=&rx_view;return 0;','    lso_fetch_phase(1,ref,&rx_view);\n    *out=&rx_view;return 0;'),
 ('fetch_rx_transfer.inc','    fetch=rx_candidate;','    fetch=rx_candidate;\n    lso_fetch_phase(2,ref,&rx_view);'),
)
FETCH_WRAPPER='''
static int selected_native_fetch(int sig,siginfo_t *si,ucontext_t *uc) {
 int result=lso_real_native_fetch(sig,si,uc);lso_fetch_return(result,sig,si,uc);return result;
}
'''
PROTECTION='''
/* Independent actual map observation after cleanup, not a verified-close claim. */
int lso_page_protection(uintptr_t page,struct li2_fetch_map_progress *receipt,unsigned *prot) {
 struct check_error error={0};
 if(!receipt || !prot || (page&4095))return 1698;
 if(read_maps_fresh(&error,receipt))return (int)error.code;
 const struct map_row *r=mapping(page);
 if(!r || r->first>page || r->end-page<4096)return 1698;
 *prot=r->prot;return 0;
}
'''
FILES=('runtime_loader.c','selected_controller.inc','native_controller.inc','selected_chain.inc','lifecycle_loader.c','fetch_loader.inc','fetch_rx_transfer.inc')
def prepare(root,out,pin):
 root,out=Path(root),Path(out);selected=root/'tools/page-entry/selected';need(not out.exists(),'unique finite source view');out.mkdir(parents=True);facts=[]
 for name in FILES:
  original=pin(selected/name);before=original.read_bytes();data=before
  for path,old,new in ADAPTERS:
   if path==name:
    need(data.count(old.encode())==1,'unique finite observer seam '+name);data=data.replace(old.encode(),new.encode())
  suffix=FETCH_WRAPPER if name=='native_controller.inc'else PROTECTION if name=='lifecycle_loader.c'else ''
  data+=suffix.encode();inverse=data[:-len(suffix)]if suffix else data
  for path,old,new in reversed(ADAPTERS):
   if path==name:
    need(inverse.count(new.encode())==1,'unique finite observer inverse '+name);inverse=inverse.replace(new.encode(),old.encode())
  need(inverse==before,'complete unchanged product recovered '+name)
  dest=out/name;dest.write_bytes(data);pin(dest);facts.append(dict(name=name,before=fact(original),after=fact(dest)))
 for name,dest in(('observe.inc','tf_lease_observe.inc'),('record.h','tf_lease_record.h')):
  original=pin(selected/'tests/tf_same_page'/name);before=original.read_bytes();data=before
  if name=='record.h':
   old,new=b'#include "../rseq_native/record.h"',b'#include "tf_lease_old_record.h"'
   need(data.count(old)==1 and new not in data,'exact complete old frame include');data=data.replace(old,new)
   need(data.replace(new,old)==before,'exact old frame include inverse')
  path=out/dest;path.write_bytes(data);pin(path);facts.append(dict(name=dest,before=fact(original),after=fact(path)))
 original=pin(selected/'tf_same_page.h');before=original.read_bytes()
 guard=b'#if LI2_TF_SAME_PAGE_LEASE != 1 || !defined(LI2_TF_HANDOFF) || \\\n    !defined(LI2_MAPS_PHASE_REUSE) || !defined(LI2_RSEQ_INACTIVE)\n#error "same-page lease requires the fixed TF/maps/rseq composition"\n#endif\n'
 need(before.count(guard)==1,'one type-header profile guard')
 data=before.replace(guard,b'');need(data.replace(b'#include "lifecycle_loader.h"\n',b'#include "lifecycle_loader.h"\n'+guard)==before,'exact type-only header inverse')
 dest=out/'tf_lease_types.h';dest.write_bytes(data);pin(dest);facts.append(dict(name=dest.name,before=fact(original),after=fact(dest)))
 original=pin(selected/'tests/rseq_native/record.h');dest=out/'tf_lease_old_record.h' ;dest.write_bytes(original.read_bytes());pin(dest)
 facts.append(dict(name=dest.name,before=fact(original),after=fact(dest)));return facts
