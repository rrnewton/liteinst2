"""Fixed observation-only adapters; every product byte has an exact inverse."""
from pathlib import Path
from page_selected import fact,need
ADAPTERS=(
 ('runtime_loader.c','static void fail(unsigned,long) __attribute__((noreturn));','static void fail(unsigned,long) __attribute__((noreturn));\nstatic void tfi_terminal(unsigned,unsigned,long);'),
 ('runtime_loader.c','    reported=1;\n','    reported=1;\n    tfi_terminal(status,code,detail);\n'),
 ('runtime_loader.c','#include "selected_controller.inc"','#include "tf_interval_observe.inc"\n#include "selected_controller.inc"'),
 ('runtime_loader.c','    li2_rseq_native_preentry();','    li2_rseq_native_preentry();\n    tfi_entry(sig,si,ptr);'),
 ('runtime_loader.c','    checked(!native_error,(unsigned)native_error,0);','    checked(!native_error,(unsigned)native_error,0);\n    tfi_initialize();'),
 ('native_controller.inc','static int selected_native_fetch(','static int tfi_real_native_fetch('),
 ('selected_chain.inc','    li2_tf_chain_begin_nx(&selected_chain,&selected_borrow,&selected_decoded,flags,sig,si,context);',
  '    tfi_begin(&selected_chain,&selected_borrow,&selected_decoded,flags,sig,si,context);'),
 ('selected_chain.inc','enum li2_chain_result result=li2_tf_chain_trace(&selected_chain,sig,si,context);',
  'enum li2_chain_result result=tfi_trace(&selected_chain,sig,si,context);'),
 ('selected_controller.inc','    long number=g[REG_RAX];','    long number=g[REG_RAX];\n    tfi_syscall_before(context);'),
 ('selected_controller.inc','    selected_release();++selected_source_syscalls;dispatch_operation(number,context);',
  '    selected_release();++selected_source_syscalls;dispatch_operation(number,context);\n    tfi_syscall_after(context);'),
)
FETCH_WRAPPER='''
static int selected_native_fetch(int sig,siginfo_t *si,ucontext_t *uc) {
 int result=tfi_real_native_fetch(sig,si,uc);tfi_fetch_return(result,sig,si,uc);return result;
}
'''
PROTECTION='''
/* Actual read-return observation only; no permission or ownership change. */
int tfi_page_protection(uintptr_t page,struct li2_fetch_map_progress *receipt,unsigned *prot) {
 struct check_error error={0};
 if(!receipt || !prot || (page&4095))return 1761;
 if(read_maps_fresh(&error,receipt))return (int)error.code;
 const struct map_row *r=mapping(page);
 if(!r || r->first>page || r->end-page<4096)return 1761;
 *prot=r->prot;return 0;
}
'''
FILES=('runtime_loader.c','selected_controller.inc','native_controller.inc','selected_chain.inc','lifecycle_loader.c','fetch_loader.inc')
def prepare(root,out,pin):
 root,out=Path(root),Path(out);selected=root/'tools/page-entry/selected'
 need(not out.exists(),'unique interval observer view');out.mkdir(parents=True);facts=[]
 for name in FILES:
  original=pin(selected/name);before=original.read_bytes();data=before
  for path,old,new in ADAPTERS:
   if path==name:
    need(data.count(old.encode())==1,'unique interval observer seam '+name);data=data.replace(old.encode(),new.encode())
  suffix=FETCH_WRAPPER if name=='native_controller.inc'else PROTECTION if name=='lifecycle_loader.c'else''
  data+=suffix.encode();inverse=data[:-len(suffix)]if suffix else data
  for path,old,new in reversed(ADAPTERS):
   if path==name:
    need(inverse.count(new.encode())==1,'unique interval observer inverse '+name);inverse=inverse.replace(new.encode(),old.encode())
  need(inverse==before,'whole unchanged product recovered '+name)
  dest=out/name;dest.write_bytes(data);pin(dest);facts.append(dict(name=name,before=fact(original),after=fact(dest)))
 for name,dest in(('observe.inc','tf_interval_observe.inc'),('record.h','tf_interval_record.h')):
  original=pin(selected/'tests/tf_interval'/name);before=original.read_bytes();data=before
  if name=='record.h':
   old,new=b'#include "../rseq_native/record.h"',b'#include "tf_interval_old_record.h"'
   need(data.count(old)==1 and new not in data,'exact original frame header');data=data.replace(old,new)
   need(data.replace(new,old)==before,'exact frame-header inverse')
  path=out/dest;path.write_bytes(data);pin(path);facts.append(dict(name=dest,before=fact(original),after=fact(path)))
 original=pin(selected/'tests/rseq_native/record.h');dest=out/'tf_interval_old_record.h'
 dest.write_bytes(original.read_bytes());pin(dest);facts.append(dict(name=dest.name,before=fact(original),after=fact(dest)))
 return facts
