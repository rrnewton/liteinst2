/* Native observer only. Guest reset instructions are identical in both roles.
   The existing complete machine/FP/source/data/stack helpers remain shared. */
#include "effects.h"
#define LC8E_APP_MAGIC UINT64_C(0x314145384332494c)
__attribute__((section(".li2_lc8e_state"))) volatile uint64_t lc8e_state[32];
static struct lc8e_app_tail lc8e_tail;
static unsigned lc8e_window;
static void lc8e_tail_state(unsigned stopped) {
 uint64_t *h=lc8e_tail.h;
 h[0]=LC8E_APP_MAGIC;h[1]=1;h[2]=sizeof lc8e_tail;h[3]=LI2_LOOP_CACHE8_EFFECT;
 h[4]=native;h[13]=stopped;h[14]=steps;h[15]=frames;
 h[18]=(uintptr_t)lc8e_state;h[19]=sizeof lc8e_state;
 copy(lc8e_tail.state,(const void *)lc8e_state,sizeof lc8e_state);
}
static int lc8e_geometry(void) {
 if((uintptr_t)lc8e_state!=LC8E_STATE_ADDRESS || sizeof lc8e_state!=LC8E_STATE_BYTES ||
    (uintptr_t)region_app_effect_end<=(uintptr_t)region_app_reset ||
    (uintptr_t)region_app_effect_end>=(uintptr_t)region_app_reset_end)return 0;
#if LI2_LOOP_CACHE8_EFFECT == 2
 return region_app_effect_syscall0==region_app_reset+72 &&
   region_app_effect_syscall1==region_app_reset+111 &&
   region_app_reset_jump==region_app_reset+179 &&
   region_app_effect_end==region_app_reset+184;
#elif LI2_LOOP_CACHE8_EFFECT == 3
 return region_app_effect_write==region_app_reset &&
   region_app_reset_jump==region_app_reset+8 && region_app_effect_end==region_app_reset+10;
#else
 return region_app_effect_load==region_app_reset &&
   region_app_effect_jump==region_app_reset+7 &&
   region_app_reset_jump==region_app_effect_jump && region_app_effect_end==region_app_reset+9;
#endif
}
static void lc8e_initialize(void) {
 need(lc8e_geometry() && !lc8e_window,190);
 for(unsigned i=0;i<32;i++)need(lc8e_state[i]==0,191);
 lc8e_tail_state(0);
}
#if LI2_LOOP_CACHE8_EFFECT != 2
static _Noreturn void lc8e_native_stop(unsigned kind) {
 /* This is a native fault/prefix reference, never a completed application. */
 need(native && started && !ended && !first_error && kind>=1 && kind<=2,192);
 observation->h[0]=1;observation->h[1]=attempt;observation->h[2]=frames;
 observation->h[3]=steps;observation->h[4]=fault_seen;observation->h[5]=1;
 copy(&observation->before,&ua_before,sizeof ua_before);
 copy(observation->before_live,ua_before_live,UA_LIVE);
 copy(observation->machine_before,current_machine,sizeof current_machine);
 copy(observation->source,region_app_page,UA_SOURCE);
 copy(observation->stack,(const void *)(ua_input.g[4]-128),UA_STACK);
 copy(observation->data,(const void *)DATA_BASE,UA_DATA);
 need(same(observation->source,prefix.source,UA_SOURCE) &&
      same(observation->stack,prefix.stack,UA_STACK),193);
 suffix.h[0]=RA_MAGIC^1;suffix.h[1]=2;suffix.h[2]=0;suffix.h[3]=1;
 suffix.h[7]=frames;suffix.h[8]=steps;suffix.h[9]=fault_seen;
 lc8e_tail_state(kind);
 need(output(&suffix,sizeof suffix) && output(&lc8e_tail,sizeof lc8e_tail),194);
 (void)RAW(SYS_exit_group,0,0,0,0,0,0);__builtin_trap();
}
#endif
static void lc8e_native_window(ucontext_t *uc) {
 need(native && handling && started && !ended && !lc8e_window && steps==83 &&
      frames==6 && (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==(uintptr_t)region_app_reset,
      195);
 /* No guest mapping instruction is replaced. These are the native reference
    owner's real tracing permissions, outside either measured generated run. */
 lc8e_tail.h[5]=1;
 long result=RAW(SYS_mprotect,region_app_page,UA_SOURCE,PROT_READ,0,0,0);
 lc8e_tail.h[6]=1;lc8e_tail.h[7]=(uint64_t)result;need(!result,196);
 lc8e_window=1;lc8e_tail.h[8]=1;
 uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)TF;
#if LI2_LOOP_CACHE8_EFFECT == 4
 /* There is no corresponding private generated address in a native process.
    Retain the complete real reset boundary, then stop without a fake target. */
 lc8e_native_stop(2);
#endif
}
static int lc8e_native_event(int sig,const siginfo_t *si,ucontext_t *uc) {
 if(!lc8e_window)return 0;
 if(lc8e_window==2)return 0;
 greg_t *g=uc->uc_mcontext.gregs;
 need(native && handling && started && !ended && steps==83 && frames==6 &&
      sig==SIGSEGV && si->si_signo==sig && si->si_code==SEGV_ACCERR && !si->si_errno &&
      g[REG_TRAPNO]==14 && (uint64_t)g[REG_EFL]==(UINT64_C(0x202)|RF),197);
 for(unsigned i=0;i<16;i++) {
  uint64_t want=ua_input.g[i];
  if(i==0)want=57;
  if(i==1)want=LI2_LOOP_CACHE8_EFFECT==2?8:0;
  if(i==8)want=1;
  need((uint64_t)g[regs[i]]==want,198+i);
 }
#if LI2_LOOP_CACHE8_EFFECT == 2
 need(g[REG_ERR]==21 && (uintptr_t)g[REG_RIP]==(uintptr_t)region_app_head &&
      (uintptr_t)si->si_addr==(uintptr_t)region_app_head &&
      (uintptr_t)g[REG_CR2]==(uintptr_t)region_app_head,215);
 need(lc8e_state[6]==0 && lc8e_state[7]==0 && lc8e_state[8]==1 &&
      lc8e_state[9]==1 && lc8e_state[10]==1 && lc8e_state[11]==1,216);
 retain(sig,si,uc,6);lc8e_tail.h[9]=1;lc8e_tail.h[10]=1;
 long result=RAW(SYS_mprotect,region_app_page,UA_SOURCE,PROT_READ|PROT_EXEC,0,0,0);
 lc8e_tail.h[11]=1;lc8e_tail.h[12]=(uint64_t)result;need(!result,217);
 lc8e_window=2;g[REG_EFL]|=(greg_t)TF;return 1;
#elif LI2_LOOP_CACHE8_EFFECT == 3
 need(g[REG_ERR]==7 && (uintptr_t)g[REG_RIP]==(uintptr_t)region_app_effect_write &&
      (uintptr_t)si->si_addr==UINT64_C(0x412400) &&
      (uintptr_t)g[REG_CR2]==UINT64_C(0x412400),218);
 fault_seen=1;retain(sig,si,uc,6);lc8e_tail.h[16]=sig;
 lc8e_tail.h[17]=(uintptr_t)si->si_addr;lc8e_native_stop(1);
#else
 need(0,219);return 0;
#endif
}
static void lc8e_complete(void) {
 need(LI2_LOOP_CACHE8_EFFECT==2 && (!native || lc8e_window==2),220);
 need(lc8e_state[6]==0 && lc8e_state[7]==0 && lc8e_state[8]==1 &&
      lc8e_state[9]==1 && lc8e_state[10]==1 && lc8e_state[11]==1,221);
 lc8e_tail_state(0);
 need(output(&lc8e_tail,sizeof lc8e_tail),222);
}
