/* Exact-inverse private observation adapter. No observation grants permission
   or supplies an owner/session. All full captures use the actual SI/UC/FP. */
#include "native_pair_runtime_record.h"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
static struct npf_record npf_record;
/* GDB's array type alignment does not encode a member's aligned attribute.
   This emitted compiler value authenticates that one member explicitly. */
static const uint64_t npf_step_frame_fp_alignment __attribute__((used)) =
 __alignof__(((struct li2_step_frame *)0)->fp);
static unsigned npf_used,npf_stages,npf_finished,npf_current=NPF_ROWS;
static const ucontext_t *npf_frame_pointer;
static const siginfo_t *npf_signal_pointer;
static const ucontext_t *npf_outer_frame_pointer;
static const siginfo_t *npf_outer_signal_pointer;
static siginfo_t npf_signal;
static void npf_copy(void *to,const void *from,size_t n) {
 unsigned char *d=to;const volatile unsigned char *s=from;
 for(size_t i=0;i<n;i++)d[i]=s[i];
}
static uint32_t npf_u32(const unsigned char *s) {
 return (uint32_t)s[0]|(uint32_t)s[1]<<8|(uint32_t)s[2]<<16|(uint32_t)s[3]<<24;
}
static uintptr_t npf_b(void) {
 unsigned c=(unsigned)npf_record.h[3];
 return c==0?RN_BODY+128:c==3?RN_TAIL:c==19?RN_GUARD+1:RN_GUARD;
}
static int npf_focal(uintptr_t pc) {
 return (pc>=RN_BODY && pc<RN_REFERENCE) || pc==NPF_CLOSE_GATE;
}
static int npf_capture(struct rn_frame *s,int sig,const siginfo_t *si,const ucontext_t *u) {
 if(!si || !u)return 0;
 uintptr_t p=(uintptr_t)u->uc_mcontext.fpregs,lo=(uintptr_t)fork_gate_stack.ss_sp;
 size_t cap=fork_gate_stack.ss_size,n=512;
 if(p<lo || cap<512 || p-lo>cap-512 || (p&15))return 0;
 const unsigned char *b=(const void *)p;
 if(npf_u32(b+464)==UINT32_C(0x46505853)) {
  n=npf_u32(b+468);size_t x=npf_u32(b+480);
  if(n<580 || n>RN_FP || n>cap-(p-lo) || x<576 || x>n-4 || npf_u32(b+n-4)!=UINT32_C(0x46505845))return 0;
 }
 s->h[1]=sizeof *u;s->h[2]=n;s->h[3]=(uintptr_t)u;
 s->h[4]=(unsigned)sig;s->h[5]=(unsigned)si->si_signo;s->h[6]=(unsigned)si->si_code;
 s->h[7]=(unsigned)si->si_errno;s->h[8]=(uintptr_t)si->si_addr;
 uint16_t fs,gs;__asm__ volatile("mov %%fs,%0;mov %%gs,%1":"=r"(fs),"=r"(gs));
 s->h[9]=fs;s->h[10]=gs;s->h[11]=*(const volatile uint64_t *)(uintptr_t)RN_WORD;
 npf_copy(s->uc,u,sizeof *u);npf_copy(s->fp,b,n);
 npf_copy(s->source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 npf_copy(s->data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 npf_copy(s->rseq,(const void *)(uintptr_t)RN_PAGE,4096);s->h[0]=1;return 1;
}
static void npf_initialize(void) {
 __asm__ volatile(""::"r"(&npf_step_frame_fp_alignment):"memory");
 volatile unsigned char *z=(void *)&npf_record;
 for(size_t i=0;i<sizeof npf_record;i++)z[i]=0;
 checked(original_main.entry==RN_MAIN && !original_main.bias,1980,0);
 uint64_t c=*(const volatile uint64_t *)(uintptr_t)(RN_DATA+8);
 uint64_t control=*(const volatile uint64_t *)(uintptr_t)(RN_DATA+96);
 checked(c<=20 && control<=1 && (c==16 || !control) &&
  *(const volatile uint64_t *)(uintptr_t)RN_DATA==RN_MAGIC,1980,1);
 npf_record.h[0]=RN_MAGIC;npf_record.h[1]=1;npf_record.h[2]=sizeof npf_record;
 npf_record.h[3]=c;npf_record.h[4]=sizeof(ucontext_t);npf_record.h[5]=sizeof(struct npf_row);
 npf_record.h[21]=control;npf_copy(&npf_record.hardware,&selected_hardware,sizeof selected_hardware);
 { uint32_t a=0,b,cx=0,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(cx),"=d"(d)::"memory");
   npf_record.h[32]=a;npf_record.h[33]=b;npf_record.h[34]=cx;npf_record.h[35]=d; }
 checked(sizeof(siginfo_t)==128 && selected_hardware.leaf0[0]>=13 &&
  (selected_hardware.leaf1[2]&UINT32_C(0x18000000))==UINT32_C(0x18000000) &&
  (selected_hardware.leaf7[1]&UINT32_C(0x40010000))==UINT32_C(0x40010000),1980,2);
 uint32_t lo,hi;__asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0):"memory");
 npf_record.h[6]=(uint64_t)lo|((uint64_t)hi<<32);
 checked((npf_record.h[6]&0xe7)==0xe7,1980,3);
 const unsigned bits[4]={2,5,6,7};
 for(unsigned i=0;i<4;i++) {
  uint32_t a=13,b,cx=bits[i],d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(cx),"=d"(d)::"memory");
  npf_record.xstate[i][0]=bits[i];npf_record.xstate[i][1]=b;
  npf_record.xstate[i][2]=a;npf_record.xstate[i][3]=cx;
 }
 npf_record.h[15]=(uintptr_t)fork_gate_stack.ss_sp;npf_record.h[16]=fork_gate_stack.ss_size;
 npf_record.h[7]=1;
}
static void npf_permits(uint64_t p[12]) {
 p[0]=selected_step_pending;p[1]=selected_pending_route;
 p[2]=li2_lifecycle_fetch_interlock();p[3]=selected_tf_attempts;p[4]=selected_tf_steps;
 p[5]=selected_step.phase;p[6]=selected_step.open_started[0];p[7]=selected_step.open_started[1];
 p[8]=selected_step.opened[0];p[9]=selected_step.opened[1];
 p[10]=li2_lifecycle_native_counts()->admissions;p[11]=li2_lifecycle_native_counts()->closed;
}
static void npf_entry(int sig,const siginfo_t *si,const ucontext_t *u) {
 /* Called after the actual pure preentry guard, before returning RAW. */
 npf_current=NPF_ROWS;npf_frame_pointer=0;npf_signal_pointer=0;
 if(!npf_record.h[7] || npf_finished || !si || !u ||
    *(const volatile uint64_t *)(uintptr_t)(RN_DATA+24)!=1)return;
 uintptr_t pc=(uintptr_t)u->uc_mcontext.gregs[REG_RIP];
 int nested=npf_record.h[3]==11 && npf_record.control[3] && !npf_record.control[4];
 if(!nested && (sig!=SIGSEGV || !npf_focal(pc)))return;
 if(npf_used==NPF_ROWS){npf_record.h[8]=1;return;}
 npf_current=npf_used++;struct npf_row *r=&npf_record.rows[npf_current];
 r->h[0]=1;r->h[1]=npf_current;r->h[2]=pc;r->h[3]=(uintptr_t)si->si_addr;
 r->h[11]=selected_flags_known;r->h[12]=selected_logical_flags;
 r->h[24]=(uintptr_t)si;r->h[26]=sizeof *si;r->h[27]=offsetof(siginfo_t,si_addr);
 npf_frame_pointer=u;npf_signal_pointer=si;npf_copy(&npf_signal,si,sizeof npf_signal);
 npf_copy(r->signal_before,si,sizeof *si);
 npf_copy(&r->pair_before,li2_native_pair_progress(),sizeof r->pair_before);
 npf_copy(&r->life_before,li2_lifecycle_pair_progress(),sizeof r->life_before);
 npf_copy(&r->rseq_before,li2_rseq_pair_progress(),sizeof r->rseq_before);
 npf_permits(r->permits[0]);
 if(!npf_capture(&r->before,sig,si,u))npf_record.h[8]=2;
}
static void npf_pair_return(int result,int sig,const siginfo_t *si,const ucontext_t *u) {
 if(npf_current==NPF_ROWS || npf_frame_pointer!=u)return;
 struct npf_row *r=&npf_record.rows[npf_current];
 if(r->h[4]){npf_record.h[8]=3;return;}
 r->h[4]=1;r->h[5]=(unsigned)result;r->h[13]=selected_flags_known;
 r->h[14]=selected_logical_flags;r->h[25]=(uintptr_t)si;
 npf_copy(r->signal_after,si,sizeof *si);
 npf_copy(&r->pair_after,li2_native_pair_progress(),sizeof r->pair_after);
 npf_copy(&r->life_after,li2_lifecycle_pair_progress(),sizeof r->life_after);
 npf_copy(&r->rseq_after,li2_rseq_pair_progress(),sizeof r->rseq_after);
 npf_copy(&r->close,li2_lifecycle_native_close_progress(),sizeof r->close);
 npf_permits(r->permits[1]);
 if(!npf_capture(&r->after,sig,si,u))npf_record.h[8]=4;
}
static void npf_fetch_return(int result,int sig,const siginfo_t *si,const ucontext_t *u) {
 (void)sig;(void)si;
 if(npf_current==NPF_ROWS || npf_frame_pointer!=u)return;
 struct npf_row *r=&npf_record.rows[npf_current];
 if(r->h[6]){npf_record.h[8]=5;return;}
 r->h[6]=1;r->h[7]=(unsigned)result;
}
void npf_stage_observe(unsigned kind,uintptr_t pc,int result) {
 if(!npf_record.h[7] || npf_finished || npf_current==NPF_ROWS || !npf_focal(pc))return;
 if(kind<NPF_PREPARED || kind>NPF_CONTROL_AFTER || npf_stages==NPF_STAGES){npf_record.h[8]=6;return;}
 struct npf_stage *s=&npf_record.stages[npf_stages++];
 s->h[1]=kind;s->h[2]=npf_current;s->h[3]=pc;s->h[4]=(uint64_t)(int64_t)result;
 s->h[5]=li2_native_pair_progress()->phase;
 npf_copy(&s->life,li2_lifecycle_pair_progress(),sizeof s->life);
 npf_copy(&s->rseq,li2_rseq_pair_progress(),sizeof s->rseq);
 npf_copy(&s->close,li2_lifecycle_native_close_progress(),sizeof s->close);s->h[0]=1;
}
/* Test-only selectors address exactly one actual seam in one fixed case.
   They are absent from all unobserved/default production translation units. */
int npf_control_match(unsigned c,unsigned sub,unsigned stage,uintptr_t pc) {
 return npf_record.h[7] && !npf_finished && npf_record.h[3]==c && npf_record.h[21]==sub &&
  !npf_record.control[3] && npf_current<NPF_ROWS && pc==npf_b() &&
  ((stage==NPF_PREPARED && li2_native_pair_progress()->phase==LI2_NP_EXTENDING) ||
   (stage==NPF_PUBLISHED && li2_native_pair_progress()->phase==LI2_NP_EXTENDING));
}
void npf_control_values(unsigned stage,uint64_t old,uint64_t now,uintptr_t canonical,uintptr_t copy) {
 checked(!npf_record.control[3] && npf_current<NPF_ROWS,1980,4);
 npf_record.control[0]=npf_record.h[3];npf_record.control[1]=npf_record.h[21];
 npf_record.control[2]=stage;npf_record.control[3]=1;npf_record.control[4]=1;
 npf_record.control[12]=old;npf_record.control[13]=now;
 npf_record.control[14]=canonical;npf_record.control[15]=copy;
}
static void npf_filter(unsigned c) {
 /* Deny exactly one fixture operation. All other calls retain the real
    kernel result. The filter changes no process outside this child. */
 struct sock_filter protect[]={
  BPF_STMT(BPF_LD|BPF_W|BPF_ABS,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,10,0,7),
  BPF_STMT(BPF_LD|BPF_W|BPF_ABS,16),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)RN_BODY,0,5),
  BPF_STMT(BPF_LD|BPF_W|BPF_ABS,20),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)(RN_BODY>>32),0,3),
  BPF_STMT(BPF_LD|BPF_W|BPF_ABS,32),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,1,0,1),
  BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
 };
 struct sock_filter sync[]={
  BPF_STMT(BPF_LD|BPF_W|BPF_ABS,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,324,0,3),
  BPF_STMT(BPF_LD|BPF_W|BPF_ABS,16),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,32,0,1),
  BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
 };
 struct sock_fprog f={.len=(unsigned short)(c==12?10:6),.filter=c==12?protect:sync};
 npf_record.control[16]=1;
 long a=raw(SYS_prctl,38,1,0,0,0,0);
 npf_record.control[17]=1;npf_record.control[18]=(uint64_t)a;checked(!a,1980,5);
 npf_record.control[19]=1;
 long b=raw(SYS_prctl,22,2,(long)&f,0,0,0);
 npf_record.control[20]=1;npf_record.control[21]=(uint64_t)b;checked(!b,1980,6);
}
void npf_control_hook(unsigned stage,uintptr_t pc) {
 unsigned c=(unsigned)npf_record.h[3];
 if((c!=11 && c!=12 && c!=15 && c!=20) ||
    !npf_control_match(c,0,stage,pc) ||
    ((c==11||c==15)?stage!=NPF_PREPARED:stage!=NPF_PUBLISHED))return;
 const struct li2_native_pair_lifecycle *l=li2_lifecycle_pair_progress();
 checked(!*(const volatile uint64_t *)(uintptr_t)RN_WORD && l->live==(stage==NPF_PREPARED?1U:2U),1980,7);
 npf_stage_observe(NPF_CONTROL_BEFORE,pc,0);
 npf_record.control[0]=c;npf_record.control[2]=stage;npf_record.control[3]=1;
 if(c==11) {
  checked(npf_frame_pointer && npf_signal_pointer && !npf_outer_frame_pointer &&
   !npf_outer_signal_pointer,1980,16);
  npf_outer_frame_pointer=npf_frame_pointer;npf_outer_signal_pointer=npf_signal_pointer;
  npf_record.control[16]=1;
  long uid=raw(SYS_getuid,0,0,0,0,0,0);
  npf_record.control[17]=1;npf_record.control[18]=(uint64_t)uid;checked(uid>=0,1980,17);
  npf_record.control[6]=(uint64_t)selected_session.pid;
  npf_record.control[7]=(uint64_t)selected_session.tid;npf_record.control[8]=SIGTRAP;
  long r=raw(SYS_tgkill,selected_session.pid,selected_session.tid,SIGTRAP,0,0,0);
  npf_record.control[4]=1;npf_record.control[5]=(uint64_t)r;
  checked(0,1980,8); /* genuine nested terminal delivery must not return */
 } else if(c==15) {
  const struct li2_native_pair_slot *s=&l->slots[1];
  checked(s->prepared==1 && !s->published && s->backing.retained_fd>=0,1980,9);
  npf_record.control[6]=4096;npf_record.control[7]=3;npf_record.control[8]=2;
  npf_record.control[9]=(uint64_t)s->backing.retained_fd;npf_record.control[10]=s->page.offset;
  long r=raw(SYS_mmap,0,4096,3,2,s->backing.retained_fd,s->page.offset);
  npf_record.control[4]=1;npf_record.control[5]=(uint64_t)r;
  checked(r>0 && !(r&4095),1980,10);
 } else {
  npf_filter(c);npf_record.control[4]=1;
 }
 npf_stage_observe(NPF_CONTROL_AFTER,pc,0);
}
int npf_inject_sync(void) {
 if(!npf_record.h[7] || npf_finished || npf_record.h[3]!=13 || npf_record.control[3] ||
    npf_current==NPF_ROWS || npf_record.rows[npf_current].h[2]!=NPF_CLOSE_GATE ||
    li2_native_pair_progress()->phase!=LI2_NP_CLOSING)return 0;
 npf_record.control[0]=13;npf_record.control[2]=NPF_CLOSE_BEFORE;
 npf_record.control[3]=1;npf_record.control[4]=1;npf_record.control[5]=(uint64_t)(int64_t)-5;
 npf_record.control[6]=SYS_membarrier;npf_record.control[7]=32;
 /* The distinct supplied branch issues no membarrier at all. */
 return 1;
}
int npf_real_instruction(const struct li2_decoded *,const ucontext_t *);
int li2_rseq_check_instruction(const struct li2_decoded *d,const ucontext_t *u) {
 unsigned c=(unsigned)npf_record.h[3];
 uintptr_t pc=c==7?RN_TAIL-14:RN_TAIL-2;
 int observe=npf_record.h[7] && c>=7 && c<=9 && d && d->pc==pc;
 struct npf_row *r=npf_current<NPF_ROWS?&npf_record.rows[npf_current]:0;
 if(observe) {
  checked(r && npf_frame_pointer==u && r->h[4] && r->h[5]==LI2_NP_FALLBACK && !r->h[8],1980,11);
  checked(npf_capture(&r->guard_before,(int)r->before.h[4],&npf_signal,u),1980,12);
  npf_permits(r->permits[2]);r->h[8]=1;
 }
 int result=npf_real_instruction(d,u);
 if(observe) {
  checked(npf_capture(&r->guard_after,(int)r->before.h[4],&npf_signal,u),1980,13);
  npf_permits(r->permits[3]);npf_copy(&r->guard_state,li2_rseq_snapshot(),sizeof r->guard_state);
  r->h[9]=1;r->h[10]=(unsigned)result;
 }
 return result;
}
static void npf_store(unsigned terminal,unsigned status,unsigned code,long detail) {
 if(npf_finished || !npf_record.h[7])return;
 npf_finished=1;npf_record.h[9]=terminal;npf_record.h[10]=status;npf_record.h[11]=code;
 npf_record.h[12]=(uint64_t)detail;npf_record.h[13]=npf_used;npf_record.h[20]=npf_stages;
 npf_record.h[17]=li2_lifecycle_native_counts()->admissions;
 npf_record.h[18]=li2_lifecycle_native_counts()->closed;
 npf_copy(&npf_record.terminal_pair,li2_native_pair_progress(),sizeof npf_record.terminal_pair);
 npf_copy(&npf_record.terminal_life,li2_lifecycle_pair_progress(),sizeof npf_record.terminal_life);
 npf_copy(&npf_record.terminal_rseq_pair,li2_rseq_pair_progress(),sizeof npf_record.terminal_rseq_pair);
 npf_copy(&npf_record.terminal_rseq,li2_rseq_snapshot(),sizeof npf_record.terminal_rseq);
 npf_copy(&npf_record.terminal_close,li2_lifecycle_native_close_progress(),sizeof npf_record.terminal_close);
 npf_copy(npf_record.terminal_source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 npf_copy(npf_record.terminal_data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 if(*(const volatile uint64_t *)(uintptr_t)(RN_DATA+24)==1) {
  npf_copy(npf_record.terminal_page,(const void *)(uintptr_t)RN_PAGE,4096);npf_record.h[14]=1;
 }
 if(terminal && npf_frame_pointer && npf_signal_pointer &&
    !npf_capture(&npf_record.terminal_frame,(int)npf_signal.si_signo,npf_signal_pointer,npf_frame_pointer))npf_record.h[8]=7;
 if(terminal && npf_outer_frame_pointer && npf_outer_signal_pointer) {
  npf_copy(npf_record.nested_outer_signal,npf_outer_signal_pointer,sizeof npf_record.nested_outer_signal);
  if(!npf_capture(&npf_record.nested_outer_frame,SIGSEGV,npf_outer_signal_pointer,
                 npf_outer_frame_pointer))npf_record.h[8]=8;
 }
 size_t at=0;
 while(at<sizeof npf_record) {
  long n=raw(SYS_write,3,(long)((const unsigned char *)&npf_record+at),sizeof npf_record-at,0,0,0);
  if(n<=0 || (size_t)n>sizeof npf_record-at)return;
  at+=(size_t)n;
 }
}
static void npf_terminal(unsigned status,unsigned code,long detail) {npf_store(1,status,code,detail);}
static void npf_safe_prefix(int sig,const siginfo_t *si,const ucontext_t *u) {
 unsigned c=(unsigned)npf_record.h[3];
 if(!npf_record.h[7] || npf_finished || (c!=14 && !(c==16 && npf_record.h[21]==1)) ||
    (uintptr_t)u->uc_mcontext.gregs[REG_RIP]!=RN_BODY)return;
 const struct li2_native_pair_progress *p=li2_native_pair_progress();
 checked(npf_used==1 && npf_current==0 && npf_frame_pointer==u && !npf_record.h[19] &&
  p->phase==LI2_NP_EXECUTING_ONE && p->live==1 && !p->in_handler && !p->entry_pending &&
  !p->first_error && !*(const volatile uint64_t *)(uintptr_t)RN_WORD,1980,14);
 checked(npf_capture(&npf_record.publication_frame,sig,si,u),1980,15);
 npf_record.h[19]=1;npf_store(0,0,0,0);
}
void npf_rseq_mutate_pin(void);
static void npf_preentry_mutate(int sig,const siginfo_t *si,const ucontext_t *u) {
 /* Supplied mutation after a genuine kernel frame exists. The saved prefix
    still has a zero word/valid pin. Nothing logs or returns RAW afterward. */
 unsigned c=(unsigned)npf_record.h[3];
 if(!npf_record.h[19] || !npf_finished || !si || !u || sig!=SIGSEGV ||
    si->si_signo!=SIGSEGV || si->si_code!=SEGV_ACCERR || si->si_errno ||
    (uintptr_t)si->si_addr!=npf_b() || (uintptr_t)u->uc_mcontext.gregs[REG_RIP]!=npf_b() ||
    u->uc_mcontext.gregs[REG_TRAPNO]!=14 || u->uc_mcontext.gregs[REG_ERR]!=21)return;
 if(c==14)*(volatile uint64_t *)(uintptr_t)RN_WORD=1;
 else if(c==16 && npf_record.h[21]==1)npf_rseq_mutate_pin();
 __asm__ volatile("":::"memory");
}
