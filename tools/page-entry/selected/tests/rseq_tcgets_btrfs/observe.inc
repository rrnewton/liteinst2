/* Fixture-only pure storage around original runtime effects. */
#include "rseq_tcgets_record.h"
#include <linux/magic.h>
extern uintptr_t li2_saved[];
#define RTC_INJECT (rtc_record.h[14])
struct rtc_row {
 struct rtc_native_row frame;
 uint64_t permits[2][4];
 struct li2_rseq_native_state native_before,native_after;
 struct li2_native_close close;
};
struct rtc_record {
 uint64_t h[64],xstate[4][4],startup[256];
 struct li2_selected_hardware hardware;
 struct rtc_row rows[RTC_ROWS];
 struct rn_frame effect_before,effect_after;
 struct li2_tcgets_state stages[7];
 struct li2_rseq_state owners[7];
 struct li2_native_close terminal_close;
 uint64_t query[256][10],injection[2][8];
 struct li2_tcgets_state injection_before[2],injection_after[2];
 unsigned char terminal_source[RN_SOURCE_BYTES],terminal_data[RN_DATA_BYTES],terminal_page[4096];
};
_Static_assert(sizeof(ucontext_t)<=RN_UC && sizeof(siginfo_t)==128 && sizeof(struct rtc_record)<(16U<<20),"bounded complete ioctl observation");
static struct rtc_record rtc_record;
static unsigned rtc_used,rtc_finished,rtc_current=RTC_ROWS;
static const ucontext_t *rtc_frame_pointer;
static const siginfo_t *rtc_signal_pointer;
static void rtc_copy(void *to,const void *from,size_t n) {
 unsigned char *d=to;const volatile unsigned char *s=from;
 for(size_t i=0;i<n;i++)d[i]=s[i];
}
static uint32_t rtc_u32(const unsigned char *s) {
 return (uint32_t)s[0]|(uint32_t)s[1]<<8|(uint32_t)s[2]<<16|(uint32_t)s[3]<<24;
}
static int rtc_capture(struct rn_frame *s,int sig,const siginfo_t *si,const ucontext_t *u) {
 if(!si || !u)return 0;
 uintptr_t p=(uintptr_t)u->uc_mcontext.fpregs,lo=(uintptr_t)fork_gate_stack.ss_sp;
 size_t cap=fork_gate_stack.ss_size,n=512;
 if(p<lo || cap<512 || p-lo>cap-512 || (p&15))return 0;
 const unsigned char *b=(const void *)p;
 if(rtc_u32(b+464)==UINT32_C(0x46505853)) {
  n=rtc_u32(b+468);size_t x=rtc_u32(b+480);
  if(n<580 || n>RN_FP || n>cap-(p-lo) || x<576 || x>n-4 || rtc_u32(b+n-4)!=UINT32_C(0x46505845))return 0;
 }
 s->h[1]=sizeof *u;s->h[2]=n;s->h[3]=(uintptr_t)u;
 s->h[4]=(unsigned)sig;s->h[5]=(unsigned)si->si_signo;s->h[6]=(unsigned)si->si_code;
 s->h[7]=(unsigned)si->si_errno;s->h[8]=(uintptr_t)si->si_addr;
 uint16_t fs,gs;__asm__ volatile("mov %%fs,%0;mov %%gs,%1":"=r"(fs),"=r"(gs));
 s->h[9]=fs;s->h[10]=gs;s->h[11]=*(const volatile uint64_t *)(uintptr_t)RN_WORD;
 rtc_copy(s->uc,u,sizeof *u);rtc_copy(s->fp,b,n);
 rtc_copy(s->source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 rtc_copy(s->data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 rtc_copy(s->rseq,(const void *)(uintptr_t)RN_PAGE,4096);
 s->h[0]=1;return 1;
}

static void rtc_stage(unsigned stage,long number,const long *args,long result) {
 if(!rtc_record.h[7] || stage>6)return;
 if(stage && stage<6 && (number!=SYS_ioctl || !li2_rseq_snapshot()->registered))return;
 if(rtc_record.h[24+stage]){rtc_record.h[8]=11;return;}
 rtc_record.h[24+stage]=1;
 rtc_copy(&rtc_record.stages[stage],li2_rseq_tcgets_snapshot(),sizeof rtc_record.stages[stage]);
 rtc_copy(&rtc_record.owners[stage],li2_rseq_snapshot(),sizeof rtc_record.owners[stage]);
 if(stage==4) {
  rtc_record.h[32]=(uint64_t)result;
  for(unsigned i=0;i<6;i++)rtc_record.h[33+i]=(uint64_t)args[i];
 }
}
static void rtc_initialize(void) {
 checked(!rtc_record.h[7] && original_main.entry==RN_MAIN && !original_main.bias,1790,0);
 uint64_t c=*(const volatile uint64_t *)(uintptr_t)(RN_DATA+8);
 checked(c<20 && *(const volatile uint64_t *)(uintptr_t)RN_DATA==RN_MAGIC,1790,1);
 rtc_record.h[0]=RTC_MAGIC;rtc_record.h[1]=1;rtc_record.h[2]=sizeof rtc_record;
 rtc_record.h[3]=c;rtc_record.h[4]=sizeof(ucontext_t);rtc_record.h[5]=sizeof(struct rtc_row);
 rtc_record.h[14]=*(const volatile uint64_t *)(uintptr_t)(RN_DATA+120);
 checked(RTC_INJECT<=16 && (!RTC_INJECT || !c),1790,8);rtc_record.h[15]=(uintptr_t)fork_gate_stack.ss_sp;rtc_record.h[16]=fork_gate_stack.ss_size;
 rtc_copy(&rtc_record.hardware,&selected_hardware,sizeof selected_hardware);
 checked(selected_hardware.leaf0[0]>=13 && (selected_hardware.leaf1[2]&UINT32_C(0x18000000))==UINT32_C(0x18000000) &&
         (selected_hardware.leaf7[1]&UINT32_C(0x40010000))==UINT32_C(0x40010000),1790,4);
 const volatile uint64_t *startup=(const void *)li2_saved[7];
 checked(startup && startup[0]==1 && !startup[2],1790,5);
 size_t end=3;while(end<126 && startup[end])++end;
 checked(end<126,1790,6);++end;
 while(end+1<256 && startup[end])end+=2;
 checked(end+1<256 && !startup[end] && !startup[end+1],1790,7);end+=2;
 rtc_record.h[22]=li2_saved[7];rtc_record.h[23]=end;
 for(size_t i=0;i<end;i++)rtc_record.startup[i]=startup[i];
 rtc_record.h[42]=(uintptr_t)li2_rseq_tcgets_snapshot();
 rtc_record.h[43]=li2_rseq_snapshot()->pid;rtc_record.h[44]=li2_rseq_snapshot()->tid;
 uint32_t lo,hi;__asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0):"memory");
 rtc_record.h[6]=(uint64_t)lo|((uint64_t)hi<<32);
 checked((rtc_record.h[6]&0xe7)==0xe7,1790,2);
 const unsigned bits[4]={2,5,6,7};
 for(unsigned i=0;i<4;i++) {
  uint32_t a=13,b,cx=bits[i],d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(cx),"=d"(d)::"memory");
  rtc_record.xstate[i][0]=bits[i];rtc_record.xstate[i][1]=b;
  rtc_record.xstate[i][2]=a;rtc_record.xstate[i][3]=cx;
 }
 rtc_record.h[7]=1;
}
static size_t rtc_private_size(void) {
 return rtc_record.h[3]==4?(size_t)(vdso_end-vdso_first):0;
}
static void rtc_private(unsigned char *out) {
 size_t n=rtc_private_size();
 checked(n<=RTC_PRIVATE_BYTES && (!n || (vdso_first && !(vdso_first&4095) && private_intersects(vdso_first,n))),1790,3);
 if(n)rtc_copy(out,(const void *)vdso_first,n);
}
static void rtc_entry(int sig,const siginfo_t *si,const ucontext_t *u) {
 rtc_current=RTC_ROWS;rtc_frame_pointer=0;rtc_signal_pointer=0;
 if(!rtc_record.h[7] || rtc_finished || sig!=SIGSEGV || !si || !u ||
    *(const volatile uint64_t *)(uintptr_t)(RN_DATA+24)!=1)return;
 uintptr_t pc=(uintptr_t)u->uc_mcontext.gregs[REG_RIP];
 if(pc!=RN_TAIL-2 && pc!=RN_TAIL)return;
 if(rtc_used==RTC_ROWS){rtc_record.h[8]=1;return;}
 rtc_current=rtc_used++;struct rtc_row *r=&rtc_record.rows[rtc_current];
 struct rtc_native_row *f=&r->frame;
 f->h[0]=1;f->h[1]=rtc_current;f->h[2]=pc;f->h[3]=(uintptr_t)si->si_addr;
 f->h[24]=(uintptr_t)si;f->h[26]=sizeof *si;f->h[27]=offsetof(siginfo_t,si_addr);
 f->h[28]=rtc_record.h[3]==4?vdso_first:0;f->h[29]=rtc_private_size();
 rtc_frame_pointer=u;rtc_signal_pointer=si;
 rtc_copy(&r->native_before,li2_rseq_native_snapshot(),sizeof r->native_before);
 r->permits[0][0]=selected_step_pending;r->permits[0][1]=selected_pending_route;
 r->permits[0][2]=li2_lifecycle_fetch_interlock();r->permits[0][3]=li2_lifecycle_native_counts()->admissions;
 if(!rtc_capture(&f->before,sig,si,u)){rtc_record.h[8]=2;return;}
 rtc_copy(f->siginfo_before,si,sizeof *si);rtc_private(f->private_before);
}
static void rtc_fetch_return(int result,int sig,const siginfo_t *si,const ucontext_t *u) {
 if(rtc_current==RTC_ROWS || rtc_frame_pointer!=u)return;
 struct rtc_row *r=&rtc_record.rows[rtc_current];struct rtc_native_row *f=&r->frame;
 if(f->h[4] || si!=rtc_signal_pointer){rtc_record.h[8]=3;return;}
 f->h[4]=1;f->h[5]=(unsigned)result;f->h[25]=(uintptr_t)si;
 rtc_copy(&r->native_after,li2_rseq_native_snapshot(),sizeof r->native_after);
 rtc_copy(&r->close,li2_lifecycle_native_close_progress(),sizeof r->close);
 r->permits[1][0]=selected_step_pending;r->permits[1][1]=selected_pending_route;
 r->permits[1][2]=li2_lifecycle_fetch_interlock();r->permits[1][3]=li2_lifecycle_native_counts()->admissions;
 if(!rtc_capture(&f->after,sig,si,u)){rtc_record.h[8]=4;return;}
 rtc_copy(f->siginfo_after,si,sizeof *si);rtc_private(f->private_after);
}
static void rtc_effect(ucontext_t *u,unsigned committed) {
 if(!rtc_record.h[7] || rtc_current!=0 || rtc_frame_pointer!=u || !rtc_signal_pointer)return;
 if(committed>1 || rtc_record.h[40+committed]){rtc_record.h[8]=5;return;}
 struct rn_frame *f=committed?&rtc_record.effect_after:&rtc_record.effect_before;
 if(!rtc_capture(f,SIGSEGV,rtc_signal_pointer,u)){rtc_record.h[8]=6;return;}
 rtc_record.h[40+committed]=1;
}
static unsigned rtc_inject_begin(struct li2_tcgets_state *s,unsigned seam,long n,long actual,long supplied) {
 unsigned i=(unsigned)rtc_record.h[20];
 if(i>=2){rtc_record.h[8]=7;return 2;}
 rtc_copy(&rtc_record.injection_before[i],s,sizeof *s);
 rtc_record.injection[i][0]=RTC_INJECT;rtc_record.injection[i][1]=seam;
 rtc_record.injection[i][2]=(uint64_t)n;rtc_record.injection[i][3]=(uint64_t)actual;
 rtc_record.injection[i][4]=(uint64_t)supplied;rtc_record.injection[i][5]=s->queries;
 ++rtc_record.h[20];return i;
}
static void rtc_inject_end(unsigned i,const struct li2_tcgets_state *s) {
 if(i<2){rtc_copy(&rtc_record.injection_after[i],s,sizeof *s);rtc_record.injection[i][6]=1;}
}
void rtc_query_observed(struct li2_tcgets_state *s,long n,long a,long b,long c,long d,long e,long f,long *result) {
 if(!rtc_record.h[7])return;
 unsigned q=(unsigned)rtc_record.h[19];
 if(q>=256){rtc_record.h[8]=8;return;}
 uint64_t *row=rtc_record.query[q];row[0]=s->queries;row[1]=n;row[2]=a;row[3]=b;row[4]=c;row[5]=d;row[6]=e;row[7]=f;
 row[8]=(uint64_t)*result;row[9]=s->phase;++rtc_record.h[19];
 if(!RTC_INJECT || s->phase!=LI2_TCGETS_CHECKING)return;
 int target=(a==1 && (n==SYS_fstat || n==SYS_fcntl || n==SYS_fstatfs || n==SYS_statx));
 int change=(RTC_INJECT==1 && target && n==SYS_fstat) || (RTC_INJECT==2 && target && n==SYS_fcntl) ||
   (RTC_INJECT==3 && target && n==SYS_fstatfs) || ((RTC_INJECT==4 || RTC_INJECT==5 || RTC_INJECT==6) && target && n==SYS_statx) ||
   (RTC_INJECT==7 && target && (n==SYS_fstat || n==SYS_statx)) || (RTC_INJECT==8 && n==SYS_openat) ||
   (RTC_INJECT==9 && n==SYS_read) || (RTC_INJECT==10 && n==SYS_close) || (RTC_INJECT==16 && target && n==SYS_fstat);
 if(!change || (RTC_INJECT!=7 && rtc_record.h[20]))return;
 long supplied=*result;if(RTC_INJECT==1 || RTC_INJECT==8 || RTC_INJECT==9 || RTC_INJECT==10)supplied=-EIO;
 if(RTC_INJECT==2)supplied|=O_PATH;
 unsigned i=rtc_inject_begin(s,1,n,*result,supplied);
 *result=s->query_result=supplied;
 if(RTC_INJECT==3)s->filesystem.f_type=PROC_SUPER_MAGIC;
 if(RTC_INJECT==4)s->statx.stx_mask&=~STATX_MNT_ID;
 if(RTC_INJECT==5)++s->statx.stx_ino;
 if(RTC_INJECT==6)s->statx.stx_mnt_id=0;
 if(RTC_INJECT==7){if(n==SYS_fstat)++s->stat.st_ino;else ++s->statx.stx_ino;}
 if(RTC_INJECT==16)s->stat.st_mode=(s->stat.st_mode&~S_IFMT)|S_IFDIR;
 rtc_inject_end(i,s);
}
void rtc_mount_observed(struct li2_tcgets_state *s,uint64_t *wanted) {
 if(!rtc_record.h[7] || s->phase!=LI2_TCGETS_CHECKING || RTC_INJECT<11 || RTC_INJECT>14 || rtc_record.h[20])return;
 unsigned i=rtc_inject_begin(s,2,0,(long)*wanted,RTC_INJECT==14?0:(long)*wanted);
 if(RTC_INJECT==11 && s->mount_bytes)s->mountinfo[s->mount_bytes-1]=' ';
 if(RTC_INJECT==12) {
  size_t n=0;while(n<s->mount_bytes && s->mountinfo[n]!='\n')++n;
  if(n<s->mount_bytes && n+1<=LI2_TCGETS_MOUNT_BYTES-s->mount_bytes) {
   ++n;rtc_copy(s->mountinfo+s->mount_bytes,s->mountinfo,n);s->mount_bytes+=n;
  } else rtc_record.h[8]=9;
 }
 if(RTC_INJECT==13) {
  size_t at=0;int changed=0;
  while(at<s->mount_bytes) {
   size_t end=at;while(end<s->mount_bytes && s->mountinfo[end]!='\n')++end;
   uint64_t id=0;size_t p=at;while(p<end && s->mountinfo[p]>='0' && s->mountinfo[p]<='9')id=id*10+(unsigned)(s->mountinfo[p++]-'0');
   if(id==*wanted)for(;p+9<=end;p++)if(s->mountinfo[p]==' ' && s->mountinfo[p+1]=='-' &&
     s->mountinfo[p+2]==' ' && s->mountinfo[p+3]=='b' && s->mountinfo[p+4]=='t' && s->mountinfo[p+5]=='r' &&
     s->mountinfo[p+6]=='f' && s->mountinfo[p+7]=='s' && s->mountinfo[p+8]==' '){s->mountinfo[p+3]='x';changed=1;break;}
   at=end+1;
  }
  if(!changed)rtc_record.h[8]=10;
 }
 if(RTC_INJECT==14)*wanted=0;
 rtc_inject_end(i,s);
}
static long rtc_result_argument(long n,const long *a,long result) {
 rtc_stage(4,n,a,result);
 if(RTC_INJECT!=15 || n!=SYS_ioctl || !li2_rseq_snapshot()->registered)return result;
 struct li2_tcgets_state *s=(struct li2_tcgets_state *)(uintptr_t)li2_rseq_tcgets_snapshot();
 unsigned i=rtc_inject_begin(s,3,n,result,0);rtc_inject_end(i,s);return 0;
}
static void rtc_terminal(unsigned status,unsigned code,long detail) {
 if(rtc_finished || !rtc_record.h[7])return;
 rtc_finished=1;rtc_record.h[9]=1;rtc_record.h[10]=status;rtc_record.h[11]=code;
 rtc_record.h[12]=(uint64_t)detail;rtc_record.h[13]=rtc_used;
 rtc_stage(6,0,0,0);
 rtc_copy(&rtc_record.terminal_close,li2_lifecycle_native_close_progress(),sizeof rtc_record.terminal_close);
 rtc_record.h[45]=li2_native_epoch_progress()->first_error;rtc_record.h[46]=li2_native_epoch_progress()->phase;
 rtc_record.h[47]=(uint64_t)li2_native_epoch_progress()->first_detail;
 rtc_record.h[17]=li2_lifecycle_native_counts()->admissions;rtc_record.h[18]=li2_lifecycle_native_counts()->closed;
 rtc_copy(rtc_record.terminal_source,(const void *)(uintptr_t)RN_MAIN,RN_SOURCE_BYTES);
 rtc_copy(rtc_record.terminal_data,(const void *)(uintptr_t)RN_DATA,RN_DATA_BYTES);
 if(li2_rseq_snapshot()->registered)rtc_copy(rtc_record.terminal_page,(const void *)(uintptr_t)RN_PAGE,4096);
 size_t at=0;
 while(at<sizeof rtc_record) {
  long n=raw(SYS_write,3,(long)((const unsigned char *)&rtc_record+at),sizeof rtc_record-at,0,0,0);
  if(n<=0 || (size_t)n>sizeof rtc_record-at)return;
  at+=(size_t)n;
 }
}
