/* Explicit application qualification profile only. The old hash observer and
   its wire remain unchanged. These are real native signal frames at a separate
   no-effect prefix; the gated application never installs this observer. */
#if !defined(LI2_CURRENT_TF_APP) || LI2_CURRENT_TF_APP != 1
#error "explicit current-custody application profile required"
#endif
extern unsigned char unrolled_current_head[],unrolled_current_end[],unrolled_current_return_high[];
#define UCT_MAGIC UINT64_C(0x315446435541494c)
static unsigned uct_count,uct_done,uct_fallback;
_Static_assert(sizeof(struct uct_sample)==75152&&sizeof(struct uct_app)==304896,
               "fixed four-frame current-custody application extension");
_Static_assert(sizeof(prefix)+sizeof(suffix)+sizeof(uct_record)<1024U*1024U,
               "complete application output below the unchanged16MiB bound");
static void uct_initialize(uintptr_t original_stack,int argc,char **argv){
 need(argc==3||(argc==4&&!strcmp(argv[3],"physical-fallback")),110);
 uct_fallback=argc==4;
 uintptr_t head=(uintptr_t)unrolled_current_head;
 need(!(head&(UA_PAGE-1))&&head<UINT64_C(0x80000000)&&
      unrolled_current_end-unrolled_current_head==UA_PAGE,111);
 static const unsigned char instructions[12]={0x66,0x90,0x66,0x90,0x66,0x90,0xff,0x25,0,0,0,0};
 static const unsigned char fill[UA_PAGE-20]={[0 ... UA_PAGE-21]=0xcc};
 need(same(unrolled_current_head,instructions,sizeof instructions)&&
      u64(unrolled_current_head+12)==(uintptr_t)unrolled_current_return_high,112);
 need(same(unrolled_current_head+20,fill,sizeof fill),113);
 copy(uct_record.source,unrolled_current_head,UA_PAGE);
 uint64_t *h=uct_record.h;
 h[0]=UCT_MAGIC;h[1]=1;h[2]=sizeof uct_record;h[3]=native;h[4]=mode;
 h[5]=head;h[6]=(uintptr_t)unrolled_app_head;h[7]=sizeof(struct uct_sample);
 if(uct_fallback){
  /* A real guest syscall with the original policy: same RW permissions on an
     actual page of the initial kernel stack. Its observed overlap retires the
     maintained stack anchor. No private cache flag or ticket is fabricated. */
  h[10]=original_stack&~(uintptr_t)(UA_PAGE-1);h[11]=1;
  h[12]=(uint64_t)RAW(SYS_mprotect,h[10],UA_PAGE,PROT_READ|PROT_WRITE,0,0,0);
  need(!h[12],114);
 }
 h[13]=uct_fallback;h[15]=(uintptr_t)unrolled_current_return_high;
}
static void uct_native_setup(void){
 need(native&&!RAW(SYS_mprotect,unrolled_current_head,UA_PAGE,PROT_READ,0,0,0),115);
}
static void uct_retain(int sig,const siginfo_t *si,const ucontext_t *uc){
 need(uct_count<4&&alt_range(si,sizeof *si)&&alt_range(uc,sizeof *uc),116);
 struct uct_sample *s=&uct_record.samples[uct_count];struct ua_frame *f=&s->frame;
 const unsigned char *p=(const void *)uc->uc_mcontext.fpregs;
 need(!((uintptr_t)p&15)&&alt_range(p,512),117);
 size_t n=u32(p+468),x=u32(p+480);
 need(u32(p+464)==UINT32_C(0x46505853)&&n>=580&&n<=UA_FP&&x==n-4&&
      x>=576&&alt_range(p,n)&&u32(p+n-4)==UINT32_C(0x46505845)&&!u64(p+520),118);
 f->h[0]=1;f->h[1]=uct_count;f->h[2]=uct_count;f->h[3]=0;f->h[4]=(unsigned)sig;
 f->h[5]=(uintptr_t)si;f->h[6]=(uintptr_t)uc;f->h[7]=sizeof *uc;
 f->h[8]=(uintptr_t)p;f->h[9]=n;f->h[10]=alt_area+UA_PAGE;f->h[11]=UA_ALT_BYTES;
 copy(f->si,si,sizeof *si);copy(f->uc,uc,sizeof *uc);copy(f->fp,p,n);
 need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&s->tls[0],0,0,0,0)&&
      !RAW(SYS_arch_prctl,ARCH_GET_GS,&s->tls[1],0,0,0,0),119);
 copy(s->stack,(void *)(ua_input.g[4]-128),UA_STACK);
 copy(s->data,(void *)UA_DATA_BASE,UA_DATA);
 need(same(s->stack,prefix.stack,UA_STACK)&&same(s->data,prefix.data,UA_DATA),120);
 ++uct_count;
}
static int uct_native_handler(int sig,siginfo_t *si,ucontext_t *uc){
 if(uct_done)return 0;
 greg_t *g=uc->uc_mcontext.gregs;uintptr_t head=(uintptr_t)unrolled_current_head;
 need(!started&&!steps&&!copies&&!frame_count&&!fault_seen&&uct_count<4,121);
 uintptr_t pc=head+2*uct_count;
 need((uintptr_t)g[REG_RIP]==pc&&(uintptr_t)si->si_addr==pc,122);
 for(unsigned i=0;i<16;i++)need((uint64_t)g[regs[i]]==ua_input.g[i],123);
 if(!uct_count){
  need(sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&g[REG_ERR]==21&&g[REG_TRAPNO]==14&&
       (uintptr_t)g[REG_CR2]==head&&(uint64_t)g[REG_EFL]==(ua_input.flags|UA_RF),124);
 }else{
  need(sig==SIGTRAP&&si->si_code==TRAP_TRACE&&g[REG_ERR]==0&&g[REG_TRAPNO]==1&&
       (uint64_t)g[REG_EFL]==(ua_input.flags|UA_TF),125);
 }
 uct_retain(sig,si,uc);
 if(uct_count==1){
  need(!RAW(SYS_mprotect,unrolled_current_head,UA_PAGE,PROT_READ|PROT_EXEC,0,0,0),126);
  g[REG_EFL]|=(greg_t)UA_TF;
 }else if(uct_count==4){
  /* Only the native reference clears observer TF here. The real runtime's
     later FF25 route is observed independently, never forced to match. */
  g[REG_EFL]&=~(greg_t)UA_TF;uct_done=1;
 }
 return 1;
}
static void uct_finish(void){
 need(same(uct_record.source,unrolled_current_head,UA_PAGE),127);
 need(native?(uct_count==4&&uct_done):(!uct_count&&!uct_done),128);
 uct_record.h[8]=uct_count;uct_record.h[9]=uct_done;uct_record.h[14]=suffix.h[5];
 need(uct_record.h[14]==1,129);
}
