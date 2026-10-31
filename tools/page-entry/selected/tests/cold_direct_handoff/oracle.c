/* Appended to the complete old216 source fixture, with actual new predicates.
   All signal/permission/source observations remain supplied, not native proof. */
static unsigned direct_forms,direct_accepted,direct_refusals,direct_closes,direct_fresh,direct_consumes;
static uint64_t status_flags(unsigned bits) {
    static const unsigned at[6]={0,2,4,6,7,11};uint64_t flags=0x202;
    for(unsigned i=0;i<6;i++)if(bits&(1U<<i))flags|=UINT64_C(1)<<at[i];
    return flags;
}
static int condition_true(unsigned cc,uint64_t f) {
    int c=!!(f&1),p=!!(f&4),z=!!(f&64),s=!!(f&128),o=!!(f&2048);
    switch(cc) {
    case 0:return o;case 1:return !o;case 2:return c;case 3:return !c;
    case 4:return z;case 5:return !z;case 6:return c||z;case 7:return !c&&!z;
    case 8:return s;case 9:return !s;case 10:return p;case 11:return !p;
    case 12:return s!=o;case 13:return s==o;case 14:return z||(s!=o);case 15:return !z&&(s==o);
    default:check(cc==16,"only JMP or16 conditions");return 1;
    }
}
static void direct_sync(void) {
    struct li2_decoded *d=decoded();sync_decoded();
    observed.pc=d->pc;observed.length=d->available;
    memset(observed.bytes,0,sizeof observed.bytes);
    if(d->available<=15)copy(observed.bytes,d->bytes,d->available);
    chain_observe(&slot()->fetch);
}
static void direct_target(uint64_t pc) {
    context.uc_mcontext.gregs[REG_RIP]=(greg_t)pc;signal_info.si_addr=(void *)(uintptr_t)pc;
    target_page=observed.pages[0];target_page.address=pc&~UINT64_C(4095);
    target_page.allocation=18;target_page.generation=19;
    target_page.vma_first=target_page.address;target_page.vma_end=target_page.address+4096;
}
static void direct_seed(unsigned cc,unsigned bits,unsigned end,unsigned offset) {
    seed(2,0,32,0);unsigned n=cc==16?5:6;
    uint64_t pc=0x400000+(end?4096-n:0),next=pc+n,target=0x600000+offset;
    uint32_t delta=(uint32_t)(target-next);struct li2_decoded *d=decoded();
    *d=(struct li2_decoded){.pc=pc,.next_pc=next,.abi_version=1,
        .code=cc==16?696:1856+3*cc,.destination=16,.length=n,.available=end?n:15};
    unsigned at=cc==16?1:2;d->bytes[0]=cc==16?0xe9:0x0f;
    if(cc<16)d->bytes[1]=(unsigned char)(0x80+cc);
    for(unsigned i=0;i<4;i++)d->bytes[at+i]=(unsigned char)(delta>>(8*i));
    for(unsigned i=n;i<d->available;i++)d->bytes[i]=0x90;
    uint64_t flags=status_flags(bits);slot()->owner.step.request.original_flags=flags;
    context.uc_mcontext.gregs[REG_EFL]=(greg_t)(flags|LI2_STEP_TF);
    slot()->owner.step.before.greg[REG_EFL]=(greg_t)flags;
    slot()->owner.step.before.greg[REG_RIP]=(greg_t)pc;
    slot()->owner.classification=(struct li2_tf_classification){.pc=pc,.next_pc=next,.abi_version=1,
        .policy=1,.code=d->code,.length=n,.flow=LI2_TF_NEAR_FLOW,.family=LI2_TF_BRANCH};
    direct_sync();direct_target(condition_true(cc,flags)?target:next);
}
static int direct_eligible(void) {
    return li2_tf_chain_span_direct_eligible(&chain,SIGTRAP,&signal_info,&context);
}
static void no_effect(void) {
    check(!trace_calls&&!release_calls&&!snapshot_calls&&!span_transfer.progress.issued,
          "pure eligibility/refusal has no observation or issued ticket");
}
static void direct_matrix(void) {
    for(unsigned cc=0;cc<=16;cc++)for(unsigned bits=0;bits<64;bits++)
    for(unsigned end=0;end<2;end++)for(unsigned offset=0;offset<2;offset++) {
        direct_seed(cc,bits,end,offset?4081:0);
        int want=end||condition_true(cc,status_flags(bits));
        check(direct_eligible()==want,"all status bits/conditions/source endings/target endpoints");
        check(!eligible(),"old register-JMP route still rejects every direct form");
        no_effect();++direct_forms;direct_accepted+=(unsigned)want;
    }
    /* Signed backward E9 uses the same original source geometry. */
    for(unsigned end=0;end<2;end++)for(unsigned offset=0;offset<2;offset++) {
        direct_seed(16,0,end,0);uint64_t target=0x300000+(offset?4081:0);
        uint32_t delta=(uint32_t)(target-decoded()->next_pc);
        for(unsigned i=0;i<4;i++)decoded()->bytes[i+1]=(unsigned char)(delta>>(8*i));
        direct_sync();direct_target(target);check(direct_eligible(),"signed backward E9");
        no_effect();++direct_forms;++direct_accepted;
    }
    /* Zero displacement makes both Jcc arm PCs equal. Each flag-selected arm
       independently retains the full original flags at the cross-page target. */
    for(unsigned bits=0;bits<64;bits++) {
        direct_seed(5,bits,1,0);memset(decoded()->bytes+2,0,4);direct_sync();
        direct_target(decoded()->next_pc);check(direct_eligible(),"equal arm PCs with exact saved condition");
        no_effect();++direct_forms;++direct_accepted;
    }
}
static void direct_negative(void) {
#define DIRECT_BAD(name,change) do {direct_seed(16,0,0,32);change;check(!direct_eligible(),name);no_effect();++direct_refusals;}while(0)
    DIRECT_BAD("wrong actual target",direct_target(0x600021));
    DIRECT_BAD("target beyond15-byte window",direct_target(0x600ff2));
    DIRECT_BAD("zero target",direct_target(0));
    DIRECT_BAD("high canonical actual target",direct_target(UINT64_C(0xffff800000000000)));
    DIRECT_BAD("noncanonical actual target",direct_target(UINT64_C(1)<<47));
    DIRECT_BAD("samepage actual target",direct_target(0x400020));
    DIRECT_BAD("source zero",slot()->owner.step.request.pages[0].address=0);
    DIRECT_BAD("source misaligned",slot()->owner.step.request.pages[0].address++);
    DIRECT_BAD("source high",slot()->owner.step.request.pages[0].address=UINT64_C(1)<<47);
    DIRECT_BAD("source page mismatch",slot()->fetch.pages[0].address+=4096);
    DIRECT_BAD("source descriptor below page",decoded()->pc=0x3fffff;direct_sync());
    DIRECT_BAD("source instruction straddle",decoded()->pc=0x400ffc;decoded()->next_pc=0x401001;direct_sync());
    DIRECT_BAD("descriptor copy differs",slot()->decoded.code++);
    DIRECT_BAD("fetch PC differs",slot()->fetch.pc++);
    DIRECT_BAD("fetch extent differs",slot()->fetch.length--);
    DIRECT_BAD("fetch available byte differs",slot()->fetch.bytes[14]^=1);
    DIRECT_BAD("unavailable descriptor tail nonzero",decoded()->bytes[15]=1;direct_sync());
    DIRECT_BAD("flags changed",context.uc_mcontext.gregs[REG_EFL]^=1);
    DIRECT_BAD("saved condition changed",slot()->owner.step.request.original_flags^=1);
    DIRECT_BAD("TF absent",context.uc_mcontext.gregs[REG_EFL]&=~LI2_STEP_TF);
    DIRECT_BAD("RF present",context.uc_mcontext.gregs[REG_EFL]|=LI2_STEP_RF);
    DIRECT_BAD("event stale",chain.event_id=slot()->event_id);
    DIRECT_BAD("chain not executing",slot()->phase=LI2_CHAIN_CLOSED);
    DIRECT_BAD("owner not running",slot()->owner.step.phase=LI2_STEP_COMPLETE);
    DIRECT_BAD("pending absent",chain.pending=0);
    DIRECT_BAD("handler active",chain.in_handler=1);
    DIRECT_BAD("owner handler active",slot()->owner.step.in_handler=1);
    DIRECT_BAD("first error",chain.first_error=1);
    DIRECT_BAD("wrong registered chain",chain_registered=&foreign_chain);
    DIRECT_BAD("uninitialized chain",chain.initialized=0);
    DIRECT_BAD("invalid active",chain.active=2);
    DIRECT_BAD("ref owner missing",slot()->fetch.ref.owner=0);
    DIRECT_BAD("ref serial missing",slot()->fetch.ref.sequence=0);
    DIRECT_BAD("request two pages",slot()->owner.step.request.page_count=2);
    DIRECT_BAD("fetch two pages",slot()->fetch.page_count=2);
    DIRECT_BAD("issued ticket",span_transfer.valid=1);
    DIRECT_BAD("closing ticket",span_transfer.progress.phase=LI2_ST_CLOSING);
    DIRECT_BAD("transfer serial exhausted",span_transfer_serial=UINT64_MAX);
    DIRECT_BAD("wrong signal",signal_info.si_signo=SIGSEGV);
    DIRECT_BAD("wrong trap",signal_info.si_code=SI_USER);
    DIRECT_BAD("signal errno",signal_info.si_errno=1);
    DIRECT_BAD("trap number",context.uc_mcontext.gregs[REG_TRAPNO]=14);
    DIRECT_BAD("trap error",context.uc_mcontext.gregs[REG_ERR]=1);
    DIRECT_BAD("signal target differs",signal_info.si_addr=(void *)0x600021);
    DIRECT_BAD("decode ABI",decoded()->abi_version=2;direct_sync());
    DIRECT_BAD("invalid decode",decoded()->decode_status=LI2_INVALID;direct_sync());
    DIRECT_BAD("selected kind",decoded()->kind=LI2_CPUID;direct_sync());
    DIRECT_BAD("destination",decoded()->destination=0;direct_sync());
    DIRECT_BAD("width",decoded()->width_bits=64;direct_sync());
    DIRECT_BAD("reserved",decoded()->reserved=1;direct_sync());
    DIRECT_BAD("candidate disposition",decoded()->step_disposition=LI2_STEP_CANDIDATE;direct_sync());
    DIRECT_BAD("short descriptor",decoded()->available=4;direct_sync());
    DIRECT_BAD("oversize descriptor",decoded()->available=16;direct_sync());
    DIRECT_BAD("wrong next",decoded()->next_pc++;direct_sync());
    DIRECT_BAD("wrong length",decoded()->length=4;direct_sync());
    DIRECT_BAD("wrong code",decoded()->code++;direct_sync());
    DIRECT_BAD("classifier ABI",slot()->owner.classification.abi_version=2);
    DIRECT_BAD("classifier refusal",slot()->owner.classification.policy=0);
    DIRECT_BAD("classifier PC",slot()->owner.classification.pc++);
    DIRECT_BAD("classifier next",slot()->owner.classification.next_pc++);
    DIRECT_BAD("classifier code",slot()->owner.classification.code++);
    DIRECT_BAD("classifier length",slot()->owner.classification.length++);
    DIRECT_BAD("classifier flow",slot()->owner.classification.flow=LI2_TF_FALLTHROUGH);
    DIRECT_BAD("classifier family",slot()->owner.classification.family=LI2_TF_CALL);
#undef DIRECT_BAD
    for(unsigned reg=0;reg<16;reg++)for(unsigned saved=0;saved<2;saved++) {
        direct_seed(16,0,0,32);
        if(saved)slot()->owner.step.before.greg[registers[reg]]^=1;
        else context.uc_mcontext.gregs[registers[reg]]^=1;
        check(!direct_eligible(),"every current and saved GPR unchanged");no_effect();++direct_refusals;
    }
    for(unsigned byte=0;byte<256;byte++) {
        direct_seed(16,0,0,32);memmove(decoded()->bytes+1,decoded()->bytes,5);
        decoded()->bytes[0]=(unsigned char)byte;decoded()->length=6;decoded()->next_pc++;
        direct_sync();check(!direct_eligible(),"every leading byte rejects prefixed E9 alias");no_effect();++direct_refusals;
    }
    static const unsigned char other[8][2]={{0xeb,0},{0x75,0},{0xe8,0},{0xc3,0},
        {0xff,0xe2},{0xff,0x22},{0xe2,0},{0x0f,0x90}};
    for(unsigned i=0;i<8;i++) {
        direct_seed(16,0,0,32);copy(decoded()->bytes,other[i],2);direct_sync();
        check(!direct_eligible(),"short/direct-call/return/register/memory/loop/other flow rejected");no_effect();++direct_refusals;
    }
    direct_seed(5,0,1,0);direct_target(decoded()->next_pc);
    check(!direct_eligible(),"JNZ actual fallthrough contradicts saved ZF0");no_effect();++direct_refusals;
    direct_seed(5,8,1,0);direct_target(0x600000);
    check(!direct_eligible(),"JNZ actual taken contradicts saved ZF1");no_effect();++direct_refusals;
    direct_seed(16,0,0,32);
    check(!li2_tf_chain_span_direct_eligible(0,SIGTRAP,&signal_info,&context),"null chain");++direct_refusals;
    check(!li2_tf_chain_span_direct_eligible(&chain,SIGTRAP,0,&context),"null signal");++direct_refusals;
    check(!li2_tf_chain_span_direct_eligible(&chain,SIGTRAP,&signal_info,0),"null context");++direct_refusals;
    check(!li2_tf_chain_span_direct_eligible(&chain,SIGSEGV,&signal_info,&context),"wrong delivered signal");++direct_refusals;
}
static void direct_close_good(void) {
    uint64_t flags=slot()->owner.step.request.original_flags;
    check(!li2_tf_chain_span_close_direct(&chain,SIGTRAP,&signal_info,&context,&ticket),"direct close success");
    check(ticket==&span_transfer && span_transfer.valid==1 && span_transfer.progress.issued==1 &&
        span_transfer.progress.serial==20 && span_transfer.progress.previous_borrow==31 &&
        span_transfer.progress.phase==LI2_ST_CLOSED && !span_origin(ticket),"actual issued direct ticket");
    check(trace_calls==1 && release_calls==1 && snapshot_calls==1 && chain.steps==1 &&
        chain.releases==1 && !chain.pending && !chain.in_handler && chain_closed(slot()),"whole direct close prefix");
    check(span_transfer.progress.pc==(uintptr_t)context.uc_mcontext.gregs[REG_RIP] &&
        (uint64_t)context.uc_mcontext.gregs[REG_EFL]==flags && span_frame_equal(SIGTRAP,&signal_info,&context),
        "whole frame changes only TF");
}
static void direct_fresh_seed(void) {
    direct_seed(16,0,1,0);direct_close_good();
    observed.pc=span_transfer.progress.pc;observed.length=15;observed.page_count=1;
    observed.progress.held=1;observed.ref.sequence=32;observed.progress.sequence=32;
    observed.pages[0]=target_page;
}
static void direct_tickets(void) {
    for(unsigned cc=0;cc<=16;cc++)for(unsigned arm=0;arm<(cc==16?1U:2U);arm++) {
        unsigned bits=0;while(bits<64 && condition_true(cc,status_flags(bits))!=(arm==0))++bits;
        check(bits<64,"each condition outcome exists");direct_seed(cc,bits,1,4081);direct_close_good();++direct_closes;
        observed.pc=span_transfer.progress.pc;observed.length=15;observed.page_count=1;
        observed.progress.held=1;observed.ref.sequence=32;observed.progress.sequence=32;observed.pages[0]=target_page;
        struct li2_span_fetch_observation out;check(!span_fresh(1,&out),"actual target-bound direct fresh borrow");++direct_fresh;
        check(!consume() && !span_transfer.valid && span_transfer.progress.consumed==1 &&
            span_transfer.progress.phase==LI2_ST_CONSUMED,"actual direct consume");++direct_consumes;
    }
#define CLOSE_BAD(name,change,call,want) do {direct_seed(16,0,1,0);change;check((call)==(want),name); \
    check(!trace_calls&&!release_calls&&!ticket&&span_transfer_serial==19,"refusal before close effects");++direct_closes;}while(0)
    CLOSE_BAD("old0 crosspage refusal",(void)0,li2_tf_chain_span_close(&chain,SIGTRAP,&signal_info,&context,&ticket),LI2_ST_ORIGIN);
    CLOSE_BAD("old1 direct refusal",(void)0,li2_tf_chain_span_close_cross_page(&chain,SIGTRAP,&signal_info,&context,&ticket),LI2_ST_ORIGIN);
    CLOSE_BAD("mode2 samepage refusal",direct_seed(5,8,0,0),li2_tf_chain_span_close_direct(&chain,SIGTRAP,&signal_info,&context,&ticket),LI2_ST_ORIGIN);
    CLOSE_BAD("mode2 null out",(void)0,li2_tf_chain_span_close_direct(&chain,SIGTRAP,&signal_info,&context,0),LI2_ST_ARGUMENT);
    CLOSE_BAD("mode2 state",chain.pending=0,li2_tf_chain_span_close_direct(&chain,SIGTRAP,&signal_info,&context,&ticket),LI2_ST_STATE);
    CLOSE_BAD("mode2 wrong target",direct_target(0x600001),li2_tf_chain_span_close_direct(&chain,SIGTRAP,&signal_info,&context,&ticket),LI2_ST_ORIGIN);
    CLOSE_BAD("unknown mode",(void)0,span_close(&chain,SIGTRAP,&signal_info,&context,&ticket,3),LI2_ST_ORIGIN);
#undef CLOSE_BAD
    direct_seed(16,0,1,0);span_transfer_serial=UINT64_MAX;
    check(li2_tf_chain_span_close_direct(&chain,SIGTRAP,&signal_info,&context,&ticket)==LI2_ST_OVERFLOW &&
        !trace_calls&&!release_calls&&!ticket&&span_transfer_serial==UINT64_MAX,"mode2 overflow before effects");++direct_closes;
    for(close_injection=1;close_injection<=12;close_injection++) {
        direct_seed(16,0,1,0);fault=close_injection;
        if(!setjmp(failure)) {
            (void)li2_tf_chain_span_close_direct(&chain,SIGTRAP,&signal_info,&context,&ticket);
            check(0,"partial direct close must terminate");
        }
        unsigned want=fault<=5||fault==9?LI2_CHAIN_FRAME:fault<=7?LI2_ST_FRAME:fault==8?LI2_CHAIN_RELEASE:LI2_ST_FETCH;
        check(aborted==want&&!ticket&&!span_transfer.valid&&!span_transfer.progress.issued&&
            span_transfer.progress.phase==LI2_ST_CLOSING&&trace_calls==1,"exact direct partial failure code/prefix");
        check(release_calls==(fault<=5?0U:1U),"direct failure release frontier");++direct_closes;
    }
#define DIRECT_FRESH_BAD(name,change) do {direct_fresh_seed();change;struct li2_span_fetch_observation out; \
    check(span_fresh(1,&out)==LI2_ST_FETCH,name);++direct_fresh;}while(0)
    DIRECT_FRESH_BAD("direct target generation",observed.pages[0].generation++);
    DIRECT_FRESH_BAD("direct predecessor page",observed.pages[0]=slot()->fetch.pages[0]);
    DIRECT_FRESH_BAD("direct actual continuation query",slot()->query.page.allocation++);
    DIRECT_FRESH_BAD("direct stale fresh borrow",observed.ref.sequence=31);
#undef DIRECT_FRESH_BAD
    direct_fresh_seed();check(!consume()&&consume()==LI2_ST_ORIGIN,"direct consumption single use");direct_consumes+=2;
#define DIRECT_CONSUME_BAD(name,change,want) do {direct_fresh_seed();change;check(consume()==(want),name); \
    check(!span_transfer.progress.consumed,"failed direct consume stays unconsumed");++direct_consumes;}while(0)
    DIRECT_CONSUME_BAD("direct closed GPR changed",context.uc_mcontext.gregs[REG_R15]++,LI2_ST_FRAME);
    DIRECT_CONSUME_BAD("direct transfer serial changed",span_transfer_serial++,LI2_ST_ORIGIN);
    DIRECT_CONSUME_BAD("direct predecessor unreleased",slot()->fetch.progress.held=1,LI2_ST_ORIGIN);
    DIRECT_CONSUME_BAD("direct fresh borrow stale",observed.ref.sequence=31,LI2_ST_FETCH);
#undef DIRECT_CONSUME_BAD
}
int main(void) {
    check(!inherited_cross_page_main(),"all original216 controls remain active");
    direct_matrix();direct_negative();direct_tickets();
    check(direct_forms==4420&&direct_accepted==3396&&direct_refusals==366&&direct_closes==53&&
        direct_fresh==37&&direct_consumes==39,"literal complete additive populations");
    puts("cold_direct_handoff forms=4420 accepted=3396 refusals=366 close=53 fresh=37 consume=39 supplied_observations=1 native_credit=0");
    return 0;
}
