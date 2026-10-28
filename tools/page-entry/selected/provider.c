#include "provider.h"
#define TF (UINT64_C(1)<<8)
#define RF (UINT64_C(1)<<16)
#define ARITHMETIC (UINT64_C(1)|(UINT64_C(1)<<2)|(UINT64_C(1)<<4)|(UINT64_C(1)<<6)|(UINT64_C(1)<<7)|(UINT64_C(1)<<11))

static void cpuid(uint32_t leaf,uint32_t subleaf,uint32_t out[4]) {
    uint32_t a=leaf,b,c=subleaf,d;
    __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d)::"memory");
    out[0]=a;out[1]=b;out[2]=c;out[3]=d;
}
int li2_selected_observe_hardware(struct li2_selected_hardware *out) {
    if(!out) return LI2_SELECTED_ARGUMENT;
    *out=(struct li2_selected_hardware){.abi_version=1};
    cpuid(0,0,out->leaf0);
    if(out->leaf0[0]>=1) cpuid(1,0,out->leaf1);
    if(out->leaf0[0]>=7) cpuid(7,0,out->leaf7);
    return LI2_SELECTED_OK;
}
static int destination(uint32_t reg) {
    switch(reg) {
    case 0:return REG_RAX;case 1:return REG_RCX;case 2:return REG_RDX;case 3:return REG_RBX;
    case 5:return REG_RBP;case 6:return REG_RSI;case 7:return REG_RDI;
    case 8:return REG_R8;case 9:return REG_R9;case 10:return REG_R10;case 11:return REG_R11;
    case 12:return REG_R12;case 13:return REG_R13;case 14:return REG_R14;case 15:return REG_R15;
    default:return -1;
    }
}
static int equal_decoded(const struct li2_decoded *a,const struct li2_decoded *b) {
    if(a->pc!=b->pc || a->next_pc!=b->next_pc || a->abi_version!=b->abi_version
       || a->decode_status!=b->decode_status || a->code!=b->code || a->kind!=b->kind
       || a->destination!=b->destination || a->width_bits!=b->width_bits
       || a->step_disposition!=b->step_disposition || a->available!=b->available
       || a->length!=b->length || a->reserved!=b->reserved) return 0;
    for(size_t i=0;i<sizeof a->bytes;i++) if(a->bytes[i]!=b->bytes[i]) return 0;
    return 1;
}
static int refuse(struct li2_selected_completion *out,int status) {
    out->status=(uint32_t)status;return status;
}
static int prepare(ucontext_t *frame,const struct li2_selected_request *request,
                   struct li2_selected_completion *out,uint32_t mechanism) {
    if(!out) return LI2_SELECTED_ARGUMENT;
    *out=(struct li2_selected_completion){.abi_version=1,.mechanism=mechanism};
    if(!frame || !request || !request->decoded || !request->source
       || !request->source_bytes || request->source_bytes>15
       || (uintptr_t)request->source>UINTPTR_MAX-request->source_bytes)
        return refuse(out,LI2_SELECTED_ARGUMENT);
    const struct li2_decoded *d=request->decoded;
    out->kind=d->kind;out->destination=d->destination;out->width_bits=d->width_bits;
    out->pc=d->pc;out->next_pc=d->next_pc;
    greg_t *g=frame->uc_mcontext.gregs;
    out->frame_flags=(uint64_t)g[REG_EFL];out->logical_flags=request->logical_flags;
    if(!(request->logical_flags&2) || (request->logical_flags&(TF|RF)))
        return refuse(out,LI2_SELECTED_FLAGS);
    if((uint64_t)g[REG_RIP]!=d->pc) return refuse(out,LI2_SELECTED_FRAME);
    if(d->abi_version!=1 || d->decode_status!=LI2_VALID || d->available!=request->source_bytes
       || !d->length || d->length>d->available || d->pc>UINT64_MAX-d->length
       || d->next_pc!=d->pc+d->length || d->reserved)
        return refuse(out,LI2_SELECTED_FACTS);
    if(request->origin==LI2_SELECTED_ORIGINAL_CONTEXT) {
        if(request->fault || out->frame_flags!=request->logical_flags)
            return refuse(out,LI2_SELECTED_FRAME);
    } else if(request->origin==LI2_SELECTED_NX_KNOWN_INPUT) {
        const siginfo_t *si=request->fault;
        if(!si || si->si_signo!=SIGSEGV || si->si_code!=SEGV_ACCERR
           || g[REG_TRAPNO]!=14 || g[REG_ERR]!=0x15
           || ((uint64_t)g[REG_CSGSFS]&3)!=3
           || (uintptr_t)si->si_addr<d->pc || (uintptr_t)si->si_addr>=d->next_pc
           || out->frame_flags!=(request->logical_flags|RF))
            return refuse(out,LI2_SELECTED_FRAME);
    } else return refuse(out,LI2_SELECTED_FRAME);
    struct li2_decoded actual;
    if(li2_decoder_decode(d->pc,request->source,request->source_bytes,&actual)!=LI2_OK)
        return refuse(out,LI2_SELECTED_DECODE);
    if(!equal_decoded(d,&actual)) return refuse(out,LI2_SELECTED_FACTS);
    if(d->kind!=LI2_RDRAND && d->kind!=LI2_RDSEED && d->kind!=LI2_RDPID)
        return refuse(out,LI2_SELECTED_KIND);
    if(d->destination==4) return refuse(out,LI2_SELECTED_RSP);
    int slot=destination(d->destination);
    if(slot<0 || (d->width_bits!=16 && d->width_bits!=32 && d->width_bits!=64)
       || (d->kind==LI2_RDPID && d->width_bits!=64) || d->step_disposition!=LI2_STEP_SELECTED)
        return refuse(out,LI2_SELECTED_FACTS);
    out->input_destination=(uint64_t)g[slot];out->phase=LI2_SELECTED_VALIDATED;
    return LI2_SELECTED_OK;
}
static int outcome_ok(const struct li2_selected_completion *out,uint64_t value,uint32_t carry) {
    if(carry>1) return 0;
    if(out->kind==LI2_RDPID) return out->width_bits==64 && !carry && value<=UINT32_MAX;
    uint64_t maximum=out->width_bits==16?UINT16_MAX:out->width_bits==32?UINT32_MAX:UINT64_MAX;
    return value<=maximum && (carry || value==0);
}
static void commit(ucontext_t *frame,struct li2_selected_completion *out,uint64_t value,uint32_t carry) {
    out->value=value;out->carry=carry;out->phase=LI2_SELECTED_OUTCOME_RETAINED;
    out->output_destination=out->width_bits==16?(out->input_destination&~UINT64_C(0xffff))|value:value;
    /* RF belongs to the successful instruction-completion transition; the
       known logical boundary is TF/RF-clear. No other input bit is masked. */
    out->output_flags=out->logical_flags&~RF;
    if(out->kind!=LI2_RDPID) out->output_flags=(out->output_flags&~ARITHMETIC)|carry;
    greg_t *g=frame->uc_mcontext.gregs;
    g[destination(out->destination)]=(greg_t)out->output_destination;
    g[REG_EFL]=(greg_t)out->output_flags;g[REG_RIP]=(greg_t)out->next_pc;
    out->status=LI2_SELECTED_OK;
    __asm__ volatile("":::"memory");
    out->phase=LI2_SELECTED_COMPLETED;
}
static int hardware_supports(const struct li2_selected_hardware *h,uint32_t kind) {
    if(!h || h->abi_version!=1 || h->reserved) return 0;
    if(kind==LI2_RDRAND) return h->leaf0[0]>=1 && (h->leaf1[2]&(UINT32_C(1)<<30));
    if(kind==LI2_RDSEED) return h->leaf0[0]>=7 && (h->leaf7[1]&(UINT32_C(1)<<18));
    if(kind==LI2_RDPID) return h->leaf0[0]>=7 && (h->leaf7[2]&(UINT32_C(1)<<22));
    return 0;
}
static uint64_t native_random(uint32_t kind,uint32_t width,uint32_t *carry) {
    unsigned char c;uint64_t result;
    if(width==16) {
        uint16_t v;
        if(kind==LI2_RDRAND) __asm__ volatile("rdrand %w0; setc %1":"=&r"(v),"=&q"(c)::"cc","memory");
        else __asm__ volatile("rdseed %w0; setc %1":"=&r"(v),"=&q"(c)::"cc","memory");
        result=v;
    } else if(width==32) {
        uint32_t v;
        if(kind==LI2_RDRAND) __asm__ volatile("rdrand %k0; setc %1":"=&r"(v),"=&q"(c)::"cc","memory");
        else __asm__ volatile("rdseed %k0; setc %1":"=&r"(v),"=&q"(c)::"cc","memory");
        result=v;
    } else {
        uint64_t v;
        if(kind==LI2_RDRAND) __asm__ volatile("rdrand %0; setc %1":"=&r"(v),"=&q"(c)::"cc","memory");
        else __asm__ volatile("rdseed %0; setc %1":"=&r"(v),"=&q"(c)::"cc","memory");
        result=v;
    }
    *carry=c;return result;
}
int li2_selected_complete_native(ucontext_t *frame,const struct li2_selected_request *request,
    const struct li2_selected_hardware *hardware,struct li2_selected_completion *out) {
    int status=prepare(frame,request,out,LI2_SELECTED_NATIVE);if(status) return status;
    if(!hardware_supports(hardware,out->kind)) return refuse(out,LI2_SELECTED_HARDWARE);
    uint64_t value;uint32_t carry=0;
    /* The single instruction is next. Its memory clobber also orders this
       retained attempted prefix before a possible real hardware exception. */
    out->native_attempts=1;out->phase=LI2_SELECTED_NATIVE_ENTERED;
    if(out->kind==LI2_RDPID) __asm__ volatile("rdpid %0":"=r"(value)::"memory");
    else value=native_random(out->kind,out->width_bits,&carry);
    out->value=value;out->carry=carry;out->phase=LI2_SELECTED_OUTCOME_RETAINED;
    if(!outcome_ok(out,value,carry)) return refuse(out,LI2_SELECTED_NATIVE_RESULT);
    commit(frame,out,value,carry);return LI2_SELECTED_OK;
}
int li2_selected_complete_scripted(ucontext_t *frame,const struct li2_selected_request *request,
    const struct li2_selected_script *script,struct li2_selected_completion *out) {
    int status=prepare(frame,request,out,LI2_SELECTED_SCRIPTED);if(status) return status;
    if(!script || script->reserved || script->kind!=out->kind || script->width_bits!=out->width_bits
       || !outcome_ok(out,script->value,script->carry)) return refuse(out,LI2_SELECTED_SCRIPT);
    commit(frame,out,script->value,script->carry);return LI2_SELECTED_OK;
}

#include "provider_callback.h"
int li2_selected_complete_callback(ucontext_t *frame,const struct li2_selected_request *request,
    li2_selected_callback callback,struct li2_selected_callback_progress *progress,
    struct li2_selected_completion *out) {
    if(progress)*progress=(struct li2_selected_callback_progress){.abi_version=1};
    int status=prepare(frame,request,out,LI2_SELECTED_SCRIPTED);
    if(status) {if(progress)progress->first_error=(uint32_t)status;return status;}
    if(!callback || !progress) {
        if(progress)progress->first_error=LI2_SELECTED_ARGUMENT;
        return refuse(out,LI2_SELECTED_ARGUMENT);
    }
    progress->input=(struct li2_selected_callback_input){1,out->kind,out->width_bits,
        out->destination,out->pc,out->next_pc,out->logical_flags,out->input_destination};
    __asm__ volatile("":::"memory");progress->entered=1;
    __asm__ volatile("":::"memory");
    progress->callback_status=callback(&progress->input,&progress->script);
    __asm__ volatile("":::"memory");progress->returned=1;
    __asm__ volatile("":::"memory");
    const struct li2_selected_script *script=&progress->script;
    if(progress->callback_status || script->reserved || script->kind!=out->kind ||
       script->width_bits!=out->width_bits || !outcome_ok(out,script->value,script->carry)) {
        progress->first_error=LI2_SELECTED_SCRIPT;
        return refuse(out,LI2_SELECTED_SCRIPT);
    }
    commit(frame,out,script->value,script->carry);
    __asm__ volatile("":::"memory");progress->committed=1;
    return LI2_SELECTED_OK;
}
