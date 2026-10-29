#include "selected_effect.h"
#include <stdatomic.h>

#define TF UINT64_C(0x100)
#define RF UINT64_C(0x10000)
#define ARITHMETIC UINT64_C(0x8d5)

const struct li2_effect_binding li2_effect_native_binding={.abi_version=LI2_EFFECT_ABI};
static void fence(void) { atomic_signal_fence(memory_order_seq_cst); }
static int zero(const void *p,size_t n) {
    const unsigned char *a=p;
    for(size_t i=0;i<n;i++)if(a[i])return 0;
    return 1;
}
static int same(const void *p,const void *q,size_t n) {
    const unsigned char *a=p,*b=q;
    for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;
    return 1;
}
static int xstate_ok(const struct li2_effect_xstate *x) {
    if(x->reserved)return 0;
    if(!x->bytes)return !x->length && !x->format;
    return x->length>=512 && x->length<=LI2_EFFECT_XSTATE_MAX && x->format &&
        (uintptr_t)x->bytes<=UINTPTR_MAX-x->length;
}
static int selectors_ok(const struct li2_effect_state *s) {
    if(s->selectors_observed&~UINT16_C(0x3f))return 0;
    for(unsigned i=0;i<6;i++)
        if(!(s->selectors_observed&(1U<<i)) && s->selectors[i])return 0;
    return 1;
}
static int random_kind(unsigned kind) {
    return kind==LI2_RDRAND || kind==LI2_RDSEED || kind==LI2_RDPID;
}
static int exit_call(const struct li2_effect_input *in) {
    return in->decoded.kind==LI2_SYSCALL &&
        (in->before.gpr[LI2_EFFECT_RAX]==60 || in->before.gpr[LI2_EFFECT_RAX]==231);
}
int li2_effect_validate_input(const struct li2_effect_input *in) {
    if(!in || in->abi_version!=LI2_EFFECT_ABI || !in->sequence)return LI2_EFFECT_ARGUMENT;
    const struct li2_decoded *d=&in->decoded;
    if(d->abi_version!=1 || d->decode_status!=LI2_VALID || d->reserved ||
       d->kind<LI2_CPUID || d->kind>LI2_SYSCALL || !d->available || d->available>15 ||
       !d->length || d->length>d->available || d->pc>UINT64_MAX-d->available ||
       d->next_pc!=d->pc+d->length || !zero(d->bytes+d->available,16-d->available) ||
       in->before.pc!=d->pc || !(in->before.logical_flags&2) ||
       (in->before.logical_flags&(TF|RF)) || in->before.reserved || !selectors_ok(&in->before) ||
       !xstate_ok(&in->before.xstate))return LI2_EFFECT_ARGUMENT;
    if(random_kind(d->kind)) {
        if(d->destination>=16 || d->destination==LI2_EFFECT_RSP ||
           (d->width_bits!=16 && d->width_bits!=32 && d->width_bits!=64) ||
           (d->kind==LI2_RDPID && d->width_bits!=64) ||
           d->step_disposition!=LI2_STEP_SELECTED)return LI2_EFFECT_ARGUMENT;
    } else if(d->destination!=16 || d->width_bits ||
        d->step_disposition!=(d->kind==LI2_SYSCALL?LI2_STEP_KERNEL_TRANSFER:LI2_STEP_SELECTED))
        return LI2_EFFECT_ARGUMENT;
    uint64_t first=d->pc&~(LI2_EFFECT_PAGE-1);
    uint64_t last=(d->pc+d->available-1)&~(LI2_EFFECT_PAGE-1);
    unsigned count=first==last?1:2;
    if(in->source_count!=count)return LI2_EFFECT_ARGUMENT;
    for(unsigned i=0;i<count;i++) {
        const struct li2_effect_source *p=&in->source[i];
        if(p->page!=first+i*LI2_EFFECT_PAGE || p->page>UINT64_MAX-LI2_EFFECT_PAGE ||
           p->reserved || !((p->backing==1 && p->object_id) || (p->backing==2 && !p->object_id)) ||
           !p->allocation || !p->generation || (p->offset&(LI2_EFFECT_PAGE-1)) ||
           p->offset>UINT64_MAX-LI2_EFFECT_PAGE)return LI2_EFFECT_ARGUMENT;
    }
    if(count==1 && !zero(&in->source[1],sizeof(in->source[1])))return LI2_EFFECT_ARGUMENT;
    struct li2_decoded actual;
    if(li2_decoder_decode(d->pc,d->bytes,d->available,&actual)!=LI2_OK ||
       !same(d,&actual,sizeof(actual)))return LI2_EFFECT_DECODE;
    return LI2_EFFECT_OK;
}
static int result_ok(const struct li2_effect_input *in,const struct li2_effect_result *r) {
    const struct li2_decoded *d=&in->decoded;
    if(r->kind!=d->kind || r->reserved)return 0;
    if(d->kind==LI2_CPUID)return !r->value && !r->carry && !r->aux;
    if(!zero(r->cpuid,sizeof(r->cpuid)))return 0;
    if(d->kind==LI2_RDTSC || d->kind==LI2_RDTSCP)
        return !r->carry && (d->kind==LI2_RDTSCP || !r->aux);
    if(d->kind==LI2_SYSCALL)return !r->carry && !r->aux;
    if(r->aux || r->carry>1)return 0;
    if(d->kind==LI2_RDPID)return !r->carry && r->value<=UINT32_MAX;
    uint64_t maximum=d->width_bits==16?UINT16_MAX:d->width_bits==32?UINT32_MAX:UINT64_MAX;
    return r->value<=maximum && (r->carry || !r->value);
}
static int decision_ok(const struct li2_effect_input *in,const struct li2_effect_decision *d) {
    if(d->reserved)return 0;
    if(d->action==LI2_EFFECT_UNCOMPLETED)
        return zero(&d->result,sizeof(d->result)) && d->fault.code &&
            (d->fault.origin==LI2_EFFECT_REFUSAL || d->fault.origin==LI2_EFFECT_PROVIDER_FAULT);
    if(!zero(&d->fault,sizeof(d->fault)))return 0;
    if(d->action==LI2_EFFECT_NATIVE)return zero(&d->result,sizeof(d->result));
    if(d->action!=LI2_EFFECT_SCRIPTED || !result_ok(in,&d->result))return 0;
    /* No synthetic memory/kernel/lifecycle effect. Native retains the complete
       existing dispatcher; the initial replacement seam is scalar identity. */
    return in->decoded.kind!=LI2_SYSCALL ||
        in->before.gpr[LI2_EFFECT_RAX]==39 || in->before.gpr[LI2_EFFECT_RAX]==186;
}
int li2_effect_fail(struct li2_effect_owner *o,unsigned error) {
    if(!o)return LI2_EFFECT_ARGUMENT;
    if(!o->first_error)o->first_error=error?error:LI2_EFFECT_STATE;
    fence();o->phase=LI2_EFFECT_FAILED;fence();return (int)o->first_error;
}
int li2_effect_begin(struct li2_effect_owner *o,const struct li2_effect_binding *binding,
                     const struct li2_effect_input *in) {
    if(!o || !binding || !in)return LI2_EFFECT_ARGUMENT;
    if(o->phase==LI2_EFFECT_EMPTY) {
        if(!zero(o,sizeof(*o)))return LI2_EFFECT_STATE;
    } else if((o->phase!=LI2_EFFECT_COMMITTED && o->phase!=LI2_EFFECT_REJECTED) ||
              o->first_error || in->sequence<=o->input.sequence)return LI2_EFFECT_STATE;
    if(binding->abi_version!=LI2_EFFECT_ABI || binding->reserved ||
       (!binding->callback && !binding->post_native && binding->context))return LI2_EFFECT_ARGUMENT;
    int status=li2_effect_validate_input(in);if(status)return status;
    *o=(struct li2_effect_owner){.input=*in,.binding=*binding,
        .decision={.action=LI2_EFFECT_NATIVE}};
    if(binding->callback) {
        o->callback_entered=1;fence();o->phase=LI2_EFFECT_CALLBACK_ENTERED;fence();
        o->callback_status=o->binding.callback(&o->input,o->binding.context,&o->decision);
        fence();o->callback_returned=1;fence();
        if(o->callback_status)return li2_effect_fail(o,LI2_EFFECT_CALLBACK);
    }
    if(!decision_ok(&o->input,&o->decision))return li2_effect_fail(o,LI2_EFFECT_RESULT);
    if(o->decision.action==LI2_EFFECT_UNCOMPLETED) {
        o->fault=o->decision.fault;fence();o->phase=LI2_EFFECT_REJECTED;fence();
        return LI2_EFFECT_NOT_COMPLETED;
    }
    fence();o->phase=LI2_EFFECT_DECIDED;fence();return LI2_EFFECT_OK;
}
static int phase(const struct li2_effect_owner *o,unsigned wanted) {
    return o && !o->first_error && o->phase==(sig_atomic_t)wanted;
}
int li2_effect_guarded(struct li2_effect_owner *o) {
    if(!phase(o,LI2_EFFECT_DECIDED))return li2_effect_fail(o,LI2_EFFECT_STATE);
    fence();o->phase=LI2_EFFECT_GUARDED;fence();return LI2_EFFECT_OK;
}
int li2_effect_native_enter(struct li2_effect_owner *o) {
    if(!phase(o,LI2_EFFECT_GUARDED) || o->decision.action!=LI2_EFFECT_NATIVE)
        return li2_effect_fail(o,LI2_EFFECT_STATE);
    o->native_entered=1;
    if(exit_call(&o->input))o->exit_entered=1;
    fence();o->phase=o->exit_entered?LI2_EFFECT_EXIT_ENTERED:LI2_EFFECT_NATIVE_ENTERED;
    fence();return LI2_EFFECT_OK;
}
int li2_effect_native_return(struct li2_effect_owner *o,const struct li2_effect_result *r) {
    if(!o || !r)return LI2_EFFECT_ARGUMENT;
    if((!phase(o,LI2_EFFECT_NATIVE_ENTERED) && !phase(o,LI2_EFFECT_EXIT_ENTERED)) ||
       !o->native_entered || o->native_returned || o->decision.action!=LI2_EFFECT_NATIVE)
        return li2_effect_fail(o,LI2_EFFECT_STATE);
    /* Retain the actual return even when its class/result or the later runtime
       post-effect guard fails. Never turn it into an unattempted operation. */
    o->native_result=*r;fence();o->native_returned=1;fence();
    if(o->exit_entered || !result_ok(&o->input,r))return li2_effect_fail(o,LI2_EFFECT_RESULT);
    o->phase=LI2_EFFECT_NATIVE_RETURNED;fence();return LI2_EFFECT_OK;
}
int li2_effect_native_outcome(struct li2_effect_owner *o) {
    if(!phase(o,LI2_EFFECT_NATIVE_RETURNED) || !o->native_entered || !o->native_returned ||
       o->exit_entered || o->decision.action!=LI2_EFFECT_NATIVE || o->post_guards_complete)
        return li2_effect_fail(o,LI2_EFFECT_STATE);
    /* This boundary belongs after the existing backend-specific postguards.
       Keep the actual return immutable even if provider processing now fails. */
    o->post_guards_complete=1;o->result=o->native_result;fence();
    if(o->binding.post_native) {
        o->post_callback_entered=1;fence();o->phase=LI2_EFFECT_POST_CALLBACK_ENTERED;fence();
        o->post_callback_status=o->binding.post_native(&o->input,&o->native_result,
                                                       o->binding.context,&o->result);
        fence();o->post_callback_returned=1;fence();
        if(o->post_callback_status)return li2_effect_fail(o,LI2_EFFECT_CALLBACK);
    }
    if(!result_ok(&o->input,&o->result) ||
       (o->input.decoded.kind==LI2_SYSCALL && o->input.before.gpr[LI2_EFFECT_RAX]!=39 &&
        o->input.before.gpr[LI2_EFFECT_RAX]!=186 &&
        !same(&o->result,&o->native_result,sizeof(o->result))))
        return li2_effect_fail(o,LI2_EFFECT_RESULT);
    o->phase=LI2_EFFECT_OUTCOME;fence();return LI2_EFFECT_OK;
}
int li2_effect_scripted_outcome(struct li2_effect_owner *o) {
    if(!phase(o,LI2_EFFECT_GUARDED) || o->decision.action!=LI2_EFFECT_SCRIPTED ||
       !decision_ok(&o->input,&o->decision))return li2_effect_fail(o,LI2_EFFECT_STATE);
    o->result=o->decision.result;fence();o->phase=LI2_EFFECT_OUTCOME;fence();
    return LI2_EFFECT_OK;
}
int li2_effect_expected(const struct li2_effect_owner *o,struct li2_effect_state *out) {
    if(!out || !phase(o,LI2_EFFECT_OUTCOME) || !result_ok(&o->input,&o->result))
        return LI2_EFFECT_STATE;
    *out=o->input.before;out->pc=o->input.decoded.next_pc;
    const struct li2_effect_result *r=&o->result;
    unsigned kind=r->kind;
    if(kind==LI2_CPUID) {
        out->gpr[LI2_EFFECT_RAX]=r->cpuid[0];out->gpr[LI2_EFFECT_RBX]=r->cpuid[1];
        out->gpr[LI2_EFFECT_RCX]=r->cpuid[2];out->gpr[LI2_EFFECT_RDX]=r->cpuid[3];
    } else if(kind==LI2_RDTSC || kind==LI2_RDTSCP) {
        out->gpr[LI2_EFFECT_RAX]=(uint32_t)r->value;
        out->gpr[LI2_EFFECT_RDX]=(uint32_t)(r->value>>32);
        if(kind==LI2_RDTSCP)out->gpr[LI2_EFFECT_RCX]=r->aux;
    } else if(kind==LI2_SYSCALL) {
        out->gpr[LI2_EFFECT_RAX]=r->value;out->gpr[LI2_EFFECT_RCX]=out->pc;
        out->gpr[LI2_EFFECT_R11]=out->logical_flags;
    } else {
        unsigned dest=o->input.decoded.destination,width=o->input.decoded.width_bits;
        out->gpr[dest]=width==16?(out->gpr[dest]&~UINT64_C(0xffff))|r->value:r->value;
        if(kind!=LI2_RDPID)out->logical_flags=(out->logical_flags&~ARITHMETIC)|r->carry;
    }
    return LI2_EFFECT_OK;
}
int li2_effect_commit(struct li2_effect_owner *o,const struct li2_effect_state *actual) {
    struct li2_effect_state expected;
    if(!actual || li2_effect_expected(o,&expected))return li2_effect_fail(o,LI2_EFFECT_STATE);
    if(actual->reserved || !selectors_ok(actual) || !xstate_ok(&actual->xstate) || actual->pc!=expected.pc ||
       actual->logical_flags!=expected.logical_flags ||
       !same(actual->gpr,expected.gpr,sizeof(actual->gpr)) ||
       !same(actual->selectors,expected.selectors,sizeof(actual->selectors)) ||
       actual->selectors_observed!=expected.selectors_observed ||
       actual->xstate.length!=expected.xstate.length || actual->xstate.format!=expected.xstate.format ||
       (expected.xstate.length &&
        (uintptr_t)actual->xstate.bytes<(uintptr_t)expected.xstate.bytes+expected.xstate.length &&
        (uintptr_t)expected.xstate.bytes<(uintptr_t)actual->xstate.bytes+actual->xstate.length) ||
       (expected.xstate.length && !same(actual->xstate.bytes,expected.xstate.bytes,expected.xstate.length)))
        return li2_effect_fail(o,LI2_EFFECT_COMMIT);
    o->committed=1;fence();o->phase=LI2_EFFECT_COMMITTED;fence();return LI2_EFFECT_OK;
}
int li2_effect_native_fault(struct li2_effect_owner *o,const struct li2_effect_fault *fault) {
    if(!o || !fault)return LI2_EFFECT_ARGUMENT;
    if((!phase(o,LI2_EFFECT_NATIVE_ENTERED) && !phase(o,LI2_EFFECT_EXIT_ENTERED)) ||
       !o->native_entered || o->native_returned || fault->origin!=LI2_EFFECT_NATIVE_FAULT ||
       !fault->code || fault->code>64)return li2_effect_fail(o,LI2_EFFECT_STATE);
    o->fault=*fault;fence();return li2_effect_fail(o,LI2_EFFECT_NOT_COMPLETED);
}
int li2_effect_script_callback(const struct li2_effect_input *in,void *context,
                               struct li2_effect_decision *out) {
    const struct li2_effect_script *script=context;
    if(!in || !out || !script || script->abi_version!=LI2_EFFECT_ABI ||
       script->count>LI2_EFFECT_SCRIPT_MAX || (!script->entries && script->count))
        return LI2_EFFECT_ARGUMENT;
    *out=(struct li2_effect_decision){.action=LI2_EFFECT_NATIVE};
    for(unsigned i=0;i<script->count;i++) {
        const struct li2_effect_script_entry *e=&script->entries[i];
        if(!e->pc || e->reserved || e->kind<LI2_CPUID || e->kind>LI2_SYSCALL)
            return LI2_EFFECT_ARGUMENT;
        for(unsigned j=0;j<i;j++)if(script->entries[j].pc==e->pc)
            return LI2_EFFECT_ARGUMENT;
        if(e->pc==in->decoded.pc) {
            if(e->kind!=in->decoded.kind || !decision_ok(in,&e->decision))return LI2_EFFECT_RESULT;
            *out=e->decision;
        }
    }
    return LI2_EFFECT_OK;
}
