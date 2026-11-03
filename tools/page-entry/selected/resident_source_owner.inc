/* Actual controller callback. No externally supplied close count, token,
   generation, or phase can satisfy this predicate. */
int li2_rsl_owner_quiet(void) {
    if(!handling || pe_busy || pe_active || pe.resuming || !pe.initialized ||
       !pe.registered || !ptr_storage() || selected_step_pending ||
       selected_pending_route!=SELECTED_NO_STEP || pe.p.first_error ||
       (pe.p.phase!=LI2_PG_IDLE && pe.p.phase!=LI2_PG_CLOSED && pe.p.phase!=LI2_PG_CANCELLED))return 0;
#ifdef LI2_PERSISTENT_RET_DISPATCH
    if(prr_pending || prr_busy || (prr.run.loaded.complete && !prr.run.consumed))return 0;
#endif
#ifdef LI2_RESIDENT_RX
    if(!li2_r3_rx_execution_quiet())return 0;
#elif defined(LI2_RESIDENT_THREE)
    if(!li2_r3_owner_quiet())return 0;
#endif
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
        const struct li2_ptr_slot *slot=&pe.retained[i];
        if(slot->generation.installed && !pda_permitted(i))return 0;
        for(unsigned j=0;j<2;j++) {
            const struct ped_bank *bank=&slot->banks[j];
            struct li2_private_code_query observed[3]={{0}};
            int prot=bank->virgin?(PROT_READ|PROT_WRITE):PROT_READ;
            if(bank->prot!=prot || pg_queries(&bank->layout,prot,observed))return 0;
        }
    }
    return 1;
}

#ifdef LI2_RESIDENT_STABLE_GENERATION
/* Only the genuine one-shot transfer's released-fetch seam uses this exact
   route predicate. Every actual old/new generated-storage query is retained. */
/* Actual controller callback. No externally supplied close count, token,
   generation, or phase can satisfy this predicate. */
int li2_rsl_source_mutation_quiet(void) {
    if(!handling || pe_busy || pe_active || pe.resuming || !pe.initialized ||
       !pe.registered || !ptr_storage() || !selected_step_pending ||
       selected_pending_route!=SELECTED_ONESHOT ||
       selected_oneshot_active!=&selected_oneshot_current || pe.p.first_error ||
       (pe.p.phase!=LI2_PG_IDLE && pe.p.phase!=LI2_PG_CLOSED && pe.p.phase!=LI2_PG_CANCELLED))return 0;
#ifdef LI2_PERSISTENT_RET_DISPATCH
    if(prr_pending || prr_busy || (prr.run.loaded.complete && !prr.run.consumed))return 0;
#endif
#ifdef LI2_RESIDENT_RX
    if(!li2_r3_rx_execution_quiet())return 0;
#elif defined(LI2_RESIDENT_THREE)
    if(!li2_r3_owner_quiet())return 0;
#endif
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++) {
        const struct li2_ptr_slot *slot=&pe.retained[i];
        if(slot->generation.installed && !pda_permitted(i))return 0;
        for(unsigned j=0;j<2;j++) {
            const struct ped_bank *bank=&slot->banks[j];
            struct li2_private_code_query observed[3]={{0}};
            int prot=bank->virgin?(PROT_READ|PROT_WRITE):PROT_READ;
            if(bank->prot!=prot || pg_queries(&bank->layout,prot,observed))return 0;
        }
    }
    return 1;
}
#endif
#ifdef LI2_RESIDENT_SOURCE_PROBE
void li2_rso_owner(uint64_t out[16],struct li2_private_code_query queries[12]) {
    const uint64_t v[]={pe.initialized,pe.p.phase,pe_busy,pe_active,pe.resuming,
        selected_pending_route,selected_step_pending,prr_pending,prr_busy,
        prr.run.loaded.complete,prr.run.consumed,prr.run.phase,prr.last_consumed,
        pe.p.serial,pe.domain.work.bound,pe.domain.work.completion};
    copy(out,v,sizeof v);
    if(queries)for(unsigned i=0;i<LI2_PTR_SLOTS;i++)for(unsigned j=0;j<2;j++) {
        const struct ped_bank *bank=&pe.retained[i].banks[j];
        pe_need(!pg_queries(&bank->layout,(int)bank->prot,queries+3*(2*i+j)),PE_STATE,180);
    }
}
#endif
