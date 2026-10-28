/* Literal checks are additive to the unchanged full three-lane comparator. */
static void short_inputs(void) {
    need(case_id==12||case_id==13,1301);vpb_seed();
    for(unsigned j=0;j<64;j++) {
        unsigned char x=(unsigned char)(j*13+7);
        vpb_vectors[17][j]=x;vpb_vectors[16][j]=(j==7||j==20)?x:(unsigned char)(x^0xa5);
    }
    vpb_masks[1]=UINT64_C(0xfedcba9876543210);
    fixture_seed[0]=UINT64_C(0x8877665544332211);
    fixture_seed[6]=case_id==12?UINT64_C(1)<<12:UINT64_C(1)<<3;
    fixture_seed[7]=data_page+256;
    memcpy((void *)fixture_seed[4],&li2_chain_record.stop,8);
}
static void short_fp(const unsigned char *before,const unsigned char *after,size_t n,int kernel) {
    vpb_inputs_observed(before,n,kernel);
    need(vpb_header(before,n,kernel)==vpb_header(after,n,kernel),1302);
    uint64_t equality=0;for(unsigned j=0;j<64;j++)
        if(before[vpb_offset(17,j)]==before[vpb_offset(16,j)])equality|=UINT64_C(1)<<j;
    need(equality==UINT64_C(0x100080)&&word(before+vpb_observations.component[5].b+8)!=equality,1303);
    size_t at=vpb_observations.component[5].b+8;
    for(size_t i=0;i<n;i++) {
        unsigned char expected=before[i];
        if(i>=at&&i<at+8)expected=(unsigned char)(equality>>(8*(i-at)));
        need(after[i]==expected,1304);
    }
}
static void short_effects(void) {
    need(vpb_observations.checked==0,1305);
    uint64_t result_mask=case_id==12?UINT64_C(0x1fff):UINT64_C(0xf);
    uint64_t result_rax=case_id==12?fixture_seed[7]+7:0;
    static const unsigned char code[]={0x62,0xb1,0x75,0x40,0x74,0xc8,0xc4,0xe1,0xfb,0x93,0xc1,
        0xc4,0xe2,0xc8,0xf3,0xd6,0x48,0x21,0xf0,0x74,0x07,0x48,0x0f,0xbd,0xc0,0x48,0x01,0xf8,0xc3};
    need(!memcmp(li2_chain_record.source+chain_cases[case_id].offset,code,sizeof code),1306);
    for(unsigned n=0;n<3;n++) {
        const struct chain_lane *l=&li2_chain_record.lanes[n];
        need(l->nx==(n==1?chain_cases[case_id].instructions+1:2)&&
            l->traces==(n?chain_cases[case_id].instructions:0),1307);
        for(unsigned r=0;r<16;r++) {
            uint64_t expected=fixture_seed[r];
            if(r==0)expected=result_rax;else if(r==4)expected+=8;else if(r==6)expected=result_mask;
            need((uint64_t)l->before.frame.greg[regs[r]]==fixture_seed[r]&&
                (uint64_t)l->after.frame.greg[regs[r]]==expected&&l->live[1].gpr[r]==expected,1308);
        }
        need(word(l->before.stack+SUBJECT_BYTES/2)==li2_chain_record.stop&&
             word(l->after.stack+SUBJECT_BYTES/2)==li2_chain_record.stop,1309);
        compare_memory(&l->before,&l->after,1310);
        short_fp(l->before.frame.fp,l->after.frame.fp,l->before.frame.fp_bytes,1);
        short_fp(l->fp[0],l->fp[1],xsave_bytes,0);
        if(case_id==13)need((l->flags&UINT64_C(0x8c5))==UINT64_C(0x44),1311);
        unsigned seen=0;
        for(unsigned j=0;j<l->event_count;j++) {
            const struct chain_event *e=&l->events[j];if(e->signal!=SIGTRAP)continue;
            need(e->code==TRAP_TRACE&&!e->error&&e->actual.frame.greg[REG_TRAPNO]==1&&
                 !e->actual.frame.greg[REG_ERR]&&e->address==e->pc,1312);
            uint64_t flags=(uint64_t)e->actual.frame.greg[REG_EFL];
            need((flags&(LI2_STEP_TF|LI2_STEP_RF))==LI2_STEP_TF&&e->trace==1&&e->owner_phase==LI2_STEP_COMPLETE&&
                 !e->owner_error&&e->release_complete&&e->query.complete&&e->query.pc==e->pc,1313);
            if(e->decoded.pc==li2_chain_record.pc) {
                need(e->decoded.code==1720&&e->pc==li2_chain_record.pc+6&&
                    word(e->actual.frame.fp+vpb_observations.component[5].b+8)==UINT64_C(0x100080),1314);seen|=1;
            } else if(e->decoded.pc==li2_chain_record.pc+6) {
                need(e->decoded.code==1933&&e->pc==li2_chain_record.pc+11&&
                    (uint64_t)e->actual.frame.greg[REG_RAX]==UINT64_C(0x100080),1315);seen|=2;
            } else if(e->decoded.pc==li2_chain_record.pc+11) {
                need(e->decoded.code==3676&&e->pc==li2_chain_record.pc+16&&
                    (uint64_t)e->actual.frame.greg[REG_RSI]==result_mask&&!(flags&UINT64_C(0x8c1)),1316);seen|=4;
            } else if(e->decoded.pc==li2_chain_record.pc+19) {
                need(e->pc==li2_chain_record.pc+(case_id==12?21:28),1317);seen|=8;
            } else if(e->decoded.pc==li2_chain_record.pc+28) {
                need(e->decoded.code==396&&e->pc==li2_chain_record.stop&&
                    (uint64_t)e->actual.frame.greg[REG_RSP]==fixture_seed[4]+8,1318);seen|=16;
            }
        }
        need(seen==(n?31U:0U),1319);
        vpb_observations.ids[n]=((uint64_t)case_id<<32)|n;
        vpb_observations.bv[n][0]=vpb_header(l->before.frame.fp,l->before.frame.fp_bytes,1);
        vpb_observations.bv[n][1]=vpb_header(l->after.frame.fp,l->after.frame.fp_bytes,1);
        vpb_observations.bv[n][2]=vpb_header(l->fp[0],xsave_bytes,0);
        vpb_observations.bv[n][3]=vpb_header(l->fp[1],xsave_bytes,0);
        ++vpb_observations.checked;
    }
    need(li2_chain_record.chain.steps==chain_cases[case_id].instructions&&
        li2_chain_record.chain.attempts==chain_cases[case_id].instructions&&
        li2_chain_record.chain.trace_entries==chain_cases[case_id].instructions-1&&
        li2_chain_record.chain.nx_entries==1&&li2_chain_record.chain.fallbacks==1,1320);
}
