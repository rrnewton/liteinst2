/* Supplied metadata and predicate results, actual production observer body.
   No guest instruction, mapping, permission, registration or receipt authority. */
static struct li2_pg_epoch before;
static unsigned char bank_before[4096];
static struct li2_lrr_counts want;
static int values[10];
static unsigned calls,mask,checks,false_cases,warm_cases,cold_cases,error_cases,disabled_cases;
static void expect(int yes,unsigned line) {
    ++checks;if(!yes){fprintf(stderr,"reason observer failure at %u\n",line);exit(124);}
}
#define CHECK(x) expect(!!(x),__LINE__)
static int test_gate(unsigned bit) {
    CHECK(bit<10 && bit==calls);++calls;mask|=1U<<bit;return values[bit];
}
static void snapshot(void) {memcpy(&before,&pe,sizeof pe);memcpy(bank_before,bank.page,4096);}
static void unchanged(void) {
    CHECK(!memcmp(&before,&pe,sizeof pe));
    CHECK(!memcmp(bank_before,bank.page,896));
    CHECK(!memcmp(bank_before+1696,bank.page+1696,4096-1696));
    CHECK(!memcmp(&want,&bank.record.reasons,sizeof want));
}
static void setup(unsigned kind,unsigned installed,unsigned occupied,unsigned selected_bank,unsigned warm) {
    CHECK(kind<3 && installed<=1 && occupied<=2 && occupied>=installed && selected_bank<2);
    memset(&pe,0xa5,sizeof pe);memset(&lrr_state,0,sizeof lrr_state);
    memset(bank.page,0,4096);memset(&want,0,sizeof want);
    li2_pgc_current=&bank.record.base.base.base;
    uint64_t *h=li2_pgc_current->header;
    h[0]=LI2_PGC_MAGIC;h[1]=5;h[2]=1696;h[3]=4096;
    h[4]=17;h[5]=19;h[6]=23;h[7]=29;h[8]=h[9]=31;
    h[10]=6;h[11]=23;h[12]=(uintptr_t)&bank;h[13]=h[14]=h[15]=1;
    pe.selected_slot=1;pe.selected_bank=selected_bank;pe.subentry_selected=kind==2;pe.warm=warm;
    pe.retained[1].generation.installed=installed;pe.retained[0].generation.installed=occupied-installed;
    pe.retained[1].publication.source.entry=kind==1?0x401000:0x402000;
    pe.entry.target.pc=0x401000;pe.entry.target.root=kind==2?0x402000:0x401000;
    for(unsigned i=0;i<10;i++)values[i]=(i&1)?-3:7;
    calls=mask=0;snapshot();
}
static void begin(unsigned kind,unsigned occupied,unsigned selected_bank) {
    lrr_begin(0x401000);want.attempts=want.in_flight=1;want.selection[kind][occupied][selected_bank]=1;unchanged();
    lrr_evaluate();unchanged();
}
static void decision(unsigned kind,unsigned first_false) {
    CHECK(first_false<=10);if(first_false<10)values[first_false]=0;
    int original=original_decision();unsigned original_calls=calls,original_mask=mask;
    calls=mask=0;int observed=observed_decision();
    CHECK(original==observed && observed==(first_false==10));
    CHECK(calls==original_calls && mask==original_mask && calls==(first_false==10?10:first_false+1));
    CHECK(mask==((1U<<calls)-1));
    for(unsigned i=0;i<calls;i++)want.seen[i]=1;
    for(unsigned i=0;i<first_false;i++)want.passed[i]=1;
    if(first_false<10)want.first_failure[kind][first_false]=1;
    unchanged();
}
static void cancellations(void) {
    for(unsigned bank_index=0;bank_index<2;bank_index++)for(unsigned kind=0;kind<3;kind++)
    for(unsigned first=0;first<10;first++) {
        /* Root/internal selections require an installed row. With neither a
           root nor internal head, the source key cannot first fail after4.
           These are supplied term vectors, not reachability claims for all
           independent earlier registry/permit/permission predicates. */
        if((kind && first==0) || (!kind && first>4))continue;
        unsigned installed=first!=0,occupied=installed?2:0;
        setup(kind,installed,occupied,bank_index,0);begin(kind,occupied,bank_index);decision(kind,first);
        lrr_plan(3);want.outcome[kind][1]=1;unchanged();
        lrr_finish(1);want.outcome[kind][6]=1;want.finished=1;want.in_flight=0;unchanged();
        CHECK(!lrr_state.stage);++false_cases;
    }
}
static void successes(void) {
    for(unsigned bank_index=0;bank_index<2;bank_index++)for(unsigned kind=1;kind<3;kind++) {
        setup(kind,1,2,bank_index,1);begin(kind,2,bank_index);decision(kind,10);
        lrr_plan(kind);want.outcome[kind][0]=1;unchanged();
        lrr_bound();want.outcome[kind][3]=1;
        if(kind==1)want.root_hits=1;else want.subentry_hits=1;unchanged();
        lrr_finish(2);want.outcome[kind][7]=1;want.finished=1;want.in_flight=0;unchanged();
        CHECK(!lrr_state.stage);++warm_cases;
    }
    for(unsigned bank_index=0;bank_index<2;bank_index++)for(unsigned path=0;path<4;path++) {
        unsigned kind=path<2?0:path-1,installed=path!=0,occupied=installed?2:1;
        setup(kind,installed,occupied,bank_index,0);begin(kind,occupied,bank_index);decision(kind,installed?4:0);
        lrr_plan(4);want.outcome[kind][2]=1;unchanged();
        lrr_bound();want.outcome[kind][installed?5:4]=1;unchanged();
        lrr_finish(2);want.outcome[kind][7]=1;want.finished=1;want.in_flight=0;unchanged();
        CHECK(!lrr_state.stage);++cold_cases;
    }
}
static void failures(void) {
    for(unsigned code=1;code<=9;code++) {
        setup(0,0,0,0,0);
        switch(code) {
        case 1:bank.record.reasons.attempts=want.attempts=UINT64_MAX;lrr_begin(0x401000);want.in_flight=1;break;
        case 2:begin(0,0,0);lrr_begin(0x401000);break;
        case 3:lrr_evaluate();break;
        case 4:CHECK(lrr_test(0,-7)==-7);break;
        case 5:lrr_plan(3);break;
        case 6:lrr_bound();break;
        case 7:begin(0,0,0);decision(0,0);lrr_plan(4);want.outcome[0][2]=1;pe.warm=1;snapshot();lrr_bound();break;
        case 8:setup(1,1,2,0,0);begin(1,2,0);decision(1,10);lrr_plan(1);want.outcome[1][0]=1;lrr_bound();break;
        case 9:lrr_finish(2);break;
        }
        want.error=code;unchanged();
        /* Once unusable, every hook is inert and direct helper return values
           remain exact; no production counter or supplied owner byte changes. */
        lrr_begin(0x401000);lrr_evaluate();CHECK(lrr_test(9,-17)==-17);lrr_plan(4);lrr_bound();lrr_finish(2);
        unchanged();++error_cases;
    }
    setup(0,0,0,0,0);begin(0,0,0);CHECK(lrr_test(1,9)==9);want.error=4;unchanged();++error_cases;
    setup(0,0,0,0,0);begin(0,0,0);CHECK(lrr_test(0,0)==0);want.seen[0]=1;want.first_failure[0][0]=1;unchanged();
    CHECK(lrr_test(1,9)==9);want.error=4;unchanged();++error_cases;
}
static void disabled(void) {
    const int returns[]={INT_MIN,-7,0,9,INT_MAX};
    for(unsigned mode=0;mode<4;mode++) {
        setup(0,0,0,0,0);
        if(mode==0)li2_pgc_current=0;
        else if(mode==1)li2_pgc_current->header[1]=4;
        else if(mode==2)li2_pgc_current->header[2]=896;
        else li2_pgc_current->header[15]=0;
        snapshot();lrr_begin(0x401000);lrr_evaluate();
        for(unsigned i=0;i<sizeof returns/sizeof *returns;i++)CHECK(lrr_test(i,returns[i])==returns[i]);
        lrr_plan(4);lrr_bound();lrr_finish(2);unchanged();CHECK(!lrr_state.stage);++disabled_cases;
    }
}
int main(void) {
    /* The source declaration range also contains these unchanged helpers;
       merely naming them avoids unused-function diagnostics without calling. */
    (void)pe_lifetime_stored;(void)pe_lifetime_matches;
    cancellations();successes();failures();disabled();
    CHECK(false_cases==46 && warm_cases==4 && cold_cases==8 && error_cases==11 && disabled_cases==4);
    puts("{\"schema\":1,\"scope\":\"actual_reason_observer_supplied_metadata\",\"first_false_cases\":46,\"warm_cases\":4,\"cold_publications\":8,\"observer_errors\":11,\"disabled_headers\":4,\"guest_executions\":0}");return 0;
}
