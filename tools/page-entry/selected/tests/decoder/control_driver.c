/* The original supplied-byte controls remain byte-for-byte in controls.c.
   This adapter adds exactly two independently executed fatal controls. */
#define main supplied_controls_main
#include "controls.c"
#undef main
#include <stdio.h>
#include <unwind.h>

extern _Unwind_Reason_Code rust_eh_personality(
    int, _Unwind_Action, _Unwind_Exception_Class,
    struct _Unwind_Exception *, struct _Unwind_Context *);

int main(int argc,char **argv) {
    if(argc==1) {
        int status=supplied_controls_main();
        struct li2_decoder_stats s;
        assert(status==0 && li2_decoder_stats(&s)==LI2_OK);
        assert(s.phase==2 && !s.first_fatal_reason);
        printf("{\"forms\":112,\"phase\":%u,\"first_fatal_reason\":%u,"
               "\"arena_bytes\":%llu,\"retained_high_water\":%llu,"
               "\"allocation_calls\":%llu,\"deallocation_calls\":%llu}\n",
               s.phase,s.first_fatal_reason,(unsigned long long)s.arena_bytes,
               (unsigned long long)s.retained_high_water,
               (unsigned long long)s.allocation_calls,
               (unsigned long long)s.deallocation_calls);
        return 0;
    }
    if(argc==2 && !strcmp(argv[1],"tiny_arena")) {
        static _Alignas(64) unsigned char tiny[1];
        struct li2_decoder_stats s;
        (void)li2_decoder_initialize(tiny,sizeof tiny,&s);
        return 3; /* Must terminate inside the actual allocator with reason 102. */
    }
    if(argc==2 && !strcmp(argv[1],"personality")) {
        (void)rust_eh_personality(1,_UA_SEARCH_PHASE,UINT64_C(0x4c49324445434f44),NULL,NULL);
        return 3; /* Must terminate via the real personality with reason 106. */
    }
    return 2;
}
