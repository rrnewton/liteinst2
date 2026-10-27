#ifndef LI2_FORK_CONTINUATION_H
#define LI2_FORK_CONTINUATION_H
#define OBS_GPR 0
#define OBS_FLAGS 128
#define OBS_PC 136
#define OBS_XCR0 144
#define OBS_XINUSE 152
#define OBS_FS 160
#define OBS_GS 168
#define OBS_SELECTORS 176
#define OBS_REDZONE 224
#define OBS_XSAVE 384
#define OBS_BYTES 65920
#define RECORD_BEFORE 4096
#define RECORD_AFTER (RECORD_BEFORE+OBS_BYTES)
#define RECORD_BYTES (RECORD_AFTER+OBS_BYTES)
#ifndef __ASSEMBLER__
#include <stdint.h>
#include <stddef.h>
struct observation {
    uint64_t gpr[16],flags,pc,xcr0,xinuse,fs,gs,selectors[6];
    unsigned char redzone[128],reserved[32],xsave[65536];
} __attribute__((aligned(64)));
struct component { uint64_t bit,offset,bytes,flags; };
struct continuation_record {
    uint64_t magic,version,bytes,role,pid,parent_pid,result,caller_sp;
    uint64_t xcr0,supported,xsave_bytes,xgetbv1,component_count,reserved[3];
    struct component components[64];
    unsigned char padding[1920];
    struct observation before,after;
} __attribute__((aligned(64)));
_Static_assert(sizeof(long)==8 && sizeof(uint64_t)==8,"x86-64 words");
_Static_assert(offsetof(struct observation,flags)==OBS_FLAGS,"flags offset");
_Static_assert(offsetof(struct observation,pc)==OBS_PC,"PC offset");
_Static_assert(offsetof(struct observation,xcr0)==OBS_XCR0,"XCR0 offset");
_Static_assert(offsetof(struct observation,xinuse)==OBS_XINUSE,"XINUSE offset");
_Static_assert(offsetof(struct observation,fs)==OBS_FS && offsetof(struct observation,gs)==OBS_GS,"base offsets");
_Static_assert(offsetof(struct observation,selectors)==OBS_SELECTORS,"selector offset");
_Static_assert(offsetof(struct continuation_record,caller_sp)==56 && offsetof(struct continuation_record,xcr0)==64,"assembly metadata offsets");
_Static_assert(sizeof(struct observation)==OBS_BYTES,"observation extent");
_Static_assert(offsetof(struct observation,xsave)==OBS_XSAVE,"XSAVE alignment");
_Static_assert(offsetof(struct observation,redzone)==OBS_REDZONE,"redzone offset");
_Static_assert(offsetof(struct continuation_record,before)==RECORD_BEFORE,"before offset");
_Static_assert(offsetof(struct continuation_record,after)==RECORD_AFTER,"after offset");
_Static_assert(sizeof(struct continuation_record)==RECORD_BYTES,"record extent");
extern struct continuation_record continuation_record;
extern long continuation_fork(void);
#endif
#endif
