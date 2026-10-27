#ifndef ABI_RECORD_H
#define ABI_RECORD_H
#define ABI_XSAVE_CAP 65536
#define ABI_PHDR_CAP 4096
#define ABI_MAPS_CAP 262144
#define ABI_STACK_CAP 2097152
#define ABI_MAGIC 0x3149424132494c
#ifndef __ASSEMBLER__
#include <stdint.h>
#include <stddef.h>
/* Serialized as little-endian u64s followed by complete initialized arrays.
 * Neither endpoint contains a pointer to the other endpoint's storage. */
struct abi_record {
    uint64_t magic, version, endpoint, total_size;
    uint64_t gpr[16]; /* AX BX CX DX SI DI BP SP R8 R9 R10 R11 R12 R13 R14 R15 */
    uint64_t flags, pc, xcr0, xinuse;
    uint64_t fs_base, gs_base, selectors[6]; /* CS SS DS ES FS GS */
    uint64_t stack_first, stack_end, stack_size, maps_size;
    uint64_t phdr_address, phdr_size, at_base_offset;
    uint64_t aux_count, xsave_size, capability_xcr0, reserved[6];
    unsigned char xsave[ABI_XSAVE_CAP];
    unsigned char phdrs[ABI_PHDR_CAP];
    unsigned char maps[ABI_MAPS_CAP];
    unsigned char stack[ABI_STACK_CAP];
};
_Static_assert(offsetof(struct abi_record,gpr)==32,"GPR assembly offset");
_Static_assert(offsetof(struct abi_record,flags)==160,"flags assembly offset");
_Static_assert(offsetof(struct abi_record,pc)==168,"PC assembly offset");
_Static_assert(offsetof(struct abi_record,xcr0)==176,"XCR0 assembly offset");
_Static_assert(offsetof(struct abi_record,xinuse)==184,"XINUSE assembly offset");
_Static_assert(offsetof(struct abi_record,xsave)==384,"XSAVE assembly offset");
_Static_assert(sizeof(struct abi_record)==2429312,"closed wire extent");
extern struct abi_record abi_record;
void abi_collect(unsigned endpoint);
#endif
#endif
