#ifndef LI2_LINKED_JMP_DOMAIN_H
#define LI2_LINKED_JMP_DOMAIN_H
#include <stdint.h>
#include <stddef.h>
#if !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1
#error "distinct active-domain cold code and directory required"
#endif
#define LI2_JD_DOMAIN_VERSION 1U
#define LI2_JD_DOMAIN_HEADS 256U
#define LI2_JD_DOMAIN_BYTES (3U*4096U)
/* Immutable during execution. No directory row is itself a lifetime permit.
   The owner authenticates each exact original/generation/head/code tuple,
   seals the full mapping R, and holds all named generations through drain. */
struct li2_jd_domain_row {
    uintptr_t pc,generated;
    uint64_t generation;
    uint32_t slot,head;
};
struct li2_jd_domain_directory {
    uint64_t version,count,serial,reserved;
    struct li2_jd_domain_row row[LI2_JD_DOMAIN_HEADS];
};
_Static_assert(sizeof(struct li2_jd_domain_row)==32,"exact searched directory stride");
_Static_assert(offsetof(struct li2_jd_domain_directory,row)==32,"exact directory header");
_Static_assert(sizeof(struct li2_jd_domain_directory)==8224,"complete bounded directory");
_Static_assert(sizeof(struct li2_jd_domain_directory)<LI2_JD_DOMAIN_BYTES,"whole zero tail retained");
#endif
