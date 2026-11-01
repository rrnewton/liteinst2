#ifndef LI2_SEALED_GENERATION_H
#define LI2_SEALED_GENERATION_H
#include "lifecycle_loader.h"
#include <stdint.h>
#include <stddef.h>

/* A distinct file-backed query. It never grants application source ownership
   and never asserts the anonymous private-code query succeeded. */
#define LI2_SEALED_QUERY_VERSION 1U
#define LI2_SEALED_QUERY_KIND 1U
#define LI2_SEALED_REQUIRED_SEALS 15U
struct li2_sealed_identity {
    int64_t fd;
    uint64_t device,inode,bytes,generation;
    uintptr_t code,proof;
    size_t code_bytes,proof_bytes;
    unsigned code_live,proof_live;
};
struct li2_sealed_evidence {
    unsigned kind,version;
    struct li2_sealed_identity identity;
    uint64_t offset;
    long seals_result,stat_result;
    size_t alias_vmas,alias_pages;
    unsigned alias_complete,reserved;
};
struct li2_sealed_code_query {
    uintptr_t first,end,first_vma,last_vma_end;
    size_t pages_checked;
    unsigned attempted,complete;
    int expected_prot,actual_prot,result;
    long detail;
    struct li2_fetch_map_progress maps;
    struct li2_sealed_evidence sealed;
};
int li2_lifecycle_sealed_code_query(const struct li2_sealed_identity *,uintptr_t,
    size_t,int,struct li2_sealed_code_query *);
/* Controller-owned routing of the same bounded generated-storage query.
   This callback cannot admit application source or grant an execution token. */
struct li2_private_code_query;
int li2_pg_storage_query(uintptr_t,size_t,int,struct li2_private_code_query *);
#endif
