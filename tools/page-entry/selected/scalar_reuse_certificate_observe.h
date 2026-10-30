#ifndef LI2_SCALAR_REUSE_CERTIFICATE_OBSERVE_H
#define LI2_SCALAR_REUSE_CERTIFICATE_OBSERVE_H
/* Qualification-only objects. Included after the actual complete publisher
   types, before sro_wire; no copied production-owner ABI declarations. */
#if LI2_SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE != 1 || \
    LI2_SCALAR_REGION_REUSE_CERTIFICATE != 1 || LI2_SCALAR_REGION_CAPTURE != 1
#error "complete distinct certificate capture profile required"
#endif
struct srco_registry {
    unsigned complete,count;
    uintptr_t table;
    struct image bridge;
    Elf64_Phdr ph[MAX_PHDR];
    struct li2_fork_range ranges[RANGES];
    unsigned char initial_code[RANGES];
    /* Exact register calls: publisher metadata, whole capture, certificate
       arena. Metadata/capture are also inside the actual bridge RW load. */
    uintptr_t address[3];
    size_t bytes[3],alignment[3];
    unsigned range_index[3],load_index[2];
};
struct srco_focal {
    unsigned source_present,slot_present,completed;
    size_t slot,copied;
    uint64_t generation,ready_generation;
    uintptr_t address;
    uint64_t before_counts[5],slot_counts[5],after_counts[5];
    struct li2_rseq_state source_rseq;
    struct srcg_current current,completed_current;
    struct srcg_publication publication;
    struct srcg_retirement retirement;
    unsigned char payload[SRCG_BYTES];
};
struct srco_wire {
    uint64_t h[16];
    struct srco_registry initial_registry,terminal_registry;
    __typeof__(srcg_store) store;
    struct srco_focal focal[SRO_ROWS];
    /* Each actual extent appears once at terminal. This includes the stable
       pending address after partial publication, without consulting a plan. */
    struct li2_private_code_query terminal_mapping[SR_PAGES];
    size_t terminal_bytes[SR_PAGES];
    unsigned char payload[SR_PAGES][SRCG_BYTES];
};
#endif
