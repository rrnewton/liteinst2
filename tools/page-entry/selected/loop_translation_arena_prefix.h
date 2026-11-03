#ifndef LI2_LOOP_TRANSLATION_ARENA_PREFIX_H
#define LI2_LOOP_TRANSLATION_ARENA_PREFIX_H
/* One terminating observation at an existing offer; never runtime authority. */
#if !defined(LI2_LOOP_TRANSLATION_ARENA_PREFIX) || LI2_LOOP_TRANSLATION_ARENA_PREFIX != 1 || \
    !defined(LI2_LOOP_TRANSLATION_ARENA_PROGRAM) || LI2_LOOP_TRANSLATION_ARENA_PROGRAM != 1 || \
    !defined(LI2_LOOP_TRANSLATION_ARENA_CAPACITY) || LI2_LOOP_TRANSLATION_ARENA_CAPACITY != 128 || \
    !defined(LI2_PG_LOOP_TRANSLATION_ARENA_PREFIX_BINDING_VERSION) || \
    LI2_PG_LOOP_TRANSLATION_ARENA_PREFIX_BINDING_VERSION != 1 || \
    !defined(LI2_PG_LOOP_TRANSLATION_ARENA_PREFIX_OFFERS) || \
    LI2_PG_LOOP_TRANSLATION_ARENA_PREFIX_OFFERS != 1024 || \
    defined(LI2_LOOP_TRANSLATION_ARENA_OBSERVE) || defined(LI2_LOOP_CACHE8_OBSERVE) || \
    defined(LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL) || defined(LI2_PERSISTENT_GROUP_COUNTERS)
#error "prefix observation requires its exact capacity128 release-only binding"
#endif
#define LTAPF_MAGIC UINT64_C(0x315846504132494c)
#define LTAPF_OFFERS UINT64_C(1024)
#define LTAPF_CORE(X) \
    X(next_serial) X(next_generation) X(offers) X(publications) X(hits) X(cold_attempts) \
    X(cancelled) X(retirements) X(permit_claims) X(entries) X(completed) X(unexpected) \
    X(subentry_selections) X(subentry_hits) X(subentry_entries) X(subentry_completed)
#define LTAPF_REASONS(X) \
    X(NONE,0) X(ROOT_UNSUPPORTED,1) X(SOURCE_INVALID,2) X(SOURCE_TRUNCATED,3) \
    X(SOURCE_OVERLAP,4) X(OUTSIDE_PAIR,5) X(HEAD_LIMIT,6) X(EXIT_LIMIT,7) \
    X(QUEUE_LIMIT,8) X(NO_EXIT,9) X(RIP_REACH,10) X(BRANCH_REACH,11) \
    X(FALLTHROUGH_REACH,12) X(GUARD_RIP_REACH,13) X(GUARD_FOLLOW_REACH,14) \
    X(ROOT_SELECTED,15) X(SINGLE_MEMBER,16) X(LINK_LIMIT,17)
#define LTAPF_LOOP(X) X(chooser_attempts) X(chooser_selected) X(chooser_no_envelope) \
    X(publications12) X(hits12) X(entries_with12) X(completed_with12) \
    X(historical_reconstructions) X(actual_entries12)
#define LTAPF_EFFECTS(X) X(chooser_attempts) X(chooser_selected) X(chooser_no_envelope) \
    X(publications13) X(hits13) X(entries_with13) X(completed_with13) \
    X(historical_reconstructions) X(actual_entries13)
#define LTAPF_CACHE(X) X(cold_calls) X(compact_build_calls) X(compact_validate_calls) \
    X(attach_attempts) X(accepted) X(source_declines)
#define LTAPF_RX(X) X(entries) X(retained_entries) X(quiet_releases) X(direct_offers) \
    X(direct_steps) X(code_opens) X(code_revokes) X(code_writes) X(code_syncs) \
    X(metadata_permissions) X(metadata_syncs) X(terminal_attempts) X(terminal_closed) \
    X(transit_offers) X(transit_steps) X(transit_declined) X(transit_limit)
#define LTAPF_ARENA(X) X(initialized) X(poisoned) X(topology_epoch) X(next_binding) \
    X(detached) X(rebound) X(rebound_peers) X(cold_nodes) X(evicted) \
    X(epoch_invalidations) X(stale_refusals) X(physical_checks)
#define LTAPF_HISTORY(X) X(decisions) X(hits) X(misses) X(full_calls) \
    X(differential_checks) X(disagreements) X(issues) X(invalidations) \
    X(abort_invalidations) X(errors) X(restored_bytes)
#define LTAPF_COMMON(X) X(issues) X(hits) X(topology_hits) X(topology_full) \
    X(topology_differential) X(common_hits) X(common_full) X(common_differential) \
    X(history_fallbacks) X(directory_writes) X(directory_queries) X(disagreements) \
    X(common_lhc_hits) X(common_revalidated_hits)
#define LTAPF_BYTE(X) X(decisions) X(hits) X(misses) X(full_scans) X(full_scan_errors) \
    X(disagreements) X(full_scan_bytes) X(issues) X(invalidations) X(abort_invalidations) \
    X(live_queries) X(live_query_errors) X(postseal_bytes)
#define LTAPF_FIELD(n) uint64_t n;
struct ltapf_core { LTAPF_CORE(LTAPF_FIELD) };
struct ltapf_loop { LTAPF_LOOP(LTAPF_FIELD) };
struct ltapf_effects { LTAPF_EFFECTS(LTAPF_FIELD) };
struct ltapf_cache { LTAPF_CACHE(LTAPF_FIELD) };
struct ltapf_rx { LTAPF_RX(LTAPF_FIELD) };
struct ltapf_arena { LTAPF_ARENA(LTAPF_FIELD) };
struct ltapf_history { LTAPF_HISTORY(LTAPF_FIELD) };
struct ltapf_common { LTAPF_COMMON(LTAPF_FIELD) };
struct ltapf_byte { LTAPF_BYTE(LTAPF_FIELD) };
#undef LTAPF_FIELD
struct ltapf_binding { uint64_t generation;uint32_t node,reserved; };
struct ltapf_node {
    uint64_t generation,root,node_epoch,issued_epoch,reusable;
    uint32_t installed,index,claim,reserved;
};
struct ltapf_record {
    uint64_t h[16];
    struct ltapf_core core;
    uint64_t misses[18],pf_backward_refused,pf_backward_cancelled;
    struct ltapf_loop loop;
    struct ltapf_effects effects;
    struct ltapf_cache cache;
    uint64_t groups[3][9];
    struct ltapf_rx rx;
    struct ltapf_arena arena;
    struct ltapf_history history;
    struct ltapf_common common;
    struct ltapf_byte byte;
    uint64_t ingress[6];
    struct li2_maps_view_stats maps_view;
    struct li2_maps_stats maps;
    uint32_t phase[24];
    struct ltapf_binding binding[8];
    struct ltapf_node node[128];
};
static _Noreturn void ltapf_stop(int,const siginfo_t *,const ucontext_t *);
#endif
