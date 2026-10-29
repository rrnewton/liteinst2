#ifndef LI2_CSO_RECORD_H
#define LI2_CSO_RECORD_H
/* Included after the unchanged lso_record type, in the observation-only view.
   Custody changes nested runtime types: every size/offset comes from the new
   emitted DWARF, never an old-profile binary layout. */
#define CSO_MAGIC UINT64_C(0x31564f5453554350)
enum cso_point { CSO_ENTRY=1,CSO_STAGE,CSO_COMMIT,CSO_RETURN,
                 CSO_HANDLER_BEFORE,CSO_HANDLER_AFTER,CSO_FAULT,CSO_TERMINAL };
struct cso_meta {
 uint64_t present,point,index;
 int result;
 unsigned slot;
 uintptr_t chain,slot_address,owner_address,step_address,ref_address,session_address,chain_session_address;
 uint64_t event,generation;
 struct li2_fetch_ref argument_ref,published_ref;
 struct li2_page_custody_stats custody;
 struct li2_maps_stats maps;
 struct li2_fetch_rx_view rx;
 struct li2_step_session session;
};
struct cso_snapshot {
 struct cso_meta meta;
 struct li2_tf_owner owner;
 struct li2_chain_fetch fetch;
 struct li2_rseq_state rseq;
};
struct cso_row {
 struct cso_meta entry,returned,handler_before;
 struct cso_snapshot stage,commit,ready;
 struct rn_frame ready_frame;
};
struct cso_record {
 /* magic,version,extent,rows,stack,fault_event,overlap,initialized,
    terminal,error,terminal_status,terminal_code,terminal_detail,row_count;
    remaining words are zero. Selectors are fixed compiler inputs. */
 uint64_t h[32];
 struct cso_row rows[LSO_ROWS];
 struct lso_native_row stack_endpoints[2];
 struct cso_snapshot fault;
 struct cso_meta terminal;
};
struct cso_stream {
 struct lso_record base;
 struct cso_record custody;
};
_Static_assert(offsetof(struct cso_stream,base)==0,"actual first serialized object");
_Static_assert(offsetof(struct cso_stream,custody)==sizeof(struct lso_record),"no unobserved stream gap");
_Static_assert(sizeof(struct cso_stream)==sizeof(struct lso_record)+sizeof(struct cso_record),"no unobserved stream tail");
_Static_assert(sizeof(struct cso_stream)<(16U<<20),"unchanged complete record cap including stack endpoints");
#endif
