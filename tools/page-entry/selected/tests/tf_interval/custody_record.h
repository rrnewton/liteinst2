#ifndef TFI_CUSTODY_RECORD_H
#define TFI_CUSTODY_RECORD_H
#include "page_custody.h"
/* Pure return-side observations; every original interval field stays present. */
struct tci_meta {
 uint64_t h[16];
 struct li2_fetch_ref argument,published;
 struct li2_step_session session;
 struct li2_page_custody_stats custody;
 struct li2_maps_stats maps;
 struct li2_fetch_rx_view view;
};
struct tci_row {
 struct li2_page_custody_stats entry,returned,ready;
 struct li2_maps_stats entry_maps,returned_maps,ready_maps;
 struct tci_meta stage,commit;
 struct tfi_trace_frame ready_frame;
};
struct tci_record {
 uint64_t h[16];
 struct tci_row rows[TFI_MAX_EVENTS];
 struct li2_page_custody_stats terminal;
};
#endif
