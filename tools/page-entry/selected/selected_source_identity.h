#ifndef LI2_SELECTED_SOURCE_IDENTITY_H
#define LI2_SELECTED_SOURCE_IDENTITY_H
#include "lifecycle_loader.h"
#include "selected_effect.h"

/* Runtime bootstrap only. registered_fd must be an original or retained FD
   already registered by lifecycle_initialize/register_initial. The function
   observes that actual sealed object again; it never opens a path or accepts
   an application address. Its ID is the never-reused object index plus one.
   This description is suitable for immutable linked-policy site bindings; it
   is not a mapping, fetch, publication, or execution permit. */
struct li2_effect_object_binding {
    uint64_t object_id;
    int registered_fd;
    unsigned complete;
    struct li2_fetch_backing actual;
};
int li2_lifecycle_bind_sealed_object(int registered_fd,
                                   struct li2_effect_object_binding *);
/* Both actual fetched fragments are retained, including a second object if
   present. All current fetch validation remains mandatory. Anonymous backing
   is described with object_id zero; no sealed-object identity is invented. */
int li2_lifecycle_effect_sources(const struct li2_fetch_ref *,
                                struct li2_effect_source out[2],size_t *count);
#endif
