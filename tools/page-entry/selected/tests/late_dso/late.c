#include "late.h"
__attribute__((constructor)) static void loaded(void) {
    li2_late_note(1, li2_late_leaf());
}
__attribute__((destructor)) static void unloaded(void) {
    li2_late_note(3, li2_late_leaf());
}
const struct ld_api *li2_late_api(void) {
    static const struct ld_api api = {1, pa_dso_setup, pa_dso_step, pa_dso_image, pa_dso_final};
    li2_late_note(2, li2_late_leaf());
    return &api;
}
