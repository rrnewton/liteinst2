#include "selected_effect.h"
/* Default linked policy. A trusted fixture can link its own constant definition
   instead; the runtime never accepts an application callback or config setter. */
const struct li2_effect_binding li2_effect_runtime_binding={.abi_version=LI2_EFFECT_ABI};
