#ifndef LI2_HELPER_TF_H
#define LI2_HELPER_TF_H
#include "tf_owner.h"
#include "write_footprint.h"
#if defined(LI2_HELPER_TF) && LI2_HELPER_TF != 1
#error "The original-PC helper TF profile must be explicitly enabled as 1"
#endif

/* Separate opt-in original-PC profile. These queries never grant an RX,
   source, write, signal or continuation permit. All buffers are distinct,
   aligned where required, owned and live for the complete call; source bytes
   are immutable under the ordinary sealed-decoder single-caller contract. */
#define LI2_HELPER_TF_X87 7U
#define LI2_HELPER_TF_VERSION 1U
enum li2_helper_tf_status { LI2_HT_OK=0,LI2_HT_ARGUMENT=5201,
    LI2_HT_FORM=5202,LI2_HT_DECODER=5203,LI2_HT_IDENTITY=5204 };
/* Each query independently reconstructs the literal instruction, invokes the
   genuine decoder and compares the whole held decoded object. No supplied
   classification is accepted. LI2_HT_FORM means this profile has no claim. */
int li2_helper_tf_classify(const struct li2_decoded *,struct li2_tf_classification *);
int li2_helper_tf_write(const struct li2_decoded *,const struct li2_write_registers *,
                        struct li2_write_footprint *);
/* Zero means this exact freshly verified form can use the unchanged PLAIN
   original-PC TF entry. The real owner still authenticates and opens source. */
int li2_helper_tf_entry(const struct li2_decoded *);
#endif
