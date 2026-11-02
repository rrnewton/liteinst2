#ifndef LI2_LOOP_RO_CERTIFICATE_H
#define LI2_LOOP_RO_CERTIFICATE_H
#include "loop_ro_profile.h"
#include "loop_history_certificate.h"
static int lrc_initialize(void);
static int lrc_state(void);
static int lrc_live(void);
static int lrc_mirror_begin(void);
static int lrc_mirror_end(void);
static void lrc_abort(void);
static void lrc_report(unsigned,unsigned);
#endif
