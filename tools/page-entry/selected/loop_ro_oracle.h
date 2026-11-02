#ifndef LI2_LOOP_RO_ORACLE_H
#define LI2_LOOP_RO_ORACLE_H
/* Test-only actual-subject mutations. Never included by a production recipe. */
#if !defined(LI2_LOOP_RO_TEST) || LI2_LOOP_RO_TEST != 1 || \
    !defined(LI2_LOOP_RO_CONTROL) || \
    (LI2_LOOP_RO_CONTROL != 1 && LI2_LOOP_RO_CONTROL != 2) || \
    !defined(LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL) || \
    LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL != 1
#error "causal suites require the distinct actual-subject every-hit DIFF test recipe"
#endif
#if !defined(LI2_PG_LOOP_RO_ORACLE_BINDING_VERSION) || LI2_PG_LOOP_RO_ORACLE_BINDING_VERSION != 1
#error "causal suites require their exact source-bound test domain"
#endif
struct pda_completion;
static int lro_initialize(void);
#if LI2_LOOP_RO_CONTROL == 2
static int lro_history_initialize(void);
#endif
static void lro_byte_hook(void);
static void lro_history_hook(const struct pda_completion *,unsigned);
static void lro_report(unsigned,unsigned);
#endif
