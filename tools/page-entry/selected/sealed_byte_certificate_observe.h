#ifndef LI2_SEALED_BYTE_CERTIFICATE_OBSERVE_H
#define LI2_SEALED_BYTE_CERTIFICATE_OBSERVE_H
#include <errno.h>
/* Observation/fault injection only. No field is an owner-issued permit. */
#if !defined(LI2_SEALED_BYTE_CERTIFICATE_OBSERVE) || LI2_SEALED_BYTE_CERTIFICATE_OBSERVE != 1 || \
    !defined(LI2_SEALED_BYTE_CERTIFICATE) || LI2_SEALED_BYTE_CERTIFICATE != 1 || \
    !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1
#error "certificate observation requires the actual sealed two-member owner"
#endif
#ifndef LI2_SEALED_BYTE_CERTIFICATE_CONTROL
#error "explicit control: 0 observe, 1 stale certificate, 2 mirror, 3 live fd"
#endif
#if LI2_SEALED_BYTE_CERTIFICATE_CONTROL < 0 || LI2_SEALED_BYTE_CERTIFICATE_CONTROL > 3
#error "exact bounded certificate control"
#endif
#if LI2_SEALED_BYTE_CERTIFICATE_CONTROL && !defined(LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL)
#error "every injected control runs the unchanged full comparison on every decision"
#endif
struct sbco_observation {
    uint64_t initialized,stage,fired,complete,stopped;
    uint64_t claim_token,claim_id,claim_serial,claim_cell,claim_member,claimed_before,claimed_after;
    uint64_t invalidated_epoch,writer_token,mirror_write_epoch,issued_serial;
    uint64_t token,phase,slot,bank,generation,domain_refs,closed_before,closed_after;
    uint64_t mirror_offset,mirror_before,mirror_after,close_attempted;
    int64_t close_result,decision_result;
    uint64_t candidate_before,candidate_after,test_detail,query_calls;
    int64_t query_error;
    struct sbc_certificate old,current;
    struct sbc_counts before,after;
    struct li2_sealed_code_query failed_query;
};
static struct sbco_observation sbco;
static int sbco_initialize(void);
static int sbco_claim(void);
static int sbco_invalidated(void);
static int sbco_mirror_write(void);
static int sbco_issue(void);
static void sbco_report(unsigned,unsigned);
static void sbco_query(const struct li2_sealed_code_query *,int);
#endif
