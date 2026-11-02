/* schedfuzz - wait-queue order invariant (O_WQ, direct form): each observed
 * waiter list must hold σ's expected waiters, sorted most-urgent first. */
#ifndef SCHEDFUZZ_CORE_WAIT_Q_ORACLE_H
#define SCHEDFUZZ_CORE_WAIT_Q_ORACLE_H

#include "rt_model.h"
#include "sigma_rt.h"

/* Optional per-pair sink; may run with the scheduler locked, so buffer output.
 * viol_auth: adapter's comparator; viol_signed: signed deadline compare. */
typedef void (*sf_wait_q_trace_fn)(void *ctx, int m, int idx,
                                   struct sf_waiter_obs prev,
                                   struct sf_waiter_obs cur,
                                   bool viol_auth, bool viol_signed);

struct sf_wait_q_result {
    uint32_t stale_order_violations;   /* adjacent pair out-of-order */
    uint32_t inspected_pairs;
    uint32_t seen_mask_m;              /* per-testcase dedup per mutex */

    uint32_t unresolved_discards;      /* mutex skipped: a waiter had no slot */
    uint32_t snapshot_overflows;       /* mutex skipped: list exceeds cap */
    uint32_t set_divergences;          /* mutex skipped: waiters != sigma's */

    /* Comparator disagreements, and pairs only the signed compare flags. */
    uint32_t cmp_disagreements;
    uint32_t stale_signed_only;

    sf_wait_q_trace_fn trace;
    void *trace_ctx;
};

static inline void sf_wait_q_result_reset_tc(struct sf_wait_q_result *r)
{
    r->seen_mask_m = 0;
}

/* Returns the new out-of-order pair count; sigma may be NULL (no set check). */
int sf_wait_q_check_order(const struct sf_rt_adapter *a,
                          const struct sigma_rt *sigma,
                          struct sf_wait_q_result *r);

#endif /* SCHEDFUZZ_CORE_WAIT_Q_ORACLE_H */
