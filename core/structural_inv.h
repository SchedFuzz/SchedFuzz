/* schedfuzz - structural invariants (I3-I5) over the sf_rt_adapter view. */
#ifndef SCHEDFUZZ_CORE_STRUCTURAL_INV_H
#define SCHEDFUZZ_CORE_STRUCTURAL_INV_H

#include "rt_model.h"
#include "invariants.h"

/* Violation counters, plus the per-testcase dedup mask for I5. */
struct sf_structural_result {
    uint32_t mutex_single_owner;
    uint32_t thread_single_wait;
    uint32_t prio_out_of_range;
    uint32_t seen_mask_so;
};

/* Each check returns the number of new violations and counts them in r. */

/* I3: the owner of a mutex is not pended on it. */
int sf_inv_check_mutex_owner_not_self_pended(const struct sf_rt_adapter *a,
                                              struct sf_structural_result *r,
                                              int thread_count_for_dedup);

/* I4: an alive task pended on M has M alive and owned. */
int sf_inv_check_thread_single_wait(const struct sf_rt_adapter *a,
                                     struct sf_structural_result *r);

/* I5: alive tasks' actual prio is in [prio_lo, prio_hi]; lo > hi disables. */
int sf_inv_check_prio_bounds(const struct sf_rt_adapter *a,
                              struct sf_structural_result *r,
                              int prio_lo, int prio_hi);


#endif /* SCHEDFUZZ_CORE_STRUCTURAL_INV_H */
