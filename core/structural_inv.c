/* schedfuzz - structural invariant implementations. */
#include "structural_inv.h"

int sf_inv_check_mutex_owner_not_self_pended(const struct sf_rt_adapter *a,
                                              struct sf_structural_result *r,
                                              int dedup_tc_id)
{
    int delta = 0;
    (void)dedup_tc_id;
    for (int t = 0; t < a->n_tasks; t++) {
        if (!a->task_alive(t)) continue;
        int pended = a->task_pended_on_mutex(t);
        if (pended < 0) continue;
        if (a->mutex_owner_slot(pended) == t) {
            r->mutex_single_owner++;
            delta++;
        }
    }
    return delta;
}

int sf_inv_check_thread_single_wait(const struct sf_rt_adapter *a,
                                     struct sf_structural_result *r)
{
    int delta = 0;
    for (int t = 0; t < a->n_tasks; t++) {
        if (!a->task_alive(t)) continue;
        int m = a->task_pended_on_mutex(t);
        if (m < 0) continue;
        if (m >= a->n_mutexes || !a->mutex_alive(m)) {
            r->thread_single_wait++;
            delta++;
            continue;
        }
        if (a->mutex_owner_slot(m) < 0) {
            r->thread_single_wait++;
            delta++;
        }
    }
    return delta;
}

int sf_inv_check_prio_bounds(const struct sf_rt_adapter *a,
                              struct sf_structural_result *r,
                              int prio_lo, int prio_hi)
{
    int delta = 0;
    if (prio_lo > prio_hi) return 0;  /* unknown bounds */
    for (int t = 0; t < a->n_tasks; t++) {
        if (!a->task_alive(t)) continue;
        if (r->seen_mask_so & (1u << t)) continue;
        int actual = a->task_actual_prio(t);
        if (actual < prio_lo || actual > prio_hi) {
            r->prio_out_of_range++;
            r->seen_mask_so |= (1u << t);
            delta++;
        }
    }
    return delta;
}

