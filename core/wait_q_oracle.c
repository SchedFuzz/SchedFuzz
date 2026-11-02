/* schedfuzz - wait-queue ordering invariant implementation. */
#include "wait_q_oracle.h"

/* wq_collect() failure codes. */
#define WQ_UNRESOLVED (-1)
#define WQ_OVERFLOW   (-2)

/* Collect m's waiters, preferring the atomic snapshot (the per-index walk is
 * not atomic).  Returns the waiter count or a WQ_* code. */
static int wq_collect(const struct sf_rt_adapter *a, int m,
                      struct sf_waiter_obs *out, int cap)
{
    int n;

    if (a->mutex_waiters_snapshot) {
        n = a->mutex_waiters_snapshot(m, out, cap);
        if (n < 0) return WQ_OVERFLOW;
    } else if (a->mutex_waiter_at) {
        for (n = 0; n < cap; n++) {
            int s = a->mutex_waiter_at(m, n);
            if (s == SF_WAITER_NONE) break;
            out[n].slot = s;
            if (s == SF_WAITER_UNRESOLVED) {
                out[n].prio = 0;
                out[n].dl   = 0;
                continue;
            }
            out[n].prio = a->task_actual_prio(s);
            out[n].dl   = a->task_actual_dl ? a->task_actual_dl(s) : 0;
        }
        /* Longer than cap: do not judge a partial queue. */
        if (n == cap && a->mutex_waiter_at(m, n) != SF_WAITER_NONE)
            return WQ_OVERFLOW;
    } else {
        return 0;
    }

    /* One unresolved waiter invalidates the whole list. */
    for (int i = 0; i < n; i++)
        if (out[i].slot == SF_WAITER_UNRESOLVED)
            return WQ_UNRESOLVED;

    return n;
}

/* Do the observed waiters equal σ's pended tasks, compared as sets? */
static bool wq_set_agrees(const struct sigma_rt *s, int m,
                          const struct sf_waiter_obs *w, int n)
{
    uint32_t observed = 0, expected = 0;

    for (int i = 0; i < n; i++)
        if (w[i].slot >= 0 && w[i].slot < RT_MAX_TASKS)
            observed |= 1u << w[i].slot;

    for (int t = 0; t < RT_MAX_TASKS; t++)
        if (s->task_alive[t] && s->task_pended_on[t] == m)
            expected |= 1u << t;

    return observed == expected;
}

int sf_wait_q_check_order(const struct sf_rt_adapter *a,
                          const struct sigma_rt *sigma,
                          struct sf_wait_q_result *r)
{
    struct sf_waiter_obs w[RT_MAX_TASKS];
    int delta = 0;

    if (!a->mutex_waiters_snapshot && !a->mutex_waiter_at) return 0;

    for (int m = 0; m < a->n_mutexes; m++) {
        if (!a->mutex_alive(m)) continue;
        if (m < 32 && (r->seen_mask_m & (1u << m))) continue;

        int n = wq_collect(a, m, w, RT_MAX_TASKS);
        if (n == WQ_UNRESOLVED) { r->unresolved_discards++; continue; }
        if (n == WQ_OVERFLOW)   { r->snapshot_overflows++;  continue; }
        if (n < 2) continue;            /* no adjacent pair to order */

        if (sigma && !wq_set_agrees(sigma, m, w, n)) {
            r->set_divergences++;
            continue;
        }

        bool m_broken = false;
        for (int i = 1; i < n; i++) {
            struct sf_waiter_obs p = w[i - 1];
            struct sf_waiter_obs c = w[i];

            /* Violation if cur is more urgent than prev, which precedes it. */
            bool viol_auth = rt_waiter_more_urgent(a, c, p);

            /* Plain signed deadline compare; only the tiebreak can differ. */
            bool viol_signed = (c.prio != p.prio)
                             ? viol_auth
                             : rt_dl_more_urgent(false, c.dl, p.dl);

            r->inspected_pairs++;
            if (viol_auth != viol_signed) r->cmp_disagreements++;
            if (viol_signed && !viol_auth) r->stale_signed_only++;

            if (r->trace)
                r->trace(r->trace_ctx, m, i, p, c, viol_auth, viol_signed);

            if (viol_auth) {
                r->stale_order_violations++;
                delta++;
                m_broken = true;
            }
        }
        if (m_broken && m < 32) r->seen_mask_m |= (1u << m);
    }
    return delta;
}
