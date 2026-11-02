/* schedfuzz - σ for RT state; each op-update encodes expected behaviour. */
#include "sigma_rt.h"
#include "coverage.h"   /* sf_hash_init / sf_hash_mix */

void sigma_rt_init(struct sigma_rt *s)
{
    for (int t = 0; t < RT_MAX_TASKS; t++) {
        s->task_alive[t]      = false;
        s->task_base[t]       = 0;
        s->task_suspended[t]  = false;
        s->task_pended_on[t]  = -1;
    }
    for (int m = 0; m < RT_MAX_MUTEXES; m++) {
        s->mutex_alive[m]      = false;
        s->mutex_owner[m]      = -1;
        s->mutex_lock_count[m] = 0;
    }
}

void sigma_rt_task_create(struct sigma_rt *s, int t, int base_prio)
{
    if (t < 0 || t >= RT_MAX_TASKS) return;
    s->task_alive[t]     = true;
    s->task_base[t]      = base_prio;
    s->task_suspended[t] = false;
    s->task_dl[t]        = 0;
    s->task_dl_set[t]    = false;
}

void sigma_rt_task_suspend(struct sigma_rt *s, int t)
{
    if (t < 0 || t >= RT_MAX_TASKS) return;
    s->task_suspended[t] = true;
}

void sigma_rt_task_resume(struct sigma_rt *s, int t)
{
    if (t < 0 || t >= RT_MAX_TASKS) return;
    s->task_suspended[t] = false;
}

void sigma_rt_task_abort(struct sigma_rt *s, int t)
{
    if (t < 0 || t >= RT_MAX_TASKS) return;
    s->task_alive[t] = false;
    s->task_pended_on[t] = -1;
    s->task_dl[t] = 0;
    s->task_dl_set[t] = false;
    /* σ never names a dead task as a mutex owner. */
    for (int m = 0; m < RT_MAX_MUTEXES; m++) {
        if (s->mutex_owner[m] == t) {
            s->mutex_owner[m]      = -1;
            s->mutex_lock_count[m] = 0;
        }
    }
}

void sigma_rt_task_pend(struct sigma_rt *s, int t, int m)
{
    if (t < 0 || t >= RT_MAX_TASKS) return;
    if (m < 0 || m >= RT_MAX_MUTEXES) return;
    s->task_pended_on[t] = m;
}

void sigma_rt_task_unpend(struct sigma_rt *s, int t)
{
    if (t < 0 || t >= RT_MAX_TASKS) return;
    s->task_pended_on[t] = -1;
}

void sigma_rt_task_prio_set(struct sigma_rt *s, int t, int new_prio)
{
    if (t < 0 || t >= RT_MAX_TASKS) return;
    s->task_base[t] = new_prio;
}

void sigma_rt_mutex_init(struct sigma_rt *s, int m)
{
    if (m < 0 || m >= RT_MAX_MUTEXES) return;
    s->mutex_alive[m]      = true;
    s->mutex_owner[m]      = -1;
    s->mutex_lock_count[m] = 0;
}

void sigma_rt_mutex_destroy(struct sigma_rt *s, int m)
{
    if (m < 0 || m >= RT_MAX_MUTEXES) return;
    s->mutex_alive[m]      = false;
    s->mutex_owner[m]      = -1;
    s->mutex_lock_count[m] = 0;
    /* A destroyed mutex cannot have anyone pended on it. */
    for (int t = 0; t < RT_MAX_TASKS; t++)
        if (s->task_pended_on[t] == m) s->task_pended_on[t] = -1;
}

void sigma_rt_mutex_take(struct sigma_rt *s, int t, int m)
{
    if (t < 0 || t >= RT_MAX_TASKS) return;
    if (m < 0 || m >= RT_MAX_MUTEXES) return;
    if (!s->mutex_alive[m] || !s->task_alive[t]) return;
    if (s->mutex_owner[m] == -1) {
        s->mutex_owner[m] = t;
        s->mutex_lock_count[m] = 1;
    } else if (s->mutex_owner[m] == t) {
        /* Recursive lock. */
        s->mutex_lock_count[m]++;
    }
    /* Otherwise: take blocks; σ unchanged. */
}

void sigma_rt_mutex_give(struct sigma_rt *s, int t, int m)
{
    if (t < 0 || t >= RT_MAX_TASKS) return;
    if (m < 0 || m >= RT_MAX_MUTEXES) return;
    if (s->mutex_owner[m] != t) return;  /* not owner: the kernel rejects it */
    if (s->mutex_lock_count[m] > 1) {
        s->mutex_lock_count[m]--;
    } else {
        s->mutex_owner[m]      = -1;
        s->mutex_lock_count[m] = 0;
    }
}

int sigma_rt_check(const struct sigma_rt *s, const struct sf_rt_adapter *a,
                   uint32_t *out_owner_div, uint32_t *out_alive_div,
                   uint32_t *out_base_div)
{
    int total = 0;

    /* Clause O_mutex_owner: for every alive mutex, σ.owner == kernel.owner. */
    for (int m = 0; m < a->n_mutexes; m++) {
        if (!s->mutex_alive[m]) continue;
        if (!a->mutex_alive(m)) continue;
        int sigma_owner  = s->mutex_owner[m];
        int kernel_owner = a->mutex_owner_slot(m);
        if (sigma_owner != kernel_owner) {
            if (out_owner_div) (*out_owner_div)++;
            total++;
        }
    }

    /* Clause O_task_alive: for every task slot, σ.alive == kernel.alive. */
    for (int t = 0; t < a->n_tasks; t++) {
        bool s_alive = s->task_alive[t];
        bool k_alive = a->task_alive(t);
        if (s_alive != k_alive) {
            if (out_alive_div) (*out_alive_div)++;
            total++;
        }
    }

    /* Clause O_task_base: for every alive task, σ.base == kernel.base. */
    for (int t = 0; t < a->n_tasks; t++) {
        if (!s->task_alive[t]) continue;
        if (!a->task_alive(t)) continue;
        int sb = s->task_base[t];
        int kb = a->task_base_prio(t);
        if (sb != kb) {
            if (out_base_div) (*out_base_div)++;
            total++;
        }
    }

    return total;
}

int sigma_rt_check_ext(const struct sigma_rt *s, const struct sf_rt_adapter *a,
                       int (*kernel_lock_count)(int m),
                       uint32_t *out_owner_div, uint32_t *out_alive_div,
                       uint32_t *out_base_div, uint32_t *out_lockcnt_div)
{
    int total = sigma_rt_check(s, a, out_owner_div, out_alive_div, out_base_div);

    if (kernel_lock_count) {
        for (int m = 0; m < a->n_mutexes; m++) {
            if (!s->mutex_alive[m]) continue;
            if (!a->mutex_alive(m)) continue;
            /* Compare only owned mutexes; an unowned count may be residual. */
            if (s->mutex_owner[m] < 0) continue;
            int sigma_lc  = s->mutex_lock_count[m];
            int kernel_lc = kernel_lock_count(m);
            if (sigma_lc != kernel_lc) {
                if (out_lockcnt_div) (*out_lockcnt_div)++;
                total++;
            }
        }
    }
    return total;
}

int sigma_rt_check_wait_graph(const struct sigma_rt *s,
                               const struct sf_rt_adapter *a,
                               uint32_t *out_wait_div)
{
    int total = 0;
    for (int t = 0; t < a->n_tasks; t++) {
        if (!s->task_alive[t]) continue;
        if (!a->task_alive(t)) continue;
        int sigma_pend  = s->task_pended_on[t];
        int kernel_pend = a->task_pended_on_mutex(t);
        if (sigma_pend != kernel_pend) {
            if (out_wait_div) (*out_wait_div)++;
            total++;
        }
    }
    return total;
}

int sigma_rt_check_suspended(const struct sigma_rt *s,
                              const struct sf_rt_adapter *a,
                              bool (*kernel_suspended)(int t),
                              uint32_t *out_susp_div)
{
    if (!kernel_suspended) return 0;
    int total = 0;
    for (int t = 0; t < a->n_tasks; t++) {
        if (!s->task_alive[t]) continue;
        if (!a->task_alive(t)) continue;
        bool s_susp = s->task_suspended[t];
        bool k_susp = kernel_suspended(t);
        if (s_susp != k_susp) {
            if (out_susp_div) (*out_susp_div)++;
            total++;
        }
    }
    return total;
}

bool sigma_rt_op_abort_task_legal(const struct sigma_rt *s, int t)
{
    if (t < 0 || t >= RT_MAX_TASKS) return false;
    if (!s->task_alive[t]) return true;  /* dead in σ: I10 holds vacuously */
    if (s->task_pended_on[t] != -1) return false;
    for (int m = 0; m < RT_MAX_MUTEXES; m++)
        if (s->mutex_owner[m] == t) return false;
    return true;
}

bool sigma_rt_op_reinit_mutex_legal(const struct sigma_rt *s, int m)
{
    if (m < 0 || m >= RT_MAX_MUTEXES) return false;
    return !s->mutex_alive[m];
}

uint32_t sigma_rt_signature(const struct sigma_rt *s)
{
    uint32_t sig = sf_hash_init();
    for (int t = 0; t < RT_MAX_TASKS; t++) {
        sig = sf_hash_mix(sig, s->task_alive[t] ? 1u : 0u);
        sig = sf_hash_mix(sig, (uint32_t)s->task_base[t]);
        sig = sf_hash_mix(sig, (uint32_t)s->task_pended_on[t]);
    }
    for (int m = 0; m < RT_MAX_MUTEXES; m++) {
        sig = sf_hash_mix(sig, s->mutex_alive[m] ? 1u : 0u);
        sig = sf_hash_mix(sig, (uint32_t)s->mutex_owner[m]);
        sig = sf_hash_mix(sig, (uint32_t)s->mutex_lock_count[m]);
    }
    return sig;
}

int sigma_rt_self_check(const struct sigma_rt *s)
{
    int violations = 0;
    for (int t = 0; t < RT_MAX_TASKS; t++) {
        int m = s->task_pended_on[t];
        if (m != -1) {
            /* C1: pended_on requires alive task + alive mutex. */
            if (!s->task_alive[t])          violations++;
            if (m < 0 || m >= RT_MAX_MUTEXES) violations++;
            else if (!s->mutex_alive[m])    violations++;
            /* C5 (a dead task holds no pend) is covered by C1. */
        }
    }
    for (int m = 0; m < RT_MAX_MUTEXES; m++) {
        int owner = s->mutex_owner[m];
        int lc    = s->mutex_lock_count[m];
        if (owner != -1) {
            /* C2: owner must be alive. */
            if (owner < 0 || owner >= RT_MAX_TASKS) violations++;
            else if (!s->task_alive[owner])         violations++;
            /* C3a: owned mutex must have positive lock_count. */
            if (lc <= 0)                            violations++;
        } else {
            /* C3b: unowned mutex must have zero lock_count. */
            if (lc != 0)                            violations++;
        }
        if (!s->mutex_alive[m]) {
            /* C4: dead mutex has no owner and zero lock_count. */
            if (owner != -1)                        violations++;
            if (lc    != 0)                         violations++;
        }
    }
    return violations;
}

void sigma_rt_task_dl_set(struct sigma_rt *s, int t, int dl)
{
    if (!s || t < 0 || t >= RT_MAX_TASKS) return;
    if (!s->task_alive[t]) return;
    s->task_dl[t]     = dl;
    s->task_dl_set[t] = true;
}
