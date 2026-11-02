/* schedfuzz - σ, the expected RT state, and its refinement relation R(σ, s)
 * against the kernel state s seen through the sf_rt_adapter. */
#ifndef SCHEDFUZZ_CORE_SIGMA_RT_H
#define SCHEDFUZZ_CORE_SIGMA_RT_H

#include <stdint.h>
#include <stdbool.h>
#include "rt_model.h"

struct sigma_rt {
    bool task_alive[RT_MAX_TASKS];
    int  task_base[RT_MAX_TASKS];
    bool task_suspended[RT_MAX_TASKS];
    int  task_pended_on[RT_MAX_TASKS];   /* mutex slot, or -1 */
    /* Requested deadline, for witnesses only; no refinement clause reads it. */
    int  task_dl[RT_MAX_TASKS];
    bool task_dl_set[RT_MAX_TASKS];
    bool mutex_alive[RT_MAX_MUTEXES];
    int  mutex_owner[RT_MAX_MUTEXES];   /* task slot, or -1 = unowned */
    int  mutex_lock_count[RT_MAX_MUTEXES];
};

void sigma_rt_init(struct sigma_rt *s);

/* Op-update functions: call after the corresponding fuzzer op. */
void sigma_rt_task_create(struct sigma_rt *s, int t, int base_prio);
void sigma_rt_task_abort(struct sigma_rt *s, int t);
void sigma_rt_task_prio_set(struct sigma_rt *s, int t, int new_prio);
void sigma_rt_task_suspend(struct sigma_rt *s, int t);
void sigma_rt_task_resume(struct sigma_rt *s, int t);
void sigma_rt_mutex_init(struct sigma_rt *s, int m);
void sigma_rt_mutex_destroy(struct sigma_rt *s, int m);
void sigma_rt_mutex_take(struct sigma_rt *s, int t, int m);
void sigma_rt_mutex_give(struct sigma_rt *s, int t, int m);
/* t blocked taking m; call sigma_rt_task_unpend() when the wait ends. */
void sigma_rt_task_pend(struct sigma_rt *s, int t, int m);
void sigma_rt_task_unpend(struct sigma_rt *s, int t);
void sigma_rt_task_dl_set(struct sigma_rt *s, int t, int dl);

/* Refinement check: returns the number of divergences; out_* may be NULL. */
int sigma_rt_check(const struct sigma_rt *s, const struct sf_rt_adapter *a,
                   uint32_t *out_owner_div, uint32_t *out_alive_div,
                   uint32_t *out_base_div);

/* sigma_rt_check() plus lock_count, read through a target callback. */
int sigma_rt_check_ext(const struct sigma_rt *s, const struct sf_rt_adapter *a,
                       int (*kernel_lock_count)(int m),
                       uint32_t *out_owner_div, uint32_t *out_alive_div,
                       uint32_t *out_base_div, uint32_t *out_lockcnt_div);

/* I7: σ.task_pended_on[t] matches task_pended_on_mutex(t) for every task. */
int sigma_rt_check_wait_graph(const struct sigma_rt *s,
                               const struct sf_rt_adapter *a,
                               uint32_t *out_wait_div);

/* I6: σ.task_suspended[t] matches kernel_suspended(t) for every alive task. */
int sigma_rt_check_suspended(const struct sigma_rt *s,
                              const struct sf_rt_adapter *a,
                              bool (*kernel_suspended)(int t),
                              uint32_t *out_susp_div);

/* Op preconditions, read from σ only; true if the precondition holds.
 *   I10: a task that holds or waits on a mutex is not deleted.
 *   I11: a mutex is re-initialised only when σ has it dead. */
bool sigma_rt_op_abort_task_legal(const struct sigma_rt *s, int t);
bool sigma_rt_op_reinit_mutex_legal(const struct sigma_rt *s, int m);

/* Coverage signature of σ for sf_coverage_seen(); excludes suspended state. */
uint32_t sigma_rt_signature(const struct sigma_rt *s);

/* σ's own consistency, clauses C1-C5; returns the number of violations. */
int sigma_rt_self_check(const struct sigma_rt *s);

#endif /* SCHEDFUZZ_CORE_SIGMA_RT_H */
