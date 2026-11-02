/* schedfuzz - the abstract RT machine: tasks, mutexes, the wait graph and
 * priority, seen through a read-only per-target adapter. */
#ifndef SCHEDFUZZ_CORE_RT_MODEL_H
#define SCHEDFUZZ_CORE_RT_MODEL_H

#include <stdint.h>
#include <stdbool.h>

/* ----- Constants ----- */
#define RT_MAX_TASKS    16     /* per-target adapter may use fewer */
#define RT_MAX_MUTEXES  16

/* ----- Wait-queue observation ----- */
struct sf_waiter_obs {
    int slot;   /* task slot, or SF_WAITER_UNRESOLVED */
    int prio;   /* task_actual_prio at snapshot time */
    int dl;     /* task_actual_dl at snapshot time (0 if unsupported) */
};

/* NONE: no waiter at that index; UNRESOLVED: waiter not in the slot table. */
#define SF_WAITER_NONE        (-1)
#define SF_WAITER_UNRESOLVED  (-2)

/* ----- The RT adapter: read-only queries over live kernel state ----- */
struct sf_rt_adapter {
    int  n_tasks;
    int  n_mutexes;

    /* true: higher number = more urgent (FreeRTOS); false: lower (Zephyr). */
    bool higher_is_more_urgent;

    bool (*task_alive)(int t);
    int  (*task_base_prio)(int t);         /* user-requested, ignoring PI */
    int  (*task_actual_prio)(int t);       /* kernel's effective prio now */

    bool (*mutex_alive)(int m);
    int  (*mutex_owner_slot)(int m);       /* task t that owns m, or -1 */

    int  (*task_pended_on_mutex)(int t);   /* mutex t is blocked on, or -1 */

    /* ----- Optional callbacks (NULL if unsupported) ----- */

    /* Deadline tiebreak between equal priorities; lower = more urgent. */
    int  (*task_actual_dl)(int t);

    /* i-th waiter of m in kernel queue order; SF_WAITER_NONE past the end. */
    int  (*mutex_waiter_at)(int m, int i);

    /* true: deadlines are wrapping 32-bit stamps, compared modularly. */
    bool dl_is_modular32;

    /* Atomic, queue-ordered copy of m's waiters; returns count, < 0 on error. */
    int (*mutex_waiters_snapshot)(int m, struct sf_waiter_obs *out, int cap);
};

static inline bool rt_dl_more_urgent(bool modular32, int d1, int d2)
{
    if (modular32) {
        /* Defined only for stamps within 2^31 of each other. */
        return (int32_t)((uint32_t)d2 - (uint32_t)d1) > 0;
    }
    return d1 < d2;
}

/* Urgency comparison over a snapshot entry pair. */
static inline bool rt_waiter_more_urgent(const struct sf_rt_adapter *a,
                                         struct sf_waiter_obs w1,
                                         struct sf_waiter_obs w2)
{
    if (w1.prio != w2.prio)
        return a->higher_is_more_urgent ? (w1.prio > w2.prio) : (w1.prio < w2.prio);
    return rt_dl_more_urgent(a->dl_is_modular32, w1.dl, w2.dl);
}

#endif /* SCHEDFUZZ_CORE_RT_MODEL_H */
