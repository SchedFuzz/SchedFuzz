/* freertos_posix_adapter.c -- FreeRTOS sf_rt_adapter; see the header. */
#include <string.h>
#include "freertos_posix_adapter.h"

struct frp_shadow    frp_shadow_g;
struct sf_rt_adapter frp_adapter_g;

/* ---- Internal handle -> slot lookups ---- */

/* Live handle -> slot. Skips DELETED slots: a new task may reuse a handle. */
static int task_slot_of(TaskHandle_t h)
{
    for (int i = 0; i < frp_shadow_g.n_tasks; i++)
        if (frp_shadow_g.task_state[i] != FRP_TASK_DELETED &&
            frp_shadow_g.task_handle[i] == h) return i;
    return -1;
}

/* ---- Adapter callbacks ---- */

static bool fr_task_alive(int t)
{
    if (t < 0 || t >= frp_shadow_g.n_tasks) return false;
    return frp_shadow_g.task_state[t] != FRP_TASK_DELETED;
}

static int fr_task_base_prio(int t)   { return frp_shadow_g.task_base_prio[t]; }

static int fr_task_actual_prio(int t)
{
    if (frp_shadow_g.task_state[t] == FRP_TASK_DELETED) return -1;
    return (int)uxTaskPriorityGet(frp_shadow_g.task_handle[t]);
}

static bool fr_mutex_alive(int m)
{
    if (m < 0 || m >= frp_shadow_g.n_mutexes) return false;
    return frp_shadow_g.mutex_alive[m] != 0;
}

static int fr_mutex_owner_slot(int m)
{
    if (!fr_mutex_alive(m)) return -1;
    TaskHandle_t h = xSemaphoreGetMutexHolder(frp_shadow_g.mutex_handle[m]);
    return h ? task_slot_of(h) : -1;
}

static int fr_task_pended_on_mutex(int t)
{
    if (!fr_task_alive(t)) return -1;
    return frp_shadow_g.task_pended_on[t];
}

/* The i-th waiter on mutex m in kernel event-list order: a task slot,
 * SF_WAITER_NONE (-1), or SF_WAITER_UNRESOLVED for a waiter with no slot. */
static int fr_mutex_waiter_at(int m, int i)
{
    if (m < 0 || m >= frp_shadow_g.n_mutexes) return -1;
    if (!frp_shadow_g.mutex_alive[m])         return -1;
    void *tcb = frq_mutex_waiter_at(frp_shadow_g.mutex_handle[m], i);
    if (tcb == NULL) return SF_WAITER_NONE;
    int slot = task_slot_of((TaskHandle_t) tcb);
    return (slot < 0) ? SF_WAITER_UNRESOLVED : slot;
}

/* Wait-list snapshot, priorities read in the same traversal. The caller must
 * hold the scheduler suspended. */
static int fr_mutex_waiters_snapshot(int m, struct sf_waiter_obs *out, int cap)
{
    if (m < 0 || m >= frp_shadow_g.n_mutexes) return 0;
    if (!frp_shadow_g.mutex_alive[m])         return 0;

    void *tcbs[RT_MAX_TASKS];
    int room = (cap < RT_MAX_TASKS) ? cap : RT_MAX_TASKS;

    int n = frq_mutex_waiters_snapshot(frp_shadow_g.mutex_handle[m], tcbs, room);
    if (n < 0) return -1;                 /* longer than we can hold: judge none */

    for (int i = 0; i < n; i++) {
        int slot = task_slot_of((TaskHandle_t) tcbs[i]);
        out[i].slot = (slot < 0) ? SF_WAITER_UNRESOLVED : slot;
        out[i].prio = (slot < 0)
                    ? 0
                    : (int) uxTaskPriorityGet((TaskHandle_t) tcbs[i]);
        out[i].dl   = 0;                  /* no EDF dimension on this target */
    }
    return n;
}

/* ---- Init / register ---- */

void frp_init(int n_tasks, int n_mutexes)
{
    memset(&frp_shadow_g, 0, sizeof(frp_shadow_g));
    frp_shadow_g.n_tasks   = n_tasks;
    frp_shadow_g.n_mutexes = n_mutexes;
    /* Unregistered slots default to DELETED so the oracle skips them. */
    for (int i = 0; i < FRP_MAX_TASKS; i++) {
        frp_shadow_g.task_state    [i] = FRP_TASK_DELETED;
        frp_shadow_g.task_pended_on[i] = -1;
    }

    frp_adapter_g = (struct sf_rt_adapter){
        .n_tasks               = n_tasks,
        .n_mutexes             = n_mutexes,
        .higher_is_more_urgent = true,
        .task_alive            = fr_task_alive,
        .task_base_prio        = fr_task_base_prio,
        .task_actual_prio      = fr_task_actual_prio,
        .mutex_alive           = fr_mutex_alive,
        .mutex_owner_slot      = fr_mutex_owner_slot,
        .task_pended_on_mutex  = fr_task_pended_on_mutex,
        /* Optional callbacks; no deadline ones, as there is no EDF dimension. */
        .mutex_waiter_at       = fr_mutex_waiter_at,
        .dl_is_modular32       = false,
        .mutex_waiters_snapshot = fr_mutex_waiters_snapshot,
    };
}

void frp_register_task(int slot, TaskHandle_t h, int base_prio)
{
    frp_shadow_g.task_handle    [slot] = h;
    frp_shadow_g.task_base_prio [slot] = base_prio;
    frp_shadow_g.task_state     [slot] = FRP_TASK_ALIVE;
    frp_shadow_g.task_pended_on [slot] = -1;
}

void frp_register_mutex(int slot, SemaphoreHandle_t h)
{
    frp_shadow_g.mutex_handle[slot] = h;
    frp_shadow_g.mutex_alive [slot] = 1;
}

void frp_task_set_state    (int slot, int state) { frp_shadow_g.task_state    [slot] = state; }
void frp_task_set_base_prio(int slot, int p)     { frp_shadow_g.task_base_prio[slot] = p;     }
void frp_task_set_pended   (int slot, int m)     { frp_shadow_g.task_pended_on[slot] = m;     }
