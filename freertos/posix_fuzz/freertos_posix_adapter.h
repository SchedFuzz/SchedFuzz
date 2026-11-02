/* freertos_posix_adapter.h -- sf_rt_adapter (core/rt_model.h) for the FreeRTOS
 * POSIX port: kernel queries where exposed, shadow state otherwise. */
#ifndef SCHEDFUZZ_FREERTOS_POSIX_ADAPTER_H
#define SCHEDFUZZ_FREERTOS_POSIX_ADAPTER_H

#include <stdint.h>
#include <stdbool.h>
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "rt_model.h"

#ifndef FRP_MAX_TASKS
#define FRP_MAX_TASKS    RT_MAX_TASKS
#endif
#ifndef FRP_MAX_MUTEXES
#define FRP_MAX_MUTEXES  RT_MAX_MUTEXES
#endif

enum {
    FRP_TASK_ALIVE     = 0,
    FRP_TASK_SUSPENDED = 1,
    FRP_TASK_DELETED   = 2,
};

/* Shadow state for queries the kernel doesn't expose directly. */
struct frp_shadow {
    int                n_tasks;
    int                n_mutexes;
    TaskHandle_t       task_handle    [FRP_MAX_TASKS];
    int                task_base_prio [FRP_MAX_TASKS];
    int                task_state     [FRP_MAX_TASKS]; /* FRP_TASK_* */
    int                task_pended_on [FRP_MAX_TASKS]; /* mutex slot, -1 if not pended */
    SemaphoreHandle_t  mutex_handle   [FRP_MAX_MUTEXES];
    int                mutex_alive    [FRP_MAX_MUTEXES];
};

extern struct frp_shadow    frp_shadow_g;
extern struct sf_rt_adapter frp_adapter_g;

/* Init / register. */
void frp_init             (int n_tasks, int n_mutexes);
void frp_register_task    (int slot, TaskHandle_t      h, int base_prio);
void frp_register_mutex   (int slot, SemaphoreHandle_t h);

/* Shadow update. */
void frp_task_set_state    (int slot, int state);
void frp_task_set_base_prio(int slot, int p);
void frp_task_set_pended   (int slot, int mutex_slot);  /* -1 = not pended */

/* Wait-list introspection (fr_queue_shim.c): the i-th waiter's TCB in kernel
 * queue order or NULL, and how many tasks are blocked taking the mutex. */
void *frq_mutex_waiter_at(QueueHandle_t xMutex, int i);
int   frq_mutex_waiter_count(QueueHandle_t xMutex);
/* One-traversal snapshot of the whole waiter list; -1 if longer than cap.
 * The caller must already hold the scheduler suspended. */
int   frq_mutex_waiters_snapshot(QueueHandle_t xMutex, void **out, int cap);

#endif /* SCHEDFUZZ_FREERTOS_POSIX_ADAPTER_H */
