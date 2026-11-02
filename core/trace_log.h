/* schedfuzz - per-iteration op trace and invariants over op sequences
 * (I12-I14).  Fixed-size buffer; ops past its end are dropped and counted. */
#ifndef SCHEDFUZZ_CORE_TRACE_LOG_H
#define SCHEDFUZZ_CORE_TRACE_LOG_H

#include <stdint.h>
#include <stdbool.h>

#define SF_TRACE_LOG_BUF  256u   /* entries per iter, 4 bytes each */

/* Coarse op class; a target that records a trace maps its ops onto these. */
typedef enum {
    SF_OP_NONE = 0,
    SF_OP_TASK_CREATE,
    SF_OP_TASK_DESTROY,         /* delete / abort */
    SF_OP_TASK_SUSPEND,
    SF_OP_TASK_RESUME,
    SF_OP_TASK_SETPRIO,
    SF_OP_MUTEX_CREATE,
    SF_OP_MUTEX_DESTROY,
    SF_OP_MUTEX_TAKE,
    SF_OP_MUTEX_GIVE,
    SF_OP_QUEUE_CREATE,
    SF_OP_QUEUE_DESTROY,
    SF_OP_OTHER,
    SF_OP__N,
} sf_op_kind_t;

struct sf_trace_entry {
    uint8_t  kind;       /* sf_op_kind_t */
    uint8_t  slot_a;     /* primary slot index (task / mutex / queue) */
    uint8_t  slot_b;     /* secondary (e.g. mutex for TAKE/GIVE) */
    uint8_t  _pad;
};

struct sf_trace_log {
    struct sf_trace_entry buf[SF_TRACE_LOG_BUF];
    uint16_t n;
};

static inline void sf_trace_log_reset(struct sf_trace_log *t)
{
    t->n = 0;
}

static inline void sf_trace_record(struct sf_trace_log *t,
                                    sf_op_kind_t kind,
                                    uint8_t slot_a, uint8_t slot_b)
{
    if (t->n >= SF_TRACE_LOG_BUF) return;
    t->buf[t->n].kind   = (uint8_t)kind;
    t->buf[t->n].slot_a = slot_a;
    t->buf[t->n].slot_b = slot_b;
    t->buf[t->n]._pad   = 0;
    t->n++;
}

/* I12: returns the number of slots with more creates than destroys. */
static inline int sf_trace_check_life_balanced(const struct sf_trace_log *t,
                                                sf_op_kind_t create_kind,
                                                sf_op_kind_t destroy_kind,
                                                uint8_t max_slots)
{
    int8_t balance[32];   /* large enough for RT_MAX_TASKS / MUTEXES */
    if (max_slots > 32) max_slots = 32;
    for (uint8_t s = 0; s < max_slots; s++) balance[s] = 0;
    for (uint16_t i = 0; i < t->n; i++) {
        const struct sf_trace_entry *e = &t->buf[i];
        if (e->slot_a >= max_slots) continue;
        if (e->kind == (uint8_t)create_kind)  balance[e->slot_a]++;
        if (e->kind == (uint8_t)destroy_kind) balance[e->slot_a]--;
    }
    int orphan = 0;
    for (uint8_t s = 0; s < max_slots; s++) if (balance[s] > 0) orphan++;
    return orphan;
}

/* I13: returns the number of (task, mutex) pairs with more takes than gives. */
static inline int sf_trace_check_lock_balanced(const struct sf_trace_log *t,
                                                uint8_t max_tasks,
                                                uint8_t max_mutexes)
{
    int8_t balance[16][16];
    if (max_tasks > 16) max_tasks = 16;
    if (max_mutexes > 16) max_mutexes = 16;
    for (uint8_t t1 = 0; t1 < max_tasks; t1++)
        for (uint8_t m = 0; m < max_mutexes; m++)
            balance[t1][m] = 0;
    for (uint16_t i = 0; i < t->n; i++) {
        const struct sf_trace_entry *e = &t->buf[i];
        if (e->slot_a >= max_tasks || e->slot_b >= max_mutexes) continue;
        if (e->kind == (uint8_t)SF_OP_MUTEX_TAKE) balance[e->slot_a][e->slot_b]++;
        if (e->kind == (uint8_t)SF_OP_MUTEX_GIVE) balance[e->slot_a][e->slot_b]--;
    }
    int orphan = 0;
    for (uint8_t t1 = 0; t1 < max_tasks; t1++)
        for (uint8_t m = 0; m < max_mutexes; m++)
            if (balance[t1][m] > 0) orphan++;
    return orphan;
}

/* I14: returns the number of tasks with more suspends than resumes. */
static inline int sf_trace_check_suspend_balanced(const struct sf_trace_log *t,
                                                   uint8_t max_tasks)
{
    int8_t balance[16];
    if (max_tasks > 16) max_tasks = 16;
    for (uint8_t s = 0; s < max_tasks; s++) balance[s] = 0;
    for (uint16_t i = 0; i < t->n; i++) {
        const struct sf_trace_entry *e = &t->buf[i];
        if (e->slot_a >= max_tasks) continue;
        if (e->kind == (uint8_t)SF_OP_TASK_SUSPEND) balance[e->slot_a]++;
        if (e->kind == (uint8_t)SF_OP_TASK_RESUME) balance[e->slot_a]--;
        if (e->kind == (uint8_t)SF_OP_TASK_DESTROY) balance[e->slot_a] = 0;
    }
    int leaked = 0;
    for (uint8_t s = 0; s < max_tasks; s++) if (balance[s] > 0) leaked++;
    return leaked;
}

#endif /* SCHEDFUZZ_CORE_TRACE_LOG_H */
