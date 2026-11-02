/* schedfuzz - target-independent operation IR for the RTOS harnesses: typed
 * argument slots, a declarative shadow effect, and a target primitive. */
#ifndef SCHEDFUZZ_CORE_OP_IR_H
#define SCHEDFUZZ_CORE_OP_IR_H

#include <stdint.h>
#include "sigma_rt.h"

#define SF_OP_MAX_ARGS 4

/* ---- Argument types ---- */
typedef enum {
    SF_ARG_UNUSED = 0,
    SF_ARG_TASK,        /* -> [0, n_tasks)            */
    SF_ARG_MUTEX,       /* -> [0, n_mutexes)          */
    SF_ARG_PRIO,        /* -> [prio_lo, prio_hi]      */
    SF_ARG_TIME_MS,     /* -> [0, time_max_ms]        */
    SF_ARG_RAW,         /* passed through unchanged   */
} sf_argkind_t;

/* ---- Shadow effects (one per sigma_rt transition) ---- */
typedef enum {
    SF_EFF_NONE = 0,        /* probes, yields, delays, nop */
    SF_EFF_TASK_CREATE,
    SF_EFF_TASK_ABORT,
    SF_EFF_TASK_PRIO_SET,
    SF_EFF_TASK_SUSPEND,
    SF_EFF_TASK_RESUME,
    SF_EFF_MUTEX_INIT,
    SF_EFF_MUTEX_DESTROY,
    SF_EFF_MUTEX_TAKE,
    SF_EFF_MUTEX_GIVE,
    SF_EFF_TASK_PEND,
    SF_EFF_TASK_UNPEND,
    /* Applied later by the harness, once the target reports the outcome. */
    SF_EFF_DEFERRED,
} sf_effect_t;

struct sf_op_decoded {
    int arg[SF_OP_MAX_ARGS];
};

/* Only SF_OP_OK applies the effect; SKIP: precondition false; FAIL: failed. */
#define SF_OP_OK    1
#define SF_OP_SKIP  0
#define SF_OP_FAIL (-1)

struct sf_op_desc {
    const char   *name;
    sf_argkind_t  arg[SF_OP_MAX_ARGS];
    sf_effect_t   effect;
    /* Indices into arg[] of the effect's operands; unused ones are ignored. */
    uint8_t       eff_task_arg;
    uint8_t       eff_mutex_arg;
    uint8_t       eff_val_arg;
    int (*perform)(const struct sf_op_decoded *a, void *ctx);
    /* Optional compound update; replaces `effect`, also only after SF_OP_OK. */
    void (*apply)(const struct sf_op_decoded *a, struct sigma_rt *sigma, void *ctx);

    /* Can leave a task on a mutex wait queue at the observation point. */
    uint8_t may_block;

    /* Can change a task's wait-queue ordering key. */
    uint8_t may_reorder;

    /* Releases a synchronization object, i.e. can wake a waiter. */
    uint8_t may_release;
};

struct sf_op_table {
    const struct sf_op_desc *ops;
    uint8_t n_ops;
    int n_tasks, n_mutexes;
    int prio_lo, prio_hi;
    int time_max_ms;
};

/* Decode raw argument bytes for op `opcode` into typed, in-range values. */
void sf_op_decode(const struct sf_op_table *t, uint8_t opcode,
                  const uint8_t *raw_args, struct sf_op_decoded *out);

/* Decode, perform, apply one step (sigma may be NULL); SKIP if no primitive. */
int sf_op_exec(const struct sf_op_table *t, uint8_t opcode,
               const uint8_t *raw_args, struct sigma_rt *sigma, void *ctx);

/* Apply a shadow effect directly, for SF_EFF_DEFERRED. */
void sf_op_apply_effect(struct sigma_rt *sigma, sf_effect_t eff,
                        int task, int mutex, int val);

/* Name of an opcode, or "?". */
const char *sf_op_name(const struct sf_op_table *t, uint8_t opcode);

#endif /* SCHEDFUZZ_CORE_OP_IR_H */
