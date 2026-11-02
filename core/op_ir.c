/* schedfuzz - operation IR: decode, execute, apply the declared effect. */
#include "op_ir.h"

static int clamp_range(int v, int lo, int hi)
{
    if (hi < lo) return lo;
    if (v < lo) v = lo;
    if (v > hi) v = hi;
    return v;
}

/* Map raw into [lo, hi] by modulo, not saturation, so the spread stays flat. */
static int fold(int raw, int lo, int hi)
{
    if (hi <= lo) return lo;
    int span = hi - lo + 1;
    return lo + (raw % span);
}

void sf_op_decode(const struct sf_op_table *t, uint8_t opcode,
                  const uint8_t *raw_args, struct sf_op_decoded *out)
{
    for (int i = 0; i < SF_OP_MAX_ARGS; i++) out->arg[i] = 0;
    if (!t || !t->ops || t->n_ops == 0 || !out) return;

    const struct sf_op_desc *d = &t->ops[opcode % t->n_ops];
    for (int i = 0; i < SF_OP_MAX_ARGS; i++) {
        int raw = raw_args ? (int)raw_args[i] : 0;
        switch (d->arg[i]) {
        case SF_ARG_TASK:
            out->arg[i] = t->n_tasks   > 0 ? fold(raw, 0, t->n_tasks   - 1) : 0;
            break;
        case SF_ARG_MUTEX:
            out->arg[i] = t->n_mutexes > 0 ? fold(raw, 0, t->n_mutexes - 1) : 0;
            break;
        case SF_ARG_PRIO:
            out->arg[i] = fold(raw, t->prio_lo, t->prio_hi);
            break;
        case SF_ARG_TIME_MS:
            out->arg[i] = clamp_range(fold(raw, 0, t->time_max_ms),
                                      0, t->time_max_ms);
            break;
        case SF_ARG_RAW:
            out->arg[i] = raw;
            break;
        case SF_ARG_UNUSED:
        default:
            out->arg[i] = 0;
            break;
        }
    }
}

void sf_op_apply_effect(struct sigma_rt *sigma, sf_effect_t eff,
                        int task, int mutex, int val)
{
    if (!sigma) return;
    switch (eff) {
    case SF_EFF_TASK_CREATE:   sigma_rt_task_create  (sigma, task, val);  break;
    case SF_EFF_TASK_ABORT:    sigma_rt_task_abort   (sigma, task);       break;
    case SF_EFF_TASK_PRIO_SET: sigma_rt_task_prio_set(sigma, task, val);  break;
    case SF_EFF_TASK_SUSPEND:  sigma_rt_task_suspend (sigma, task);       break;
    case SF_EFF_TASK_RESUME:   sigma_rt_task_resume  (sigma, task);       break;
    case SF_EFF_MUTEX_INIT:    sigma_rt_mutex_init   (sigma, mutex);      break;
    case SF_EFF_MUTEX_DESTROY: sigma_rt_mutex_destroy(sigma, mutex);      break;
    case SF_EFF_MUTEX_TAKE:    sigma_rt_mutex_take   (sigma, task, mutex);break;
    case SF_EFF_MUTEX_GIVE:    sigma_rt_mutex_give   (sigma, task, mutex);break;
    case SF_EFF_TASK_PEND:     sigma_rt_task_pend    (sigma, task, mutex);break;
    case SF_EFF_TASK_UNPEND:   sigma_rt_task_unpend  (sigma, task);       break;
    case SF_EFF_DEFERRED:      /* applied when the target reports */
    case SF_EFF_NONE:
    default:                                                             break;
    }
}

int sf_op_exec(const struct sf_op_table *t, uint8_t opcode,
               const uint8_t *raw_args, struct sigma_rt *sigma, void *ctx)
{
    if (!t || !t->ops || t->n_ops == 0) return SF_OP_SKIP;
    const struct sf_op_desc *d = &t->ops[opcode % t->n_ops];

    struct sf_op_decoded a;
    sf_op_decode(t, opcode, raw_args, &a);

    if (!d->perform) return SF_OP_SKIP;
    int rc = d->perform(&a, ctx);

    /* The shadow effect applies only on success. */
    if (rc == SF_OP_OK) {
        if (d->apply) d->apply(&a, sigma, ctx);   /* compound: replaces effect */
        else sf_op_apply_effect(sigma, d->effect,
                                a.arg[d->eff_task_arg],
                                a.arg[d->eff_mutex_arg],
                                a.arg[d->eff_val_arg]);
    }
    return rc;
}

const char *sf_op_name(const struct sf_op_table *t, uint8_t opcode)
{
    if (!t || !t->ops || t->n_ops == 0) return "?";
    const char *n = t->ops[opcode % t->n_ops].name;
    return n ? n : "?";
}
