/* schedfuzz - generic core utility implementations. */
#include <string.h>
#include "fuzz_core.h"

void sf_mut_bitflip(uint8_t *tc, uint8_t n, size_t step_size, sf_rng_t *r)
{
    if (n == 0) return;
    uint32_t step = sf_rng_range(r, 0, n - 1);
    uint32_t byte_in_step = 1 + sf_rng_range(r, 0, step_size - 2);
    uint32_t bit = sf_rng_range(r, 0, 7);
    tc[step * step_size + byte_in_step] ^= (uint8_t)(1u << bit);
}

void sf_mut_byte_overwrite(uint8_t *tc, uint8_t n, size_t step_size,
                           sf_rng_t *r)
{
    if (n == 0) return;
    uint32_t step = sf_rng_range(r, 0, n - 1);
    uint32_t byte_in_step = 1 + sf_rng_range(r, 0, step_size - 2);
    tc[step * step_size + byte_in_step] = (uint8_t)sf_rng_next(r);
}

void sf_mut_change_op(uint8_t *tc, uint8_t n, size_t step_size,
                      sf_rng_t *r, uint8_t n_ops)
{
    if (n == 0 || n_ops == 0) return;
    uint32_t step = sf_rng_range(r, 0, n - 1);
    tc[step * step_size + 0] = (uint8_t)sf_rng_range(r, 0, n_ops - 1);
}

int sf_mut_insert_step(uint8_t *tc, uint8_t *n_p, uint8_t max_n,
                       size_t step_size, sf_rng_t *r, uint8_t n_ops)
{
    uint8_t n = *n_p;
    if (n >= max_n || n_ops == 0) return 0;
    uint32_t at = sf_rng_range(r, 0, n);
    memmove(tc + (at + 1) * step_size,
            tc + at * step_size,
            (n - at) * step_size);
    uint8_t *slot = tc + at * step_size;
    slot[0] = (uint8_t)sf_rng_range(r, 0, n_ops - 1);
    for (size_t i = 1; i < step_size; i++)
        slot[i] = (uint8_t)sf_rng_next(r);
    *n_p = n + 1;
    return 1;
}

int sf_mut_remove_step(uint8_t *tc, uint8_t *n_p, size_t step_size,
                       sf_rng_t *r)
{
    uint8_t n = *n_p;
    if (n <= 1) return 0;
    uint32_t at = sf_rng_range(r, 0, n - 1);
    memmove(tc + at * step_size,
            tc + (at + 1) * step_size,
            (n - 1 - at) * step_size);
    *n_p = n - 1;
    return 1;
}

int sf_mut_dup_step(uint8_t *tc, uint8_t *n_p, uint8_t max_n,
                    size_t step_size, sf_rng_t *r)
{
    uint8_t n = *n_p;
    if (n == 0 || n >= max_n) return 0;
    uint32_t at = sf_rng_range(r, 0, n - 1);
    /* memmove leaves slot `at` intact, so `at` and `at+1` become identical. */
    memmove(tc + (at + 1) * step_size,
            tc + at * step_size,
            (size_t)(n - at) * step_size);
    *n_p = n + 1;
    return 1;
}

int sf_mut_swap_steps(uint8_t *tc, uint8_t n, size_t step_size, sf_rng_t *r)
{
    if (n < 2) return 0;
    uint32_t i = sf_rng_range(r, 0, n - 1);
    uint32_t j = sf_rng_range(r, 0, n - 1);
    if (i == j) return 0;
    for (size_t b = 0; b < step_size; b++) {
        uint8_t t8 = tc[i * step_size + b];
        tc[i * step_size + b] = tc[j * step_size + b];
        tc[j * step_size + b] = t8;
    }
    return 1;
}

/* Donor bounds; a step larger than SF_SPLICE_MAX_STEP makes splice a no-op. */
#define SF_SPLICE_MAX_STEPS 16
#define SF_SPLICE_MAX_STEP  12

int sf_mut_splice(uint8_t *tc, uint8_t n, size_t step_size, sf_rng_t *r,
                  const struct sf_op_table *t)
{
    if (n == 0 || t == NULL) return 0;
    if (step_size > SF_SPLICE_MAX_STEP) return 0;

    uint8_t donor[SF_SPLICE_MAX_STEPS * SF_SPLICE_MAX_STEP];
    uint8_t dn = (uint8_t)sf_rng_range(r, 1, SF_SPLICE_MAX_STEPS);
    /* Donor is freshly generated, not taken from the corpus. */
    sf_gen_tc(donor, dn, step_size, t, r, 70, 80);

    uint8_t k  = (uint8_t)sf_rng_range(r, 1, dn);
    uint32_t at = sf_rng_range(r, 0, n - 1);
    if (at + k > n) k = (uint8_t)(n - at);
    memcpy(tc + at * step_size, donor, (size_t)k * step_size);
    return 1;
}

/* Perturb a byte around its current value. */
static void sf__scale_byte(uint8_t *b, sf_rng_t *r)
{
    uint32_t num = sf_rng_range(r, 1, 4);
    uint32_t den = sf_rng_range(r, 1, 4);
    int32_t  v   = (int32_t)(((uint32_t)*b * num) / den);
    v += (int32_t)sf_rng_range(r, 0, 2) - 1;   /* -1/0/+1 so 0 and 1 can move */
    if (v < 0)   v = 0;
    if (v > 255) v = 255;
    *b = (uint8_t)v;
}

void sf_mut_byte_overwrite_typed(uint8_t *tc, uint8_t n, size_t step_size,
                                 sf_rng_t *r, const struct sf_op_table *t)
{
    if (n == 0 || step_size < 2) return;
    uint32_t step = sf_rng_range(r, 0, n - 1);
    uint32_t byte_in_step = 1 + sf_rng_range(r, 0, step_size - 2);
    size_t off = step * step_size + byte_in_step;

    int kind = SF_ARG_UNUSED;
    if (t && t->n_ops) {
        const struct sf_op_desc *d = &t->ops[tc[step * step_size] % t->n_ops];
        int argi = (int)byte_in_step - 1;
        if (argi < SF_OP_MAX_ARGS) kind = d->arg[argi];
    }

    if (kind == SF_ARG_PRIO || kind == SF_ARG_TIME_MS || kind == SF_ARG_RAW)
        sf__scale_byte(&tc[off], r);
    else
        tc[off] = (uint8_t)sf_rng_next(r);
}

void sf_mut_change_op_typed(uint8_t *tc, uint8_t n, size_t step_size,
                            sf_rng_t *r, const struct sf_op_table *t)
{
    if (n == 0 || t == NULL || t->n_ops == 0) return;
    uint32_t step = sf_rng_range(r, 0, n - 1);
    uint8_t cur = (uint8_t)(tc[step * step_size] % t->n_ops);
    const sf_argkind_t *sig = t->ops[cur].arg;

    uint8_t cand[SF_GEN_MAX_OPS];
    uint8_t nc = 0;
    for (uint8_t i = 0; i < t->n_ops && nc < SF_GEN_MAX_OPS; i++) {
        if (i == cur) continue;
        int same = 1;
        for (int a = 0; a < SF_OP_MAX_ARGS; a++)
            if (t->ops[i].arg[a] != sig[a]) { same = 0; break; }
        if (same) cand[nc++] = i;
    }
    if (nc == 0) return;
    tc[step * step_size] = cand[sf_rng_range(r, 0, nc - 1)];
}

void sf_mut_mix_typed(uint8_t *tc, uint8_t *n_p, uint8_t max_n,
                      size_t step_size, sf_rng_t *r,
                      const struct sf_op_table *t)
{
    uint8_t n_ops = t ? t->n_ops : 0;
    uint32_t n_mut = 1 + sf_rng_range(r, 0, 3);
    for (uint32_t k = 0; k < n_mut; k++) {
        if (*n_p == 0) break;
        switch (sf_rng_range(r, 0, 7)) {
        case 0: sf_mut_bitflip(tc, *n_p, step_size, r);                  break;
        case 1:
            if (t) sf_mut_byte_overwrite_typed(tc, *n_p, step_size, r, t);
            else   sf_mut_byte_overwrite(tc, *n_p, step_size, r);
            break;
        case 2:
            if (t) sf_mut_change_op_typed(tc, *n_p, step_size, r, t);
            else   sf_mut_change_op(tc, *n_p, step_size, r, n_ops);
            break;
        case 3: (void)sf_mut_insert_step(tc, n_p, max_n, step_size, r, n_ops); break;
        case 4: (void)sf_mut_remove_step(tc, n_p, step_size, r);         break;
        case 5: (void)sf_mut_dup_step(tc, n_p, max_n, step_size, r);     break;
        case 6: (void)sf_mut_swap_steps(tc, *n_p, step_size, r);         break;
        case 7: (void)sf_mut_splice(tc, *n_p, step_size, r, t);          break;
        }
    }
}

/* ---- Corpus ---- */

void sf_corpus_init(struct sf_corpus *c, uint8_t *entries_storage,
                    uint8_t *energy_storage, uint16_t entry_size,
                    uint8_t max_entries)
{
    c->entries     = entries_storage;
    c->energy      = energy_storage;
    c->entry_size  = entry_size;
    c->max_entries = max_entries;
    c->n           = 0;
}

void sf_corpus_add(struct sf_corpus *c, const void *tc, uint8_t initial_energy)
{
    if (c->n < c->max_entries) {
        memcpy(c->entries + c->n * c->entry_size, tc, c->entry_size);
        c->energy[c->n] = initial_energy;
        c->n++;
    } else {
        uint8_t worst = 0;
        for (uint8_t i = 1; i < c->max_entries; i++)
            if (c->energy[i] < c->energy[worst]) worst = i;
        memcpy(c->entries + worst * c->entry_size, tc, c->entry_size);
        c->energy[worst] = initial_energy;
    }
}

void *sf_corpus_get(struct sf_corpus *c, uint8_t idx)
{
    if (idx >= c->n) return (void *)0;
    if (c->energy[idx] > 0) c->energy[idx]--;
    return c->entries + idx * c->entry_size;
}

void *sf_corpus_get_weighted(struct sf_corpus *c, sf_rng_t *r,
                              uint8_t *out_idx)
{
    if (!c || c->n == 0) return (void *)0;
    uint32_t total = 0;
    for (uint8_t i = 0; i < c->n; i++) total += c->energy[i];
    if (total == 0) {
        /* All zero: fall back to uniform pick. */
        uint8_t i = (uint8_t)sf_rng_range(r, 0, c->n - 1);
        if (out_idx) *out_idx = i;
        return c->entries + i * c->entry_size;
    }
    uint32_t target = sf_rng_range(r, 0, total - 1);
    uint32_t cum = 0;
    for (uint8_t i = 0; i < c->n; i++) {
        cum += c->energy[i];
        if (target < cum) {
            if (c->energy[i] > 0) c->energy[i]--;
            if (out_idx) *out_idx = i;
            return c->entries + i * c->entry_size;
        }
    }
    /* Unreachable - guard for the compiler. */
    if (out_idx) *out_idx = 0;
    return c->entries;
}

/* ---- Generation ---- */

static uint8_t sf__pend_ops(const struct sf_op_table *t, uint8_t *out, uint8_t max)
{
    uint8_t n = 0;
    for (uint8_t i = 0; i < t->n_ops && n < max; i++)
        if (t->ops[i].may_block) out[n++] = i;
    return n;
}

static uint8_t sf__rekey_ops(const struct sf_op_table *t, uint8_t *out, uint8_t max)
{
    uint8_t n = 0;
    for (uint8_t i = 0; i < t->n_ops && n < max; i++)
        if (t->ops[i].may_reorder) out[n++] = i;
    return n;
}

static uint8_t sf__release_ops(const struct sf_op_table *t, uint8_t *out, uint8_t max)
{
    uint8_t n = 0;
    for (uint8_t i = 0; i < t->n_ops && n < max; i++)
        if (t->ops[i].may_release) out[n++] = i;
    return n;
}

/* Fill one step; force_mutex >= 0 pins every mutex argument to that slot. */
static void sf__fill_step(uint8_t *step, size_t step_size, uint8_t op,
                          const struct sf_op_table *t, sf_rng_t *r,
                          int force_mutex, int force_task,
                          uint8_t mutex_locality_pct,
                          uint8_t task_spread_pct, int *last_mutex, int *last_task)
{
    int n_mtx  = t->n_mutexes > 0 ? t->n_mutexes : 1;
    int n_task = t->n_tasks   > 0 ? t->n_tasks   : 1;
    const struct sf_op_desc *d = &t->ops[op % t->n_ops];
    step[0] = op;
    for (size_t j = 1; j < step_size; j++) {
        int argi = (int)j - 1;
        int kind = (argi < SF_OP_MAX_ARGS) ? d->arg[argi] : SF_ARG_UNUSED;
        int raw;
        switch (kind) {
        case SF_ARG_MUTEX:
            if (force_mutex >= 0) {
                raw = force_mutex;
            } else if (sf_rng_range(r, 0, 99) < mutex_locality_pct) {
                raw = *last_mutex;
            } else {
                raw = (int)sf_rng_range(r, 0, (uint32_t)n_mtx - 1);
                *last_mutex = raw;
            }
            break;
        case SF_ARG_TASK:
            if (force_task >= 0) {
                raw = force_task;
            } else if (n_task > 1 && sf_rng_range(r, 0, 99) < task_spread_pct) {
                int off = 1 + (int)sf_rng_range(r, 0, (uint32_t)(n_task - 2));
                raw = (*last_task + off) % n_task;
            } else {
                raw = (int)sf_rng_range(r, 0, (uint32_t)n_task - 1);
            }
            *last_task = raw;
            break;
        default:
            raw = (int)sf_rng_range(r, 0, 255);
            break;
        }
        step[j] = (uint8_t)raw;
    }
}

void sf_gen_tc(uint8_t *tc_bytes, uint8_t n_steps, size_t step_size,
               const struct sf_op_table *table, sf_rng_t *r,
               uint8_t mutex_locality_pct, uint8_t task_spread_pct)
{
    sf_gen_tc_ex(tc_bytes, n_steps, step_size, table, r,
                 mutex_locality_pct, task_spread_pct, SF_CONTENTION_BURST_PCT);
}

void sf_gen_tc_ex(uint8_t *tc_bytes, uint8_t n_steps, size_t step_size,
                  const struct sf_op_table *table, sf_rng_t *r,
                  uint8_t mutex_locality_pct, uint8_t task_spread_pct,
                  uint8_t burst_pct)
{
    if (!tc_bytes || !table || !table->ops || table->n_ops == 0 || step_size < 1)
        return;

    int n_mtx  = table->n_mutexes > 0 ? table->n_mutexes : 1;
    int n_task = table->n_tasks   > 0 ? table->n_tasks   : 1;
    int last_mutex = (int)sf_rng_range(r, 0, (uint32_t)n_mtx - 1);
    int last_task  = (int)sf_rng_range(r, 0, (uint32_t)n_task - 1);

    uint8_t pend[SF_GEN_MAX_OPS];
    uint8_t n_pend = sf__pend_ops(table, pend, (uint8_t)sizeof pend);
    uint8_t rekey[SF_GEN_MAX_OPS];
    uint8_t n_rekey = sf__rekey_ops(table, rekey, (uint8_t)sizeof rekey);
    uint8_t release[SF_GEN_MAX_OPS];
    uint8_t n_release = sf__release_ops(table, release, (uint8_t)sizeof release);

    uint8_t s = 0;
    while (s < n_steps) {
        /* Contention burst: a run of blocking ops naming one mutex slot. */
        uint8_t room = (uint8_t)(n_steps - s);
        if (n_pend > 0 && room >= 2 && sf_rng_range(r, 0, 99) < burst_pct) {
            int slot = (int)sf_rng_range(r, 0, (uint32_t)n_mtx - 1);
            last_mutex = slot;
            /* The first op acquires the mutex: len ops leave len-1 waiters. */
            uint8_t max_extra = room >= 5 ? 3 : (room >= 4 ? 2 : (room >= 3 ? 1 : 0));
            uint8_t len = (uint8_t)(2 + sf_rng_range(r, 0, max_extra));
            /* Tasks the burst names, for the follow-up and release steps. */
            int burst_tasks[6]; uint8_t n_bt = 0;
            for (uint8_t k = 0; k < len; k++) {
                uint8_t op = pend[sf_rng_range(r, 0, (uint32_t)n_pend - 1)];
                sf__fill_step(tc_bytes + (size_t)s * step_size, step_size, op,
                              table, r, slot, -1, mutex_locality_pct,
                              /* inside a burst the waiters must differ */ 100,
                              &last_mutex, &last_task);
                if (n_bt < (uint8_t)(sizeof burst_tasks / sizeof burst_tasks[0]))
                    burst_tasks[n_bt++] = last_task;
                s++;
            }
            /* Follow-up: a may_reorder op on one of the burst's tasks. */
            if (n_rekey > 0 && n_bt > 0 && s < n_steps
                && sf_rng_range(r, 0, 99) < SF_REKEY_AFTER_BURST_PCT) {
                uint8_t op = rekey[sf_rng_range(r, 0, (uint32_t)n_rekey - 1)];
                int who = burst_tasks[sf_rng_range(r, 0, (uint32_t)n_bt - 1)];
                sf__fill_step(tc_bytes + (size_t)s * step_size, step_size, op,
                              table, r, slot, who, mutex_locality_pct,
                              task_spread_pct, &last_mutex, &last_task);
                s++;
            }
            /* Release by the holder: burst_tasks[0], whose op took it. */
            if (n_release > 0 && n_bt > 0 && s < n_steps
                && sf_rng_range(r, 0, 99) < SF_RELEASE_AFTER_BURST_PCT) {
                uint8_t op = release[sf_rng_range(r, 0, (uint32_t)n_release - 1)];
                sf__fill_step(tc_bytes + (size_t)s * step_size, step_size, op,
                              table, r, slot, burst_tasks[0], mutex_locality_pct,
                              task_spread_pct, &last_mutex, &last_task);
                s++;
            }
            continue;
        }
        uint8_t op = (uint8_t)sf_rng_range(r, 0, (uint32_t)table->n_ops - 1);
        sf__fill_step(tc_bytes + (size_t)s * step_size, step_size, op, table, r,
                      -1, -1, mutex_locality_pct, task_spread_pct,
                      &last_mutex, &last_task);
        s++;
    }
}
