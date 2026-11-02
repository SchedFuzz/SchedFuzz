/* zephyr_fuzz -- schedfuzz for Zephyr RTOS: generates typed op sequences over
 * thread and mutex slots, judges O_WQ and counts kernel faults in-guest.
 * Build and run: zephyr/run_fuzzer.sh. */
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/version.h>
#include <stdint.h>
#include <string.h>

/* ---- Slot pools ---- */
#define N_TASK_SLOTS   8
#define N_MUTEX_SLOTS  6

#define SLOT_STACK_SIZE 1024
K_THREAD_STACK_ARRAY_DEFINE(slot_stacks, N_TASK_SLOTS, SLOT_STACK_SIZE);
static struct k_thread slot_threads[N_TASK_SLOTS];
k_tid_t                 slot_tid[N_TASK_SLOTS];
int                     slot_alive[N_TASK_SLOTS];

struct k_mutex          slot_mutex[N_MUTEX_SLOTS];
int                     slot_mutex_alive[N_MUTEX_SLOTS];

/* ---- Oracle and self-check counters (model_zephyr.c) ---- */
extern int  oracle_waitq_stale;
extern int  oracle_obs_discarded;
extern int  oracle_wq_inspected;
extern int  oracle_obs_discarded_tc;
extern int  oracle_wq_cmp_disagree;
extern int  oracle_wq_signed_only;
extern int  oracle_wq_unresolved;
extern int  oracle_wq_overflow;
extern int  oracle_wq_setdiv;
extern int  oracle_struct_owner;
extern int  oracle_struct_wait;
extern int  oracle_struct_prio;
/* I10: aborts refused (not issued); I11: reinits of a live mutex (issued). */
static uint32_t z_abort_refused     = 0;
static uint32_t z_reinit_live_mutex = 0;

static struct sf_trace_log z_trace;
static uint32_t z_total_life_leaks = 0;
static uint32_t z_total_lock_leaks = 0;
static uint32_t z_total_susp_leaks = 0;
extern uint32_t sigma_owner_div, sigma_alive_div, sigma_base_div, sigma_lc_div, sigma_susp_div, sigma_wait_div;
extern uint32_t registry_hit_count(int idx);
extern void model_init_zephyr(void);
extern void zephyr_oracle_check(void);
extern void zephyr_oracle_reset_tc(void);
extern void model_apply_prio_set(int task_slot, int prio);

/* ---- Slot tasks ---- */
#define INSTR_NOP             0
#define INSTR_TAKE_MUTEX      1
#define INSTR_GIVE_MUTEX      2
#define INSTR_DELAY           3
#define INSTR_SUSPEND_SELF    4
#define INSTR_NESTED_TAKE     5   /* lower 4 bits = mtx1, upper 4 = mtx2 */
#define INSTR_TIMED_TAKE      6
#define INSTR_HOLD_TAKE       7

/* Per-task mailbox {instr, arg}: set by the fuzzer, polled by the slot task. */
static volatile uint8_t task_instr[N_TASK_SLOTS][2];

static void slot_task_entry(void *a, void *b, void *c)
{
    int slot = (int)(intptr_t)a;
    for (;;) {
        uint8_t op  = task_instr[slot][0];
        uint8_t arg = task_instr[slot][1];
        task_instr[slot][0] = INSTR_NOP;

        switch (op) {
        case INSTR_TAKE_MUTEX:
            if (arg < N_MUTEX_SLOTS && slot_mutex_alive[arg])
                k_mutex_lock(&slot_mutex[arg], K_MSEC(50));
            break;
        case INSTR_GIVE_MUTEX:
            if (arg < N_MUTEX_SLOTS && slot_mutex_alive[arg]) {
                /* Return value ignored (-EPERM when not the owner). */
                k_mutex_unlock(&slot_mutex[arg]);
            }
            break;
        case INSTR_DELAY:
            k_sleep(K_MSEC(1 + (arg & 0x7)));
            break;
        case INSTR_SUSPEND_SELF:
            k_thread_suspend(k_current_get());
            break;
        case INSTR_NESTED_TAKE: {
            int m1 = arg & 0xF;
            int m2 = (arg >> 4) & 0xF;
            if (m1 < N_MUTEX_SLOTS && slot_mutex_alive[m1])
                k_mutex_lock(&slot_mutex[m1], K_MSEC(20));
            if (m2 < N_MUTEX_SLOTS && slot_mutex_alive[m2] && m2 != m1)
                k_mutex_lock(&slot_mutex[m2], K_MSEC(20));
            break;
        }
        case INSTR_TIMED_TAKE:
            if (arg < N_MUTEX_SLOTS && slot_mutex_alive[arg])
                k_mutex_lock(&slot_mutex[arg], K_MSEC(2));
            break;
        case INSTR_HOLD_TAKE:
            /* Long timeout so the pend survives to the oracle check. */
            if (arg < N_MUTEX_SLOTS && slot_mutex_alive[arg])
                k_mutex_lock(&slot_mutex[arg], K_MSEC(300));
            break;
        default:
            k_sleep(K_MSEC(1));
            break;
        }
    }
}

/* ---- Testcases ---- */
#define TC_MAX 16
#define SC_ARGS 8

/* sf_mut_* treat each step as 9 raw bytes: op at offset 0, then args[8]. */
struct sc_step {
    uint8_t op;
    uint8_t args[SC_ARGS];
};
struct testcase {
    int n;
    struct sc_step step[TC_MAX];
};

#define OP_SLOT_TAKE_MUTEX     0
#define OP_SLOT_GIVE_MUTEX     1
#define OP_SLOT_DELAY          2
#define OP_SLOT_SUSPEND_SELF   3
#define OP_PRIO_SET            4
#define OP_DELETE              5
#define OP_CREATE              6
#define OP_NOP                 7
#define OP_SET_DEADLINE        8
#define OP_NESTED_TAKE         9
#define OP_SUSPEND_OTHER      10
#define OP_RESUME_OTHER       11
#define OP_TIMED_TAKE         12
#define OP_MUTEX_REINIT       13
#define OP_YIELD              14
#define OP_PRIO_GET_PROBE     15
#define OP_HOLD_TAKE          16
#define N_OPS                 17
/* All generated priorities are valid: -4..11 (PRIO_SET), 5..12 (CREATE). */

#include "fuzz_core.h"
#define xorshift32(s)        sf_xorshift32(s)
#define rnd(s, bound)        sf_rnd((s), (bound))

/* Tentative definition; initialised after the op primitives below. */
static struct sf_op_table Z_TABLE;

/* Locality knobs for sf_gen_tc; -D overridable. */
#ifndef SF_MUTEX_LOCALITY_PCT
#define SF_MUTEX_LOCALITY_PCT 70
#endif
#ifndef SF_TASK_SPREAD_PCT
#define SF_TASK_SPREAD_PCT    80
#endif

static void tc_gen_random(struct testcase *tc, uint32_t *s)
{
    sf_rng_t r; r.s = *s;
    tc->n = 4 + (int)sf_rng_range(&r, 0, TC_MAX - 5);
    sf_gen_tc((uint8_t *)tc->step, (uint8_t)tc->n, 1 + SC_ARGS,
              &Z_TABLE, &r, SF_MUTEX_LOCALITY_PCT, SF_TASK_SPREAD_PCT);
    *s = r.s;
}

#include "sigma_rt.h"
#include "crossdomain.h"
#include "coverage.h"
#include "op_ir.h"
#include "trace_log.h"
extern struct sigma_rt zephyr_sigma;
static int z_create_prio;   /* prio chosen by zp_create, read by its apply hook */
extern uint32_t sigma_owner_div, sigma_alive_div, sigma_base_div, sigma_lc_div, sigma_susp_div, sigma_wait_div;

#define CORPUS_MAX 32
static struct testcase corpus_storage[CORPUS_MAX];
static uint8_t          corpus_energy_storage[CORPUS_MAX];
static struct sf_corpus the_corpus;

static void corpus_init_storage(void)
{
    sf_corpus_init(&the_corpus,
                   (uint8_t *)corpus_storage,
                   corpus_energy_storage,
                   sizeof(struct testcase),
                   CORPUS_MAX);
}

static void tc_mutate_in_place(struct testcase *tc, uint32_t *s)
{
    sf_rng_t r = { .s = *s };
    uint8_t n = (uint8_t)tc->n;
    sf_mut_mix_typed((uint8_t *)tc->step, &n, TC_MAX, sizeof(struct sc_step),
                     &r, &Z_TABLE);
    tc->n = n;
    *s = r.s;
}

static void tc_pick(struct testcase *tc, uint32_t *s)
{
    if (the_corpus.n > 0 && rnd(s, 100) < 60) {
        /* Energy-weighted pick; uniform fallback once every energy has decayed. */
        sf_rng_t wr = { .s = *s };
        uint8_t pick_idx = 0;
        void *src = sf_corpus_get_weighted(&the_corpus, &wr, &pick_idx);
        *s = wr.s;
        if (src == NULL) src = sf_corpus_get(&the_corpus, (uint8_t)rnd(s, the_corpus.n));
        memcpy(tc, src, sizeof(*tc));
        tc_mutate_in_place(tc, s);
    } else {
        tc_gen_random(tc, s);
    }
}

#define corpus_n  the_corpus.n

static void corpus_add(const struct testcase *tc, int initial_energy)
{
    sf_corpus_add(&the_corpus, tc, (uint8_t)initial_energy);
}

/* ---- Dispatcher: sc_step -> Zephyr kernel calls ---- */
static void zp_seed_deadline(int slot);

static void harness_reset(void)
{
    /* Per-testcase clean slate (not a generated op, so I10 does not apply):
     * abort all slot tasks, reinit mutexes, recreate slots 0..2, resync sigma. */
    for (int i = 0; i < N_TASK_SLOTS; i++) {
        if (slot_alive[i]) { k_thread_abort(slot_tid[i]); slot_alive[i] = 0; }
        task_instr[i][0] = INSTR_NOP;
    }
    for (int m = 0; m < N_MUTEX_SLOTS; m++) { k_mutex_init(&slot_mutex[m]); slot_mutex_alive[m] = 1; }
    for (int i = 0; i < 3; i++) {
        slot_tid[i] = k_thread_create(&slot_threads[i], slot_stacks[i], SLOT_STACK_SIZE,
            slot_task_entry, (void *)(intptr_t)i, NULL, NULL, 7, 0, K_NO_WAIT);
        slot_alive[i] = 1;
        zp_seed_deadline(i);
        model_apply_prio_set(i, 7);
    }
    sigma_rt_init(&zephyr_sigma);
    for (int m = 0; m < N_MUTEX_SLOTS; m++) sigma_rt_mutex_init(&zephyr_sigma, m);
    for (int i = 0; i < 3; i++) sigma_rt_task_create(&zephyr_sigma, i, 7);
    k_sleep(K_MSEC(5));
}

/* ---- Op table (core/op_ir.h) ----
 * Args arrive decoded by type, so slot indices are in range; sigma is
 * stepped only after a primitive returns SF_OP_OK. */
static int zp_alive(int slot) { return slot_alive[slot]; }

static int zp_take(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0], mtx = a->arg[1];
    if (!zp_alive(slot)) return SF_OP_SKIP;
    task_instr[slot][0] = INSTR_TAKE_MUTEX;
    task_instr[slot][1] = mtx;
    sf_trace_record(&z_trace, SF_OP_MUTEX_TAKE, slot, mtx);
    return SF_OP_OK;
}
static void zp_take_apply(const struct sf_op_decoded *a, struct sigma_rt *sg, void *ctx)
{
    (void)ctx; int slot = a->arg[0], mtx = a->arg[1];
    /* Held by another task -> pend; free -> take sets the owner. */
    if (sg->mutex_owner[mtx] >= 0 && sg->mutex_owner[mtx] != slot)
        sigma_rt_task_pend(sg, slot, mtx);
    sigma_rt_mutex_take(sg, slot, mtx);
}

static int zp_hold_take(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0], mtx = a->arg[1];
    if (!zp_alive(slot)) return SF_OP_SKIP;
    task_instr[slot][0] = INSTR_HOLD_TAKE;
    task_instr[slot][1] = (uint8_t)mtx;
    sf_trace_record(&z_trace, SF_OP_MUTEX_TAKE, slot, mtx);
    /* Give the take time to acquire or pend before the next op. */
    k_sleep(K_MSEC(8));
    return SF_OP_OK;
}

static int zp_give(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0], mtx = a->arg[1];
    if (!zp_alive(slot)) return SF_OP_SKIP;
    sf_trace_record(&z_trace, SF_OP_MUTEX_GIVE, slot, mtx);
    task_instr[slot][0] = INSTR_GIVE_MUTEX;
    task_instr[slot][1] = mtx;
    return SF_OP_OK;
}
/* Record the requested (relative) deadline for the O_WQ witness. */
static void zp_set_deadline_apply(const struct sf_op_decoded *a,
                                  struct sigma_rt *sg, void *ctx)
{
    (void)ctx;
    int slot = a->arg[0];
    int dl   = (int)(((uint32_t)a->arg[1] << 8) | (uint32_t)a->arg[2]);
    sigma_rt_task_dl_set(sg, slot, dl);
}

static void zp_give_apply(const struct sf_op_decoded *a, struct sigma_rt *sg, void *ctx)
{
    (void)ctx; int slot = a->arg[0], mtx = a->arg[1];
    /* sigma predicts the highest-priority waiter wins. */
    int best_w = -1, best_pr = 0x7FFFFFFF;
    for (int w = 0; w < N_TASK_SLOTS; w++) {
        if (!sg->task_alive[w]) continue;
        if (sg->task_pended_on[w] != mtx) continue;
        int pr = sg->task_base[w];
        if (pr < best_pr) { best_pr = pr; best_w = w; }
    }
    if (best_w >= 0) sigma_rt_task_unpend(sg, best_w);
    sigma_rt_mutex_give(sg, slot, mtx);
    if (best_w >= 0) sigma_rt_mutex_take(sg, best_w, mtx);
}

static int zp_delay(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0];
    if (!zp_alive(slot)) return SF_OP_SKIP;
    task_instr[slot][0] = INSTR_DELAY;
    task_instr[slot][1] = (uint8_t)a->arg[1];
    return SF_OP_OK;
}

static int zp_suspend_self(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0];
    if (!zp_alive(slot)) return SF_OP_SKIP;
    task_instr[slot][0] = INSTR_SUSPEND_SELF;
    sf_trace_record(&z_trace, SF_OP_TASK_SUSPEND, slot, 0);
    return SF_OP_OK;
}

static int zp_prio_set(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0], prio = a->arg[1];
    if (!zp_alive(slot)) return SF_OP_SKIP;
    k_thread_priority_set(slot_tid[slot], prio);
    model_apply_prio_set(slot, prio);
    return SF_OP_OK;
}

static int zp_delete(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0];
    if (!zp_alive(slot)) return SF_OP_SKIP;
    /* I10: aborting a task that holds or awaits a mutex is refused. */
    if (!sigma_rt_op_abort_task_legal(&zephyr_sigma, slot)) {
        z_abort_refused++;
        return SF_OP_SKIP;
    }
    sf_trace_record(&z_trace, SF_OP_TASK_DESTROY, slot, 0);
    k_thread_abort(slot_tid[slot]);
    slot_alive[slot] = 0;
    return SF_OP_OK;
}

/* New slot threads start at deadline Z_DL_SEED, past the generated range. */
#define Z_DL_SEED 65536
static void zp_seed_deadline(int slot)
{
#ifdef CONFIG_SCHED_DEADLINE
    if (slot >= 0 && slot < N_TASK_SLOTS && slot_tid[slot])
        k_thread_deadline_set(slot_tid[slot], Z_DL_SEED);
#else
    (void)slot;
#endif
}

static int zp_create(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0];
    if (zp_alive(slot)) return SF_OP_SKIP;
    sf_trace_record(&z_trace, SF_OP_TASK_CREATE, slot, 0);
    int prio = 5 + (a->arg[1] & 0x7);           /* preemptible 5..12 */
    slot_tid[slot] = k_thread_create(
        &slot_threads[slot], slot_stacks[slot], SLOT_STACK_SIZE,
        slot_task_entry, (void *)(intptr_t)slot, NULL, NULL,
        prio, 0, K_NO_WAIT);
    slot_alive[slot] = 1;
    zp_seed_deadline(slot);
    model_apply_prio_set(slot, prio);
    z_create_prio = prio;
    return SF_OP_OK;
}
static void zp_create_apply(const struct sf_op_decoded *a, struct sigma_rt *sg, void *ctx)
{
    (void)ctx; sigma_rt_task_create(sg, a->arg[0], z_create_prio);
}

static int zp_set_deadline(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0];
    if (!zp_alive(slot)) return SF_OP_SKIP;
    /* Let slot instructions posted by earlier ops run before this op. */
    k_sleep(K_MSEC(12));
    int dl = (int)(((uint32_t)a->arg[1] << 8) | (uint32_t)a->arg[2]);
    k_thread_deadline_set(slot_tid[slot], dl);
    return SF_OP_OK;
}

static int zp_nested_take(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0], m1 = a->arg[1], m2 = a->arg[2];
    if (!zp_alive(slot) || m1 == m2) return SF_OP_SKIP;
    task_instr[slot][0] = INSTR_NESTED_TAKE;
    task_instr[slot][1] = (uint8_t)(m1 | (m2 << 4));
    return SF_OP_OK;
}
static void zp_nested_apply(const struct sf_op_decoded *a, struct sigma_rt *sg, void *ctx)
{
    (void)ctx; int slot = a->arg[0], m1 = a->arg[1], m2 = a->arg[2];
    if (slot_mutex_alive[m1]) {
        sigma_rt_mutex_take(sg, slot, m1);
        sf_trace_record(&z_trace, SF_OP_MUTEX_TAKE, (uint8_t)slot, (uint8_t)m1);
    }
    if (slot_mutex_alive[m2]) {
        sigma_rt_mutex_take(sg, slot, m2);
        sf_trace_record(&z_trace, SF_OP_MUTEX_TAKE, (uint8_t)slot, (uint8_t)m2);
    }
}

static int zp_suspend_other(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0], target = a->arg[1];
    if (target == slot || !zp_alive(target)) return SF_OP_SKIP;
    k_thread_suspend(slot_tid[target]);
    sf_trace_record(&z_trace, SF_OP_TASK_SUSPEND, target, 0);
    return SF_OP_OK;
}
static int zp_resume_other(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0], target = a->arg[1];
    if (target == slot || !zp_alive(target)) return SF_OP_SKIP;
    k_thread_resume(slot_tid[target]);
    sf_trace_record(&z_trace, SF_OP_TASK_RESUME, target, 0);
    return SF_OP_OK;
}

static int zp_timed_take(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0], mtx = a->arg[1];
    if (!zp_alive(slot)) return SF_OP_SKIP;
    task_instr[slot][0] = INSTR_TIMED_TAKE;
    task_instr[slot][1] = mtx;
    /* Not modelled: sigma is not stepped for a timed take. */
    return SF_OP_OK;
}

static int zp_mutex_reinit(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int mtx = a->arg[1];
    if (!slot_mutex_alive[mtx]) return SF_OP_SKIP;
    if (!sigma_rt_op_reinit_mutex_legal(&zephyr_sigma, mtx))
        z_reinit_live_mutex++;
    k_mutex_init(&slot_mutex[mtx]);
    return SF_OP_OK;
}

static int zp_yield(const struct sf_op_decoded *a, void *ctx)
{ (void)a; (void)ctx; k_yield(); return SF_OP_OK; }

static int zp_probe(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; int slot = a->arg[0];
    if (!zp_alive(slot)) return SF_OP_SKIP;
    volatile int pr = k_thread_priority_get(slot_tid[slot]);
    (void)pr;
    return SF_OP_OK;
}
static int zp_nop(const struct sf_op_decoded *a, void *ctx)
{ (void)a; (void)ctx; return SF_OP_OK; }

#define ZA_T  SF_ARG_TASK
#define ZA_M  SF_ARG_MUTEX
#define ZA_P  SF_ARG_PRIO
#define ZA_R  SF_ARG_RAW
#define ZA_X  SF_ARG_UNUSED

static const struct sf_op_desc Z_OPS[N_OPS] = {
 [OP_SLOT_TAKE_MUTEX]  = { "take",  {ZA_T,ZA_M,ZA_X,ZA_X}, SF_EFF_NONE, 0,1,0, zp_take,          zp_take_apply },
 [OP_SLOT_GIVE_MUTEX]  = { "give",  {ZA_T,ZA_M,ZA_X,ZA_X}, SF_EFF_NONE, 0,1,0, zp_give,          zp_give_apply, .may_release = 1 },
 [OP_SLOT_DELAY]       = { "delay", {ZA_T,ZA_R,ZA_X,ZA_X}, SF_EFF_NONE, 0,0,0, zp_delay,         NULL },
 [OP_SLOT_SUSPEND_SELF]= { "suspS", {ZA_T,ZA_X,ZA_X,ZA_X}, SF_EFF_TASK_SUSPEND,  0,0,0, zp_suspend_self, NULL },
 [OP_PRIO_SET]         = { "prio",  {ZA_T,ZA_P,ZA_X,ZA_X}, SF_EFF_TASK_PRIO_SET, 0,0,1, zp_prio_set,     NULL, .may_reorder = 1 },
 [OP_DELETE]           = { "del",   {ZA_T,ZA_X,ZA_X,ZA_X}, SF_EFF_TASK_ABORT,    0,0,0, zp_delete,       NULL },
 [OP_CREATE]           = { "new",   {ZA_T,ZA_R,ZA_X,ZA_X}, SF_EFF_NONE, 0,0,1, zp_create,        zp_create_apply },
 [OP_NOP]              = { "nop",   {ZA_X,ZA_X,ZA_X,ZA_X}, SF_EFF_NONE, 0,0,0, zp_nop,           NULL },
 [OP_SET_DEADLINE]     = { "dl",    {ZA_T,ZA_R,ZA_R,ZA_X}, SF_EFF_NONE, 0,0,0, zp_set_deadline,  zp_set_deadline_apply, .may_reorder = 1 },
 [OP_NESTED_TAKE]      = { "ntake", {ZA_T,ZA_M,ZA_M,ZA_X}, SF_EFF_NONE, 0,1,0, zp_nested_take,   zp_nested_apply },
 [OP_SUSPEND_OTHER]    = { "suspO", {ZA_T,ZA_T,ZA_X,ZA_X}, SF_EFF_TASK_SUSPEND,  1,0,0, zp_suspend_other, NULL },
 [OP_RESUME_OTHER]     = { "resO",  {ZA_T,ZA_T,ZA_X,ZA_X}, SF_EFF_TASK_RESUME,   1,0,0, zp_resume_other,  NULL },
 [OP_TIMED_TAKE]       = { "ttake", {ZA_T,ZA_M,ZA_X,ZA_X}, SF_EFF_NONE, 0,1,0, zp_timed_take,    NULL },
 [OP_MUTEX_REINIT]     = { "reinit",{ZA_T,ZA_M,ZA_X,ZA_X}, SF_EFF_MUTEX_INIT,    0,1,0, zp_mutex_reinit,  NULL },
 [OP_YIELD]            = { "yield", {ZA_X,ZA_X,ZA_X,ZA_X}, SF_EFF_NONE, 0,0,0, zp_yield,         NULL },
 [OP_PRIO_GET_PROBE]   = { "probe", {ZA_T,ZA_X,ZA_X,ZA_X}, SF_EFF_NONE, 0,0,0, zp_probe,         NULL },
 [OP_HOLD_TAKE]        = { "hold",  {ZA_T,ZA_M,ZA_X,ZA_X}, SF_EFF_NONE, 0,1,0, zp_hold_take,     zp_take_apply, .may_block = 1 },
};

static struct sf_op_table Z_TABLE = {
    .ops = Z_OPS, .n_ops = N_OPS,
    .n_tasks = N_TASK_SLOTS, .n_mutexes = N_MUTEX_SLOTS,
    .prio_lo = -4, .prio_hi = 11,     /* SF_ARG_PRIO = (raw & 0xF) - 4 */
    .time_max_ms = 255,
};

static void exec_step(const struct sc_step *st)
{
    sf_op_exec(&Z_TABLE, st->op, st->args, &zephyr_sigma, NULL);
    k_sleep(K_MSEC(2));  /* let the slot task observe the new instr */
}

/* ---- TIMESLICE_FAIRNESS probe (run outside the fuzz loop) ---- */
/* Two equal-prio preemptible threads count in tight loops for TS_PROBE_MS. */
#define TS_PROBE_MS    200
#define TS_PROBE_PRIO  8

static volatile uint32_t ts_count_a, ts_count_b;
static volatile int ts_probe_active;
static int ts_baseline_violation;
K_THREAD_STACK_DEFINE(ts_stack_a, 512);
K_THREAD_STACK_DEFINE(ts_stack_b, 512);
static struct k_thread ts_thread_a, ts_thread_b;

static void ts_probe_entry(void *which, void *b, void *c)
{
	(void)b; (void)c;
	volatile uint32_t *cnt = (which == 0) ? &ts_count_a : &ts_count_b;
	while (ts_probe_active) (*cnt)++;
}

static int ts_run_fairness(void)
{
	ts_count_a = ts_count_b = 0;
	/* Re-arm time slicing from the configured values. */
	k_sched_time_slice_set(CONFIG_TIMESLICE_SIZE, CONFIG_TIMESLICE_PRIORITY);
	ts_probe_active = 1;
	k_tid_t a = k_thread_create(&ts_thread_a, ts_stack_a, 512,
		ts_probe_entry, (void *)0, NULL, NULL,
		TS_PROBE_PRIO, 0, K_NO_WAIT);
	k_tid_t b = k_thread_create(&ts_thread_b, ts_stack_b, 512,
		ts_probe_entry, (void *)1, NULL, NULL,
		TS_PROBE_PRIO, 0, K_NO_WAIT);
	k_sleep(K_MSEC(TS_PROBE_MS));
	ts_probe_active = 0;
	k_sleep(K_MSEC(5));
	printk("  [ts] a=%u b=%u  a{prio=%d state=0x%02x} b{prio=%d state=0x%02x}\n",
	       ts_count_a, ts_count_b,
	       k_thread_priority_get(a), (unsigned)a->base.thread_state,
	       k_thread_priority_get(b), (unsigned)b->base.thread_state);
	printk("  [ts] slots:");
	for (int i = 0; i < N_TASK_SLOTS; i++) {
		if (!slot_alive[i]) continue;
		printk(" T%d{prio=%d state=0x%02x}", i,
		       k_thread_priority_get(slot_tid[i]),
		       (unsigned)slot_tid[i]->base.thread_state);
	}
	printk("\n");
	k_thread_abort(a);
	k_thread_abort(b);
	uint32_t lo = ts_count_a < ts_count_b ? ts_count_a : ts_count_b;
	uint32_t hi = ts_count_a > ts_count_b ? ts_count_a : ts_count_b;
	if (hi == 0) return 0;
	/* Fires if lo < 35% of hi (64-bit multiply: lo * 100 can exceed uint32). */
	return (((uint64_t)lo * 100u) / hi) < 35 ? 1 : 0;
}

/* ---- EDF_ORDER probe ---- */
/* Same-prio A and B resume together; B (earlier deadline) should run first. */
#define EDF_ROUNDS 8

static volatile uint32_t edf_seq;
static volatile uint32_t edf_a_first, edf_b_first;
static volatile int edf_run_phase;
K_THREAD_STACK_DEFINE(edf_stack_a, 512);
K_THREAD_STACK_DEFINE(edf_stack_b, 512);
static struct k_thread edf_thread_a, edf_thread_b;

static void edf_probe_entry(void *which, void *b, void *c)
{
	(void)b; (void)c;
	volatile uint32_t *slot = (which == 0) ? &edf_a_first : &edf_b_first;
	int last_phase = -1;
	while (1) {
		if (edf_run_phase != last_phase) {
			last_phase = edf_run_phase;
			if (last_phase < 0) k_thread_suspend(k_current_get());
			else {
				/* Claim edf_seq once per phase (0xFFFFFFFF = unset). */
				if (*slot == 0xFFFFFFFFu)
					*slot = edf_seq++;
			}
		}
		/* tight spin lets the scheduler tick observe us */
		for (int i = 0; i < 100; i++) __asm__ volatile("nop");
	}
}

static int edf_run_order(void)
{
	int violations = 0;
	edf_seq = 0;
	edf_a_first = edf_b_first = 0xFFFFFFFFu;
	edf_run_phase = -1;
	k_tid_t a = k_thread_create(&edf_thread_a, edf_stack_a, 512,
		edf_probe_entry, (void *)0, NULL, NULL,
		TS_PROBE_PRIO, 0, K_MSEC(2));
	k_tid_t b = k_thread_create(&edf_thread_b, edf_stack_b, 512,
		edf_probe_entry, (void *)1, NULL, NULL,
		TS_PROBE_PRIO, 0, K_MSEC(2));

	for (int round = 0; round < EDF_ROUNDS; round++) {
		edf_a_first = edf_b_first = 0xFFFFFFFFu;
		edf_seq = 0;
		k_thread_suspend(a);
		k_thread_suspend(b);
		k_thread_deadline_set(a, 1000000);
		k_thread_deadline_set(b,    1000);
		edf_run_phase = round;
		k_thread_resume(a);
		k_thread_resume(b);
		k_sleep(K_MSEC(20));
		k_thread_suspend(a);
		k_thread_suspend(b);
		edf_run_phase = -1;

		uint32_t a_seq = edf_a_first;
		uint32_t b_seq = edf_b_first;
		/* B should claim seq 0 (run first); A claims seq 1. */
		int violation = !(b_seq == 0 || (b_seq != 0xFFFFFFFFu && (a_seq == 0xFFFFFFFFu || b_seq < a_seq)));
		if (violation) violations++;
	}
	k_thread_abort(a);
	k_thread_abort(b);
	printk("  [edf] rounds=%d violations=%d\n", EDF_ROUNDS, violations);
	return violations > (EDF_ROUNDS / 2) ? 1 : 0;
}

/* ---- Fatal-error oracle ---- */
volatile int oracle_zephyr_fault = 0;

/* Overrides Zephyr's default handler: count the fault instead of halting. */
void k_sys_fatal_error_handler(unsigned int reason, const struct arch_esf *esf)
{
    (void)esf;
    oracle_zephyr_fault++;
    printk("[FAULT] reason=%u oracle_zephyr_fault=%d\n",
        reason, oracle_zephyr_fault);
    k_thread_abort(k_current_get());
}

/* ---- PHASE 2: reduction, run after the test phase ---- */
#ifndef SF_PEROP_SETTLE_MS
#define SF_PEROP_SETTLE_MS 20
#endif

#ifndef SF_REDUCE_MAX
#define SF_REDUCE_MAX 3          /* how many findings to reduce; 0 disables */
#endif

/* Oracle-kind bits. */
#define K_OWN      (1u << 2)
#define K_WAIT     (1u << 3)
#define K_PRIO     (1u << 4)
#define K_FAULT    (1u << 6)
#define K_WAITQ    (1u << 7)
#define K_SOWN     (1u << 8)
#define K_SLC      (1u << 9)
#define K_SWAIT    (1u << 10)
#define K_NBITS    11

static const char *kind_name(uint32_t bit)
{
    switch (bit) {
    case K_OWN:     return "STRUCT_OWN";
    case K_WAIT:    return "STRUCT_WAIT";
    case K_PRIO:    return "STRUCT_PRIO";
    case K_FAULT:   return "FAULT";
    case K_WAITQ:   return "WAITQ_STALE";
    case K_SOWN:    return "SIGMA_OWNER";
    case K_SLC:     return "SIGMA_LC";
    case K_SWAIT:   return "SIGMA_WAIT";
    default:        return "?";
    }
}

static void print_kinds(uint32_t m)
{
    if (!m) { printk("none"); return; }
    int first = 1;
    for (int b = 0; b < K_NBITS; b++) {
        uint32_t bit = 1u << b;
        if (m & bit) { printk("%s%s", first ? "" : "+", kind_name(bit)); first = 0; }
    }
}

/* Replay one testcase as the phase-1 loop does; return the kinds it fires. */
static uint32_t run_tc_kinds(const struct testcase *tc)
{
    zephyr_oracle_reset_tc();
    harness_reset();
    int ow_b = oracle_struct_owner,  wa_b = oracle_struct_wait;
    int pr_b = oracle_struct_prio;
    int fa_b = oracle_zephyr_fault,  wq_b = oracle_waitq_stale;
    uint32_t so_b = sigma_owner_div, sl_b = sigma_lc_div, sw_b = sigma_wait_div;

    /* SF_PEROP_CHECK (default off): settle, then check, after every op (slot
     * tasks run their instructions asynchronously). */
    for (int s = 0; s < tc->n; s++) {
        exec_step(&tc->step[s]);
#if defined(SF_PEROP_CHECK) && SF_PEROP_CHECK
        k_sleep(K_MSEC(SF_PEROP_SETTLE_MS));
        zephyr_oracle_check();
#endif
    }
    k_sleep(K_MSEC(100));
    zephyr_oracle_check();

    uint32_t m = 0;
    if (oracle_struct_owner  > ow_b) m |= K_OWN;
    if (oracle_struct_wait   > wa_b) m |= K_WAIT;
    if (oracle_struct_prio   > pr_b) m |= K_PRIO;
    if (oracle_zephyr_fault  > fa_b) m |= K_FAULT;
    if (oracle_waitq_stale   > wq_b) m |= K_WAITQ;
    if (sigma_owner_div      > so_b) m |= K_SOWN;
    if (sigma_lc_div         > sl_b) m |= K_SLC;
    if (sigma_wait_div       > sw_b) m |= K_SWAIT;
    return m;
}

static struct testcase finding_tc[SF_REDUCE_MAX > 0 ? SF_REDUCE_MAX : 1];
static uint32_t        finding_mask[SF_REDUCE_MAX > 0 ? SF_REDUCE_MAX : 1];
static int             finding_iter[SF_REDUCE_MAX > 0 ? SF_REDUCE_MAX : 1];
static int             n_findings;

/* Drop-one-step delta debugging to a fixpoint; no recorded kind may be lost. */
static void reduce_one(struct testcase *cur, uint32_t want, uint32_t *out_mask)
{
    uint32_t cur_mask = want;
    int improved = 1;
    while (improved && cur->n > 1) {
        improved = 0;
        for (int d = 0; d < cur->n; d++) {
            struct testcase cand;
            cand.n = cur->n - 1;
            int j = 0;
            for (int s = 0; s < cur->n; s++) {
                if (s == d) continue;
                cand.step[j++] = cur->step[s];
            }
            uint32_t m = run_tc_kinds(&cand) & want;
            if ((m & cur_mask) == cur_mask) {
                *cur = cand;
                cur_mask = m;
                improved = 1;
                break;
            }
        }
    }
    *out_mask = cur_mask;
}

static void reduction_phase(void)
{
#if SF_REDUCE_MAX > 0
    printk("\n=== PHASE 2: reduction (%d finding(s); separate from testing) ===\n",
           n_findings);
    if (n_findings == 0) {
        printk("  (nothing recorded to reduce)\n");
        return;
    }
    for (int i = 0; i < n_findings; i++) {
        struct testcase cur = finding_tc[i];
        uint32_t verified = 0;
        int before = cur.n;
        reduce_one(&cur, finding_mask[i], &verified);
        printk("\n  it=%d: %d -> %d steps; replay-verified kinds=",
               finding_iter[i], before, cur.n);
        print_kinds(verified);
        uint32_t lost = finding_mask[i] & ~verified;
        if (lost) { printk("  (NOT preserved: "); print_kinds(lost); printk(")"); }
        printk("\n");
        for (int s = 0; s < cur.n; s++) {
            printk("      %-6s args=%u,%u,%u\n",
                   sf_op_name(&Z_TABLE, cur.step[s].op),
                   cur.step[s].args[0], cur.step[s].args[1], cur.step[s].args[2]);
        }
    }
#else
    printk("\n=== PHASE 2: reduction DISABLED (SF_REDUCE_MAX=0) ===\n");
#endif
}

/* ---- Main fuzz loop ---- */
int main(void)
{
    printk("=== Zephyr %s schedfuzz SMP=%d ===\n", KERNEL_VERSION_STRING,
           CONFIG_MP_MAX_NUM_CPUS);
    printk("=== Zephyr schedfuzz harness ===\n");
    printk("    slots: tasks=%d mutexes=%d\n", N_TASK_SLOTS, N_MUTEX_SLOTS);

    for (int i = 0; i < N_MUTEX_SLOTS; i++) {
        k_mutex_init(&slot_mutex[i]);
        slot_mutex_alive[i] = 1;
    }
    for (int i = 0; i < 3; i++) {
        slot_tid[i] = k_thread_create(
            &slot_threads[i], slot_stacks[i], SLOT_STACK_SIZE,
            slot_task_entry, (void *)(intptr_t)i, NULL, NULL,
            7, 0, K_NO_WAIT);
        slot_alive[i] = 1;
        zp_seed_deadline(i);
    }

    model_init_zephyr();
    corpus_init_storage();

    printk("\n  [ts-baseline] measuring time-slice fairness before the campaign\n");
    ts_baseline_violation = ts_run_fairness();
    printk("  corpus seeded with %d testcases (NO SEEDS -- everything below is "
           "generated)\n", corpus_n);

#ifdef SF_N_ITERS
    int n_iters = SF_N_ITERS;
#else
    int n_iters = 50;   /* smoke-run default */
#endif
    int total_hits = 0;
    int hits_fault = 0;
    int fault_baseline = oracle_zephyr_fault;
    int sigma_self_violations = 0;
    struct sf_xdom xdom = {0};
    static struct sf_coverage zcov;
    sf_coverage_init(&zcov);

    for (int it = 0; it < n_iters; it++) {
        /* Seed from SF_SEED_BASE and the iteration index (-D overridable). */
#ifndef SF_SEED_BASE
#define SF_SEED_BASE 0xCAFE0000u
#endif
        uint32_t seed = (uint32_t)SF_SEED_BASE ^ (uint32_t)(it * 0x9e3779b9u);
        struct testcase tc;
        tc_pick(&tc, &seed);
        zephyr_oracle_reset_tc();
        harness_reset();
        int own_before  = oracle_struct_owner;
        uint32_t sigma_owner_before = sigma_owner_div;
        uint32_t sigma_lc_before    = sigma_lc_div;
        uint32_t sigma_wait_before  = sigma_wait_div;
        int wait_before = oracle_struct_wait;
        int prio_before = oracle_struct_prio;
        int wq_before   = oracle_waitq_stale;

        printk("  it=%d seed=0x%08x steps=%d", it, seed, tc.n);

        for (int s = 0; s < tc.n; s++) {
            exec_step(&tc.step[s]);
#if defined(SF_PEROP_CHECK) && SF_PEROP_CHECK
            k_sleep(K_MSEC(SF_PEROP_SETTLE_MS));
            zephyr_oracle_check();
#endif
        }
        /* Settle so slot tasks finish their pending instructions first. */
        k_sleep(K_MSEC(100));
        zephyr_oracle_check();
        int own_delta  = oracle_struct_owner - own_before;
        int wait_delta = oracle_struct_wait  - wait_before;
        int prio_delta = oracle_struct_prio  - prio_before;
        int fault_delta = oracle_zephyr_fault - fault_baseline;
        fault_baseline = oracle_zephyr_fault;

        /* An iteration is cross-domain when >= 2 distinct domains fired. */
        uint32_t sigma_owner_delta = sigma_owner_div - sigma_owner_before;
        uint32_t sigma_lc_delta    = sigma_lc_div    - sigma_lc_before;
        uint32_t sigma_wait_delta  = sigma_wait_div  - sigma_wait_before;

        sf_xdom_reset_iter(&xdom);
        sf_xdom_record_delta(&xdom, SF_DOMAIN_SINGLE_FIELD, own_delta);
        sf_xdom_record_delta(&xdom, SF_DOMAIN_SINGLE_FIELD, wait_delta);
        sf_xdom_record_delta(&xdom, SF_DOMAIN_SINGLE_FIELD, prio_delta);
        sf_xdom_record_delta(&xdom, SF_DOMAIN_KERNEL_ASSERT, fault_delta);
        sf_xdom_record_delta(&xdom, SF_DOMAIN_REFINEMENT,   (int)sigma_owner_delta);
        sf_xdom_record_delta(&xdom, SF_DOMAIN_REFINEMENT,   (int)sigma_lc_delta);
        sf_xdom_record_delta(&xdom, SF_DOMAIN_REFINEMENT,   (int)sigma_wait_delta);
        bool is_xdom = sf_xdom_close_iter(&xdom);

        /* Cumulative O_WQ counters on every iteration line (wqp = pairs
         * judged); run_fuzzer.sh takes its phase-1 totals from them. */
        printk(" wqp=%d", oracle_wq_inspected);
        if (oracle_wq_signed_only)  printk(" wqSIGNEDONLY=%d", oracle_wq_signed_only);
        if (oracle_wq_cmp_disagree) printk(" wqCMPDIS=%d", oracle_wq_cmp_disagree);
        if (oracle_wq_unresolved)   printk(" wqUNRES=%d", oracle_wq_unresolved);
        if (oracle_wq_overflow)     printk(" wqOVF=%d", oracle_wq_overflow);
        if (oracle_wq_setdiv)       printk(" wqSETDIV=%d", oracle_wq_setdiv);

        int wq_delta = oracle_waitq_stale - wq_before;

        /* A hit is a kernel fault, or O_WQ on an accepted observation;
         * structural and sigma deltas are self-checks and do not count. */
        bool hit = (fault_delta > 0)
                || (!oracle_obs_discarded_tc && wq_delta > 0);
        if (hit) {
            total_hits++;
            printk(" HIT");
            if (own_delta)     {                 printk(" S_OWN+%d", own_delta); }
            if (wait_delta)    {                 printk(" S_WAIT+%d", wait_delta); }
            if (prio_delta)    {                 printk(" S_PRIO+%d", prio_delta); }
            if (wq_delta)      {                 printk(" WAITQ+%d", wq_delta); }
            if (fault_delta)   { hits_fault++;   printk(" FAULT+%d", fault_delta); }
            if (is_xdom) printk(" [X-DOMAIN]");
            printk("\n");
            corpus_add(&tc, is_xdom ? 32 : 16);
#if SF_REDUCE_MAX > 0
            /* Record only; reduction_phase() runs after the test phase. */
            if (n_findings < SF_REDUCE_MAX) {
                uint32_t m = 0;
                if (own_delta)     m |= K_OWN;
                if (wait_delta)    m |= K_WAIT;
                if (prio_delta)    m |= K_PRIO;
                if (wq_delta)      m |= K_WAITQ;
                if (fault_delta)   m |= K_FAULT;
                if (sigma_owner_delta) m |= K_SOWN;
                if (sigma_lc_delta)    m |= K_SLC;
                if (sigma_wait_delta)  m |= K_SWAIT;
                if (m) {
                    finding_tc[n_findings]   = tc;
                    finding_mask[n_findings] = m;
                    finding_iter[n_findings] = it;
                    n_findings++;
                }
            }
#endif
        }
        sigma_self_violations += sigma_rt_self_check(&zephyr_sigma);
        /* Trace invariants (I12 / I13 / I14) over this iter's op log. */
        z_total_life_leaks += sf_trace_check_life_balanced(&z_trace,
            SF_OP_TASK_CREATE, SF_OP_TASK_DESTROY, N_TASK_SLOTS);
        z_total_lock_leaks += sf_trace_check_lock_balanced(&z_trace,
            N_TASK_SLOTS, N_MUTEX_SLOTS);
        z_total_susp_leaks += sf_trace_check_suspend_balanced(&z_trace,
            N_TASK_SLOTS);
        sf_trace_log_reset(&z_trace);
        /* A new sigma signature adds the testcase at low energy. */
        int is_novel_sig = (sf_coverage_seen(&zcov, sigma_rt_signature(&zephyr_sigma)) == 0);
        if (!hit && is_novel_sig) {
            printk(" ok NOVEL+corpus\n");
            corpus_add(&tc, 8);
        } else if (!hit) {
            printk(" ok\n");
        }
    }
    printk("  --- PHASE 1 (testing) complete ---\n");
    printk("  corpus size at end: %d\n", corpus_n);
    printk("  cross-domain hits: %u (testcases that fired 2+ oracle domains)\n",
           (unsigned)xdom.total_crossdomain_iters);
    printk("  σ-self-viol:       %d (fuzzer-side σ-update bug; SHOULD be 0)\n",
           sigma_self_violations);
    printk("  unique sigs:       %u (coverage proxy via core/coverage.h)\n",
           (unsigned)sf_coverage_count(&zcov));

    /* PHASE 2 runs after phase 1 and before the end-of-run probes. */
    reduction_phase();

    printk("\n  [ts-end] (same probe, after the campaign)\n");
    int ts_violation_pre = ts_baseline_violation;
    int ts_violation = ts_run_fairness();

    printk("\n  [ts-noslots] (same probe, after aborting every leftover slot thread)\n");
    for (int i = 0; i < N_TASK_SLOTS; i++) {
        if (slot_alive[i]) { k_thread_abort(slot_tid[i]); slot_alive[i] = 0; }
    }
    k_sleep(K_MSEC(20));
    int ts_violation_noslots = ts_run_fairness();
    int edf_violation = edf_run_order();

    printk("\n=== aggregate: %d/%d iters triggered an oracle ===\n",
        total_hits, n_iters);
    printk("  STRUCT_OWN : %d   <- D2 single-field: owner pended on its own mutex\n", oracle_struct_owner);
    printk("  STRUCT_WAIT: %d   <- D2 single-field: dangling pended_on\n", oracle_struct_wait);
    printk("  STRUCT_PRIO: %d   <- D2 single-field: actual_prio out of [-4,15]\n", oracle_struct_prio);

    printk("\n=== seL4-style op pre-condition counters ===\n");
    printk("  I10 abort refused          : %u (target has an outstanding lock operation; an abort releases no mutex; not issued)\n",
        (unsigned)z_abort_refused);
    printk("  I11 reinit of a live mutex : %u (issued)\n",
        (unsigned)z_reinit_live_mutex);

    printk("\n=== trace invariants (per-iter temporal, I12/I13/I14) ===\n");
    printk("  I12 life-leaked iters     : %u (create without matching destroy)\n",
        (unsigned)z_total_life_leaks);
    printk("  I13 lock-leaked iters     : %u (take without matching give)\n",
        (unsigned)z_total_lock_leaks);
    printk("  I14 susp-leaked iters     : %u (suspend without resume/destroy)\n",
        (unsigned)z_total_susp_leaks);
    printk("  FAULT      : %d   <- D1 kernel-assert: assert/oops/stack-sentinel\n", hits_fault);
    /* The verdict is the run with the leftover slot threads aborted. */
    printk("  TIMESLICE  : %d   <- D4 inter-field: same-prio fairness <35%%\n",
           ts_violation_noslots);
    printk("               context: %d with the campaign's idle workers still "
           "polling, %d on a clean boot", ts_violation, ts_violation_pre);
    if (ts_violation != ts_violation_pre &&
        ts_violation_noslots == ts_violation_pre)
        printk(" -- the probe discriminates, and the\n"
               "               difference is the harness's 1 ms poll, not the kernel.");
    printk("\n");
    if (ts_violation && !ts_violation_pre)
        printk("  !! the probe is fair on a clean boot and unfair after the "
               "campaign: this measures accumulated state, NOT the kernel's "
               "time-slicing, and must not be cited as a silent control.\n");
    printk("  EDF_ORDER  : %d   <- D4 inter-field: earlier deadline didn't run first\n", edf_violation);
    printk("  WAITQ_STALE: %d   <- D4 inter-field: wait_q out of urgency order (O_WQ)\n", oracle_waitq_stale);
    printk("               judged on %d adjacent (prev,cur) pair(s)", oracle_wq_inspected);
    if (oracle_wq_setdiv)
        printk("; %d mutex(es) NOT judged: observed waiter set != sigma's", oracle_wq_setdiv);
    if (oracle_wq_unresolved)
        printk("; %d NOT judged: a waiter had no slot", oracle_wq_unresolved);
    if (oracle_wq_overflow)
        printk("; %d NOT judged: queue longer than the snapshot buffer", oracle_wq_overflow);
    printk("\n");
    printk("  obs discarded by self-check: %d  (O_WQ NOT evaluated on those)\n",
           oracle_obs_discarded);
    printk("\n=== sigma-refinement (D3 - core/sigma_rt) ===\n");
    printk("  SIGMA_OWNER: %u   <- mutex.owner sigma vs kernel mismatch\n",
        (unsigned)sigma_owner_div);
    printk("  SIGMA_ALIVE: %u   <- task alive sigma vs kernel mismatch\n",
        (unsigned)sigma_alive_div);
    printk("  SIGMA_BASE : %u   <- task base prio sigma vs kernel mismatch\n",
        (unsigned)sigma_base_div);
    printk("  SIGMA_LC   : %u   <- mutex lock_count sigma vs kernel mismatch\n",
        (unsigned)sigma_lc_div);
    printk("  SIGMA_SUSP : %u   <- task suspended state sigma vs kernel mismatch\n",
        (unsigned)sigma_susp_div);
    printk("  SIGMA_WAIT : %u   <- task pended_on sigma vs kernel mismatch (I7)\n",
        (unsigned)sigma_wait_div);
    /* registry_hit_count() indices 0..2: RT_INV_OWNER, WAIT, PRIO. */
    printk("\n=== registry cross-check (core/rt_invariants) ===\n");
    printk("  registry[OWNER] = %u   (manual STRUCT_OWN=%d)\n",
        (unsigned)registry_hit_count(0), oracle_struct_owner);
    printk("  registry[WAIT ] = %u   (manual STRUCT_WAIT=%d)\n",
        (unsigned)registry_hit_count(1), oracle_struct_wait);
    printk("  registry[PRIO ] = %u   (manual STRUCT_PRIO=%d)\n",
        (unsigned)registry_hit_count(2), oracle_struct_prio);

    extern void model_zephyr_per_domain_counts(uint32_t out[SF_DOMAIN__N]);
    uint32_t per_domain[SF_DOMAIN__N];
    model_zephyr_per_domain_counts(per_domain);
    per_domain[SF_DOMAIN_KERNEL_ASSERT] += (uint32_t)hits_fault;
    per_domain[SF_DOMAIN_INTER_FIELD]   += (uint32_t)ts_violation_noslots
                                         + (uint32_t)edf_violation;
    printk("\n=== per-domain counts (the counts above, by domain label) ===\n");
    printk("  D1 kernel-assert : %u   (FAULT)\n",
           (unsigned)per_domain[SF_DOMAIN_KERNEL_ASSERT]);
    printk("  D2 single-field  : %u   (registry OWNER+WAIT+PRIO)\n",
           (unsigned)per_domain[SF_DOMAIN_SINGLE_FIELD]);
    printk("  D3 refinement    : %u   (SIGMA_*)\n",
           (unsigned)per_domain[SF_DOMAIN_REFINEMENT]);
    printk("  D4 inter-field   : %u   (TIMESLICE+EDF_ORDER+WAITQ_STALE)\n",
           (unsigned)per_domain[SF_DOMAIN_INTER_FIELD]);

    /* End-of-run marker: run_fuzzer.sh stops qemu on this line. */
    printk("=== fuzzer complete ===\n");
    return 0;
}
