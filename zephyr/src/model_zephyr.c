/* Zephyr adapter for the shared core/ oracles: kernel queries for pended_on,
 * mutex owner, priority, deadline, and an atomic wait-queue snapshot. */
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <stdint.h>

#include "../../core/structural_inv.h"
#include "../../core/rt_invariants.h"
#include "../../core/sigma_rt.h"
#include "../../core/wait_q_oracle.h"

#define N_TASK_SLOTS   8
#define N_MUTEX_SLOTS  6

extern k_tid_t          slot_tid[N_TASK_SLOTS];
extern int              slot_alive[N_TASK_SLOTS];
extern struct k_mutex   slot_mutex[N_MUTEX_SLOTS];
extern int              slot_mutex_alive[N_MUTEX_SLOTS];

int oracle_struct_owner = 0;
int oracle_struct_wait  = 0;
int oracle_struct_prio  = 0;
int oracle_waitq_stale  = 0;     /* O_WQ: wait-list ordering stale */
int oracle_obs_discarded = 0;    /* observations a self-check rejected */
int oracle_obs_discarded_tc = 0; /* was this testcase's observation discarded? */
int oracle_wq_inspected = 0;     /* adjacent (prev,cur) pairs O_WQ judged */
/* Pairs where the signed and modular deadline compares disagree, and mutexes
 * O_WQ did not judge (no-slot waiter, snapshot overflow, set divergence). */
int oracle_wq_cmp_disagree  = 0;
int oracle_wq_signed_only   = 0;
int oracle_wq_unresolved    = 0;
int oracle_wq_overflow      = 0;
int oracle_wq_setdiv        = 0;
static struct sf_wait_q_result wait_q_state;

/* sigma: shadow state (core/sigma_rt.h), stepped by main.c's dispatcher. */
struct sigma_rt zephyr_sigma;
uint32_t sigma_owner_div = 0;
uint32_t sigma_alive_div = 0;
uint32_t sigma_base_div  = 0;
uint32_t sigma_lc_div    = 0;
uint32_t sigma_susp_div  = 0;
uint32_t sigma_wait_div  = 0;

static int zephyr_kernel_lock_count(int m)
{
    if (m < 0 || m >= N_MUTEX_SLOTS) return 0;
    return (int)slot_mutex[m].lock_count;
}

/* 0x10 = _THREAD_SUSPENDED (BIT(4), kernel_structs.h). */
static bool zephyr_kernel_task_suspended(int t)
{
    if (t < 0 || t >= N_TASK_SLOTS) return false;
    if (!slot_alive[t]) return false;
    return (slot_tid[t]->base.thread_state & 0x10) != 0;
}

static int task_base_prio[N_TASK_SLOTS];
static struct sf_structural_result struct_state;

static struct sf_invariant         reg_items[RT_INV__N];
static uint32_t                    reg_hit[RT_INV__N];
static uint32_t                    reg_seen[RT_INV__N];
static struct sf_invariant_registry reg;
static struct rt_inv_ctx            reg_ctx;
static int registry_inited = 0;

/* ---- Adapter callbacks ---- */

static bool zephyr_task_alive(int t)
{
    if (t < 0 || t >= N_TASK_SLOTS) return false;
    return slot_alive[t] != 0;
}

static int zephyr_task_base_prio(int t)
{
    return task_base_prio[t];
}

static int zephyr_task_actual_prio(int t)
{
    return k_thread_priority_get(slot_tid[t]);
}

static bool zephyr_mutex_alive(int m)
{
    if (m < 0 || m >= N_MUTEX_SLOTS) return false;
    return slot_mutex_alive[m] != 0;
}

static int zephyr_mutex_owner_slot(int m)
{
    k_tid_t o = slot_mutex[m].owner;
    if (!o) return -1;
    for (int t = 0; t < N_TASK_SLOTS; t++) {
        if (slot_alive[t] && slot_tid[t] == o) return t;
    }
    return -1;
}

static int zephyr_task_pended_on_mutex(int t)
{
    void *p = (void *)slot_tid[t]->base.pended_on;
    if (!p) return -1;
    for (int m = 0; m < N_MUTEX_SLOTS; m++) {
        if (!slot_mutex_alive[m]) continue;
        if (p == (void *)&slot_mutex[m].wait_q) return m;
    }
    return -1;
}

#ifdef CONFIG_SCHED_DEADLINE
/* EDF tiebreak key: absolute deadline in cycles; lower = more urgent. */
static int zephyr_task_actual_dl(int t)
{
    if (t < 0 || t >= N_TASK_SLOTS || !slot_alive[t]) return 0;
    return (int)slot_tid[t]->base.prio_deadline;
}

/* Zephyr does not separate base and inherited deadlines. */
#endif

/* Slot of the i-th waiter on mutex m, in kernel queue order. */
static int zephyr_mutex_waiter_at(int m, int i)
{
    if (m < 0 || m >= N_MUTEX_SLOTS || !slot_mutex_alive[m]) return SF_WAITER_NONE;
    struct k_thread *th = NULL;
    int idx = 0;
#ifdef CONFIG_WAITQ_SCALABLE
    RB_FOR_EACH_CONTAINER(&slot_mutex[m].wait_q.waitq.tree, th, base.qnode_rb) {
        if (idx++ == i) goto found;
    }
#else
    sys_dnode_t *dn;
    SYS_DLIST_FOR_EACH_NODE(&slot_mutex[m].wait_q.waitq, dn) {
        if (idx++ == i) {
            th = CONTAINER_OF(dn, struct k_thread, base.qnode_dlist);
            goto found;
        }
    }
#endif
    return SF_WAITER_NONE;
found:
    for (int t = 0; t < N_TASK_SLOTS; t++)
        if (slot_alive[t] && slot_tid[t] == th) return t;
    /* A real waiter with no slot: not reported as "no i-th waiter". */
    return SF_WAITER_UNRESOLVED;
}

/* Atomic wait-list snapshot used by O_WQ: one traversal under irq_lock(),
 * reading each waiter's prio and deadline with its position. */
static int zephyr_mutex_waiters_snapshot(int m, struct sf_waiter_obs *out,
                                         int cap)
{
    if (m < 0 || m >= N_MUTEX_SLOTS || !slot_mutex_alive[m]) return 0;

    int n = 0;
    unsigned int key = irq_lock();

    struct k_thread *th;
#ifdef CONFIG_WAITQ_SCALABLE
    RB_FOR_EACH_CONTAINER(&slot_mutex[m].wait_q.waitq.tree, th, base.qnode_rb) {
#else
    sys_dnode_t *dn;
    SYS_DLIST_FOR_EACH_NODE(&slot_mutex[m].wait_q.waitq, dn) {
        th = CONTAINER_OF(dn, struct k_thread, base.qnode_dlist);
#endif
        if (n >= cap) { n = -1; break; }        /* caller must not judge a partial queue */

        int slot = SF_WAITER_UNRESOLVED;
        for (int t = 0; t < N_TASK_SLOTS; t++)
            if (slot_alive[t] && slot_tid[t] == th) { slot = t; break; }

        out[n].slot = slot;
        /* Direct field reads: no kernel calls while interrupts are masked. */
        out[n].prio = (int)th->base.prio;
#ifdef CONFIG_SCHED_DEADLINE
        out[n].dl   = (int)th->base.prio_deadline;
#else
        out[n].dl   = 0;
#endif
        n++;
    }

    irq_unlock(key);
    return n;
}

const struct sf_rt_adapter zephyr_adapter = {
    .n_tasks                = N_TASK_SLOTS,
    .n_mutexes              = N_MUTEX_SLOTS,
    .higher_is_more_urgent  = false,    /* Zephyr: lower number = higher prio */
    .task_alive             = zephyr_task_alive,
    .task_base_prio         = zephyr_task_base_prio,
    .task_actual_prio       = zephyr_task_actual_prio,
    .mutex_alive            = zephyr_mutex_alive,
    .mutex_owner_slot       = zephyr_mutex_owner_slot,
    .task_pended_on_mutex   = zephyr_task_pended_on_mutex,
#ifdef CONFIG_SCHED_DEADLINE
    .task_actual_dl         = zephyr_task_actual_dl,
    /* prio_deadline is a wrapping 32-bit stamp the kernel orders modularly. */
    .dl_is_modular32        = true,
#endif
    .mutex_waiter_at        = zephyr_mutex_waiter_at,
    .mutex_waiters_snapshot = zephyr_mutex_waiters_snapshot,
};

/* ---- API used by main.c ---- */

void model_init_zephyr(void)
{
    for (int t = 0; t < N_TASK_SLOTS; t++) task_base_prio[t] = 7;
    sigma_rt_init(&zephyr_sigma);
    /* Mirror the slot tasks main.c pre-creates (prio 7) in sigma. */
    for (int t = 0; t < 3; t++) sigma_rt_task_create(&zephyr_sigma, t, 7);
    for (int m = 0; m < N_MUTEX_SLOTS; m++) sigma_rt_mutex_init(&zephyr_sigma, m);

    /* Registry: a cross-check of the direct sf_inv_check_* calls. */
    rt_inv_ctx_init(&reg_ctx, &zephyr_adapter, -4, 15);
    rt_inv_make_registry(&reg, reg_items, reg_hit, reg_seen);
    registry_inited = 1;
}

void zephyr_oracle_reset_tc(void)
{
    struct_state.seen_mask_so = 0;
    if (registry_inited) {
        rt_inv_ctx_reset_tc(&reg_ctx);
        sf_inv_reset_tc(&reg);
    }
}

uint32_t registry_hit_count(int idx)
{
    if (idx < 0 || idx >= RT_INV__N) return 0;
    return reg_hit[idx];
}

/* This file's counts by domain: registry (D2), sigma (D3), O_WQ (D4). */
void model_zephyr_per_domain_counts(uint32_t out[SF_DOMAIN__N])
{
    for (int d = 0; d < SF_DOMAIN__N; d++) out[d] = 0;
    if (registry_inited) {
        sf_inv_per_domain_counts(&reg, out);
    }
    out[SF_DOMAIN_REFINEMENT] += sigma_owner_div + sigma_alive_div +
                                  sigma_base_div  + sigma_lc_div     +
                                  sigma_susp_div  + sigma_wait_div;
    out[SF_DOMAIN_INTER_FIELD] += (uint32_t)oracle_waitq_stale;
}

void model_apply_prio_set(int task_slot, int prio)
{
    if (task_slot < 0 || task_slot >= N_TASK_SLOTS) return;
    task_base_prio[task_slot] = prio;
}

void zephyr_oracle_check(void)
{
    /* One observation: structural gate, then O_WQ, registry and sigma checks. */
    uint32_t owner_before = struct_state.mutex_single_owner;
    uint32_t wait_before  = struct_state.thread_single_wait;
    uint32_t prio_before  = struct_state.prio_out_of_range;

    sf_inv_check_mutex_owner_not_self_pended(&zephyr_adapter, &struct_state, 0);
    sf_inv_check_thread_single_wait        (&zephyr_adapter, &struct_state);
    sf_inv_check_prio_bounds(&zephyr_adapter, &struct_state, -4, 15);

    /* O_WQ: each wait_q must be sorted most-urgent first (prio, then deadline).
     * A structural failure discards the observation: counted, O_WQ skipped. */
    uint32_t struct_bad = (struct_state.mutex_single_owner - owner_before)
                        + (struct_state.thread_single_wait - wait_before)
                        + (struct_state.prio_out_of_range  - prio_before);
    uint32_t wq_new = 0;
    oracle_obs_discarded_tc = struct_bad ? 1 : 0;
    if (struct_bad) {
        oracle_obs_discarded++;
        printk("\n    [OBS_DISCARDED] structural self-check failed (%u) -- O_WQ "
               "NOT evaluated on this observation", struct_bad);
    } else {
        uint32_t wq_before = wait_q_state.stale_order_violations;
        sf_wait_q_result_reset_tc(&wait_q_state);
        sf_wait_q_check_order(&zephyr_adapter, &zephyr_sigma, &wait_q_state);
        oracle_wq_inspected    = (int)wait_q_state.inspected_pairs;
        oracle_wq_cmp_disagree = (int)wait_q_state.cmp_disagreements;
        oracle_wq_signed_only  = (int)wait_q_state.stale_signed_only;
        oracle_wq_unresolved   = (int)wait_q_state.unresolved_discards;
        oracle_wq_overflow     = (int)wait_q_state.snapshot_overflows;
        oracle_wq_setdiv       = (int)wait_q_state.set_divergences;
        wq_new = wait_q_state.stale_order_violations - wq_before;
        if (wq_new) { oracle_waitq_stale += wq_new;
            printk("\n    [WAITQ_STALE] new=%u (wait-list out-of-order)", wq_new);
            /* Witness: each queue of 2+ waiters, in kernel order. */
            for (int m = 0; m < N_MUTEX_SLOTS; m++) {
                struct sf_waiter_obs w[N_TASK_SLOTS];
                int n = zephyr_mutex_waiters_snapshot(m, w, N_TASK_SLOTS);
                if (n < 2) continue;
                printk("\n      m%d queue:", m);
                for (int i = 0; i < n; i++) {
                    if (w[i].slot < 0) { printk(" [unresolved]"); continue; }
                    printk(" T%d(prio %d, dl %u", w[i].slot, w[i].prio,
                           (unsigned)w[i].dl);
                    if (zephyr_sigma.task_dl_set[w[i].slot])
                        printk(", asked %d", zephyr_sigma.task_dl[w[i].slot]);
                    printk(")");
                }
            }
        }
    }

    uint32_t owner_new = struct_state.mutex_single_owner  - owner_before;
    uint32_t wait_new  = struct_state.thread_single_wait  - wait_before;
    uint32_t prio_new  = struct_state.prio_out_of_range   - prio_before;
    if (owner_new) { oracle_struct_owner += owner_new;
        printk("\n    [STRUCT_OWNER] new=%u", owner_new); }
    if (wait_new)  { oracle_struct_wait  += wait_new;
        printk("\n    [STRUCT_WAIT] new=%u", wait_new); }
    if (prio_new)  { oracle_struct_prio  += prio_new;
        printk("\n    [STRUCT_PRIO] new=%u", prio_new); }

    /* Registry cross-check, with its own dedup state (reg_ctx). */
    if (registry_inited) {
        (void)sf_inv_check_all(&reg, &reg_ctx);
    }

    /* D3 sigma refinement; a divergence is a self-check count. */
    uint32_t s_owner_before = sigma_owner_div;
    uint32_t s_alive_before = sigma_alive_div;
    uint32_t s_base_before  = sigma_base_div;
    uint32_t s_lc_before = sigma_lc_div;
    uint32_t s_susp_before = sigma_susp_div;
    sigma_rt_check_ext(&zephyr_sigma, &zephyr_adapter,
                       zephyr_kernel_lock_count,
                       &sigma_owner_div, &sigma_alive_div, &sigma_base_div,
                       &sigma_lc_div);
    /* I6 suspend-state refinement. */
    sigma_rt_check_suspended(&zephyr_sigma, &zephyr_adapter,
                              zephyr_kernel_task_suspended,
                              &sigma_susp_div);
    if (sigma_lc_div - s_lc_before)
        printk("\n    [SIGMA_LC] new=%u (mutex lock_count sigma vs kernel mismatch)",
            sigma_lc_div - s_lc_before);
    if (sigma_susp_div - s_susp_before)
        printk("\n    [SIGMA_SUSP] new=%u (task suspended state sigma vs kernel mismatch)",
            sigma_susp_div - s_susp_before);

    /* I7 wait-graph consistency. */
    uint32_t s_wait_before = sigma_wait_div;
    sigma_rt_check_wait_graph(&zephyr_sigma, &zephyr_adapter, &sigma_wait_div);
    if (sigma_wait_div - s_wait_before)
        printk("\n    [SIGMA_WAIT] new=%u (task pended_on sigma vs kernel mismatch)",
            sigma_wait_div - s_wait_before);
    if (sigma_owner_div - s_owner_before)
        printk("\n    [SIGMA_OWNER] new=%u (mutex.owner diverges)",
            sigma_owner_div - s_owner_before);
    if (sigma_alive_div - s_alive_before)
        printk("\n    [SIGMA_ALIVE] new=%u (task alive state diverges)",
            sigma_alive_div - s_alive_before);
    if (sigma_base_div - s_base_before)
        printk("\n    [SIGMA_BASE]  new=%u (task base_prio diverges)",
            sigma_base_div - s_base_before);
}
