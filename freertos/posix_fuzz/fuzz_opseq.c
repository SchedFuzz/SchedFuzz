/* fuzz_opseq.c -- FreeRTOS op-sequence fuzzer, using the generator, corpus,
 * shadow state and checks in ../../core/. The driver is a task above the
 * workers; ops that must run in a worker's context go to its mailbox. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "queue.h"

#include "freertos_posix_adapter.h"
#include "fuzz_core.h"
#include "sigma_rt.h"
#include "coverage.h"
#include "rt_invariants.h"
#include "wait_q_oracle.h"
#include "op_ir.h"

/* ---------------- geometry ---------------- */
#define N_TASK_SLOTS   4
#define N_MUTEX_SLOTS  3
#define TC_MAX        16          /* max ops per testcase */
#define SC_ARGS        4
#define CORPUS_MAX    32
#define WORKER_PRIO_LO 2
/* Highest priority a worker can take without outranking the driver. */
#define WORKER_PRIO_HI 8
#define DRIVER_PRIO    9
#define SETTLE_TICKS   pdMS_TO_TICKS(2)
/* OP_TAKE_MUTEX timeout (ms), bounded so the worker can still be torn down. */
#define BLOCK_TAKE_MS  60
/* OP_HOLD_TAKE timeout (ms): the waiter is still pended when judge() looks. */
#define HOLD_TAKE_MS   300
/* Settle (ms) before the one verdict per sequence. */
#define SEQ_SETTLE_MS  100

/* Generator slot-locality knobs (see core/fuzz_core.h). */
#ifndef SF_MUTEX_LOCALITY_PCT
#define SF_MUTEX_LOCALITY_PCT 70
#endif
#ifndef SF_TASK_SPREAD_PCT
#define SF_TASK_SPREAD_PCT    80
#endif

#ifndef N_ITERS
#define N_ITERS 150
#endif

/* ---------------- testcase representation ----------------
 * A step is the op byte then the arg bytes, as the core/ mutators expect. */
struct sc_step { uint8_t op; uint8_t args[SC_ARGS]; };
struct testcase { int n; struct sc_step step[TC_MAX]; };

/* ---------------- op vocabulary ---------------- */
#define OP_TAKE_MUTEX      0   /* worker: take, block up to BLOCK_TAKE_MS   */
#define OP_GIVE_MUTEX      1   /* worker: give                              */
#define OP_TIMED_TAKE      2   /* worker: take with a short timeout         */
#define OP_NESTED_TAKE     3   /* worker: take m, then m'                   */
#define OP_PRIO_SET        4   /* driver: vTaskPrioritySet                  */
#define OP_TASK_DELETE     5   /* driver: vTaskDelete                       */
#define OP_TASK_CREATE     6   /* driver: re-create a deleted slot          */
#define OP_SUSPEND_OTHER   7   /* driver: vTaskSuspend                      */
#define OP_RESUME_OTHER    8   /* driver: vTaskResume                       */
#define OP_DELAY           9   /* driver: let the system settle             */
#define OP_YIELD          10   /* driver: taskYIELD                         */
#define OP_PRIO_GET_PROBE 11   /* driver: read a task's priority            */
#define OP_NOP            12
#define OP_HOLD_TAKE      13   /* worker: take with a long block             */
#define OP_SUSPEND_SELF   14   /* worker: vTaskSuspend(NULL)                 */
#define OP_MUTEX_REINIT   15   /* driver: delete + recreate a mutex slot     */
#define N_OPS             16
/* Teardown only; never generated or mutated into. */
#define OP_QUIT          200

/* ---------------- worker command mailbox ----------------
 * A worker's take and give reach sigma's ownership only through its ack. */
struct wcmd { uint8_t op; uint8_t m1; uint8_t m2; };
struct wack { uint8_t slot; uint8_t op; uint8_t m1; uint8_t m2; uint8_t ok; };

static TaskHandle_t      g_task[N_TASK_SLOTS];
static QueueHandle_t     g_mbox[N_TASK_SLOTS];
static QueueHandle_t     g_ack;          /* workers -> driver, shared */
static int               g_holds[N_TASK_SLOTS][N_MUTEX_SLOTS];  /* slot holds m? */
static SemaphoreHandle_t g_mutex[N_MUTEX_SLOTS];
static int               g_base_prio[N_TASK_SLOTS];
static int               g_suspended[N_TASK_SLOTS];

/* Mutex slot a worker is committed to taking, or -1: set before it reads
 * g_mutex[m], cleared after the take returns. Deleters wait for it to clear. */
static volatile int      g_in_take_m[N_TASK_SLOTS];

static int worker_in_take_on(int m)
{
    for (int t = 0; t < N_TASK_SLOTS; t++)
        if (g_in_take_m[t] == m) return 1;
    return 0;
}

static struct sigma_rt   g_sigma;
static struct sf_coverage g_cov;

/* Structural invariants OWNER, WAIT, PRIO: hits are counted, not gating. */
static struct sf_invariant_registry g_reg;
static struct sf_invariant          g_reg_items[RT_INV__N];
static uint32_t                     g_reg_hit[RT_INV__N];
static uint32_t                     g_reg_seen[RT_INV__N];
static struct rt_inv_ctx            g_reg_ctx;

/* Times a live mutex was seen with >=2 waiters (corpus feedback only). */
static uint32_t g_queue_depth_hits;

/* per-run tallies */
static uint32_t n_owner_div, n_alive_div, n_base_div, n_wait_div, n_selfchk;
static uint32_t obs_discarded;      /* structural self-check rejected the state */
static uint32_t n_skip_precond;        /* ops refused by a precondition check */
static uint32_t n_mbox_leaked;         /* worker outlived teardown */
static uint32_t n_mutex_leaked;        /* mutex still had waiters at teardown */
static uint8_t  g_cur_op;           /* opcode being executed (take variants share a primitive) */
/* Failed configASSERTs (FreeRTOSConfig.h); not static, the kernel uses it. */
unsigned long fr_kernel_asserts;

/* ---------------- O_WQ, dequeue form ----------------
 * Each give records which waiter the kernel woke; judge_dequeue() checks at the
 * scenario boundary that it was among the most urgent waiters. */
#define WAKE_EV_MAX 24
#define WAKE_NONE   (-1)   /* the give woke nobody -- no waiters to choose from */
#define WAKE_AMBIG  (-2)   /* >1 waiter left between the two reads: unattributable */
struct wake_ev {
    int8_t  m;                        /* mutex slot released */
    uint8_t n_pre;                    /* waiters immediately before the give */
    int8_t  pre_slot[N_TASK_SLOTS];
    int16_t pre_prio[N_TASK_SLOTS];   /* read with the set, not re-read later */
    int8_t  wakee;
};
static struct wake_ev g_wake[WAKE_EV_MAX];
static uint8_t  g_wake_n;
static uint32_t n_deq_judged;   /* wake events with >=2 waiters and one attributable wakee */
static uint32_t n_deq_viol;     /* ... where the woken task was not among the most urgent */
static uint32_t n_deq_ambig;    /* discarded: could not attribute the wake */
/* discarded: the pre-wake list and sigma's pended-on set for the mutex differ */
static uint32_t n_deq_setdiv;
static uint32_t n_deq_dropped;  /* discarded: more wake events in one scenario than we hold */

/* Judge every recorded wake: the wakee must have the highest priority among
 * the waiters (higher is more urgent); any waiter tying the maximum passes. */
static void judge_dequeue(void)
{
    for (uint8_t e = 0; e < g_wake_n; e++) {
        const struct wake_ev *w = &g_wake[e];

        if (w->n_pre < 2) continue;
        if (w->wakee == WAKE_NONE)  continue;
        if (w->wakee == WAKE_AMBIG) { n_deq_ambig++; continue; }

        /* Precondition: the pre-wake list equals sigma's pended-on set. */
        uint32_t obs_set = 0, sig_set = 0;
        for (uint8_t i = 0; i < w->n_pre; i++)
            if (w->pre_slot[i] >= 0 && w->pre_slot[i] < RT_MAX_TASKS)
                obs_set |= 1u << w->pre_slot[i];
        for (int t = 0; t < RT_MAX_TASKS; t++)
            if (g_sigma.task_alive[t] && g_sigma.task_pended_on[t] == w->m)
                sig_set |= 1u << t;
        if (obs_set != sig_set) { n_deq_setdiv++; continue; }

        int best = -32768;
        for (uint8_t i = 0; i < w->n_pre; i++)
            if (w->pre_prio[i] > best) best = w->pre_prio[i];

        int woke_prio = -32768;
        for (uint8_t i = 0; i < w->n_pre; i++)
            if (w->pre_slot[i] == w->wakee) { woke_prio = w->pre_prio[i]; break; }

        n_deq_judged++;
        if (woke_prio < best) {
            n_deq_viol++;
            /* Witness. Printed only outside the vTaskSuspendAll() bracket. */
            printf("\n    [O_WQ deq WITNESS] m%d  pre-wake list:", w->m);
            for (uint8_t i = 0; i < w->n_pre; i++)
                printf(" T%d(p=%d)%s", w->pre_slot[i], w->pre_prio[i],
                       w->pre_prio[i] == best ? "*" : "");
            printf("   woke=T%d(p=%d)  best=p%d  (* = a most-urgent waiter;"
                   " waking any of them is a pass)", w->wakee, woke_prio, best);
        }
    }
    g_wake_n = 0;
}

/* ---------------- worker ---------------- */
static void ack(int slot, uint8_t op, uint8_t m1, uint8_t m2, int ok)
{
    struct wack a = { (uint8_t)slot, op, m1, m2, (uint8_t)(ok ? 1 : 0) };
    if (g_ack) xQueueSend(g_ack, &a, 0);
}

/* Each use of g_mutex[] is NULL-checked; teardown may null a slot meanwhile. */
static void worker_fn(void *p)
{
    int slot = (int)(intptr_t)p;
    /* Own mailbox, captured once; only this task deletes it (OP_QUIT). */
    QueueHandle_t mb = g_mbox[slot];
    struct wcmd c;
    if (mb == NULL) vTaskDelete(NULL);
    for (;;) {
        if (xQueueReceive(mb, &c, portMAX_DELAY) != pdTRUE) continue;
        switch (c.op) {
        case OP_TAKE_MUTEX: {
            /* g_in_take_m is set before the handle is read (see its decl); the
             * adapter pend is recorded just before blocking. */
            g_in_take_m[slot] = c.m1;
            __sync_synchronize();
            QueueHandle_t h = g_mutex[c.m1];
            if (h == NULL) { g_in_take_m[slot] = -1; ack(slot, OP_TAKE_MUTEX, c.m1, 0, 0); break; }
            frp_task_set_pended(slot, c.m1);
            int ok = (xSemaphoreTake(h, pdMS_TO_TICKS(BLOCK_TAKE_MS)) == pdTRUE);
            frp_task_set_pended(slot, -1);
            g_in_take_m[slot] = -1;
            ack(slot, OP_TAKE_MUTEX, c.m1, 0, ok);
            break;
        }
        case OP_HOLD_TAKE: {
            g_in_take_m[slot] = c.m1;
            __sync_synchronize();
            QueueHandle_t h = g_mutex[c.m1];
            if (h == NULL) { g_in_take_m[slot] = -1; ack(slot, OP_HOLD_TAKE, c.m1, 0, 0); break; }
            frp_task_set_pended(slot, c.m1);
            int ok = (xSemaphoreTake(h, pdMS_TO_TICKS(HOLD_TAKE_MS)) == pdTRUE);
            frp_task_set_pended(slot, -1);
            g_in_take_m[slot] = -1;
            ack(slot, OP_HOLD_TAKE, c.m1, 0, ok);
            break;
        }
        case OP_SUSPEND_SELF: {
            /* Ack before suspending; reset_world waits on acks. */
            ack(slot, OP_SUSPEND_SELF, 0, 0, 1);
            vTaskSuspend(NULL);
            break;
        }
        case OP_TIMED_TAKE: {
            g_in_take_m[slot] = c.m1;
            __sync_synchronize();
            QueueHandle_t h = g_mutex[c.m1];
            if (h == NULL) { g_in_take_m[slot] = -1; ack(slot, OP_TIMED_TAKE, c.m1, 0, 0); break; }
            frp_task_set_pended(slot, c.m1);
            int ok = (xSemaphoreTake(h, pdMS_TO_TICKS(5)) == pdTRUE);
            frp_task_set_pended(slot, -1);
            g_in_take_m[slot] = -1;
            ack(slot, OP_TIMED_TAKE, c.m1, 0, ok);
            break;
        }
        case OP_NESTED_TAKE: {
            g_in_take_m[slot] = c.m1;
            __sync_synchronize();
            QueueHandle_t h1 = g_mutex[c.m1];
            if (h1 == NULL) { g_in_take_m[slot] = -1; ack(slot, OP_TIMED_TAKE, c.m1, 0, 0); break; }
            frp_task_set_pended(slot, c.m1);
            int ok1 = (xSemaphoreTake(h1, pdMS_TO_TICKS(5)) == pdTRUE);
            frp_task_set_pended(slot, -1);
            g_in_take_m[slot] = -1;
            ack(slot, OP_TIMED_TAKE, c.m1, 0, ok1);
            if (ok1) {
                g_in_take_m[slot] = c.m2;
                __sync_synchronize();
                QueueHandle_t h2 = g_mutex[c.m2];
                if (h2 == NULL) { g_in_take_m[slot] = -1; ack(slot, OP_TIMED_TAKE, c.m2, 0, 0); break; }
                frp_task_set_pended(slot, c.m2);
                int ok2 = (xSemaphoreTake(h2, pdMS_TO_TICKS(5)) == pdTRUE);
                frp_task_set_pended(slot, -1);
                g_in_take_m[slot] = -1;
                ack(slot, OP_TIMED_TAKE, c.m2, 0, ok2);
            }
            break;
        }
        case OP_QUIT: {
            TaskHandle_t me = xTaskGetCurrentTaskHandle();
            for (int m = 0; m < N_MUTEX_SLOTS; m++)
                while (g_mutex[m] && xSemaphoreGetMutexHolder(g_mutex[m]) == me)
                    if (xSemaphoreGive(g_mutex[m]) != pdTRUE) break;
            ack(slot, OP_QUIT, 0, 0, 1);
            if (g_mbox[slot] == mb) g_mbox[slot] = NULL;
            vQueueDelete(mb);
            vTaskDelete(NULL);
            break;
        }
        case OP_GIVE_MUTEX: {
            if (g_mutex[c.m1] == NULL) { ack(slot, OP_GIVE_MUTEX, c.m1, 0, 0); break; }
            int ok;
            /* Snapshot the waiters before and after the give, scheduler
             * suspended: the waiter that left is the one the kernel woke. */
            vTaskSuspendAll();
            {
                struct sf_waiter_obs pre[N_TASK_SLOTS], post[N_TASK_SLOTS];
                int npre = frp_adapter_g.mutex_waiters_snapshot
                         ? frp_adapter_g.mutex_waiters_snapshot(c.m1, pre, N_TASK_SLOTS)
                         : 0;
                ok = (xSemaphoreGive(g_mutex[c.m1]) == pdTRUE);
                int npost = frp_adapter_g.mutex_waiters_snapshot
                          ? frp_adapter_g.mutex_waiters_snapshot(c.m1, post, N_TASK_SLOTS)
                          : 0;

                if (npre > 0 && g_wake_n >= WAKE_EV_MAX) {
                    n_deq_dropped++;
                } else if (npre > 0) {
                    struct wake_ev *w = &g_wake[g_wake_n++];
                    w->m = (int8_t)c.m1;
                    w->n_pre = (uint8_t)npre;
                    int n_gone = 0;
                    int8_t gone = WAKE_NONE;
                    for (int i = 0; i < npre; i++) {
                        w->pre_slot[i] = (int8_t)pre[i].slot;
                        w->pre_prio[i] = (int16_t)pre[i].prio;
                        int still = 0;
                        for (int j = 0; j < npost; j++)
                            if (post[j].slot == pre[i].slot) { still = 1; break; }
                        if (!still) { gone = (int8_t)pre[i].slot; n_gone++; }
                    }
                    w->wakee = (n_gone > 1) ? WAKE_AMBIG : gone;
                }
            }
            (void)xTaskResumeAll();
            ack(slot, OP_GIVE_MUTEX, c.m1, 0, ok);
            break;
        }
        default: break;
        }
    }
}

/* Apply the outcomes workers have reported since the last drain to sigma. */
static void drain_acks(void)
{
    struct wack a;
    while (g_ack && xQueueReceive(g_ack, &a, 0) == pdTRUE) {
        /* A take that timed out still ends the wait. */
        if (!a.ok) {
            if (a.op == OP_TAKE_MUTEX || a.op == OP_TIMED_TAKE
                || a.op == OP_HOLD_TAKE)
                sf_op_apply_effect(&g_sigma, SF_EFF_TASK_UNPEND, a.slot, 0, 0);
            continue;
        }
        switch (a.op) {
        case OP_TAKE_MUTEX:
        case OP_TIMED_TAKE:
            sf_op_apply_effect(&g_sigma, SF_EFF_TASK_UNPEND, a.slot, 0, 0);
            sf_op_apply_effect(&g_sigma, SF_EFF_MUTEX_TAKE, a.slot, a.m1, 0);
            g_holds[a.slot][a.m1] = 1;
            break;
        case OP_GIVE_MUTEX:
            sf_op_apply_effect(&g_sigma, SF_EFF_MUTEX_GIVE, a.slot, a.m1, 0);
            g_holds[a.slot][a.m1] = 0;
            break;
        default: break;
        }
    }
}

/* ---------------- slot helpers ---------------- */
static int slot_alive(int t)
{
    return t >= 0 && t < N_TASK_SLOTS && g_task[t] != NULL;
}

static void spawn_slot_raw(int t, int prio)
{
    char nm[8]; snprintf(nm, sizeof nm, "w%d", t);
    if (g_mbox[t] == NULL) g_mbox[t] = xQueueCreate(4, sizeof(struct wcmd));
    if (xTaskCreate(worker_fn, nm, 2048, (void *)(intptr_t)t,
                    (UBaseType_t)prio, &g_task[t]) != pdPASS) {
        g_task[t] = NULL; return;
    }
    g_base_prio[t] = prio;
    g_suspended[t] = 0;
    frp_register_task(t, g_task[t], prio);
    frp_task_set_pended(t, -1);
    sigma_rt_task_create(&g_sigma, t, prio);
}

static int slot_holds_any(int t)
{
    if (!slot_alive(t)) return 0;
    for (int m = 0; m < N_MUTEX_SLOTS; m++)
        if (g_mutex[m] && xSemaphoreGetMutexHolder(g_mutex[m]) == g_task[t])
            return 1;
    return 0;
}

static void kill_slot_raw(int t)
{
    if (!slot_alive(t)) return;
    vTaskDelete(g_task[t]);
    g_task[t] = NULL;
    frp_task_set_state(t, FRP_TASK_DELETED);
    frp_task_set_pended(t, -1);
    sigma_rt_task_abort(&g_sigma, t);
    g_suspended[t] = 0;
}

/* Lock depth for the extended sigma check, as 0/1: FreeRTOS does not expose a
 * plain mutex's count (exact for non-recursive use). */
static int kernel_lock_count(int m)
{
    if (m < 0 || m >= N_MUTEX_SLOTS || !g_mutex[m]) return 0;
    return xSemaphoreGetMutexHolder(g_mutex[m]) ? 1 : 0;
}

/* ---------------- one op ---------------- */
static void post(int t, uint8_t op, uint8_t m1, uint8_t m2)
{
    if (!slot_alive(t) || g_mbox[t] == NULL) return;
    struct wcmd c = { op, m1, m2 };
    xQueueSend(g_mbox[t], &c, 0);
}

/* ---------------- the op table (core/op_ir.h) ----------------
 * sf_op_exec applies an op's shadow effect only if its primitive returns
 * SF_OP_OK. Args: [0] task, [1] mutex or priority, [2] second mutex (nested
 * take), [3] time. */
static int prim_take(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx;
    int t = a->arg[0], m = a->arg[1], m2 = a->arg[2];
    if (!slot_alive(t)) return SF_OP_SKIP;
    TaskHandle_t h = g_mutex[m] ? xSemaphoreGetMutexHolder(g_mutex[m]) : NULL;
    if (h == g_task[t]) return SF_OP_SKIP;      /* already ours: not a wait */
    post(t, g_cur_op, (uint8_t)m, (uint8_t)m2);
    /* OK (sigma pends the task) only if the mutex is held; the driver
     * outranks the worker, so it yields until the worker has pended. */
    if (h != NULL) {
        for (int w = 0; w < 8 && frp_shadow_g.task_pended_on[t] != m; w++)
            vTaskDelay(1);
    }
    return h != NULL ? SF_OP_OK : SF_OP_SKIP;
}

static int prim_give(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx;
    int t = a->arg[0], m = a->arg[1];
    if (!slot_alive(t)) return SF_OP_SKIP;
    /* Only the holder may give: a non-holder give is refused and counted. */
    if (m < 0 || m >= N_MUTEX_SLOTS || g_mutex[m] == NULL) return SF_OP_SKIP;
    if (xSemaphoreGetMutexHolder(g_mutex[m]) != g_task[t]) {
        n_skip_precond++;
        return SF_OP_SKIP;
    }
    post(t, OP_GIVE_MUTEX, (uint8_t)m, 0);
    return SF_OP_OK;                            /* effect is deferred to the ack */
}

static int prim_prio_set(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx;
    int t = a->arg[0], p = a->arg[1];
    if (!slot_alive(t)) return SF_OP_SKIP;
    vTaskPrioritySet(g_task[t], (UBaseType_t)p);
    g_base_prio[t] = p;
    frp_task_set_base_prio(t, p);
    return SF_OP_OK;
}

static int prim_delete(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx;
    int t = a->arg[0];
    if (!slot_alive(t)) return SF_OP_SKIP;
    /* I10: refuse (and count) deleting a task that holds or waits on a mutex. */
    if (slot_holds_any(t) || frp_shadow_g.task_pended_on[t] >= 0) {
        n_skip_precond++;
        return SF_OP_SKIP;
    }
    kill_slot_raw(t);
    return SF_OP_OK;
}

static int prim_create(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx;
    int t = a->arg[0], p = a->arg[1];
    if (slot_alive(t)) return SF_OP_SKIP;
    spawn_slot_raw(t, p);
    return slot_alive(t) ? SF_OP_OK : SF_OP_FAIL;
}

static int prim_suspend(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx;
    int t = a->arg[0];
    if (!slot_alive(t) || g_suspended[t]) return SF_OP_SKIP;
    vTaskSuspend(g_task[t]);
    g_suspended[t] = 1;
    return SF_OP_OK;
}

static int prim_resume(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx;
    int t = a->arg[0];
    if (!slot_alive(t) || !g_suspended[t]) return SF_OP_SKIP;
    vTaskResume(g_task[t]);
    g_suspended[t] = 0;
    return SF_OP_OK;
}

static int prim_delay(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx; vTaskDelay(pdMS_TO_TICKS(1 + a->arg[3])); return SF_OP_OK;
}
static int prim_yield(const struct sf_op_decoded *a, void *ctx)
{
    (void)a; (void)ctx; taskYIELD(); return SF_OP_OK;
}
static int prim_probe(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx;
    int t = a->arg[0];
    if (!slot_alive(t)) return SF_OP_SKIP;
    (void)uxTaskPriorityGet(g_task[t]);
    return SF_OP_OK;
}
static int prim_suspend_self(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx;
    int t = a->arg[0];
    if (!slot_alive(t) || g_suspended[t]) return SF_OP_SKIP;
    post(t, OP_SUSPEND_SELF, 0, 0);
    g_suspended[t] = 1;
    return SF_OP_OK;
}

static int prim_mutex_reinit(const struct sf_op_decoded *a, void *ctx)
{
    (void)ctx;
    int m = a->arg[1];
    if (m < 0 || m >= N_MUTEX_SLOTS || !g_mutex[m]) return SF_OP_SKIP;
    /* Refused while held, and (counted) while any task waits on it. */
    if (xSemaphoreGetMutexHolder(g_mutex[m]) != NULL) return SF_OP_SKIP;
    if (frq_mutex_waiter_count(g_mutex[m]) > 0) { n_skip_precond++; return SF_OP_SKIP; }
    /* Publish NULL, wait (bounded) for waiters and in-progress takes, delete
     * only if none remain (else count a leak), and recreate the slot. */
    QueueHandle_t doomed = g_mutex[m];
    g_mutex[m] = NULL;
    __sync_synchronize();
    for (int w = 0; w < 120 &&
         (frq_mutex_waiter_count(doomed) > 0 || worker_in_take_on(m)); w++)
        vTaskDelay(pdMS_TO_TICKS(5));
    if (frq_mutex_waiter_count(doomed) > 0 || worker_in_take_on(m))
        n_mutex_leaked++;
    else
        vSemaphoreDelete(doomed);
    g_mutex[m] = xSemaphoreCreateMutex();
    frp_register_mutex(m, g_mutex[m]);
    for (int t = 0; t < N_TASK_SLOTS; t++) g_holds[t][m] = 0;
    return g_mutex[m] ? SF_OP_OK : SF_OP_SKIP;
}

static int prim_nop(const struct sf_op_decoded *a, void *ctx)
{
    (void)a; (void)ctx; return SF_OP_OK;
}

#define A_T   SF_ARG_TASK
#define A_M   SF_ARG_MUTEX
#define A_P   SF_ARG_PRIO
#define A_MS  SF_ARG_TIME_MS
#define A_X   SF_ARG_UNUSED

static const struct sf_op_desc FR_OPS[] = {
 /* OP_TAKE_MUTEX    */ { "take",   {A_T,A_M,A_M,A_X}, SF_EFF_TASK_PEND,     0,1,0, prim_take, NULL, 0 },
 /* OP_GIVE_MUTEX    */ { "give",   {A_T,A_M,A_X,A_X}, SF_EFF_DEFERRED,      0,1,0, prim_give, NULL, .may_release = 1 },
 /* OP_TIMED_TAKE    */ { "ttake",  {A_T,A_M,A_M,A_X}, SF_EFF_TASK_PEND,     0,1,0, prim_take, NULL, 0 },
 /* OP_NESTED_TAKE   */ { "ntake",  {A_T,A_M,A_M,A_X}, SF_EFF_TASK_PEND,     0,1,0, prim_take, NULL, 0 },
 /* OP_PRIO_SET      */ { "prio",   {A_T,A_P,A_X,A_X}, SF_EFF_TASK_PRIO_SET, 0,0,1, prim_prio_set, NULL, 0, 1 },
 /* OP_TASK_DELETE   */ { "del",    {A_T,A_X,A_X,A_X}, SF_EFF_TASK_ABORT,    0,0,0, prim_delete },
 /* OP_TASK_CREATE   */ { "new",    {A_T,A_P,A_X,A_X}, SF_EFF_TASK_CREATE,   0,0,1, prim_create },
 /* OP_SUSPEND_OTHER */ { "susp",   {A_T,A_X,A_X,A_X}, SF_EFF_TASK_SUSPEND,  0,0,0, prim_suspend },
 /* OP_RESUME_OTHER  */ { "res",    {A_T,A_X,A_X,A_X}, SF_EFF_TASK_RESUME,   0,0,0, prim_resume },
 /* OP_DELAY         */ { "delay",  {A_X,A_X,A_X,A_MS},SF_EFF_NONE,          0,0,0, prim_delay },
 /* OP_YIELD         */ { "yield",  {A_X,A_X,A_X,A_X}, SF_EFF_NONE,          0,0,0, prim_yield },
 /* OP_PRIO_GET_PROBE*/ { "probe",  {A_T,A_X,A_X,A_X}, SF_EFF_NONE,          0,0,0, prim_probe },
 /* OP_NOP           */ { "nop",    {A_X,A_X,A_X,A_X}, SF_EFF_NONE,          0,0,0, prim_nop },
 /* OP_HOLD_TAKE     */ { "hold",   {A_T,A_M,A_X,A_X}, SF_EFF_TASK_PEND,     0,1,0, prim_take, NULL, 1 },
 /* OP_SUSPEND_SELF  */ { "suspS",  {A_T,A_X,A_X,A_X}, SF_EFF_TASK_SUSPEND,  0,0,0, prim_suspend_self },
 /* OP_MUTEX_REINIT  */ { "reinit", {A_T,A_M,A_X,A_X}, SF_EFF_MUTEX_INIT,    0,1,0, prim_mutex_reinit },
};

static struct sf_op_table FR_TABLE = {
    .ops = FR_OPS, .n_ops = N_OPS,
    .n_tasks = N_TASK_SLOTS, .n_mutexes = N_MUTEX_SLOTS,
    .prio_lo = WORKER_PRIO_LO, .prio_hi = WORKER_PRIO_HI,
    .time_max_ms = 4,
};

static void exec_step(const struct sc_step *st)
{
    g_cur_op = st->op % N_OPS;                  /* the take primitive is shared */
    sf_op_exec(&FR_TABLE, st->op, st->args, &g_sigma, NULL);
    vTaskDelay(SETTLE_TICKS);   /* let the worker observe the posted command */
    drain_acks();
}

/* ---------------- judgement ---------------- */
static void judge(void)
{
    vTaskDelay(pdMS_TO_TICKS(SEQ_SETTLE_MS));   /* settle before the verdict */
    drain_acks();                      /* advance sigma on reported outcomes */

    /* Gate: if sigma fails its self-check, the observation is discarded. */
    if (sigma_rt_self_check(&g_sigma) != 0) {
        n_selfchk++;
        obs_discarded++;
        return;
    }

    uint32_t od = 0, ad = 0, bd = 0, lc = 0, wd = 0;
    sigma_rt_check_ext(&g_sigma, &frp_adapter_g, kernel_lock_count,
                       &od, &ad, &bd, &lc);
    sigma_rt_check_wait_graph(&g_sigma, &frp_adapter_g, &wd);
    n_owner_div += od; n_alive_div += ad; n_base_div += bd; n_wait_div += wd;

    uint32_t hb = 0;
    for (int i = 0; i < RT_INV__N; i++) hb += g_reg_hit[i];
    sf_inv_check_all(&g_reg, &g_reg_ctx);
    uint32_t ha = 0;
    for (int i = 0; i < RT_INV__N; i++) ha += g_reg_hit[i];

    /* Count live mutexes with >=2 waiters (a search signal; nothing is
     * compared), with the scheduler suspended for the whole walk. */
    vTaskSuspendAll();
    {
        struct sf_waiter_obs w[N_TASK_SLOTS];
        for (int m = 0; m < N_MUTEX_SLOTS; m++) {
            if (g_mutex[m] == NULL) continue;
            int n = frp_adapter_g.mutex_waiters_snapshot
                  ? frp_adapter_g.mutex_waiters_snapshot(m, w, N_TASK_SLOTS) : 0;
            if (n >= 2) g_queue_depth_hits++;
        }
    }
    (void)xTaskResumeAll();

    judge_dequeue();
}

/* ---------------- one testcase ---------------- */
static void reset_world(void)
{
    /* Drop wake events the previous scenario recorded but did not judge. */
    g_wake_n = 0;

    /* Retire every worker with OP_QUIT (each deletes itself); suspended
     * workers are resumed first so they can dequeue it. */
    for (int t = 0; t < N_TASK_SLOTS; t++)
        if (g_task[t] && g_suspended[t]) { vTaskResume(g_task[t]); g_suspended[t] = 0; }
    int expect = 0;
    for (int t = 0; t < N_TASK_SLOTS; t++)
        if (slot_alive(t)) { post(t, OP_QUIT, 0, 0); expect++; }
    /* Wait (bounded) for OP_QUIT acks; a worker still blocked quits later. */
    for (int w = 0; w < 60 && expect > 0; w++) {
        struct wack a;
        while (g_ack && xQueueReceive(g_ack, &a, 0) == pdTRUE)
            if (a.op == OP_QUIT) expect--;
        if (expect <= 0) break;
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    vTaskDelay(pdMS_TO_TICKS(10));          /* let the deletions complete */
    for (int t = 0; t < N_TASK_SLOTS; t++) {
        g_task[t] = NULL;
        frp_task_set_state(t, FRP_TASK_DELETED);
        frp_task_set_pended(t, -1);
        g_suspended[t] = 0;
    }
    /* Delete each mutex once no worker waits on it or is entering a take on
     * it; otherwise it is not deleted, only counted (mutexes LEAKED). */
    for (int m = 0; m < N_MUTEX_SLOTS; m++) {
        if (!g_mutex[m]) continue;
        QueueHandle_t doomed = g_mutex[m];
        g_mutex[m] = NULL;
        __sync_synchronize();
        for (int w = 0; w < 120 &&
             (frq_mutex_waiter_count(doomed) > 0 || worker_in_take_on(m)); w++)
            vTaskDelay(pdMS_TO_TICKS(5));
        if (frq_mutex_waiter_count(doomed) > 0 || worker_in_take_on(m)) {
            n_mutex_leaked++;
            continue;
        }
        vSemaphoreDelete(doomed);
    }
    for (int t = 0; t < N_TASK_SLOTS; t++) {
        /* Workers delete their own mailboxes; one still set is counted. */
        if (g_mbox[t] != NULL) { n_mbox_leaked++; g_mbox[t] = NULL; }
    }
    vTaskDelay(SETTLE_TICKS);

    if (g_ack == NULL) g_ack = xQueueCreate(64, sizeof(struct wack));
    else { struct wack d; while (xQueueReceive(g_ack, &d, 0) == pdTRUE) {} }
    memset(g_holds, 0, sizeof g_holds);

    sigma_rt_init(&g_sigma);
    frp_init(N_TASK_SLOTS, N_MUTEX_SLOTS);
    rt_inv_ctx_init(&g_reg_ctx, &frp_adapter_g, 0, configMAX_PRIORITIES - 1);

    for (int m = 0; m < N_MUTEX_SLOTS; m++) {
        g_mutex[m] = xSemaphoreCreateMutex();
        frp_register_mutex(m, g_mutex[m]);
        sigma_rt_mutex_init(&g_sigma, m);
    }
    for (int t = 0; t < N_TASK_SLOTS; t++)
        spawn_slot_raw(t, WORKER_PRIO_LO + (t % (WORKER_PRIO_HI - WORKER_PRIO_LO + 1)));
    vTaskDelay(SETTLE_TICKS);
}

static void run_tc(const struct testcase *tc)
{
    reset_world();
    sf_inv_reset_tc(&g_reg);
    rt_inv_ctx_reset_tc(&g_reg_ctx);
    for (int i = 0; i < tc->n; i++)
        exec_step(&tc->step[i]);
    judge();
}

/* ================= PHASE 2: reduction and clean replay =================
 * Each replay goes through reset_world(): new workers, mutexes and sigma. */
#define FK_DEQ     (1u << 0)   /* O_WQ, dequeue form  (woke a non-best task) */

/* How many findings PHASE 1 keeps for PHASE 2; 0 disables the reduction. */
#ifndef SF_REDUCE_MAX
#define SF_REDUCE_MAX 1
#endif

static void print_kinds(uint32_t m)
{
    printf("%s", (m & FK_DEQ) ? "O_WQ_DEQUEUE" : "(none)");
}

/* Run one testcase from a clean world; return the finding kinds that fired
 * (0 also when the observation was discarded). */
static uint32_t run_tc_kinds(const struct testcase *tc)
{
    uint32_t dq_b = n_deq_viol;

    run_tc(tc);

    uint32_t m = 0;
    if (n_deq_viol > dq_b) m |= FK_DEQ;
    return m;
}

static struct testcase finding_tc[SF_REDUCE_MAX];
static uint32_t        finding_mask[SF_REDUCE_MAX];
static int             finding_iter[SF_REDUCE_MAX];
static int             n_findings;

/* Greedy delta debugging: drop one step at a time while every kind in `want`
 * (the PHASE 1 mask) still fires. */
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
            if ((m & cur_mask) == cur_mask) {   /* lose nothing */
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
    printf("\n=== PHASE 2: reduction (%d finding(s); separate from testing) ===\n",
           n_findings);
    if (n_findings == 0) {
        printf("  (nothing recorded to reduce)\n");
        return;
    }
    for (int i = 0; i < n_findings; i++) {
        struct testcase cur = finding_tc[i];
        uint32_t verified = 0;
        int before = cur.n;
        reduce_one(&cur, finding_mask[i], &verified);
        printf("\n  it=%d: %d -> %d steps; replay-verified kinds=",
               finding_iter[i], before, cur.n);
        print_kinds(verified);
        uint32_t lost = finding_mask[i] & ~verified;
        if (lost) { printf("  (NOT preserved: "); print_kinds(lost); printf(")"); }
        printf("\n");
        for (int s = 0; s < cur.n; s++)
            printf("      %-6s args=%u,%u,%u\n",
                   sf_op_name(&FR_TABLE, cur.step[s].op),
                   cur.step[s].args[0], cur.step[s].args[1], cur.step[s].args[2]);
    }
#else
    printf("\n=== PHASE 2: reduction DISABLED (SF_REDUCE_MAX=0) ===\n");
#endif
}

/* ============ CONTROL: unblock on a correctly ordered wait list ============
 * Negative control for O_WQ: a holder releases a mutex two waiters with
 * distinct priorities block on, so the correct wakee is unique. */
static uint32_t ctrl_rounds, ctrl_wakes, ctrl_deq_viol, ctrl_skipped;

static void control_unblock_ordered(int rounds)
{
    printf("\n=== CONTROL: unblock with a correctly ordered wait list ===\n");
    for (int r = 0; r < rounds; r++) {
        reset_world();
        uint32_t dq_b = n_deq_viol, jd_b = n_deq_judged;

        int m = r % N_MUTEX_SLOTS;
        const int h = 0, w1 = 1, w2 = 2;          /* holder + two waiters */
        if (!slot_alive(h) || !slot_alive(w1) || !slot_alive(w2)
            || g_mutex[m] == NULL) { ctrl_skipped++; continue; }

        const int ph = WORKER_PRIO_LO, p1 = WORKER_PRIO_LO + 1, p2 = WORKER_PRIO_LO + 2;
        int who[3] = { h, w1, w2 }, pr[3] = { ph, p1, p2 };
        for (int i = 0; i < 3; i++) {
            vTaskPrioritySet(g_task[who[i]], (UBaseType_t)pr[i]);
            g_base_prio[who[i]] = pr[i];
            frp_task_set_base_prio(who[i], pr[i]);
        }

        /* post() applies no shadow effect, so sigma is stepped by hand. */
        post(h, OP_HOLD_TAKE, (uint8_t)m, 0);      /* holder acquires */
        vTaskDelay(pdMS_TO_TICKS(20)); drain_acks();
        sf_op_apply_effect(&g_sigma, SF_EFF_MUTEX_TAKE, h, m, 0);

        post(w1, OP_HOLD_TAKE, (uint8_t)m, 0);     /* both block behind it */
        post(w2, OP_HOLD_TAKE, (uint8_t)m, 0);
        vTaskDelay(pdMS_TO_TICKS(20)); drain_acks();
        sf_op_apply_effect(&g_sigma, SF_EFF_TASK_PEND, w1, m, 0);
        sf_op_apply_effect(&g_sigma, SF_EFF_TASK_PEND, w2, m, 0);

        post(h, OP_GIVE_MUTEX, (uint8_t)m, 0);
        vTaskDelay(pdMS_TO_TICKS(SEQ_SETTLE_MS)); drain_acks();

        judge_dequeue();

        ctrl_rounds++;
        ctrl_wakes    += (n_deq_judged - jd_b);
        ctrl_deq_viol += (n_deq_viol - dq_b);
    }
    printf("  rounds run          : %u", ctrl_rounds);
    if (ctrl_skipped) printf("   (%u skipped: slots or mutex unavailable)", ctrl_skipped);
    printf("\n  wake decisions judged: %u  <- the denominator. A round whose waiters\n"
           "                        timed out before the give offers no decision to\n"
           "                        check, and silence over zero decisions is not a\n"
           "                        silent control.\n", ctrl_wakes);
    printf("  O_WQ dequeue violations: %u  (expected 0)\n", ctrl_deq_viol);
    if (ctrl_wakes == 0)
        printf("  !! NO wake decision was judged -- this control established nothing.\n");
    else if (ctrl_deq_viol)
        printf("  !! the oracle fired on a correctly ordered wait list -- either the\n"
               "     control is mis-built or the relation has a false-positive path.\n");
}

/* ---------------- generation / corpus ---------------- */
static void tc_gen_random(struct testcase *tc, uint32_t *s)
{
    sf_rng_t r; r.s = *s;
    tc->n = 4 + (int)sf_rng_range(&r, 0, TC_MAX - 5);
    sf_gen_tc((uint8_t *)tc->step, (uint8_t)tc->n, 1 + SC_ARGS,
              &FR_TABLE, &r, SF_MUTEX_LOCALITY_PCT, SF_TASK_SPREAD_PCT);
    *s = r.s;
}

static struct testcase corpus_storage[CORPUS_MAX];
static uint8_t         corpus_energy[CORPUS_MAX];
static struct sf_corpus the_corpus;

static void tc_mutate(struct testcase *tc, uint32_t *s)
{
    sf_rng_t r = { .s = *s };
    uint8_t n = (uint8_t)tc->n;
    sf_mut_mix_typed((uint8_t *)tc->step, &n, TC_MAX, sizeof(struct sc_step),
                     &r, &FR_TABLE);
    tc->n = n;
    *s = r.s;
}

/* ---------------- driver ---------------- */
static void driver_task(void *p)
{
    (void)p;
    /* Seed: SF_SEED_BASE at compile time, overridden by the SF_SEED env var. */
#ifndef SF_SEED_BASE
#define SF_SEED_BASE 0xF4EE0001u
#endif
    uint32_t seed = (uint32_t)SF_SEED_BASE;
    { const char *_e = getenv("SF_SEED");
      if (_e && *_e) seed = (uint32_t)strtoul(_e, (char **)0, 0); }
    printf("##SEED=0x%08x\n", (unsigned)seed);
    fflush(stdout);

    sf_coverage_init(&g_cov);
    sf_corpus_init(&the_corpus, (uint8_t *)corpus_storage, corpus_energy,
                   sizeof(struct testcase), CORPUS_MAX);
    rt_inv_make_registry(&g_reg, g_reg_items, g_reg_hit, g_reg_seen);

    printf("=== FreeRTOS op-sequence fuzzer, %d iters ===\n", N_ITERS);
    printf("    %d ops, %d task slots, %d mutex slots, corpus %d\n",
           N_OPS, N_TASK_SLOTS, N_MUTEX_SLOTS, CORPUS_MAX);

    /* Throughput in ops over the campaign loop only (host monotonic clock). */
    static unsigned long long g_total_steps = 0;
    struct timespec camp_t0, camp_t1;
    clock_gettime(CLOCK_MONOTONIC, &camp_t0);
    int novel = 0;
    for (int it = 0; it < N_ITERS; it++) {
        struct testcase tc;
        void *pick = NULL;
        if (the_corpus.n > 0 && (sf_rnd(&seed, 100) < 50)) {
            sf_rng_t wr = { .s = seed };
            uint8_t pick_idx = 0;
            pick = sf_corpus_get_weighted(&the_corpus, &wr, &pick_idx);
            seed = wr.s;
            if (pick == NULL)   /* every energy decayed to zero */
                pick = sf_corpus_get(&the_corpus, (uint8_t)sf_rnd(&seed, the_corpus.n));
        }
        if (pick) { memcpy(&tc, pick, sizeof tc); tc_mutate(&tc, &seed); }
        else      { tc_gen_random(&tc, &seed); }
        if (tc.n < 1) tc.n = 1;
        if (tc.n > TC_MAX) tc.n = TC_MAX;
        g_total_steps += (unsigned long long)tc.n;

        uint32_t before = n_owner_div + n_alive_div + n_base_div + n_wait_div;
        uint32_t hits_before = 0;
        for (int i = 0; i < RT_INV__N; i++)
            hits_before += g_reg_hit[i];
        uint32_t depth_before = g_queue_depth_hits;
        uint32_t dq_before    = n_deq_viol;

        run_tc(&tc);

        uint32_t after = n_owner_div + n_alive_div + n_base_div + n_wait_div;
        uint32_t hits_after = 0;
        for (int i = 0; i < RT_INV__N; i++)
            hits_after += g_reg_hit[i];
        int wq_looked = (g_queue_depth_hits > depth_before);
        int dq_fired  = (n_deq_viol > dq_before);

        int is_novel = (sf_coverage_seen(&g_cov, sigma_rt_signature(&g_sigma)) == 0);
        if (is_novel) novel++;
        if (is_novel || after > before || hits_after > hits_before
            || wq_looked)
            sf_corpus_add(&the_corpus, &tc,
                          dq_fired ? 32
                        : (after > before || hits_after > hits_before) ? 16 : 8);

        /* Record the first SF_REDUCE_MAX O_WQ findings for PHASE 2. */
        {
            if (dq_fired && n_findings < SF_REDUCE_MAX) {
                int slot = n_findings++;
                finding_tc[slot]   = tc;
                finding_mask[slot] = FK_DEQ;
                finding_iter[slot] = it;
            }
        }

        /* One record per evaluated scenario; qdepth and wakes are cumulative. */
        printf("  it=%d steps=%d qdepth=%u wakes=%u", it, tc.n,
               g_queue_depth_hits, n_deq_judged);
        {
            if (dq_fired)
                printf("  [O_WQ deq] violations=%u wakes=%u",
                       n_deq_viol, n_deq_judged);
            if (after > before)
                printf("  [SIGMA] owner=%u alive=%u base=%u wait=%u",
                       n_owner_div, n_alive_div, n_base_div, n_wait_div);
            if (hits_after > hits_before) {
                printf("  [INV]");
                for (int i = 0; i < RT_INV__N; i++)
                    if (g_reg_hit[i])
                        printf(" %s=%u", g_reg_items[i].name, g_reg_hit[i]);
            }
            printf("%s\n", is_novel ? "  NOVEL+corpus" : "");
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &camp_t1);
    double camp_secs = (double)(camp_t1.tv_sec - camp_t0.tv_sec)
                     + (double)(camp_t1.tv_nsec - camp_t0.tv_nsec) / 1e9;

    /* ---- totals ---- */
    uint32_t inv_total = 0;
    for (int i = 0; i < RT_INV__N; i++) inv_total += g_reg_hit[i];
    printf("\n=== op-sequence campaign done ===\n");
    printf("  iterations        : %d\n", N_ITERS);
    printf("  unique sigma sigs : %u\n", (unsigned)sf_coverage_count(&g_cov));
    printf("  corpus entries    : %u\n", (unsigned)the_corpus.n);
    printf("  novel testcases   : %d\n", novel);
    printf("  sigma divergences : owner=%u alive=%u base=%u wait=%u\n",
           n_owner_div, n_alive_div, n_base_div, n_wait_div);
    printf("  invariant hits    :");
    for (int i = 0; i < RT_INV__N; i++)
        printf(" %s=%u", g_reg_items[i].name, g_reg_hit[i]);
    printf("  (total %u)\n", inv_total);
    printf("  O_WQ deq violations: %u\n", n_deq_viol);
    printf("  O_WQ wakes judged  : %u  <- wake events with >=2 waiters and an\n"
           "                       attributable wakee; a give with 0 or 1 waiter\n"
           "                       offers no choice to get wrong\n", n_deq_judged);
    if (n_deq_setdiv)
        printf("  O_WQ deq set-diverged: %u  (the observed pre-wake list and sigma's\n"
               "                       pended-on set for that mutex disagreed, so\n"
               "                       there was no single set to order -- the\n"
               "                       paper's sigma_P.waiters(q) precondition;\n"
               "                       DISCARDED, never counted as a pass)\n", n_deq_setdiv);
    if (n_deq_ambig)
        printf("  O_WQ deq ambiguous : %u  (a concurrent timeout unlinked a waiter\n"
               "                       too, so the wake could not be attributed --\n"
               "                       discarded, not guessed)\n", n_deq_ambig);
    if (n_deq_dropped)
        printf("  O_WQ deq dropped   : %u  (more wakes in one scenario than the\n"
               "                       event buffer holds -- NOT judged)\n", n_deq_dropped);
    printf("  queue-depth hits  : %u  <- observations where a live mutex held\n"
           "                         >=2 waiters; a wake is only a decision\n"
           "                         when there was something to choose from\n",
           g_queue_depth_hits);
    if (g_queue_depth_hits == 0)
        printf("  WARNING: ZERO multi-waiter queues observed -- O_WQ says NOTHING\n"
               "           about this run. Never evaluable is not the same as satisfied.\n");
    printf("  kernel asserts    : %lu\n", fr_kernel_asserts);
    printf("  OBS_DISCARDED     : %u  (sigma self-check rejected the state;"
           " the oracle was NOT evaluated on those)\n", obs_discarded);
    printf("  precondition SKIPS: %u  (ops not issued because their precondition"
           " did not hold)\n", n_skip_precond);
    printf("  mailboxes LEAKED  : %u  (worker had not acked QUIT; it owns and"
           " frees its own mailbox)\n", n_mbox_leaked);
    printf("  mutexes LEAKED    : %u  (still had waiters at teardown: leaked"
           " rather than freed under a live task)\n", n_mutex_leaked);
    if (n_deq_viol == 0)
        printf("  NOTE: no O_WQ violation -- report as 'none observed' over %d"
               " iterations, not as 'clean'.\n", N_ITERS);
    printf("  steps executed    : %llu\n", g_total_steps);
    printf("  campaign wall time: %.3f s\n", camp_secs);
    printf("  throughput        : %.1f ops/s\n",
           camp_secs > 0.0 ? (double)g_total_steps / camp_secs : 0.0);
    printf("##TOTAL_STEPS=%llu\n", g_total_steps);
    printf("=== PHASE 1 (testing) complete ===\n");
    fflush(stdout);

    reduction_phase();
    printf("=== PHASE 2 (reduction) complete ===\n");
    fflush(stdout);

#ifndef SF_CONTROL_ROUNDS
#define SF_CONTROL_ROUNDS 12
#endif
#if SF_CONTROL_ROUNDS > 0
    control_unblock_ordered(SF_CONTROL_ROUNDS);
    printf("=== PHASE 3 (control) complete ===\n");
#endif
    fflush(stdout);
    exit(0);
}

int main(void)
{
    for (int t = 0; t < N_TASK_SLOTS; t++) g_in_take_m[t] = -1;
    xTaskCreate(driver_task, "drv", 16384, NULL, DRIVER_PRIO, NULL);
    vTaskStartScheduler();
    for (;;);
}
/* Each hook prints a marker line, then spins. The stack-overflow hook is
 * inactive while configCHECK_FOR_STACK_OVERFLOW is 0. */
void vApplicationStackOverflowHook(TaskHandle_t t, char *n)
{
    (void)t;
    printf("\n##STACK_OVERFLOW task=%s\n", n ? n : "(unnamed)");
    fflush(stdout);
    for (;;);
}
void vApplicationMallocFailedHook(void)
{
    printf("\n##MALLOC_FAILED heap exhausted\n");
    fflush(stdout);
    for (;;);
}
void vApplicationIdleHook(void) { }
void vApplicationTickHook(void) { }
