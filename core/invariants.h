/* schedfuzz - generic invariant framework: named predicates over kernel
 * state, grouped by observation domain. */
#ifndef SCHEDFUZZ_CORE_INVARIANTS_H
#define SCHEDFUZZ_CORE_INVARIANTS_H

#include <stdint.h>
#include <stdbool.h>

/* ----- Domains ----- */

typedef enum {
    /* D1: the kernel's own asserts (WARN/BUG/KASAN/CONFIG_ASSERT). */
    SF_DOMAIN_KERNEL_ASSERT = 0,

    /* D2: single-field bounds and state of one kernel object. */
    SF_DOMAIN_SINGLE_FIELD = 1,

    /* D3: refinement: expected state σ diffed against kernel state s. */
    SF_DOMAIN_REFINEMENT = 2,

    /* D4: inter-field coherence on the kernel side, e.g. wait-queue order. */
    SF_DOMAIN_INTER_FIELD = 3,

    /* D5: return code agrees with the resulting state; no check uses it. */
    SF_DOMAIN_API_RETURN = 4,

    SF_DOMAIN__N,
} sf_domain_t;

/* ----- Invariant descriptor ----- */

struct sf_invariant {
    const char  *name;
    sf_domain_t  domain;

    /* Returns the number of new violations (0 = holds), deduped per testcase. */
    int (*check)(void *ctx);

    /* Caller-supplied storage. */
    uint32_t *hit_count;       /* cumulative across run */
    uint32_t *seen_mask;       /* per-testcase dedup, one bit per entity */
};

/* ----- Registry ----- */

struct sf_invariant_registry {
    const struct sf_invariant *items;
    uint8_t n;
};

/* Returns the total number of new violations across all invariants. */
int sf_inv_check_all(const struct sf_invariant_registry *reg, void *ctx);

/* Reset per-testcase dedup state on all invariants. */
void sf_inv_reset_tc(const struct sf_invariant_registry *reg);

void sf_inv_per_domain_counts(const struct sf_invariant_registry *reg,
                              uint32_t out[SF_DOMAIN__N]);

#endif /* SCHEDFUZZ_CORE_INVARIANTS_H */
