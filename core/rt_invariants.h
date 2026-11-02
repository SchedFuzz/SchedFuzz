/* schedfuzz - registers the structural RT invariants (I3-I5) with the
 * sf_invariant framework. */
#ifndef SCHEDFUZZ_CORE_RT_INVARIANTS_H
#define SCHEDFUZZ_CORE_RT_INVARIANTS_H

#include "rt_model.h"
#include "structural_inv.h"
#include "invariants.h"

struct rt_inv_ctx {
    const struct sf_rt_adapter *adapter;
    struct sf_structural_result struct_state;
    int prio_lo, prio_hi;  /* for I5; set to lo>hi to disable */
};

static inline void rt_inv_ctx_init(struct rt_inv_ctx *ctx,
                                    const struct sf_rt_adapter *adapter,
                                    int prio_lo, int prio_hi)
{
    const struct sf_structural_result struct_zero = {0};
    ctx->adapter      = adapter;
    ctx->struct_state = struct_zero;
    ctx->prio_lo      = prio_lo;
    ctx->prio_hi      = prio_hi;
}

static inline void rt_inv_ctx_reset_tc(struct rt_inv_ctx *ctx)
{
    ctx->struct_state.seen_mask_so = 0;
}

/* Indices into the registry. */
enum {
    RT_INV_OWNER    = 0,     /* I3: owner-not-self-pended */
    RT_INV_WAIT     = 1,     /* I4: wait-graph well-formed */
    RT_INV_PRIO     = 2,     /* I5: actual_prio bounds */
    RT_INV__N       = 3,
};

/* Storage is caller-supplied.  Checks take a struct rt_inv_ctx * as ctx. */
void rt_inv_make_registry(struct sf_invariant_registry *out_reg,
                          struct sf_invariant items[RT_INV__N],
                          uint32_t hit_count[RT_INV__N],
                          uint32_t seen_mask[RT_INV__N]);

#endif /* SCHEDFUZZ_CORE_RT_INVARIANTS_H */
