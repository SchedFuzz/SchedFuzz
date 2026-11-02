/* schedfuzz - registry adapters for the structural RT invariants (I3-I5). */
#include "rt_invariants.h"

static int check_owner(void *ctx_v)
{
    struct rt_inv_ctx *ctx = (struct rt_inv_ctx *)ctx_v;
    int before = (int)ctx->struct_state.mutex_single_owner;
    sf_inv_check_mutex_owner_not_self_pended(ctx->adapter,
                                              &ctx->struct_state, 0);
    return (int)ctx->struct_state.mutex_single_owner - before;
}

static int check_wait(void *ctx_v)
{
    struct rt_inv_ctx *ctx = (struct rt_inv_ctx *)ctx_v;
    int before = (int)ctx->struct_state.thread_single_wait;
    sf_inv_check_thread_single_wait(ctx->adapter, &ctx->struct_state);
    return (int)ctx->struct_state.thread_single_wait - before;
}

static int check_prio(void *ctx_v)
{
    struct rt_inv_ctx *ctx = (struct rt_inv_ctx *)ctx_v;
    int before = (int)ctx->struct_state.prio_out_of_range;
    sf_inv_check_prio_bounds(ctx->adapter, &ctx->struct_state,
                              ctx->prio_lo, ctx->prio_hi);
    return (int)ctx->struct_state.prio_out_of_range - before;
}

void rt_inv_make_registry(struct sf_invariant_registry *out_reg,
                          struct sf_invariant items[RT_INV__N],
                          uint32_t hit_count[RT_INV__N],
                          uint32_t seen_mask[RT_INV__N])
{
    for (int i = 0; i < RT_INV__N; i++) {
        hit_count[i] = 0;
        seen_mask[i] = 0;
    }

    items[RT_INV_OWNER] = (struct sf_invariant){
        .name = "OWNER", .domain = SF_DOMAIN_SINGLE_FIELD,
        .check = check_owner,
        .hit_count = &hit_count[RT_INV_OWNER],
        .seen_mask = &seen_mask[RT_INV_OWNER],
    };
    items[RT_INV_WAIT] = (struct sf_invariant){
        .name = "WAIT", .domain = SF_DOMAIN_SINGLE_FIELD,
        .check = check_wait,
        .hit_count = &hit_count[RT_INV_WAIT],
        .seen_mask = &seen_mask[RT_INV_WAIT],
    };
    items[RT_INV_PRIO] = (struct sf_invariant){
        .name = "PRIO", .domain = SF_DOMAIN_SINGLE_FIELD,
        .check = check_prio,
        .hit_count = &hit_count[RT_INV_PRIO],
        .seen_mask = &seen_mask[RT_INV_PRIO],
    };

    out_reg->items = items;
    out_reg->n     = RT_INV__N;
}
