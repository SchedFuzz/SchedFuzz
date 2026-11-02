/* schedfuzz - invariant registry runner. */
#include "invariants.h"

int sf_inv_check_all(const struct sf_invariant_registry *reg, void *ctx)
{
    int total_delta = 0;
    for (uint8_t i = 0; i < reg->n; i++) {
        const struct sf_invariant *inv = &reg->items[i];
        if (!inv->check) continue;
        int delta = inv->check(ctx);
        if (delta > 0) {
            if (inv->hit_count) *inv->hit_count += (uint32_t)delta;
            total_delta += delta;
        }
    }
    return total_delta;
}

void sf_inv_reset_tc(const struct sf_invariant_registry *reg)
{
    for (uint8_t i = 0; i < reg->n; i++) {
        if (reg->items[i].seen_mask) *reg->items[i].seen_mask = 0;
    }
}

void sf_inv_per_domain_counts(const struct sf_invariant_registry *reg,
                              uint32_t out[SF_DOMAIN__N])
{
    for (int d = 0; d < SF_DOMAIN__N; d++) out[d] = 0;
    for (uint8_t i = 0; i < reg->n; i++) {
        const struct sf_invariant *inv = &reg->items[i];
        if (inv->hit_count && inv->domain < SF_DOMAIN__N)
            out[inv->domain] += *inv->hit_count;
    }
}
