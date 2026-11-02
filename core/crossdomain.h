/* schedfuzz - cross-domain confirmation: tally the SF_DOMAIN_* domains that
 * fire in an iteration and count iterations where two or more did. */
#ifndef SCHEDFUZZ_CORE_CROSSDOMAIN_H
#define SCHEDFUZZ_CORE_CROSSDOMAIN_H

#include <stdint.h>
#include <stdbool.h>
#include "invariants.h"

struct sf_xdom {
    bool fired[SF_DOMAIN__N];
    uint32_t total_crossdomain_iters;
};

static inline void sf_xdom_reset_iter(struct sf_xdom *x)
{
    for (int d = 0; d < SF_DOMAIN__N; d++) x->fired[d] = false;
}

/* delta > 0 marks the domain as fired this iteration. */
static inline void sf_xdom_record_delta(struct sf_xdom *x,
                                        sf_domain_t domain, int delta)
{
    if (delta > 0 && domain >= 0 && domain < SF_DOMAIN__N) {
        x->fired[domain] = true;
    }
}

static inline int sf_xdom_count(const struct sf_xdom *x)
{
    int n = 0;
    for (int d = 0; d < SF_DOMAIN__N; d++) if (x->fired[d]) n++;
    return n;
}

/* End of iteration: returns true, and counts it, if >= 2 domains fired. */
static inline bool sf_xdom_close_iter(struct sf_xdom *x)
{
    if (sf_xdom_count(x) >= 2) {
        x->total_crossdomain_iters++;
        return true;
    }
    return false;
}

#endif /* SCHEDFUZZ_CORE_CROSSDOMAIN_H */
