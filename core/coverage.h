/* schedfuzz - state-signature coverage: a fixed-size Bloom filter recording
 * which 32-bit kernel-state signatures have been seen. */
#ifndef SCHEDFUZZ_CORE_COVERAGE_H
#define SCHEDFUZZ_CORE_COVERAGE_H

#include <stdint.h>
#include <string.h>

#define SF_COV_BITS  (1u << 16)
#define SF_COV_BYTES (SF_COV_BITS / 8u)

struct sf_coverage {
    uint8_t  bitmap[SF_COV_BYTES];
    uint32_t unique_count;
};

static inline void sf_coverage_init(struct sf_coverage *c)
{
    memset(c->bitmap, 0, sizeof c->bitmap);
    c->unique_count = 0;
}

/* Returns 1 if sig was already seen, 0 if novel. */
static inline int sf_coverage_seen(struct sf_coverage *c, uint32_t sig)
{
    uint32_t idx  = sig % SF_COV_BITS;
    uint8_t  mask = (uint8_t)(1u << (idx & 7u));
    uint32_t byte = idx >> 3;
    if (c->bitmap[byte] & mask) return 1;
    c->bitmap[byte] |= mask;
    c->unique_count++;
    return 0;
}

static inline uint32_t sf_coverage_count(const struct sf_coverage *c)
{
    return c->unique_count;
}

/* djb2-style 32-bit hash combiner for building signatures. */
static inline uint32_t sf_hash_init(void) { return 5381u; }
static inline uint32_t sf_hash_mix(uint32_t h, uint32_t v)
{
    return h * 33u + v;
}

#endif /* SCHEDFUZZ_CORE_COVERAGE_H */
