/* schedfuzz - target-independent fuzzing core: xorshift32 PRNG, testcase
 * generation and mutation over byte buffers, and an energy-scheduled corpus. */
#ifndef SCHEDFUZZ_CORE_FUZZ_CORE_H
#define SCHEDFUZZ_CORE_FUZZ_CORE_H

#include <stdint.h>
#include <stddef.h>
#include "op_ir.h"

/* ---- PRNG ---- */

typedef struct { uint32_t s; } sf_rng_t;

static inline uint32_t sf_rng_next(sf_rng_t *r)
{
    uint32_t x = r->s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    r->s = x;
    return x;
}

static inline uint32_t sf_rng_range(sf_rng_t *r, uint32_t lo, uint32_t hi_inclusive)
{
    if (hi_inclusive <= lo) return lo;
    return lo + (sf_rng_next(r) % (hi_inclusive - lo + 1));
}

/* sf_rng_next() over a bare uint32_t state. */
static inline uint32_t sf_xorshift32(uint32_t *s)
{
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *s = x;
    return x;
}

/* Returns a value in [0, bound), or 0 if bound == 0. */
static inline uint32_t sf_rnd(uint32_t *s, uint32_t bound)
{
    return bound ? (sf_xorshift32(s) % bound) : 0;
}

/* ---- Generation and mutation (step[0] = op code, then args) ---- */

/* Chance (%) that a step starts a burst of may_block ops on one mutex slot. */
#ifndef SF_CONTENTION_BURST_PCT
#define SF_CONTENTION_BURST_PCT 25
#endif
/* After a burst: chance (%) of a may_reorder op on one of the burst's tasks. */
#ifndef SF_REKEY_AFTER_BURST_PCT
#define SF_REKEY_AFTER_BURST_PCT 70
#endif
/* After a burst: chance (%) of a may_release op by the holder. */
#ifndef SF_RELEASE_AFTER_BURST_PCT
#define SF_RELEASE_AFTER_BURST_PCT 40
#endif
#define SF_GEN_MAX_OPS          64

/* mutex_locality_pct: chance (%) a mutex argument reuses the last mutex slot;
 * task_spread_pct: chance (%) a task argument avoids the last task. */
void sf_gen_tc(uint8_t *tc_bytes, uint8_t n_steps, size_t step_size,
               const struct sf_op_table *table, sf_rng_t *r,
               uint8_t mutex_locality_pct, uint8_t task_spread_pct);

/* sf_gen_tc() with an explicit burst probability (%). */
void sf_gen_tc_ex(uint8_t *tc_bytes, uint8_t n_steps, size_t step_size,
                  const struct sf_op_table *table, sf_rng_t *r,
                  uint8_t mutex_locality_pct, uint8_t task_spread_pct,
                  uint8_t burst_pct);

/* Flip a single random bit in a random step's args. */
void sf_mut_bitflip(uint8_t *tc_bytes, uint8_t n_steps, size_t step_size,
                    sf_rng_t *r);

/* Overwrite a single random arg byte with a fresh random value. */
void sf_mut_byte_overwrite(uint8_t *tc_bytes, uint8_t n_steps, size_t step_size,
                           sf_rng_t *r);

void sf_mut_change_op(uint8_t *tc_bytes, uint8_t n_steps, size_t step_size,
                      sf_rng_t *r, uint8_t n_ops);

/* Insert, remove, dup, swap and splice return 1 if applied, 0 otherwise. */
int sf_mut_insert_step(uint8_t *tc_bytes, uint8_t *n_steps, uint8_t max_steps,
                       size_t step_size, sf_rng_t *r, uint8_t n_ops);

int sf_mut_remove_step(uint8_t *tc_bytes, uint8_t *n_steps, size_t step_size,
                       sf_rng_t *r);

int sf_mut_dup_step(uint8_t *tc_bytes, uint8_t *n_steps, uint8_t max_steps,
                    size_t step_size, sf_rng_t *r);

int sf_mut_swap_steps(uint8_t *tc_bytes, uint8_t n_steps, size_t step_size,
                      sf_rng_t *r);

/* Overwrite a run of steps with freshly generated ones; length is unchanged. */
int sf_mut_splice(uint8_t *tc_bytes, uint8_t n_steps, size_t step_size,
                  sf_rng_t *r, const struct sf_op_table *table);

/* Redraw a slot operand, or perturb a numeric arg around its current value. */
void sf_mut_byte_overwrite_typed(uint8_t *tc_bytes, uint8_t n_steps,
                                 size_t step_size, sf_rng_t *r,
                                 const struct sf_op_table *table);

/* Rewrite an op code to another op with the same operand types. */
void sf_mut_change_op_typed(uint8_t *tc_bytes, uint8_t n_steps,
                            size_t step_size, sf_rng_t *r,
                            const struct sf_op_table *table);

/* Apply 1-4 random mutations chosen uniformly among eight operators. */
void sf_mut_mix_typed(uint8_t *tc_bytes, uint8_t *n_steps, uint8_t max_steps,
                      size_t step_size, sf_rng_t *r,
                      const struct sf_op_table *table);

/* ---- Corpus ---- */

struct sf_corpus {
    uint8_t *entries;       /* max_entries * entry_size bytes */
    uint8_t *energy;        /* picks left, one byte per entry */
    uint16_t entry_size;
    uint8_t  max_entries;
    uint8_t  n;             /* current count */
};

/* Initialize the corpus with caller-supplied storage. */
void sf_corpus_init(struct sf_corpus *c, uint8_t *entries_storage,
                    uint8_t *energy_storage, uint16_t entry_size,
                    uint8_t max_entries);

/* When full, replaces the lowest-energy entry. */
void sf_corpus_add(struct sf_corpus *c, const void *tc, uint8_t initial_energy);

/* Pointer into the corpus (not a copy), or NULL; decrements its energy. */
void *sf_corpus_get(struct sf_corpus *c, uint8_t idx);

/* Energy-weighted pick, otherwise like sf_corpus_get(); NULL if empty. */
void *sf_corpus_get_weighted(struct sf_corpus *c, sf_rng_t *r,
                              uint8_t *out_idx);

#endif /* SCHEDFUZZ_CORE_FUZZ_CORE_H */
