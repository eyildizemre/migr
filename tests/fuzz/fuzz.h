// The interface between a fuzz harness, the generated seeds, and the replay
// driver. A harness is built twice: with libFuzzer for open-ended discovery
// (make fuzz), and with replay_main.c into a deterministic test binary that
// make test runs over the generated seeds and the checked-in corpus.
//
// Each replay binary links one seed set for its input format: the journal
// seeds (seeds_journal.c), shared by every harness that reads a journal, or
// a set of its own.

#ifndef FUZZ_H
#define FUZZ_H

#include <stddef.h>
#include <stdint.h>

#define FUZZ_MAX_BOUNDARIES 256U

typedef struct {
    const char *name;
    unsigned char *data;
    size_t size;
    // The outcome each harness must report, by fuzz_outcome()'s names: one
    // per journal harness, or outcome in a set only one harness reads.
    const char *parse_outcome;
    const char *load_outcome;
    const char *outcome;
    // Unedited writer output, so every prefix of it is what a killed process
    // leaves. boundaries holds the offset just past each record that ends a
    // group (ENTRY_COMMIT, DELETE, CLAIM) where the seed's builder knows
    // them; edited seeds have none.
    int writer_output;
    size_t boundaries[FUZZ_MAX_BOUNDARIES];
    size_t boundary_count;
} FuzzSeed;

// The seeds are made up, never taken from a real backup. Building them
// aborts on failure: they are fixed inputs, not test subjects.
void fuzz_seeds_build(FuzzSeed **seeds, size_t *count);
void fuzz_seeds_free(FuzzSeed *seeds, size_t count);

// Each harness defines these. LLVMFuzzerTestOneInput aborts on an oracle
// violation, so libFuzzer keeps the input; fuzz_check_seed adds the oracles
// that hold for generated seeds only.
extern const char fuzz_target_name[];
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
const char *fuzz_outcome(const uint8_t *data, size_t size);
const char *fuzz_seed_outcome(const FuzzSeed *seed);
void fuzz_check_seed(const FuzzSeed *seed);

#endif
