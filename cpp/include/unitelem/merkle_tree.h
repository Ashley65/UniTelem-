#ifndef UNITELEM_MERKLE_TREE_H
#define UNITELEM_MERKLE_TREE_H

#include "unitelem/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ut_merkle_leaf_input {
    const char *node_id;
    const char *topic;
    const uint8_t *value_bytes;
    size_t value_len;
    bool is_json;
    uint64_t lamport_time;
} ut_merkle_leaf_input_t;

typedef struct ut_merkle_leaf {
    char *key; /* "node_id:topic" */
    uint8_t hash[UT_SHA256_SIZE];
} ut_merkle_leaf_t;

typedef struct ut_merkle_tree {
    uint8_t root[UT_SHA256_SIZE];
    ut_merkle_leaf_t *leaves;
    size_t leaf_count;
} ut_merkle_tree_t;

ut_status_t ut_merkle_empty_root(uint8_t out_root[UT_SHA256_SIZE]);

ut_status_t ut_merkle_tree_init(ut_merkle_tree_t *tree);
void ut_merkle_tree_destroy(ut_merkle_tree_t *tree);

/**
 * Rebuilds the deterministic Merkle tree from an array of state registers.
 */
ut_status_t ut_merkle_tree_update(
    ut_merkle_tree_t *tree,
    const ut_merkle_leaf_input_t *inputs,
    size_t input_count
);

/**
 * Formats a JSON (or raw) value using Python's StateMerkleTree canonical val_str rules
 * into a heap-allocated NUL-terminated string (caller must free).
 */
ut_status_t ut_merkle_canonical_val_str(
    const uint8_t *value_bytes,
    size_t value_len,
    bool is_json,
    char **out_str,
    size_t *out_len
);

/**
 * Serializes {"root": "<hex>", "leaves": {"node:topic": "<hex>", ...}}
 * into a heap-allocated JSON string (caller must free).
 */
ut_status_t ut_merkle_tree_summary_json(
    const ut_merkle_tree_t *tree,
    char **out_json,
    size_t *out_len
);

/**
 * Parses remote summary JSON and returns divergent "node_id:topic" keys.
 * Caller must free each string and the array via ut_merkle_free_keys().
 */
ut_status_t ut_merkle_tree_divergent_keys(
    const ut_merkle_tree_t *tree,
    const char *remote_summary_json,
    size_t remote_json_len,
    char ***out_keys,
    size_t *out_count,
    char *out_remote_root_hex,
    size_t remote_root_cap
);

void ut_merkle_free_keys(char **keys, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* UNITELEM_MERKLE_TREE_H */
