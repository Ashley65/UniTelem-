#ifndef UNITELEM_STATE_CRDT_H
#define UNITELEM_STATE_CRDT_H

#include "unitelem/merkle_tree.h"
#include "unitelem/types.h"

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ut_lww_register {
    char node_id[UT_NODE_ID_MAX + 1];
    char *topic;
    uint8_t *value;
    size_t value_len;
    bool is_json;
    uint64_t lamport_time;
    double wall_time;
} ut_lww_register_t;

typedef struct ut_swarm_state {
    char local_node_id[UT_NODE_ID_MAX + 1];
    uint64_t clock;
    ut_lww_register_t *registers;
    size_t count;
    size_t capacity;
    pthread_mutex_t lock;
} ut_swarm_state_t;

ut_status_t ut_swarm_state_init(ut_swarm_state_t *state, const char *local_node_id);
void ut_swarm_state_destroy(ut_swarm_state_t *state);

uint64_t ut_swarm_state_clock(ut_swarm_state_t *state);

ut_status_t ut_swarm_state_update_local(
    ut_swarm_state_t *state,
    const char *topic,
    const uint8_t *value,
    size_t value_len,
    bool is_json,
    uint64_t *out_lamport_time,
    double *out_wall_time
);

ut_status_t ut_swarm_state_merge_remote(
    ut_swarm_state_t *state,
    const char *node_id,
    const char *topic,
    const uint8_t *value,
    size_t value_len,
    bool is_json,
    uint64_t lamport_time,
    double wall_time,
    bool *out_updated
);

ut_status_t ut_swarm_state_get_value(
    ut_swarm_state_t *state,
    const char *path,
    uint8_t *out_buf,
    size_t out_cap,
    size_t *out_len,
    bool *out_is_json
);

ut_status_t ut_swarm_state_compute_merkle(
    ut_swarm_state_t *state,
    ut_merkle_tree_t *tree
);

ut_status_t ut_swarm_state_export_registers_json(
    ut_swarm_state_t *state,
    const char *const *keys,
    size_t key_count,
    char **out_json,
    size_t *out_len
);

ut_status_t ut_swarm_state_merge_batch_json(
    ut_swarm_state_t *state,
    const char *json_str,
    size_t json_len,
    size_t *out_updated_count
);

ut_status_t ut_swarm_state_snapshot_json(
    ut_swarm_state_t *state,
    char **out_json,
    size_t *out_len
);

#ifdef __cplusplus
}
#endif

#endif /* UNITELEM_STATE_CRDT_H */
