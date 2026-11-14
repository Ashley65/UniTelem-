#include "unitelem/state_crdt.h"
#include "yyjson.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

static double current_wall_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static char *dup_cstr(const char *s) {
    size_t n = strlen(s);
    char *p = (char *)malloc(n + 1u);
    if (p) memcpy(p, s, n + 1u);
    return p;
}

static ut_lww_register_t *find_reg(ut_swarm_state_t *state, const char *node_id, const char *topic) {
    for (size_t i = 0u; i < state->count; ++i) {
        if (strcmp(state->registers[i].node_id, node_id) == 0 &&
            strcmp(state->registers[i].topic, topic) == 0) {
            return &state->registers[i];
        }
    }
    return NULL;
}

static ut_status_t insert_or_replace_reg(
    ut_swarm_state_t *state,
    const char *node_id,
    const char *topic,
    const uint8_t *value,
    size_t value_len,
    bool is_json,
    uint64_t lamport_time,
    double wall_time,
    bool *out_updated
) {
    if (out_updated) *out_updated = false;
    ut_lww_register_t *reg = find_reg(state, node_id, topic);
    if (reg) {
        bool newer = (lamport_time > reg->lamport_time) ||
                     (lamport_time == reg->lamport_time && wall_time > reg->wall_time);
        if (!newer) {
            return UT_OK;
        }
        uint8_t *val_copy = NULL;
        if (value_len > 0u) {
            val_copy = (uint8_t *)malloc(value_len + 1u);
            if (!val_copy) return UT_ERR_NO_MEMORY;
            memcpy(val_copy, value, value_len);
            val_copy[value_len] = '\0';
        }
        free(reg->value);
        reg->value = val_copy;
        reg->value_len = value_len;
        reg->is_json = is_json;
        reg->lamport_time = lamport_time;
        reg->wall_time = wall_time;
        if (out_updated) *out_updated = true;
        return UT_OK;
    }

    if (state->count == state->capacity) {
        size_t new_cap = (state->capacity == 0u) ? 32u : state->capacity * 2u;
        ut_lww_register_t *grown = (ut_lww_register_t *)realloc(
            state->registers, new_cap * sizeof(ut_lww_register_t));
        if (!grown) return UT_ERR_NO_MEMORY;
        state->registers = grown;
        state->capacity = new_cap;
    }

    char *topic_copy = dup_cstr(topic);
    if (!topic_copy) return UT_ERR_NO_MEMORY;
    uint8_t *val_copy = NULL;
    if (value_len > 0u) {
        val_copy = (uint8_t *)malloc(value_len + 1u);
        if (!val_copy) {
            free(topic_copy);
            return UT_ERR_NO_MEMORY;
        }
        memcpy(val_copy, value, value_len);
        val_copy[value_len] = '\0';
    }

    ut_lww_register_t *slot = &state->registers[state->count++];
    memset(slot, 0, sizeof(*slot));
    size_t nid_len = strnlen(node_id, UT_NODE_ID_MAX);
    memcpy(slot->node_id, node_id, nid_len);
    slot->node_id[nid_len] = '\0';
    slot->topic = topic_copy;
    slot->value = val_copy;
    slot->value_len = value_len;
    slot->is_json = is_json;
    slot->lamport_time = lamport_time;
    slot->wall_time = wall_time;
    if (out_updated) *out_updated = true;
    return UT_OK;
}

ut_status_t ut_swarm_state_init(ut_swarm_state_t *state, const char *local_node_id) {
    if (!state || !local_node_id) return UT_ERR_INVALID_ARG;
    memset(state, 0, sizeof(*state));
    size_t len = strnlen(local_node_id, UT_NODE_ID_MAX);
    memcpy(state->local_node_id, local_node_id, len);
    state->local_node_id[len] = '\0';
    if (pthread_mutex_init(&state->lock, NULL) != 0) {
        return UT_ERR_IO;
    }
    return UT_OK;
}

void ut_swarm_state_destroy(ut_swarm_state_t *state) {
    if (!state) return;
    for (size_t i = 0u; i < state->count; ++i) {
        free(state->registers[i].topic);
        free(state->registers[i].value);
    }
    free(state->registers);
    state->registers = NULL;
    state->count = 0u;
    state->capacity = 0u;
    pthread_mutex_destroy(&state->lock);
}

uint64_t ut_swarm_state_clock(ut_swarm_state_t *state) {
    if (!state) return 0u;
    pthread_mutex_lock(&state->lock);
    uint64_t c = state->clock;
    pthread_mutex_unlock(&state->lock);
    return c;
}

ut_status_t ut_swarm_state_update_local(
    ut_swarm_state_t *state,
    const char *topic,
    const uint8_t *value,
    size_t value_len,
    bool is_json,
    uint64_t *out_lamport_time,
    double *out_wall_time
) {
    if (!state || !topic || (!value && value_len > 0u)) {
        return UT_ERR_INVALID_ARG;
    }
    pthread_mutex_lock(&state->lock);
    state->clock += 1u;
    uint64_t l_ts = state->clock;
    double w_ts = current_wall_time_sec();
    bool updated = false;
    ut_status_t st = insert_or_replace_reg(
        state, state->local_node_id, topic, value, value_len, is_json, l_ts, w_ts, &updated);
    pthread_mutex_unlock(&state->lock);
    if (st == UT_OK) {
        if (out_lamport_time) *out_lamport_time = l_ts;
        if (out_wall_time) *out_wall_time = w_ts;
    }
    return st;
}

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
) {
    if (!state || !node_id || !topic || (!value && value_len > 0u)) {
        return UT_ERR_INVALID_ARG;
    }
    pthread_mutex_lock(&state->lock);
    if (lamport_time > state->clock) {
        state->clock = lamport_time;
    }
    state->clock += 1u;
    ut_status_t st = insert_or_replace_reg(
        state, node_id, topic, value, value_len, is_json, lamport_time, wall_time, out_updated);
    pthread_mutex_unlock(&state->lock);
    return st;
}

ut_status_t ut_swarm_state_get_value(
    ut_swarm_state_t *state,
    const char *path,
    uint8_t *out_buf,
    size_t out_cap,
    size_t *out_len,
    bool *out_is_json
) {
    if (!state || !path) return UT_ERR_INVALID_ARG;

    pthread_mutex_lock(&state->lock);
    ut_lww_register_t *reg = NULL;
    const char *slash = strchr(path, '/');
    if (slash) {
        size_t nid_len = (size_t)(slash - path);
        if (nid_len <= UT_NODE_ID_MAX) {
            char nid[UT_NODE_ID_MAX + 1];
            memcpy(nid, path, nid_len);
            nid[nid_len] = '\0';
            reg = find_reg(state, nid, slash + 1);
        }
    }
    if (!reg) {
        reg = find_reg(state, state->local_node_id, path);
    }
    if (!reg && slash) {
        size_t nid_len = (size_t)(slash - path);
        if (nid_len <= UT_NODE_ID_MAX) {
            char nid[UT_NODE_ID_MAX + 1];
            memcpy(nid, path, nid_len);
            nid[nid_len] = '\0';
            reg = find_reg(state, nid, path);
        }
    }

    if (!reg) {
        pthread_mutex_unlock(&state->lock);
        return UT_ERR_NOT_FOUND;
    }

    if (out_len) *out_len = reg->value_len;
    if (out_is_json) *out_is_json = reg->is_json;
    if (!out_buf || out_cap < reg->value_len) {
        pthread_mutex_unlock(&state->lock);
        return UT_ERR_BUFFER_TOO_SMALL;
    }
    if (reg->value_len > 0u) {
        memcpy(out_buf, reg->value, reg->value_len);
    }
    if (out_cap > reg->value_len) {
        out_buf[reg->value_len] = '\0';
    }
    pthread_mutex_unlock(&state->lock);
    return UT_OK;
}

ut_status_t ut_swarm_state_compute_merkle(ut_swarm_state_t *state, ut_merkle_tree_t *tree) {
    if (!state || !tree) return UT_ERR_INVALID_ARG;

    pthread_mutex_lock(&state->lock);
    size_t n = state->count;
    ut_merkle_leaf_input_t *inputs = NULL;
    if (n > 0u) {
        inputs = (ut_merkle_leaf_input_t *)calloc(n, sizeof(ut_merkle_leaf_input_t));
        if (!inputs) {
            pthread_mutex_unlock(&state->lock);
            return UT_ERR_NO_MEMORY;
        }
        for (size_t i = 0u; i < n; ++i) {
            inputs[i].node_id = state->registers[i].node_id;
            inputs[i].topic = state->registers[i].topic;
            inputs[i].value_bytes = state->registers[i].value;
            inputs[i].value_len = state->registers[i].value_len;
            inputs[i].is_json = state->registers[i].is_json;
            inputs[i].lamport_time = state->registers[i].lamport_time;
        }
    }
    ut_status_t st = ut_merkle_tree_update(tree, inputs, n);
    free(inputs);
    pthread_mutex_unlock(&state->lock);
    return st;
}

static yyjson_mut_val *json_val_from_register(yyjson_mut_doc *doc, const ut_lww_register_t *reg) {
    if (reg->is_json && reg->value && reg->value_len > 0u) {
        yyjson_doc *tmp = yyjson_read((const char *)reg->value, reg->value_len, 0);
        if (tmp) {
            yyjson_mut_val *copied = yyjson_val_mut_copy(doc, yyjson_doc_get_root(tmp));
            yyjson_doc_free(tmp);
            if (copied) return copied;
        }
    }
    if (reg->value && reg->value_len > 0u) {
        return yyjson_mut_strncpy(doc, (const char *)reg->value, reg->value_len);
    }
    return yyjson_mut_null(doc);
}

ut_status_t ut_swarm_state_export_registers_json(
    ut_swarm_state_t *state,
    const char *const *keys,
    size_t key_count,
    char **out_json,
    size_t *out_len
) {
    if (!state || !out_json || (!keys && key_count > 0u)) return UT_ERR_INVALID_ARG;

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) return UT_ERR_NO_MEMORY;
    yyjson_mut_val *arr = yyjson_mut_arr(doc);
    yyjson_mut_doc_set_root(doc, arr);

    pthread_mutex_lock(&state->lock);
    for (size_t i = 0u; i < key_count; ++i) {
        const char *k = keys[i];
        const char *sep = strchr(k, ':');
        if (!sep) sep = strchr(k, '/');
        char nid[UT_NODE_ID_MAX + 1];
        const char *topic = NULL;
        if (sep) {
            size_t nid_len = (size_t)(sep - k);
            if (nid_len > UT_NODE_ID_MAX) continue;
            memcpy(nid, k, nid_len);
            nid[nid_len] = '\0';
            topic = sep + 1;
        } else {
            memcpy(nid, state->local_node_id, sizeof(nid));
            topic = k;
        }
        ut_lww_register_t *reg = find_reg(state, nid, topic);
        if (!reg) continue;

        yyjson_mut_val *obj = yyjson_mut_obj(doc);
        yyjson_mut_obj_add_strcpy(doc, obj, "node_id", reg->node_id);
        yyjson_mut_obj_add_strcpy(doc, obj, "topic", reg->topic);
        yyjson_mut_obj_add_val(doc, obj, "value", json_val_from_register(doc, reg));
        yyjson_mut_obj_add_uint(doc, obj, "lamport_time", reg->lamport_time);
        yyjson_mut_obj_add_real(doc, obj, "wall_time", reg->wall_time);
        yyjson_mut_arr_append(arr, obj);
    }
    pthread_mutex_unlock(&state->lock);

    size_t len = 0u;
    char *s = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);
    if (!s) return UT_ERR_NO_MEMORY;
    *out_json = s;
    if (out_len) *out_len = len;
    return UT_OK;
}

ut_status_t ut_swarm_state_merge_batch_json(
    ut_swarm_state_t *state,
    const char *json_str,
    size_t json_len,
    size_t *out_updated_count
) {
    if (!state || !json_str) return UT_ERR_INVALID_ARG;
    if (out_updated_count) *out_updated_count = 0u;

    yyjson_doc *doc = yyjson_read(json_str, json_len, 0);
    if (!doc) return UT_ERR_MALFORMED;
    yyjson_val *arr = yyjson_doc_get_root(doc);
    if (!yyjson_is_arr(arr)) {
        yyjson_doc_free(doc);
        return UT_ERR_MALFORMED;
    }

    size_t updated_total = 0u;
    size_t idx = 0u, max = 0u;
    yyjson_val *item = NULL;

    pthread_mutex_lock(&state->lock);
    yyjson_arr_foreach(arr, idx, max, item) {
        if (!yyjson_is_obj(item)) continue;
        yyjson_val *v_nid = yyjson_obj_get(item, "node_id");
        yyjson_val *v_top = yyjson_obj_get(item, "topic");
        yyjson_val *v_val = yyjson_obj_get(item, "value");
        yyjson_val *v_lts = yyjson_obj_get(item, "lamport_time");
        yyjson_val *v_wts = yyjson_obj_get(item, "wall_time");
        if (!yyjson_is_str(v_nid) || !yyjson_is_str(v_top) || !v_val || !yyjson_is_uint(v_lts)) {
            continue;
        }
        const char *nid = yyjson_get_str(v_nid);
        const char *top = yyjson_get_str(v_top);
        uint64_t l_ts = yyjson_get_uint(v_lts);
        double w_ts = yyjson_is_num(v_wts) ? yyjson_get_num(v_wts) : 0.0;

        size_t val_len = 0u;
        char *val_json = yyjson_val_write(v_val, 0, &val_len);
        if (!val_json) continue;

        if (l_ts > state->clock) {
            state->clock = l_ts;
        }
        state->clock += 1u;

        bool updated = false;
        insert_or_replace_reg(
            state, nid, top, (const uint8_t *)val_json, val_len, true, l_ts, w_ts, &updated);
        free(val_json);
        if (updated) updated_total += 1u;
    }
    pthread_mutex_unlock(&state->lock);

    yyjson_doc_free(doc);
    if (out_updated_count) *out_updated_count = updated_total;
    return UT_OK;
}

ut_status_t ut_swarm_state_snapshot_json(
    ut_swarm_state_t *state,
    char **out_json,
    size_t *out_len
) {
    if (!state || !out_json) return UT_ERR_INVALID_ARG;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) return UT_ERR_NO_MEMORY;
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    pthread_mutex_lock(&state->lock);
    for (size_t i = 0u; i < state->count; ++i) {
        const ut_lww_register_t *reg = &state->registers[i];
        yyjson_mut_val *node_obj = yyjson_mut_obj_get(root, reg->node_id);
        if (!node_obj) {
            node_obj = yyjson_mut_obj(doc);
            yyjson_mut_obj_add(root, yyjson_mut_strcpy(doc, reg->node_id), node_obj);
        }
        yyjson_mut_val *k = yyjson_mut_strcpy(doc, reg->topic);
        yyjson_mut_val *v = json_val_from_register(doc, reg);
        yyjson_mut_obj_add(node_obj, k, v);
    }
    pthread_mutex_unlock(&state->lock);

    size_t len = 0u;
    char *s = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);
    if (!s) return UT_ERR_NO_MEMORY;
    *out_json = s;
    if (out_len) *out_len = len;
    return UT_OK;
}
