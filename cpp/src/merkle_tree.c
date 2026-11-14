#include "unitelem/merkle_tree.h"
#include "unitelem/crypto.h"
#include "yyjson.h"

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct str_buf {
    char *data;
    size_t len;
    size_t cap;
} str_buf_t;

static bool sb_reserve(str_buf_t *sb, size_t extra) {
    if (sb->len + extra + 1u <= sb->cap) {
        return true;
    }
    size_t new_cap = (sb->cap == 0u) ? 128u : sb->cap * 2u;
    while (new_cap < sb->len + extra + 1u) {
        if (new_cap > SIZE_MAX / 2u) {
            new_cap = sb->len + extra + 1u;
            break;
        }
        new_cap *= 2u;
    }
    char *p = (char *)realloc(sb->data, new_cap);
    if (!p) {
        return false;
    }
    sb->data = p;
    sb->cap = new_cap;
    return true;
}

static bool sb_append_n(str_buf_t *sb, const char *s, size_t n) {
    if (!sb_reserve(sb, n)) {
        return false;
    }
    if (n > 0u) {
        memcpy(sb->data + sb->len, s, n);
        sb->len += n;
    }
    sb->data[sb->len] = '\0';
    return true;
}

static bool sb_append_cstr(str_buf_t *sb, const char *s) {
    return sb_append_n(sb, s, strlen(s));
}

static bool sb_append_json_escaped(str_buf_t *sb, const char *s, size_t n) {
    if (!sb_append_n(sb, "\"", 1u)) return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  if (!sb_append_n(sb, "\\\"", 2u)) return false; break;
            case '\\': if (!sb_append_n(sb, "\\\\", 2u)) return false; break;
            case '\b': if (!sb_append_n(sb, "\\b", 2u)) return false; break;
            case '\f': if (!sb_append_n(sb, "\\f", 2u)) return false; break;
            case '\n': if (!sb_append_n(sb, "\\n", 2u)) return false; break;
            case '\r': if (!sb_append_n(sb, "\\r", 2u)) return false; break;
            case '\t': if (!sb_append_n(sb, "\\t", 2u)) return false; break;
            default:
                if (c < 0x20u) {
                    char esc[7];
                    snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)c);
                    if (!sb_append_n(sb, esc, 6u)) return false;
                } else {
                    if (!sb_append_n(sb, (const char *)&c, 1u)) return false;
                }
                break;
        }
    }
    return sb_append_n(sb, "\"", 1u);
}

static bool sb_append_py_float(str_buf_t *sb, double d) {
    if (isnan(d)) return sb_append_cstr(sb, "nan");
    if (isinf(d)) return sb_append_cstr(sb, d < 0 ? "-inf" : "inf");
    char tmp[64];
    int n = snprintf(tmp, sizeof(tmp), "%.16g", d);
    if (n <= 0) return false;
    bool has_dot_or_exp = false;
    for (int i = 0; i < n; ++i) {
        if (tmp[i] == '.' || tmp[i] == 'e' || tmp[i] == 'E') {
            has_dot_or_exp = true;
            break;
        }
    }
    if (!sb_append_n(sb, tmp, (size_t)n)) return false;
    if (!has_dot_or_exp) {
        if (!sb_append_n(sb, ".0", 2u)) return false;
    }
    return true;
}

typedef struct kv_pair {
    const char *key;
    size_t key_len;
    yyjson_val *val;
} kv_pair_t;

static int cmp_kv_pair(const void *a, const void *b) {
    const kv_pair_t *ka = (const kv_pair_t *)a;
    const kv_pair_t *kb = (const kv_pair_t *)b;
    size_t min_len = (ka->key_len < kb->key_len) ? ka->key_len : kb->key_len;
    int c = memcmp(ka->key, kb->key, min_len);
    if (c != 0) return c;
    if (ka->key_len < kb->key_len) return -1;
    if (ka->key_len > kb->key_len) return 1;
    return 0;
}

/* Formats JSON value identically to Python json.dumps(val, sort_keys=True) */
static bool format_json_dumps(str_buf_t *sb, yyjson_val *val) {
    if (!val) return sb_append_cstr(sb, "null");
    switch (yyjson_get_type(val)) {
        case YYJSON_TYPE_NULL:
            return sb_append_cstr(sb, "null");
        case YYJSON_TYPE_BOOL:
            return sb_append_cstr(sb, yyjson_get_bool(val) ? "true" : "false");
        case YYJSON_TYPE_NUM: {
            if (yyjson_is_sint(val)) {
                char buf[32];
                int n = snprintf(buf, sizeof(buf), "%" PRId64, yyjson_get_sint(val));
                return n > 0 && sb_append_n(sb, buf, (size_t)n);
            }
            if (yyjson_is_uint(val)) {
                char buf[32];
                int n = snprintf(buf, sizeof(buf), "%" PRIu64, yyjson_get_uint(val));
                return n > 0 && sb_append_n(sb, buf, (size_t)n);
            }
            return sb_append_py_float(sb, yyjson_get_real(val));
        }
        case YYJSON_TYPE_STR:
            return sb_append_json_escaped(sb, yyjson_get_str(val), yyjson_get_len(val));
        case YYJSON_TYPE_ARR: {
            if (!sb_append_n(sb, "[", 1u)) return false;
            size_t idx, max;
            yyjson_val *elem;
            yyjson_arr_foreach(val, idx, max, elem) {
                if (idx > 0u && !sb_append_n(sb, ", ", 2u)) return false;
                if (!format_json_dumps(sb, elem)) return false;
            }
            return sb_append_n(sb, "]", 1u);
        }
        case YYJSON_TYPE_OBJ: {
            size_t count = yyjson_obj_size(val);
            kv_pair_t *pairs = NULL;
            if (count > 0u) {
                pairs = (kv_pair_t *)malloc(count * sizeof(kv_pair_t));
                if (!pairs) return false;
                size_t idx = 0u, max = 0u;
                yyjson_val *k, *v;
                yyjson_obj_foreach(val, idx, max, k, v) {
                    pairs[idx].key = yyjson_get_str(k);
                    pairs[idx].key_len = yyjson_get_len(k);
                    pairs[idx].val = v;
                }
                qsort(pairs, count, sizeof(kv_pair_t), cmp_kv_pair);
            }
            bool ok = sb_append_n(sb, "{", 1u);
            for (size_t i = 0u; ok && i < count; ++i) {
                if (i > 0u) ok = sb_append_n(sb, ", ", 2u);
                if (ok) ok = sb_append_json_escaped(sb, pairs[i].key, pairs[i].key_len);
                if (ok) ok = sb_append_n(sb, ": ", 2u);
                if (ok) ok = format_json_dumps(sb, pairs[i].val);
            }
            if (ok) ok = sb_append_n(sb, "}", 1u);
            free(pairs);
            return ok;
        }
        default:
            return sb_append_cstr(sb, "null");
    }
}

ut_status_t ut_merkle_canonical_val_str(
    const uint8_t *value_bytes,
    size_t value_len,
    bool is_json,
    char **out_str,
    size_t *out_len
) {
    if (!out_str || (!value_bytes && value_len > 0u)) {
        return UT_ERR_INVALID_ARG;
    }
    str_buf_t sb = {0};

    if (!is_json) {
        if (!sb_append_n(&sb, (const char *)value_bytes, value_len)) {
            free(sb.data);
            return UT_ERR_NO_MEMORY;
        }
        *out_str = sb.data;
        if (out_len) *out_len = sb.len;
        return UT_OK;
    }

    yyjson_doc *doc = yyjson_read((const char *)value_bytes, value_len, 0);
    if (!doc) {
        if (!sb_append_n(&sb, (const char *)value_bytes, value_len)) {
            free(sb.data);
            return UT_ERR_NO_MEMORY;
        }
        *out_str = sb.data;
        if (out_len) *out_len = sb.len;
        return UT_OK;
    }

    yyjson_val *root = yyjson_doc_get_root(doc);
    bool ok = false;
    switch (yyjson_get_type(root)) {
        case YYJSON_TYPE_NULL:
            ok = sb_append_cstr(&sb, "None");
            break;
        case YYJSON_TYPE_BOOL:
            ok = sb_append_cstr(&sb, yyjson_get_bool(root) ? "True" : "False");
            break;
        case YYJSON_TYPE_STR:
            ok = sb_append_n(&sb, yyjson_get_str(root), yyjson_get_len(root));
            break;
        case YYJSON_TYPE_NUM:
            if (yyjson_is_sint(root)) {
                char buf[32];
                int n = snprintf(buf, sizeof(buf), "%" PRId64, yyjson_get_sint(root));
                ok = n > 0 && sb_append_n(&sb, buf, (size_t)n);
            } else if (yyjson_is_uint(root)) {
                char buf[32];
                int n = snprintf(buf, sizeof(buf), "%" PRIu64, yyjson_get_uint(root));
                ok = n > 0 && sb_append_n(&sb, buf, (size_t)n);
            } else {
                ok = sb_append_py_float(&sb, yyjson_get_real(root));
            }
            break;
        default:
            ok = format_json_dumps(&sb, root);
            break;
    }
    yyjson_doc_free(doc);

    if (!ok) {
        free(sb.data);
        return UT_ERR_NO_MEMORY;
    }
    *out_str = sb.data;
    if (out_len) *out_len = sb.len;
    return UT_OK;
}

ut_status_t ut_merkle_empty_root(uint8_t out_root[UT_SHA256_SIZE]) {
    static const char tag[] = "UNITELEM_EMPTY_MERKLE_TREE";
    return ut_sha256((const uint8_t *)tag, sizeof(tag) - 1u, out_root);
}

static void clear_leaves(ut_merkle_tree_t *tree) {
    if (tree->leaves) {
        for (size_t i = 0u; i < tree->leaf_count; ++i) {
            free(tree->leaves[i].key);
        }
        free(tree->leaves);
        tree->leaves = NULL;
    }
    tree->leaf_count = 0u;
}

ut_status_t ut_merkle_tree_init(ut_merkle_tree_t *tree) {
    if (!tree) return UT_ERR_INVALID_ARG;
    memset(tree, 0, sizeof(*tree));
    return ut_merkle_empty_root(tree->root);
}

void ut_merkle_tree_destroy(ut_merkle_tree_t *tree) {
    if (!tree) return;
    clear_leaves(tree);
}

static int cmp_merkle_leaf(const void *a, const void *b) {
    const ut_merkle_leaf_t *la = (const ut_merkle_leaf_t *)a;
    const ut_merkle_leaf_t *lb = (const ut_merkle_leaf_t *)b;
    return strcmp(la->key, lb->key);
}

ut_status_t ut_merkle_tree_update(
    ut_merkle_tree_t *tree,
    const ut_merkle_leaf_input_t *inputs,
    size_t input_count
) {
    if (!tree || (!inputs && input_count > 0u)) {
        return UT_ERR_INVALID_ARG;
    }

    clear_leaves(tree);
    if (input_count == 0u) {
        return ut_merkle_empty_root(tree->root);
    }

    ut_merkle_leaf_t *leaves = (ut_merkle_leaf_t *)calloc(input_count, sizeof(ut_merkle_leaf_t));
    if (!leaves) {
        return UT_ERR_NO_MEMORY;
    }

    for (size_t i = 0u; i < input_count; ++i) {
        const ut_merkle_leaf_input_t *in = &inputs[i];
        size_t nid_len = strlen(in->node_id);
        size_t top_len = strlen(in->topic);
        size_t key_len = nid_len + 1u + top_len;
        leaves[i].key = (char *)malloc(key_len + 1u);
        if (!leaves[i].key) {
            for (size_t j = 0u; j < i; ++j) free(leaves[j].key);
            free(leaves);
            return UT_ERR_NO_MEMORY;
        }
        memcpy(leaves[i].key, in->node_id, nid_len);
        leaves[i].key[nid_len] = ':';
        memcpy(leaves[i].key + nid_len + 1u, in->topic, top_len);
        leaves[i].key[key_len] = '\0';

        char *val_str = NULL;
        size_t val_str_len = 0u;
        ut_status_t st = ut_merkle_canonical_val_str(
            in->value_bytes, in->value_len, in->is_json, &val_str, &val_str_len);
        if (st != UT_OK) {
            for (size_t j = 0u; j <= i; ++j) free(leaves[j].key);
            free(leaves);
            return st;
        }

        char clock_buf[32];
        int clock_len = snprintf(clock_buf, sizeof(clock_buf), "%" PRIu64, in->lamport_time);
        size_t msg_len = key_len + 1u + (size_t)clock_len + 1u + val_str_len;
        uint8_t *msg = (uint8_t *)malloc(msg_len);
        if (!msg) {
            free(val_str);
            for (size_t j = 0u; j <= i; ++j) free(leaves[j].key);
            free(leaves);
            return UT_ERR_NO_MEMORY;
        }
        size_t off = 0u;
        memcpy(msg + off, leaves[i].key, key_len); off += key_len;
        msg[off++] = ':';
        memcpy(msg + off, clock_buf, (size_t)clock_len); off += (size_t)clock_len;
        msg[off++] = ':';
        if (val_str_len > 0u) {
            memcpy(msg + off, val_str, val_str_len);
        }
        st = ut_sha256(msg, msg_len, leaves[i].hash);
        free(msg);
        free(val_str);
        if (st != UT_OK) {
            for (size_t j = 0u; j <= i; ++j) free(leaves[j].key);
            free(leaves);
            return st;
        }
    }

    qsort(leaves, input_count, sizeof(ut_merkle_leaf_t), cmp_merkle_leaf);
    tree->leaves = leaves;
    tree->leaf_count = input_count;

    if (input_count == 1u) {
        memcpy(tree->root, leaves[0].hash, UT_SHA256_SIZE);
        return UT_OK;
    }

    uint8_t *level = (uint8_t *)malloc(input_count * UT_SHA256_SIZE);
    uint8_t *next_level = (uint8_t *)malloc(((input_count + 1u) / 2u) * UT_SHA256_SIZE);
    if (!level || !next_level) {
        free(level);
        free(next_level);
        return UT_ERR_NO_MEMORY;
    }
    for (size_t i = 0u; i < input_count; ++i) {
        memcpy(level + i * UT_SHA256_SIZE, leaves[i].hash, UT_SHA256_SIZE);
    }

    size_t cur_count = input_count;
    while (cur_count > 1u) {
        size_t next_count = 0u;
        for (size_t i = 0u; i < cur_count; i += 2u) {
            uint8_t pair_buf[UT_SHA256_SIZE * 2u];
            memcpy(pair_buf, level + i * UT_SHA256_SIZE, UT_SHA256_SIZE);
            if (i + 1u < cur_count) {
                memcpy(pair_buf + UT_SHA256_SIZE, level + (i + 1u) * UT_SHA256_SIZE, UT_SHA256_SIZE);
            } else {
                memcpy(pair_buf + UT_SHA256_SIZE, level + i * UT_SHA256_SIZE, UT_SHA256_SIZE);
            }
            ut_status_t st = ut_sha256(pair_buf, sizeof(pair_buf), next_level + next_count * UT_SHA256_SIZE);
            if (st != UT_OK) {
                free(level);
                free(next_level);
                return st;
            }
            next_count += 1u;
        }
        memcpy(level, next_level, next_count * UT_SHA256_SIZE);
        cur_count = next_count;
    }

    memcpy(tree->root, level, UT_SHA256_SIZE);
    free(level);
    free(next_level);
    return UT_OK;
}

ut_status_t ut_merkle_tree_summary_json(
    const ut_merkle_tree_t *tree,
    char **out_json,
    size_t *out_len
) {
    if (!tree || !out_json) {
        return UT_ERR_INVALID_ARG;
    }
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) return UT_ERR_NO_MEMORY;
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    char root_hex[UT_SHA256_SIZE * 2u + 1u];
    ut_hex_encode(tree->root, UT_SHA256_SIZE, root_hex, sizeof(root_hex));
    yyjson_mut_obj_add_strcpy(doc, root, "root", root_hex);

    yyjson_mut_val *leaves_obj = yyjson_mut_obj(doc);
    for (size_t i = 0u; i < tree->leaf_count; ++i) {
        char leaf_hex[UT_SHA256_SIZE * 2u + 1u];
        ut_hex_encode(tree->leaves[i].hash, UT_SHA256_SIZE, leaf_hex, sizeof(leaf_hex));
        yyjson_mut_obj_add_strcpy(doc, leaves_obj, tree->leaves[i].key, leaf_hex);
    }
    yyjson_mut_obj_add_val(doc, root, "leaves", leaves_obj);

    size_t len = 0u;
    char *json_str = yyjson_mut_write(doc, 0, &len);
    yyjson_mut_doc_free(doc);
    if (!json_str) return UT_ERR_NO_MEMORY;

    *out_json = json_str;
    if (out_len) *out_len = len;
    return UT_OK;
}

static int cmp_cstr_ptr(const void *a, const void *b) {
    const char *sa = *(const char *const *)a;
    const char *sb = *(const char *const *)b;
    return strcmp(sa, sb);
}

ut_status_t ut_merkle_tree_divergent_keys(
    const ut_merkle_tree_t *tree,
    const char *remote_summary_json,
    size_t remote_json_len,
    char ***out_keys,
    size_t *out_count,
    char *out_remote_root_hex,
    size_t remote_root_cap
) {
    if (!tree || !remote_summary_json || !out_keys || !out_count) {
        return UT_ERR_INVALID_ARG;
    }
    *out_keys = NULL;
    *out_count = 0u;

    yyjson_doc *doc = yyjson_read(remote_summary_json, remote_json_len, 0);
    if (!doc) return UT_ERR_MALFORMED;

    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *r_root = yyjson_obj_get(root, "root");
    yyjson_val *r_leaves = yyjson_obj_get(root, "leaves");
    if (!yyjson_is_str(r_root) || !yyjson_is_obj(r_leaves)) {
        yyjson_doc_free(doc);
        return UT_ERR_MALFORMED;
    }

    if (out_remote_root_hex && remote_root_cap > 0u) {
        const char *rs = yyjson_get_str(r_root);
        size_t rl = yyjson_get_len(r_root);
        size_t copy_n = (rl < remote_root_cap - 1u) ? rl : (remote_root_cap - 1u);
        memcpy(out_remote_root_hex, rs, copy_n);
        out_remote_root_hex[copy_n] = '\0';
    }

    size_t max_keys = tree->leaf_count + yyjson_obj_size(r_leaves);
    char **div = NULL;
    size_t div_count = 0u;
    if (max_keys > 0u) {
        div = (char **)calloc(max_keys, sizeof(char *));
        if (!div) {
            yyjson_doc_free(doc);
            return UT_ERR_NO_MEMORY;
        }
    }

    /* Check local leaves against remote */
    for (size_t i = 0u; i < tree->leaf_count; ++i) {
        const char *k = tree->leaves[i].key;
        char local_hex[UT_SHA256_SIZE * 2u + 1u];
        ut_hex_encode(tree->leaves[i].hash, UT_SHA256_SIZE, local_hex, sizeof(local_hex));
        yyjson_val *rv = yyjson_obj_get(r_leaves, k);
        if (!rv || !yyjson_is_str(rv) || strcmp(yyjson_get_str(rv), local_hex) != 0) {
            div[div_count] = strdup(k);
            if (!div[div_count]) {
                ut_merkle_free_keys(div, div_count);
                yyjson_doc_free(doc);
                return UT_ERR_NO_MEMORY;
            }
            div_count += 1u;
        }
    }

    /* Check remote keys missing locally */
    size_t idx = 0u, max = 0u;
    yyjson_val *rk, *rv;
    yyjson_obj_foreach(r_leaves, idx, max, rk, rv) {
        (void)rv;
        const char *k = yyjson_get_str(rk);
        bool exists = false;
        for (size_t i = 0u; i < tree->leaf_count; ++i) {
            if (strcmp(tree->leaves[i].key, k) == 0) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            div[div_count] = strdup(k);
            if (!div[div_count]) {
                ut_merkle_free_keys(div, div_count);
                yyjson_doc_free(doc);
                return UT_ERR_NO_MEMORY;
            }
            div_count += 1u;
        }
    }

    yyjson_doc_free(doc);

    if (div_count > 1u) {
        qsort(div, div_count, sizeof(char *), cmp_cstr_ptr);
    }
    *out_keys = div;
    *out_count = div_count;
    return UT_OK;
}

void ut_merkle_free_keys(char **keys, size_t count) {
    if (!keys) return;
    for (size_t i = 0u; i < count; ++i) {
        free(keys[i]);
    }
    free(keys);
}
