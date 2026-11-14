#include "unitelem/ring_buffer.h"

#include <stdlib.h>
#include <string.h>

static ut_status_t grow_internal(ut_ringbuf_t *rb, size_t new_capacity) {
    if (new_capacity <= rb->capacity) {
        return UT_OK;
    }
    if (new_capacity > SIZE_MAX / rb->elem_size) {
        return UT_ERR_NO_MEMORY;
    }
    uint8_t *new_buf = (uint8_t *)calloc(new_capacity, rb->elem_size);
    if (!new_buf) {
        return UT_ERR_NO_MEMORY;
    }
    for (size_t i = 0; i < rb->size; ++i) {
        size_t src_idx = (rb->head + i) % rb->capacity;
        memcpy(new_buf + i * rb->elem_size,
               rb->buffer + src_idx * rb->elem_size,
               rb->elem_size);
    }
    free(rb->buffer);
    rb->buffer = new_buf;
    rb->head = 0u;
    rb->tail = rb->size;
    rb->capacity = new_capacity;
    return UT_OK;
}

ut_status_t ut_ringbuf_init(
    ut_ringbuf_t *rb,
    size_t capacity,
    size_t elem_size,
    bool auto_expand,
    ut_ringbuf_overflow_fn overflow_handler,
    void *overflow_ctx
) {
    if (!rb || capacity == 0u || elem_size == 0u) {
        return UT_ERR_INVALID_ARG;
    }
    if (capacity > SIZE_MAX / elem_size) {
        return UT_ERR_NO_MEMORY;
    }
    memset(rb, 0, sizeof(*rb));
    rb->buffer = (uint8_t *)calloc(capacity, elem_size);
    if (!rb->buffer) {
        return UT_ERR_NO_MEMORY;
    }
    rb->elem_size = elem_size;
    rb->capacity = capacity;
    rb->auto_expand = auto_expand;
    rb->overflow_handler = overflow_handler;
    rb->overflow_ctx = overflow_ctx;

    if (pthread_mutex_init(&rb->lock, NULL) != 0) {
        free(rb->buffer);
        rb->buffer = NULL;
        return UT_ERR_IO;
    }
    return UT_OK;
}

void ut_ringbuf_destroy(ut_ringbuf_t *rb) {
    if (!rb) {
        return;
    }
    free(rb->buffer);
    rb->buffer = NULL;
    rb->capacity = 0u;
    rb->size = 0u;
    pthread_mutex_destroy(&rb->lock);
}

void ut_ringbuf_set_auto_expand(ut_ringbuf_t *rb, bool enable) {
    if (!rb) return;
    pthread_mutex_lock(&rb->lock);
    rb->auto_expand = enable;
    pthread_mutex_unlock(&rb->lock);
}

void ut_ringbuf_set_overflow_handler(
    ut_ringbuf_t *rb,
    ut_ringbuf_overflow_fn handler,
    void *user_ctx
) {
    if (!rb) return;
    pthread_mutex_lock(&rb->lock);
    rb->overflow_handler = handler;
    rb->overflow_ctx = user_ctx;
    pthread_mutex_unlock(&rb->lock);
}

ut_status_t ut_ringbuf_push(ut_ringbuf_t *rb, const void *item) {
    if (!rb || !item) {
        return UT_ERR_INVALID_ARG;
    }

    uint8_t stack_evicted[512];
    uint8_t *evicted_ptr = NULL;
    bool has_evicted = false;
    ut_ringbuf_overflow_fn handler = NULL;
    void *ctx = NULL;

    pthread_mutex_lock(&rb->lock);
    handler = rb->overflow_handler;
    ctx = rb->overflow_ctx;

    if (rb->size == rb->capacity) {
        if (rb->auto_expand) {
            ut_status_t st = grow_internal(rb, rb->capacity * 2u);
            if (st != UT_OK) {
                pthread_mutex_unlock(&rb->lock);
                return st;
            }
        } else {
            if (handler) {
                if (rb->elem_size <= sizeof(stack_evicted)) {
                    evicted_ptr = stack_evicted;
                } else {
                    evicted_ptr = (uint8_t *)malloc(rb->elem_size);
                }
                if (evicted_ptr) {
                    memcpy(evicted_ptr, rb->buffer + rb->head * rb->elem_size, rb->elem_size);
                    has_evicted = true;
                }
            }
            rb->head = (rb->head + 1u) % rb->capacity;
            rb->dropped_count += 1u;
            rb->size -= 1u;
        }
    }

    memcpy(rb->buffer + rb->tail * rb->elem_size, item, rb->elem_size);
    rb->tail = (rb->tail + 1u) % rb->capacity;
    rb->size += 1u;
    pthread_mutex_unlock(&rb->lock);

    if (has_evicted && handler) {
        handler(evicted_ptr, ctx);
    }
    if (evicted_ptr && evicted_ptr != stack_evicted) {
        free(evicted_ptr);
    }
    return UT_OK;
}

size_t ut_ringbuf_push_batch(ut_ringbuf_t *rb, const void *items, size_t count) {
    if (!rb || !items || count == 0u) {
        return 0u;
    }

    const uint8_t *src = (const uint8_t *)items;
    uint8_t *evicted_buf = NULL;
    size_t evicted_count = 0u;
    ut_ringbuf_overflow_fn handler = NULL;
    void *ctx = NULL;

    pthread_mutex_lock(&rb->lock);
    handler = rb->overflow_handler;
    ctx = rb->overflow_ctx;

    if (rb->auto_expand && (rb->size + count > rb->capacity)) {
        size_t new_cap = rb->capacity * 2u;
        while (new_cap < rb->size + count) {
            if (new_cap > SIZE_MAX / 2u) {
                new_cap = rb->size + count;
                break;
            }
            new_cap *= 2u;
        }
        if (grow_internal(rb, new_cap) != UT_OK) {
            pthread_mutex_unlock(&rb->lock);
            return 0u;
        }
    }

    if (handler && !rb->auto_expand && (rb->size + count > rb->capacity)) {
        size_t potential_evict = (rb->size + count) - rb->capacity;
        if (potential_evict <= SIZE_MAX / rb->elem_size) {
            evicted_buf = (uint8_t *)malloc(potential_evict * rb->elem_size);
        }
    }

    for (size_t i = 0; i < count; ++i) {
        if (rb->size == rb->capacity) {
            if (evicted_buf) {
                memcpy(evicted_buf + evicted_count * rb->elem_size,
                       rb->buffer + rb->head * rb->elem_size,
                       rb->elem_size);
                evicted_count += 1u;
            }
            rb->head = (rb->head + 1u) % rb->capacity;
            rb->dropped_count += 1u;
            rb->size -= 1u;
        }
        memcpy(rb->buffer + rb->tail * rb->elem_size,
               src + i * rb->elem_size,
               rb->elem_size);
        rb->tail = (rb->tail + 1u) % rb->capacity;
        rb->size += 1u;
    }

    pthread_mutex_unlock(&rb->lock);

    if (handler && evicted_buf) {
        for (size_t i = 0; i < evicted_count; ++i) {
            handler(evicted_buf + i * rb->elem_size, ctx);
        }
    }
    free(evicted_buf);
    return count;
}

ut_status_t ut_ringbuf_pop(ut_ringbuf_t *rb, void *out_item) {
    if (!rb || !out_item) {
        return UT_ERR_INVALID_ARG;
    }
    pthread_mutex_lock(&rb->lock);
    if (rb->size == 0u) {
        pthread_mutex_unlock(&rb->lock);
        return UT_ERR_EMPTY;
    }
    memcpy(out_item, rb->buffer + rb->head * rb->elem_size, rb->elem_size);
    rb->head = (rb->head + 1u) % rb->capacity;
    rb->size -= 1u;
    pthread_mutex_unlock(&rb->lock);
    return UT_OK;
}

size_t ut_ringbuf_pop_batch(ut_ringbuf_t *rb, void *out_items, size_t max_items) {
    if (!rb || !out_items || max_items == 0u) {
        return 0u;
    }
    uint8_t *dst = (uint8_t *)out_items;
    pthread_mutex_lock(&rb->lock);
    if (rb->size == 0u) {
        pthread_mutex_unlock(&rb->lock);
        return 0u;
    }
    size_t count = (rb->size < max_items) ? rb->size : max_items;
    for (size_t i = 0; i < count; ++i) {
        memcpy(dst + i * rb->elem_size,
               rb->buffer + rb->head * rb->elem_size,
               rb->elem_size);
        rb->head = (rb->head + 1u) % rb->capacity;
        rb->size -= 1u;
    }
    pthread_mutex_unlock(&rb->lock);
    return count;
}

void ut_ringbuf_clear(ut_ringbuf_t *rb) {
    if (!rb) return;
    pthread_mutex_lock(&rb->lock);
    rb->head = 0u;
    rb->tail = 0u;
    rb->size = 0u;
    pthread_mutex_unlock(&rb->lock);
}

size_t ut_ringbuf_capacity(ut_ringbuf_t *rb) {
    if (!rb) return 0u;
    pthread_mutex_lock(&rb->lock);
    size_t v = rb->capacity;
    pthread_mutex_unlock(&rb->lock);
    return v;
}

size_t ut_ringbuf_size(ut_ringbuf_t *rb) {
    if (!rb) return 0u;
    pthread_mutex_lock(&rb->lock);
    size_t v = rb->size;
    pthread_mutex_unlock(&rb->lock);
    return v;
}

size_t ut_ringbuf_dropped_count(ut_ringbuf_t *rb) {
    if (!rb) return 0u;
    pthread_mutex_lock(&rb->lock);
    size_t v = rb->dropped_count;
    pthread_mutex_unlock(&rb->lock);
    return v;
}

bool ut_ringbuf_is_empty(ut_ringbuf_t *rb) {
    return ut_ringbuf_size(rb) == 0u;
}

bool ut_ringbuf_is_full(ut_ringbuf_t *rb) {
    if (!rb) return false;
    pthread_mutex_lock(&rb->lock);
    bool full = (rb->size == rb->capacity);
    pthread_mutex_unlock(&rb->lock);
    return full;
}
