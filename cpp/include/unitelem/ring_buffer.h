#ifndef UNITELEM_RING_BUFFER_H
#define UNITELEM_RING_BUFFER_H

#include "unitelem/types.h"

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UT_RINGBUF_DEFAULT_CAPACITY 65536u

typedef void (*ut_ringbuf_overflow_fn)(const void *evicted_item, void *user_ctx);

typedef struct ut_ringbuf {
    uint8_t *buffer;
    size_t elem_size;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t size;
    size_t dropped_count;
    bool auto_expand;
    ut_ringbuf_overflow_fn overflow_handler;
    void *overflow_ctx;
    pthread_mutex_t lock;
} ut_ringbuf_t;

ut_status_t ut_ringbuf_init(
    ut_ringbuf_t *rb,
    size_t capacity,
    size_t elem_size,
    bool auto_expand,
    ut_ringbuf_overflow_fn overflow_handler,
    void *overflow_ctx
);

void ut_ringbuf_destroy(ut_ringbuf_t *rb);

void ut_ringbuf_set_auto_expand(ut_ringbuf_t *rb, bool enable);
void ut_ringbuf_set_overflow_handler(
    ut_ringbuf_t *rb,
    ut_ringbuf_overflow_fn handler,
    void *user_ctx
);

ut_status_t ut_ringbuf_push(ut_ringbuf_t *rb, const void *item);
size_t ut_ringbuf_push_batch(ut_ringbuf_t *rb, const void *items, size_t count);

ut_status_t ut_ringbuf_pop(ut_ringbuf_t *rb, void *out_item);
size_t ut_ringbuf_pop_batch(ut_ringbuf_t *rb, void *out_items, size_t max_items);

void ut_ringbuf_clear(ut_ringbuf_t *rb);

size_t ut_ringbuf_capacity(ut_ringbuf_t *rb);
size_t ut_ringbuf_size(ut_ringbuf_t *rb);
size_t ut_ringbuf_dropped_count(ut_ringbuf_t *rb);
bool ut_ringbuf_is_empty(ut_ringbuf_t *rb);
bool ut_ringbuf_is_full(ut_ringbuf_t *rb);

#ifdef __cplusplus
}
#endif

#endif /* UNITELEM_RING_BUFFER_H */
