#include "unitelem/state_crdt.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    ut_swarm_state_t st;
    assert(ut_swarm_state_init(&st, "craft_alpha") == UT_OK);

    uint64_t lts = 0;
    assert(ut_swarm_state_update_local(
        &st, "nav/alt", (const uint8_t *)"125.5", 5, true, &lts, NULL) == UT_OK);
    assert(lts == 1);

    bool updated = false;
    /* Newer lamport_time wins */
    assert(ut_swarm_state_merge_remote(
        &st, "craft_beta", "nav/alt", (const uint8_t *)"200.0", 5, true, 5, 100.0, &updated) == UT_OK);
    assert(updated == true);

    /* Stale lamport_time rejected */
    assert(ut_swarm_state_merge_remote(
        &st, "craft_beta", "nav/alt", (const uint8_t *)"150.0", 5, true, 3, 999.0, &updated) == UT_OK);
    assert(updated == false);

    /* Equal lamport_time uses wall_time tie-breaker */
    assert(ut_swarm_state_merge_remote(
        &st, "craft_beta", "nav/alt", (const uint8_t *)"210.0", 5, true, 5, 101.0, &updated) == UT_OK);
    assert(updated == true);

    char buf[64];
    size_t len = 0;
    assert(ut_swarm_state_get_value(&st, "craft_beta/nav/alt", (uint8_t *)buf, sizeof(buf), &len, NULL) == UT_OK);
    assert(strcmp(buf, "210.0") == 0);
    assert(ut_swarm_state_get_value(&st, "nav/alt", (uint8_t *)buf, sizeof(buf), &len, NULL) == UT_OK);
    assert(strcmp(buf, "125.5") == 0);

    /* Export & import batch JSON */
    const char *keys[] = {"craft_alpha:nav/alt", "craft_beta:nav/alt"};
    char *batch_json = NULL;
    size_t batch_len = 0;
    assert(ut_swarm_state_export_registers_json(&st, keys, 2, &batch_json, &batch_len) == UT_OK);
    assert(batch_json != NULL);

    ut_swarm_state_t st2;
    assert(ut_swarm_state_init(&st2, "craft_gamma") == UT_OK);
    size_t merged = 0;
    assert(ut_swarm_state_merge_batch_json(&st2, batch_json, batch_len, &merged) == UT_OK);
    assert(merged == 2);

    assert(ut_swarm_state_get_value(&st2, "craft_beta/nav/alt", (uint8_t *)buf, sizeof(buf), &len, NULL) == UT_OK);
    assert(strcmp(buf, "210.0") == 0);

    free(batch_json);
    ut_swarm_state_destroy(&st2);
    ut_swarm_state_destroy(&st);
    printf("test_state_crdt passed\n");
    return 0;
}
