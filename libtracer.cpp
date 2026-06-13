#include <stdio.h>
#include <stdint.h>
#include <sys/shm.h>

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#include "config.h"
#include "types.h"

// static uint8_t coverage_found[MAP_SIZE];
static uint32_t total_guards = 0;

static u8 * trace_blocks;

#define NO_COV __attribute__((no_sanitize("coverage")))

NO_COV
void init_blocks(void)
{
    const char *shm_env = getenv(SHM_ID_ENV);
    if (shm_env == NULL || strlen(shm_env) == 0)
    {
        fprintf(stderr, "[Tracer] no shm id");
        exit(1);
    }
    int shm_id = atoi(shm_env);
    trace_blocks = (u8 *)shmat(shm_id, 0, 0);
    if (trace_blocks == (u8 *)-1)
    {
        trace_blocks = NULL;
        fprintf(stderr, "[Tracer] blocks not set");
        exit(1);
    }
}

// 1. Add NO_COV to the initialization function
NO_COV 
extern "C" void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop)
{
    init_blocks();
    if (start == stop || *start)
        return;

    for (uint32_t *x = start; x < stop; x++)
    {
        *x = ++total_guards;
        if (total_guards >= MAP_SIZE)
        {
            fprintf(stderr, "[Tracer] blocks not set");
            exit(1);
        }
    }
}


NO_COV
extern "C" void __sanitizer_cov_trace_pc_guard(uint32_t *guard)
{
    if (!*guard)
        return;
    uint32_t idx = *guard - 1;
    if (trace_blocks == nullptr) {
        fprintf(stderr, "[Tracer] trace block not found");
        exit(1);
    }
    if (!trace_blocks[idx])
    {
        trace_blocks[idx] = 1;
    }
}
