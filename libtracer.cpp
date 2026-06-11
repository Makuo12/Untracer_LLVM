#include <stdio.h>
#include <stdint.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>

#define MAX_GUARDS 300000
static uint8_t coverage_found[MAX_GUARDS];
static uint32_t total_guards = 0;

static const uintptr_t *g_pcs_beg;
static const uintptr_t *g_pcs_end;

#define NO_COV __attribute__((no_sanitize("coverage")))


// 1. Add NO_COV to the initialization function
NO_COV 
extern "C" void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop)
{
    if (start == stop || *start)
        return;

    for (uint32_t *x = start; x < stop; x++)
    {
        *x = ++total_guards;

        // 2. Add \n so the buffer flushes to the screen immediately

        if (total_guards >= MAX_GUARDS)
        {
            exit(1);
        }
    }
}


NO_COV
extern "C" void __sanitizer_cov_trace_pc_guard(uint32_t *guard)
{
    if (!*guard)
        return;
    const char *write_out = std::getenv("COVERAGE");
    if (write_out == nullptr)
        return;
    uint32_t idx = *guard - 1;
    if (!coverage_found[idx])
    {
        coverage_found[idx] = 1;
        // Open the log file in append mode
        FILE *f = fopen(write_out, "a");
        if (f)
        {
            fprintf(f, "%d\n", idx);
            fclose(f);
        }
    }
}

extern "C" void __sanitizer_cov_pcs_init(
    const uintptr_t *pcs_beg,
    const uintptr_t *pcs_end)
{
    g_pcs_beg = pcs_beg;
    g_pcs_end = pcs_end;
    const char *write_out = std::getenv("WRITE_OUT");
    if (write_out == nullptr)
        return;

    const char *out_path = (write_out[0] != '\0') ? write_out : "pcs_output.csv";

    FILE *f = std::fopen(out_path, "w");
    if (f == nullptr)
    {
        fprintf(stderr, "[Tracer] Failed to open output file: %s\n", out_path);
        return;
    }

    fprintf(f, "index,pc,flags\n");

    std::size_t idx = 0;
    for (const uintptr_t *p = pcs_beg; p < pcs_end; p += 2, ++idx)
    {
        fprintf(f, "%zu,0x%lx,%lu\n", idx, p[0], p[1]);
    }

    printf("-----------------------------------\n");
}