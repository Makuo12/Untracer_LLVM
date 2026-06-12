#ifndef DATA_H_
#define DATA_H_
#include <sys/types.h> // Standard POSIX types
typedef struct {
    char d_name[256];
    off_t st_size; // off_t is the standard POSIX type for file sizes
    char file_path[512];
    int has_issues;
    int single_pass;
    int full_pass;
    int path_found;
    int trace_count;
} Entry;

#endif 