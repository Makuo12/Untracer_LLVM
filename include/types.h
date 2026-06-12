#ifndef TYPES_H_
#define TYPES_H_
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define unlikely(x) \
    __builtin_expect(!!(x), 0)
#define MEM_BARRIER() \
    __asm__ volatile("" ::: "memory")
#endif