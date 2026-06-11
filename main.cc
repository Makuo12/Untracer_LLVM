#include <stdio.h>

__attribute__((noinline)) void test_branch(int x)
{
    if (x > 5)
    {
        printf("Hello from Branch A!\n");
    }
    else
    {
        printf("Hello from Branch B!\n");
    }
}

int main()
{
    printf("Starting program...\n");
    test_branch(10);
    return 0;
}