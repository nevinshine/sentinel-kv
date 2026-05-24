#include "skv_stub.h"

struct my_data {
    int a;
    int b;
};

int __init my_module_init(void) {
    struct my_data *p = (struct my_data *)kmalloc(sizeof(struct my_data), GFP_KERNEL);
    if (!p) return -1;
    
    // Out-of-bounds write
    // The struct has size 8. p+1 points to offset 8.
    // Dereferencing it writes 4 bytes at offset 8, which is out of bounds.
    int *oob = (int *)(p + 1);
    *oob = 30;
    
    kfree(p);
    return 0;
}
