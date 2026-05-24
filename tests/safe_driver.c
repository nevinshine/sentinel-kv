#include "skv_stub.h"

struct my_data {
    int a;
    int b;
};

int __init my_module_init(void) {
    struct my_data *p = (struct my_data *)kmalloc(sizeof(struct my_data), GFP_KERNEL);
    if (!p) return -1;
    
    p->a = 10;
    p->b = 20;
    
    kfree(p);
    return 0;
}
