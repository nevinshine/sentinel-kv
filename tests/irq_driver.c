#include "skv_stub.h"

struct shared_state {
    int value;
    int active;
};

static struct shared_state *global_state;

/* Interrupt handler — registered via request_irq */
static irqreturn_t my_irq_handler(int irq, void *dev_id) {
    /* This handler frees the shared state */
    if (global_state) {
        kfree(global_state);
        global_state = (struct shared_state *)0;
    }
    return IRQ_HANDLED;
}

int __init irq_module_init(void) {
    global_state = (struct shared_state *)kmalloc(
        sizeof(struct shared_state), GFP_KERNEL);
    if (!global_state) return -1;

    /* Register the interrupt handler */
    int ret = request_irq(10, my_irq_handler, IRQF_SHARED, "skv_irq", (void *)0);
    if (ret) {
        kfree(global_state);
        return ret;
    }

    /* Main path writes to shared state — potential IRQ race:
     * if the interrupt fires between allocation and this write,
     * global_state is freed and this becomes a use-after-free. */
    global_state->value = 42;
    global_state->active = 1;

    return 0;
}
