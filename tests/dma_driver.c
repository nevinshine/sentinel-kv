#include "skv_stub.h"

struct dma_buf {
    int data[4];  /* 16 bytes */
};

int __init dma_module_init(void) {
    struct device *dev = (struct device *)0;
    dma_addr_t dma_handle;

    /* Allocate a 16-byte DMA buffer */
    struct dma_buf *buf = (struct dma_buf *)dma_alloc_coherent(
        dev, sizeof(struct dma_buf), &dma_handle, GFP_KERNEL);
    if (!buf) return -1;

    /* Safe write within DMA allocation bounds */
    buf->data[0] = 42;
    buf->data[3] = 99;

    /* UNSAFE: Map more bytes than allocated — DMA bounds violation */
    dma_map_single(dev, buf, 64, 0);

    dma_free_coherent(dev, sizeof(struct dma_buf), buf, dma_handle);
    return 0;
}
