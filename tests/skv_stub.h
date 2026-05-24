#ifndef SKV_STUB_H
#define SKV_STUB_H

#include <stddef.h>

#define GFP_KERNEL 0
#define __init
#define __exit
#define IRQ_HANDLED 0
#define IRQF_SHARED 0

typedef unsigned long dma_addr_t;
typedef int irqreturn_t;

/* Minimal device stub */
struct device;

void *kmalloc(size_t size, int flags);
void *kzalloc(size_t size, int flags);
void kfree(const void *objp);
int printk(const char *fmt, ...);
void *memset(void *s, int c, size_t n);
void *memcpy(void *dest, const void *src, size_t n);

/* DMA API stubs */
void *dma_alloc_coherent(struct device *dev, size_t size,
                         dma_addr_t *dma_handle, int flags);
dma_addr_t dma_map_single(struct device *dev, void *ptr,
                          size_t size, int direction);
void dma_free_coherent(struct device *dev, size_t size,
                       void *vaddr, dma_addr_t dma_handle);

/* IRQ API stubs */
int request_irq(unsigned int irq,
                irqreturn_t (*handler)(int, void *),
                unsigned long flags, const char *name, void *dev);
void free_irq(unsigned int irq, void *dev);

#endif
