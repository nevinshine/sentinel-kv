CC = clang
CFLAGS = -O0 -Xclang -disable-O0-optnone -S -emit-llvm

all: safe_driver.ll unsafe_driver.ll dma_driver.ll irq_driver.ll

safe_driver.ll: safe_driver.c skv_stub.h
	$(CC) $(CFLAGS) $< -o $@

unsafe_driver.ll: unsafe_driver.c skv_stub.h
	$(CC) $(CFLAGS) $< -o $@

dma_driver.ll: dma_driver.c skv_stub.h
	$(CC) $(CFLAGS) $< -o $@

irq_driver.ll: irq_driver.c skv_stub.h
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.ll
