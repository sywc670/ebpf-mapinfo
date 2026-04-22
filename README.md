
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c map_iter.bpf.c -o map_iter.o
```