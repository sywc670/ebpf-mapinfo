# build

```sh
cd bpf/
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -g -O2 -target bpf -c map_stats.bpf.c -o map_stats.o
clang -g -O2 -target bpf -c map_owner.bpf.c -o map_owner.o

cd ../
go run main.go
```

# dev build
```sh
cd bpf/
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -g -O2 -target bpf -c map_stats.bpf.c -o map_stats.o
clang -g -O2 -target bpf -c map_owner.bpf.c -o map_owner.o

# 1. 挂载 bpffs (如果没挂载的话)
sudo mount -t bpf bpf /sys/fs/bpf

# 2. 加载并 Pin 迭代器
rm -f /sys/fs/bpf/map_stats
rm -f /sys/fs/bpf/map_owner
sudo bpftool iter pin map_stats.o /sys/fs/bpf/map_stats
sudo bpftool iter pin map_owner.o /sys/fs/bpf/map_owner

# 3. 读取结果 (就像读普通文本文件一样)
cat /sys/fs/bpf/map_stats
cat /sys/fs/bpf/map_owner
```

# test

```sh
# 定义一个关联数组 @mystash，并等待输入
# 该进程会一直持有 BPF Map 的 FD
sudo bpftrace -e 'BEGIN { @mystash[1] = 100; printf("Map created. Press Ctrl+C to exit...\n"); }'
```