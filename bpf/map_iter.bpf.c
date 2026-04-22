#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

// 声明内核中的 map 操作符号，用于比对
extern const void bpf_map_fops __ksym;

struct iter_entry {
  __u32 pid;
  __u32 map_id;
  char comm[16];
};

SEC("iter/task_file")
int find_map_owners(struct bpf_iter__task_file *ctx) {
  struct file *file = ctx->file;
  struct task_struct *task = ctx->task;

  if (!file || !task)
    return 0;

  // 关键过滤逻辑：只关心 BPF Map 类型的文件
  if (file->f_op != &bpf_map_fops)
    return 0;

  // 从 file 的 private_data 中提取 bpf_map 结构
  // private_data 在这里指向 struct bpf_map
  struct bpf_map *map = (struct bpf_map *)file->private_data;

  struct iter_entry e = {};
  e.pid = task->tgid;
  e.map_id = BPF_CORE_READ(map, id);
  bpf_probe_read_kernel_str(&e.comm, sizeof(e.comm), task->comm);

  // 将结果写入 seq_file 输出流
  bpf_seq_printf(ctx->meta->seq, "PID: %-8d | COMM: %-16s | MAP_ID: %-8d\n",
                 e.pid, e.comm, e.map_id);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";