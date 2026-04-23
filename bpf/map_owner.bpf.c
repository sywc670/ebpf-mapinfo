#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

volatile const u64 bpf_map_fops_addr = 0;

SEC("iter/task_file")
int dump_map_owner(struct bpf_iter__task_file *ctx) {
  struct file *file = ctx->file;
  struct task_struct *task = ctx->task;
  struct seq_file *seq = ctx->meta->seq;

  if (!file || !task || !seq)
    return 0;

  if ((u64)file->f_op != bpf_map_fops_addr)
    return 0;

  struct bpf_map *map = (struct bpf_map *)file->private_data;
  if (!map)
    return 0;

  __u32 map_id = BPF_CORE_READ(map, id);

  __u64 args[4];
  args[0] = task->pid;
  args[1] = (__u64)task->comm;
  args[2] = map_id;
  args[3] = (__u64)map->name;

  static const char fmt[] = "%-8u %-16s %-8u %-16s\n";
  bpf_seq_printf(seq, fmt, sizeof(fmt), args, sizeof(args));

  return 0;
}

char LICENSE[] SEC("license") = "GPL";