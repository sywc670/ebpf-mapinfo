#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

extern __s64 bpf_map_sum_elem_count(struct bpf_map *map) __ksym __weak;

SEC("iter/bpf_map")
int dump_map_stats(struct bpf_iter__bpf_map *ctx) {
  struct seq_file *seq = ctx->meta->seq;
  struct bpf_map *map = ctx->map;

  if (!map)
    return 0;

  if (ctx->meta->seq_num == 0) {
    static const char header[] =
        "MAP_ID   MAP_TYPE  MAP_NAME         CUR_ENTRIES  MAX_ENTRIES\n";
    bpf_seq_printf(seq, header, sizeof(header), NULL, 0);
  }

  __s64 cur_count = 0;
  if (bpf_map_sum_elem_count) {
    cur_count = bpf_map_sum_elem_count(map);
  }

  __u64 args[5];
  args[0] = map->id;
  args[1] = map->map_type;
  args[2] = (__u64)map->name;
  args[3] = (__u64)cur_count;
  args[4] = map->max_entries;

  static const char fmt[] = "%-8u %-8u  %-16s %-12lld %-12u\n";
  bpf_seq_printf(seq, fmt, sizeof(fmt), args, sizeof(args));

  return 0;
}

char LICENSE[] SEC("license") = "GPL";