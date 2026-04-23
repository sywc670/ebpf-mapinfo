package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func findKsym(name string) (uint64, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		// fields[0] 是地址, fields[2] 是符号名
		if fields[2] == name {
			return strconv.ParseUint(fields[0], 16, 64)
		}
	}
	return 0, fmt.Errorf("内核符号 %s 未找到", name)
}

func main() {
	fopsAddr, err := findKsym("bpf_map_fops")
	if err != nil {
		log.Fatalf("无法获取符号地址: %v", err)
	}

	err = loadAndReadIter(
		"bpf/map_stats.o",
		"dump_map_stats",
		"map_stats_output",
		nil,
	)
	if err != nil {
		log.Fatalf("加载 map_stats 失败: %v", err)
	}

	err = loadAndReadIter(
		"bpf/map_owner.o",
		"dump_map_owner",
		"map_owner_output",
		map[string]any{
			"bpf_map_fops_addr": fopsAddr,
		},
	)
	if err != nil {
		log.Fatalf("加载 map_owner 失败: %v", err)
	}
}

func loadAndReadIter(objPath string, progName string, label string, constants map[string]any) error {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("解析对象文件失败: %w", err)
	}

	for name, value := range constants {
		if v, ok := spec.Variables[name]; ok {
			if err := v.Set(value); err != nil {
				return fmt.Errorf("设置变量 %s 失败: %w", name, err)
			}
		} else {
			log.Printf("警告: BPF 程序中未找到变量 %s", name)
		}
	}

	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return fmt.Errorf("加载到内核失败: %w", err)
	}
	defer c.Close()

	prog := c.Programs[progName]
	if prog == nil {
		return fmt.Errorf("未找到名为 %s 的程序", progName)
	}

	iterLink, err := link.AttachIter(link.IterOptions{
		Program: prog,
	})
	if err != nil {
		return fmt.Errorf("附加 Iter 失败: %w", err)
	}
	defer iterLink.Close()

	reader, err := iterLink.Open()
	if err != nil {
		return fmt.Errorf("打开 Iter 输出流失败: %w", err)
	}
	defer reader.Close()

	output, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("读取输出失败: %w", err)
	}

	fmt.Printf("--- %s ---\n", label)
	fmt.Print(string(output))

	return nil
}
