package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
)

const (
	defaultPinDir = "/sys/fs/bpf/xdp/globals"
	statsMapName  = "xdp_stats_map"
	pinDirEnv     = "GO_UPF_EBPF_PIN_PATH"
)

var statNames = []string{
	"rx",
	"pass",
	"ul_hit",
	"dl_exact_hit",
	"dl_default_hit",
	"qos_miss",
	"cpu_select_fail",
	"redirect",
}

func main() {
	var (
		pinDir   = flag.String("pin-dir", defaultPinDirFromEnv(), "directory containing the pinned xdp_stats_map")
		interval = flag.Duration("interval", 0, "print deltas at this interval; 0 prints once")
	)
	flag.Parse()

	stats, err := ebpf.LoadPinnedMap(filepath.Join(*pinDir, statsMapName), nil)
	if err != nil {
		log.Fatalf("load pinned %s: %v", statsMapName, err)
	}
	defer stats.Close()

	prev, err := readStats(stats)
	if err != nil {
		log.Fatal(err)
	}
	printStats("total", prev, nil)
	if *interval == 0 {
		return
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for range ticker.C {
		cur, err := readStats(stats)
		if err != nil {
			log.Fatal(err)
		}
		printStats("delta", cur, prev)
		prev = cur
	}
}

func defaultPinDirFromEnv() string {
	if pinDir := os.Getenv(pinDirEnv); pinDir != "" {
		return pinDir
	}
	return defaultPinDir
}

func readStats(stats *ebpf.Map) ([]uint64, error) {
	values := make([]uint64, len(statNames))
	for key := range statNames {
		k := uint32(key)
		if err := stats.Lookup(k, &values[key]); err != nil {
			return nil, fmt.Errorf("lookup %s[%d]: %w", statsMapName, key, err)
		}
	}
	return values, nil
}

func printStats(label string, cur, prev []uint64) {
	now := time.Now().Format(time.RFC3339)
	fmt.Printf("%s %s\n", now, label)
	for idx, name := range statNames {
		value := cur[idx]
		if prev != nil {
			value -= prev[idx]
		}
		fmt.Printf("  %-16s %d\n", name, value)
	}
}
