package main

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/JSInvasor/just-http3/internal/profiles"
	"github.com/JSInvasor/just-http3/internal/sender"
)

func runBench(cfg config, prof profiles.Profile) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// work channel feeds goroutines; feeder closes it when done or ctx cancelled.
	work := make(chan struct{}, cfg.concurrency)
	go func() {
		defer close(work)
		var sent int64
		for {
			if cfg.numRequests > 0 && sent >= cfg.numRequests {
				return
			}
			select {
			case work <- struct{}{}:
				sent++
			case <-ctx.Done():
				return
			}
		}
	}()

	var (
		totalReqs atomic.Int64
		totalErrs atomic.Int64
		mu        sync.Mutex
		latencies []time.Duration
	)

	start := time.Now()

	// Live stats line updated every second.
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var prev int64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cur := totalReqs.Load()
				elapsed := time.Since(start).Seconds()
				fmt.Fprintf(os.Stderr,
					"\r  req: %-8d  err: %-6d  rps(now): %-8.0f  rps(avg): %-8.1f",
					cur, totalErrs.Load(), float64(cur-prev), float64(cur)/elapsed)
				prev = cur
			}
		}
	}()

	var wg sync.WaitGroup
	for range cfg.concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range work {
				if ctx.Err() != nil {
					continue
				}
				reqCtx, reqCancel := context.WithTimeout(ctx, cfg.timeout)
				t0 := time.Now()
				res, err := sender.Do(reqCtx, cfg.url, sender.Options{
					Profile:  prof,
					Method:   cfg.method,
					Timeout:  cfg.timeout,
					Insecure: cfg.insecure,
				})
				reqCancel()
				lat := time.Since(t0)

				totalReqs.Add(1)
				if err != nil || (res != nil && res.StatusCode >= 400) {
					totalErrs.Add(1)
				} else {
					mu.Lock()
					latencies = append(latencies, lat)
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	cancel()

	elapsed := time.Since(start)
	fmt.Fprintln(os.Stderr)

	printBenchSummary(totalReqs.Load(), totalErrs.Load(), elapsed, latencies)
}

func printBenchSummary(total, errs int64, elapsed time.Duration, latencies []time.Duration) {
	tty := isTTY()
	bold := paint(tty, "1")
	dim := paint(tty, "2")

	rps := float64(total) / elapsed.Seconds()

	fmt.Printf("\n%s\n", bold("── Benchmark ──────────────────────────────────────"))
	fmt.Printf("  %-16s %d\n", "requests", total)
	fmt.Printf("  %-16s %d\n", "errors", errs)
	fmt.Printf("  %-16s %.2fs\n", "duration", elapsed.Seconds())
	fmt.Printf("  %-16s %.1f req/s\n", "RPS", rps)

	if len(latencies) == 0 {
		fmt.Println()
		return
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	pct := func(p float64) time.Duration {
		idx := int(math.Ceil(p/100.0*float64(len(latencies)))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(latencies) {
			idx = len(latencies) - 1
		}
		return latencies[idx]
	}

	fmt.Printf("\n  %s\n", dim("latency (total round-trip incl. handshake)"))
	fmt.Printf("  %-16s %s\n", "min", fmtDur(latencies[0]))
	fmt.Printf("  %-16s %s\n", "p50", fmtDur(pct(50)))
	fmt.Printf("  %-16s %s\n", "p90", fmtDur(pct(90)))
	fmt.Printf("  %-16s %s\n", "p95", fmtDur(pct(95)))
	fmt.Printf("  %-16s %s\n", "p99", fmtDur(pct(99)))
	fmt.Printf("  %-16s %s\n", "max", fmtDur(latencies[len(latencies)-1]))
	fmt.Println()
}
