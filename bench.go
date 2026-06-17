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
	sigCtx, sigCancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigCancel()

	var ctx context.Context
	var cancel context.CancelFunc
	if cfg.benchDuration > 0 {
		ctx, cancel = context.WithTimeout(sigCtx, cfg.benchDuration)
	} else {
		ctx, cancel = context.WithCancel(sigCtx)
	}
	defer cancel()

	opts := sender.Options{
		Profile:  prof,
		Method:   cfg.method,
		Timeout:  cfg.timeout,
		Insecure: cfg.insecure,
		ProxyURL: cfg.proxyURL,
	}

	// Create one persistent connection per worker. Each connection performs
	// exactly one QUIC handshake and then reuses it for all requests.
	conns := make([]*sender.Conn, cfg.concurrency)
	dialCtx, dialCancel := context.WithTimeout(ctx, cfg.timeout)
	defer dialCancel()

	fmt.Fprintf(os.Stderr, "  dialing %d connections...\n", cfg.concurrency)
	var dialErr error
	for i := range conns {
		conns[i], dialErr = sender.Dial(cfg.url, opts)
		if dialErr != nil {
			fmt.Fprintf(os.Stderr, "error: dial failed: %v\n", dialErr)
			os.Exit(1)
		}
		// Warm up: send one request to complete the handshake now so bench
		// start times are not skewed by concurrent handshake latency.
		warmCtx, warmCancel := context.WithTimeout(dialCtx, cfg.timeout)
		_, _ = conns[i].Do(warmCtx)
		warmCancel()
	}
	fmt.Fprintf(os.Stderr, "  ready\n\n")

	defer func() {
		for _, c := range conns {
			c.Close()
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
				elapsed := time.Since(start)
				rps := float64(cur - prev)
				prev = cur

				var line string
				if cfg.benchDuration > 0 {
					line = fmt.Sprintf("\r  [%s / %s]   req: %-8d   err: %-6d   rps: %-7.0f",
						fmtElapsed(elapsed), fmtElapsed(cfg.benchDuration),
						cur, totalErrs.Load(), rps)
				} else {
					line = fmt.Sprintf("\r  [%s]   req: %-8d   err: %-6d   rps: %-7.0f",
						fmtElapsed(elapsed), cur, totalErrs.Load(), rps)
				}
				fmt.Fprint(os.Stderr, line)
			}
		}
	}()

	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Add(1)
		go func(c *sender.Conn) {
			defer wg.Done()
			for ctx.Err() == nil {
				reqCtx, reqCancel := context.WithTimeout(ctx, cfg.timeout)
				t0 := time.Now()
				res, err := c.Do(reqCtx)
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
		}(conn)
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
	errPaint := paint(tty, "31")

	rps := float64(total) / elapsed.Seconds()

	fmt.Printf("\n%s\n", bold("── Result ─────────────────────────────────────────"))
	fmt.Printf("  %-12s %d\n", "requests", total)
	if errs > 0 {
		fmt.Printf("  %-12s %s\n", "errors", errPaint(fmt.Sprintf("%d", errs)))
	} else {
		fmt.Printf("  %-12s %d\n", "errors", errs)
	}
	fmt.Printf("  %-12s %s\n", "duration", elapsed.Round(time.Millisecond))
	fmt.Printf("  %-12s %.1f req/s\n", "RPS", rps)

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

	fmt.Printf("\n  %s\n", dim("latency"))
	fmt.Printf("  %-12s %s\n", "min", fmtDur(latencies[0]))
	fmt.Printf("  %-12s %s\n", "p50", fmtDur(pct(50)))
	fmt.Printf("  %-12s %s\n", "p90", fmtDur(pct(90)))
	fmt.Printf("  %-12s %s\n", "p95", fmtDur(pct(95)))
	fmt.Printf("  %-12s %s\n", "p99", fmtDur(pct(99)))
	fmt.Printf("  %-12s %s\n", "max", fmtDur(latencies[len(latencies)-1]))
	fmt.Println()
}
