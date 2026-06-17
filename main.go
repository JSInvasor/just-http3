// Command http3-beta sends HTTP/3 requests while impersonating a real
// browser's QUIC + TLS fingerprint.
//
// Single request:
//
//	http3-beta https://example.com
//
// Benchmark mode:
//
//	http3-beta https://example.com 30s 50
package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JSInvasor/just-http3/internal/profiles"
	"github.com/JSInvasor/just-http3/internal/sender"
)

const version = "0.1.0-beta"

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		fmt.Fprintln(os.Stderr)
		usage(os.Stderr)
		os.Exit(2)
	}
	if cfg.showHelp {
		usage(os.Stdout)
		return
	}
	if cfg.showVersion {
		fmt.Println("http3-beta", version)
		return
	}

	prof, ok := profiles.Get(cfg.profile)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: unknown profile %q (available: %s)\n",
			cfg.profile, strings.Join(profiles.Names(), ", "))
		os.Exit(2)
	}

	if cfg.concurrency > 0 {
		runBench(cfg, prof)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	res, err := sender.Do(ctx, cfg.url, sender.Options{
		Profile:   prof,
		Method:    cfg.method,
		Timeout:   cfg.timeout,
		Insecure:  cfg.insecure,
		UserAgent: cfg.userAgent,
		KeepBody:  cfg.showBody,
		MaxBody:   cfg.maxBody,
		ProxyURL:  cfg.proxyURL,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "request failed:", err)
		os.Exit(1)
	}

	printResult(res, cfg)
}

type config struct {
	url           string
	profile       string
	method        string
	userAgent     string
	timeout       time.Duration
	insecure      bool
	verbose       bool
	showBody      bool
	maxBody       int64
	concurrency   int
	benchDuration time.Duration
	proxyURL      *url.URL
	showHelp      bool
	showVersion   bool
}

func parseArgs(args []string) (config, error) {
	cfg := config{
		profile: profiles.Default,
		method:  "GET",
		timeout: 30 * time.Second,
	}
	var positional []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			cfg.showHelp = true
		case a == "--version":
			cfg.showVersion = true
		case a == "-v" || a == "--verbose":
			cfg.verbose = true
		case a == "-k" || a == "--insecure":
			cfg.insecure = true
		case a == "-b" || a == "--body":
			cfg.showBody = true
		case a == "-p" || a == "--profile":
			val, err := next(args, &i, a)
			if err != nil {
				return cfg, err
			}
			cfg.profile = val
		case strings.HasPrefix(a, "--profile="):
			cfg.profile = strings.TrimPrefix(a, "--profile=")
		case a == "-A" || a == "--user-agent":
			val, err := next(args, &i, a)
			if err != nil {
				return cfg, err
			}
			cfg.userAgent = val
		case strings.HasPrefix(a, "--user-agent="):
			cfg.userAgent = strings.TrimPrefix(a, "--user-agent=")
		case a == "-X" || a == "--method":
			val, err := next(args, &i, a)
			if err != nil {
				return cfg, err
			}
			cfg.method = strings.ToUpper(val)
		case a == "-t" || a == "--timeout":
			val, err := next(args, &i, a)
			if err != nil {
				return cfg, err
			}
			d, err := time.ParseDuration(val)
			if err != nil {
				return cfg, fmt.Errorf("invalid timeout %q: %w", val, err)
			}
			cfg.timeout = d
		case a == "-x" || a == "--proxy":
			val, err := next(args, &i, a)
			if err != nil {
				return cfg, err
			}
			u, err := url.Parse(val)
			if err != nil || u.Scheme != "socks5" {
				return cfg, fmt.Errorf("invalid proxy %q: must be socks5://[user:pass@]host:port", val)
			}
			cfg.proxyURL = u
		case strings.HasPrefix(a, "-"):
			return cfg, fmt.Errorf("unknown flag %q", a)
		default:
			positional = append(positional, a)
		}
	}

	if cfg.showHelp || cfg.showVersion {
		return cfg, nil
	}
	if len(positional) == 0 {
		return cfg, fmt.Errorf("missing URL")
	}
	if len(positional) != 1 && len(positional) != 3 {
		return cfg, fmt.Errorf("usage: http3-beta <url>  or  http3-beta <url> <duration> <threads>")
	}

	cfg.url = positional[0]
	if !strings.Contains(cfg.url, "://") {
		cfg.url = "https://" + cfg.url
	}

	if len(positional) == 3 {
		dur, err := time.ParseDuration(positional[1])
		if err != nil || dur < 0 {
			return cfg, fmt.Errorf("invalid duration %q — use e.g. 30s, 1m, 2m30s, 0 for unlimited", positional[1])
		}
		cfg.benchDuration = dur

		n, err := strconv.Atoi(positional[2])
		if err != nil || n < 1 {
			return cfg, fmt.Errorf("invalid thread count %q — must be >= 1", positional[2])
		}
		cfg.concurrency = n
	}

	return cfg, nil
}

func next(args []string, i *int, flag string) (string, error) {
	if *i+1 >= len(args) {
		return "", fmt.Errorf("flag %s needs a value", flag)
	}
	*i++
	return args[*i], nil
}

func printResult(res *sender.Result, cfg config) {
	tty := isTTY()
	bold := paint(tty, "1")
	dim := paint(tty, "2")
	statusPaint := paint(tty, "32")
	if res.StatusCode >= 400 {
		statusPaint = paint(tty, "31")
	}

	fmt.Printf("%s\n", bold("→ "+cfg.method+" "+res.URL))
	fmt.Printf("  %s  %s\n", dim("profile "), res.Profile.Label)
	fmt.Printf("  %s  %s\n", dim("resolved"), res.RemoteAddr)
	if res.ALPN != "" {
		fmt.Printf("  %s  %s\n", dim("alpn    "), res.ALPN)
	}
	if res.TLSVersion != 0 {
		fmt.Printf("  %s  %s / %s\n", dim("tls     "),
			sender.TLSVersionName(res.TLSVersion), sender.CipherName(res.CipherID))
	}
	fmt.Println()

	t := res.Timings
	bar := func(label string, d time.Duration) {
		fmt.Printf("  %-16s %s\n", label, fmtDur(d))
	}
	bar("DNS lookup", t.DNS)
	bar("QUIC handshake", t.Handshake)
	bar("TTFB", t.TTFB)
	bar("download", t.Download)
	fmt.Printf("  %s\n", dim(strings.Repeat("─", 30)))
	fmt.Printf("  %-16s %s\n", "total", bold(fmtDur(t.Total)))
	fmt.Println()

	fmt.Printf("  %s  %s\n", statusPaint(res.Proto+" "+res.Status), fmtBytes(res.BodyBytes))

	if cfg.verbose {
		fmt.Println()
		fmt.Printf("  %s\n", dim("response headers"))
		keys := make([]string, 0, len(res.Header))
		for k := range res.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range res.Header[k] {
				fmt.Printf("    %s: %s\n", k, v)
			}
		}
	}

	if cfg.showBody && len(res.Body) > 0 {
		fmt.Println()
		fmt.Println(string(res.Body))
	}
}

func paint(tty bool, code string) func(string) string {
	return func(s string) string {
		if !tty {
			return s
		}
		return "\033[" + code + "m" + s + "\033[0m"
	}
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func fmtDur(d time.Duration) string {
	ms := float64(d.Microseconds()) / 1000.0
	return fmt.Sprintf("%8.2f ms", ms)
}

func fmtElapsed(d time.Duration) string {
	s := int(d.Seconds())
	if s < 60 {
		return fmt.Sprintf("%ds", s)
	}
	return fmt.Sprintf("%dm%ds", s/60, s%60)
}

func fmtBytes(n int) string {
	switch {
	case n <= 0:
		return "0 B"
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `http3-beta %s — HTTP/3 request sender with browser fingerprint impersonation

USAGE
  http3-beta [flags] <url>                        single request
  http3-beta [flags] <url> <duration> <threads>   benchmark mode

  duration: how long to run (30s, 1m, 2m30s). Use 0 for unlimited (Ctrl+C to stop).
  threads:  number of concurrent workers.

FLAGS
  -p, --profile <name>   browser profile (default: %s, available: %s)
  -A, --user-agent <ua>  override User-Agent
  -X, --method <method>  HTTP method (default: GET)
  -t, --timeout <dur>    per-request timeout (default: 30s)
  -k, --insecure         skip TLS certificate verification
  -v, --verbose          print response headers
  -b, --body             print response body
  -x, --proxy <url>      SOCKS5 proxy (socks5://[user:pass@]host:port)
      --version          print version
  -h, --help             show this help

EXAMPLES
  http3-beta https://example.com                        # single request
  http3-beta https://example.com 30s 50                 # 30 seconds, 50 threads
  http3-beta https://example.com 0 100                  # unlimited, 100 threads
  http3-beta -p safari https://example.com 1m 20        # macOS Safari profile
  http3-beta -k https://example.com 10s 10              # skip TLS verify
`, version, profiles.Default, strings.Join(profiles.Names(), ", "))
}
