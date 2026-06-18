// Package sender drives HTTP/3 requests using a browser fingerprint profile.
//
// For single requests use Do. For high-throughput benchmarks use Dial to
// create a persistent Conn and call Conn.Do in a loop — the QUIC handshake
// is performed once and the connection is reused for every subsequent request.
package sender

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	quic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/http3"

	"github.com/JSInvasor/just-http3/internal/profiles"
)

// Timings holds the measured durations of each request phase.
type Timings struct {
	DNS       time.Duration // hostname resolution
	Handshake time.Duration // QUIC dial + TLS 1.3 handshake (until handshake complete)
	TTFB      time.Duration // from request write to first response byte (headers)
	Download  time.Duration // reading the response body
	Total     time.Duration // DNS + everything else
}

// Result is the outcome of a request.
type Result struct {
	Profile    profiles.Profile
	URL        string
	RemoteAddr string
	Status     string
	StatusCode int
	Proto      string
	TLSVersion uint16
	CipherID   uint16
	ALPN       string
	BodyBytes  int
	Body       []byte
	Header     http.Header
	Timings    Timings
}

// Options configures a request.
type Options struct {
	Profile      profiles.Profile
	Method       string
	Timeout      time.Duration
	Insecure     bool // skip TLS certificate verification
	ServerName   string
	UserAgent    string // overrides the profile's User-Agent when set
	ExtraHeaders []profiles.Header
	KeepBody     bool  // retain the response body in Result.Body
	MaxBody      int64 // cap on body bytes read (0 = unlimited)
	ProxyURL     *url.URL // socks5://[user:pass@]host:port; nil = direct
}

// Do performs the HTTP/3 request described by rawURL and opts.
func Do(ctx context.Context, rawURL string, opts Options) (*Result, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("http3 requires https, got %q", u.Scheme)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}

	// --- DNS phase ---------------------------------------------------------
	// Resolved separately so we can attribute the lookup time on its own.
	dnsStart := time.Now()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	dnsDur := time.Since(dnsStart)
	if err != nil {
		return nil, fmt.Errorf("dns lookup for %q failed: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %q", host)
	}

	serverName := opts.ServerName
	if serverName == "" {
		serverName = host
	}

	spec, err := opts.Profile.Spec()
	if err != nil {
		return nil, fmt.Errorf("loading quic spec for profile %q: %w", opts.Profile.Name, err)
	}

	// uquic uses its own utls.Config (a drop-in for crypto/tls.Config).
	tlsConf := &utls.Config{
		ServerName:         serverName,
		NextProtos:         opts.Profile.ALPN,
		InsecureSkipVerify: opts.Insecure,
	}
	quicConf := &quic.Config{}

	// We build the UDP socket and UTransport ourselves so the dial — and
	// therefore the handshake — can be timed precisely via a wrapper.
	var pc net.PacketConn
	if opts.ProxyURL != nil {
		pc, err = dialSOCKS5UDP(opts.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("socks5 proxy: %w", err)
		}
	} else {
		pc, err = net.ListenUDP("udp", nil)
		if err != nil {
			return nil, fmt.Errorf("opening udp socket: %w", err)
		}
	}
	defer pc.Close()
	uTransport := &quic.UTransport{
		Transport: &quic.Transport{Conn: pc},
		QUICSpec:  &spec,
	}

	var handshakeDur time.Duration
	dialer := func(ctx context.Context, addr string, tlsCfg *utls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		start := time.Now()
		conn, err := uTransport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
		if err != nil {
			return nil, err
		}
		// DialEarly returns as soon as an (early) connection is usable; block
		// until the full handshake completes so the measurement reflects the
		// real TLS 1.3 + QUIC handshake cost.
		select {
		case <-conn.HandshakeComplete():
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		handshakeDur = time.Since(start)
		return conn, nil
	}

	rt := &http3.RoundTripper{
		TLSClientConfig: tlsConf,
		QuicConfig:      quicConf,
		Dial:            dialer,
	}
	uRT := http3.GetURoundTripper(rt, &spec, uTransport)
	defer uRT.Close()

	method := opts.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	applyHeaders(req, opts.Profile.Headers)
	applyHeaders(req, opts.ExtraHeaders)
	if opts.UserAgent != "" {
		req.Header.Set("user-agent", opts.UserAgent)
	}

	// --- request + TTFB ----------------------------------------------------
	reqStart := time.Now()
	resp, err := uRT.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	ttfb := time.Since(reqStart)

	// --- body download -----------------------------------------------------
	var reader io.Reader = resp.Body
	if opts.MaxBody > 0 {
		reader = io.LimitReader(resp.Body, opts.MaxBody)
	}
	dlStart := time.Now()
	var body []byte
	var bodyBytes int
	if opts.KeepBody {
		body, err = io.ReadAll(reader)
		bodyBytes = len(body)
	} else {
		var n int64
		n, err = io.Copy(io.Discard, reader)
		bodyBytes = int(n)
	}
	dlDur := time.Since(dlStart)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	res := &Result{
		Profile:    opts.Profile,
		URL:        rawURL,
		RemoteAddr: net.JoinHostPort(ips[0].String(), port),
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Proto:      resp.Proto,
		BodyBytes:  bodyBytes,
		Body:       body,
		Header:     resp.Header,
		Timings: Timings{
			DNS:       dnsDur,
			Handshake: handshakeDur,
			TTFB:      ttfb,
			Download:  dlDur,
			Total:     dnsDur + ttfb + dlDur,
		},
	}
	if resp.TLS != nil {
		res.TLSVersion = resp.TLS.Version
		res.CipherID = resp.TLS.CipherSuite
		res.ALPN = resp.TLS.NegotiatedProtocol
	}
	return res, nil
}

// Conn is a persistent HTTP/3 connection with a fixed browser fingerprint.
// The QUIC handshake happens once (on the first Do call); every subsequent
// Do reuses the same connection — no DNS lookup, no handshake overhead.
// Conn.Do is safe to call concurrently from multiple goroutines.
type Conn struct {
	rt interface {
		RoundTrip(*http.Request) (*http.Response, error)
		Close() error
	}
	pc     net.PacketConn // underlying UDP or SOCKS5 socket
	opts   Options
	rawURL string
	method string
}

// Dial creates a Conn ready to send requests to rawURL. The QUIC transport
// is set up here but the actual handshake is deferred to the first Do call.
func Dial(rawURL string, opts Options) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("http3 requires https, got %q", u.Scheme)
	}

	serverName := opts.ServerName
	if serverName == "" {
		serverName = u.Hostname()
	}

	spec, err := opts.Profile.Spec()
	if err != nil {
		return nil, fmt.Errorf("loading quic spec: %w", err)
	}

	tlsConf := &utls.Config{
		ServerName:         serverName,
		NextProtos:         opts.Profile.ALPN,
		InsecureSkipVerify: opts.Insecure,
	}

	var pc net.PacketConn
	if opts.ProxyURL != nil {
		pc, err = dialSOCKS5UDP(opts.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("socks5 proxy: %w", err)
		}
	} else {
		pc, err = net.ListenUDP("udp", nil)
		if err != nil {
			return nil, fmt.Errorf("opening udp socket: %w", err)
		}
	}

	uTransport := &quic.UTransport{
		Transport: &quic.Transport{Conn: pc},
		QUICSpec:  &spec,
	}

	dialer := func(ctx context.Context, addr string, tlsCfg *utls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		conn, err := uTransport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
		if err != nil {
			return nil, err
		}
		select {
		case <-conn.HandshakeComplete():
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return conn, nil
	}

	rt := &http3.RoundTripper{
		TLSClientConfig: tlsConf,
		QuicConfig:      &quic.Config{},
		Dial:            dialer,
	}
	uRT := http3.GetURoundTripper(rt, &spec, uTransport)

	method := opts.Method
	if method == "" {
		method = http.MethodGet
	}

	return &Conn{
		rt:     uRT,
		pc:     pc,
		opts:   opts,
		rawURL: rawURL,
		method: method,
	}, nil
}

// Do sends one HTTP/3 request over the persistent connection.
func (c *Conn) Do(ctx context.Context) (*Result, error) {
	req, err := http.NewRequestWithContext(ctx, c.method, c.rawURL, nil)
	if err != nil {
		return nil, err
	}
	applyHeaders(req, c.opts.Profile.Headers)
	if c.opts.UserAgent != "" {
		req.Header.Set("user-agent", c.opts.UserAgent)
	}

	t0 := time.Now()
	resp, err := c.rt.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	ttfb := time.Since(t0)

	dlStart := time.Now()
	n, copyErr := io.Copy(io.Discard, resp.Body)
	dlDur := time.Since(dlStart)
	if copyErr != nil {
		return nil, fmt.Errorf("reading body: %w", copyErr)
	}

	return &Result{
		Profile:    c.opts.Profile,
		URL:        c.rawURL,
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Proto:      resp.Proto,
		BodyBytes:  int(n),
		Header:     resp.Header,
		Timings: Timings{
			TTFB:     ttfb,
			Download: dlDur,
			Total:    ttfb + dlDur,
		},
	}, nil
}

// Close shuts down the connection and releases the underlying socket.
func (c *Conn) Close() {
	c.rt.Close()
	c.pc.Close()
}

func applyHeaders(req *http.Request, hs []profiles.Header) {
	for _, h := range hs {
		// User-Agent and others set via Header map; the HTTP/3 writer emits
		// them after the pseudo-headers.
		req.Header.Set(h.Key, h.Val)
	}
}

// TLSVersionName returns a human label for a TLS version constant.
func TLSVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// CipherName returns a human label for a cipher suite id.
func CipherName(id uint16) string {
	if name := tls.CipherSuiteName(id); name != "" && !strings.HasPrefix(name, "0x") {
		return name
	}
	return fmt.Sprintf("0x%04x", id)
}
