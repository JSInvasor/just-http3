// Package sender drives a single HTTP/3 request using a browser fingerprint
// profile and reports a detailed timing breakdown.
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
	Profile        profiles.Profile
	Method         string
	Timeout        time.Duration
	Insecure       bool // skip TLS certificate verification
	ServerName     string
	ExtraHeaders   []profiles.Header
	KeepBody       bool          // retain the response body in Result.Body
	MaxBody        int64         // cap on body bytes read (0 = unlimited)
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
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("opening udp socket: %w", err)
	}
	uTransport := &quic.UTransport{
		Transport: &quic.Transport{Conn: udpConn},
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
