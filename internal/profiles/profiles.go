// Package profiles holds browser fingerprint presets for HTTP/3 requests.
//
// Each profile bundles together everything that makes a request look like it
// came from a real browser over HTTP/3:
//
//   - the QUIC fingerprint (uquic spec: Initial packet layout, transport
//     parameters, GREASE values and the TLS ClientHello byte layout that
//     drives the JA3/JA4 hash reported by sites like tls.peet.ws)
//   - the default request header set, in the order a browser sends them
//
// We deliberately reuse the QUIC specs that ship with uquic instead of
// hand-rolling them, because matching a browser byte-for-byte is exactly what
// that library was built for.
package profiles

import (
	quic "github.com/refraction-networking/uquic"
)

// Header is a single request header. We keep these in an ordered slice rather
// than an http.Header map because header ordering is itself part of the
// fingerprint a server sees.
type Header struct {
	Key string
	Val string
}

// Profile is a named browser impersonation preset.
type Profile struct {
	// Name is the user-facing identifier (e.g. "chrome").
	Name string
	// Label is a human description shown in output (e.g. "Chrome 115").
	Label string
	// quicID selects the uquic fingerprint spec.
	quicID quic.QUICID
	// ALPN is the negotiated application protocol list. For HTTP/3 this is
	// always just "h3", but kept explicit so it shows up in the spec.
	ALPN []string
	// UserAgent is the User-Agent header value the browser would send.
	UserAgent string
	// Headers are the default request headers in browser order. The :method,
	// :scheme, :authority and :path pseudo-headers are added by the HTTP/3
	// layer; these are the regular headers that follow.
	Headers []Header
}

// Spec resolves the uquic QUIC spec for this profile.
func (p Profile) Spec() (quic.QUICSpec, error) {
	return quic.QUICID2Spec(p.quicID)
}

// chrome115 mimics a desktop Chrome 115 on Windows.
var chrome115 = Profile{
	Name:      "chrome",
	Label:     "Chrome 115 (h3)",
	quicID:    quic.QUICChrome_115,
	ALPN:      []string{"h3"},
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
	Headers: []Header{
		{"sec-ch-ua", `"Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115"`},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", `"Windows"`},
		{"upgrade-insecure-requests", "1"},
		{"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"sec-fetch-dest", "document"},
		{"accept-encoding", "gzip, deflate, br"},
		{"accept-language", "en-US,en;q=0.9"},
	},
}

// firefox116 mimics a desktop Firefox 116 on Windows.
var firefox116 = Profile{
	Name:      "firefox",
	Label:     "Firefox 116 (h3)",
	quicID:    quic.QUICFirefox_116,
	ALPN:      []string{"h3"},
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0",
	Headers: []Header{
		{"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0"},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
		{"accept-language", "en-US,en;q=0.5"},
		{"accept-encoding", "gzip, deflate, br"},
		{"upgrade-insecure-requests", "1"},
		{"sec-fetch-dest", "document"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-user", "?1"},
		{"te", "trailers"},
	},
}

// registry maps profile names to their definitions.
var registry = map[string]Profile{
	chrome115.Name:  chrome115,
	firefox116.Name: firefox116,
}

// Default is the profile used when none is specified.
const Default = "chrome"

// Get returns the profile with the given name, or false if it is unknown.
func Get(name string) (Profile, bool) {
	p, ok := registry[name]
	return p, ok
}

// Names returns the available profile names.
func Names() []string {
	return []string{chrome115.Name, firefox116.Name}
}
