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
	tls "github.com/refraction-networking/utls"
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
	// quicID selects the uquic fingerprint spec. Ignored when rawSpec is set.
	quicID quic.QUICID
	// rawSpec holds a hand-built QUIC spec for browsers not covered by uquic's
	// built-in ID table (e.g. Safari). When non-nil it takes precedence over quicID.
	rawSpec *quic.QUICSpec
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
	if p.rawSpec != nil {
		return *p.rawSpec, nil
	}
	return quic.QUICID2Spec(p.quicID)
}

// chromeUA / chromeMajor define the modern Chrome version we present in headers.
//
// IMPORTANT: the underlying QUIC + TLS fingerprint comes from uquic's
// validated Chrome 115 spec (the latest uquic ships). That spec is still
// structurally "Chrome" and yields a stable JA4, but it does NOT carry the
// post-quantum key share (Kyber768 / MLKEM768) that Chrome 124+ sends —
// uquic v0.0.6 cannot model the resulting multi-packet Initial. So we keep
// the proven spec and only refresh the version-revealing headers. See README.
const (
	chromeMajor = "137"
	chromeUA    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
)

// chrome is the default profile: latest Chrome on Windows. The QUIC/TLS
// layer is the Chrome 115 spec (see note above) with refreshed client hints.
var chrome = Profile{
	Name:      "chrome",
	Label:     "Chrome " + chromeMajor + " (h3)",
	quicID:    quic.QUICChrome_115,
	ALPN:      []string{"h3"},
	UserAgent: chromeUA,
	Headers: []Header{
		{"sec-ch-ua", `"Google Chrome";v="` + chromeMajor + `", "Chromium";v="` + chromeMajor + `", "Not A Brand";v="24"`},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", `"Windows"`},
		{"upgrade-insecure-requests", "1"},
		{"user-agent", chromeUA},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"sec-fetch-dest", "document"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", "en-US,en;q=0.9"},
		{"priority", "u=0, i"},
	},
}

// chrome115 keeps the exact Chrome 115 presentation for users who want the
// version string to match uquic's validated fingerprint baseline.
var chrome115 = Profile{
	Name:      "chrome115",
	Label:     "Chrome 115 (h3, baseline)",
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

// firefox136 mimics a desktop Firefox 136 on Windows.
// The QUIC/TLS layer uses uquic's Firefox 116 spec (the only Firefox spec in
// uquic v0.0.6), with updated headers to reflect Firefox 136.
var firefox116 = Profile{
	Name:      "firefox",
	Label:     "Firefox 136 (h3)",
	quicID:    quic.QUICFirefox_116,
	ALPN:      []string{"h3"},
	UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
	Headers: []Header{
		{"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0"},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/jxl,*/*;q=0.8"},
		{"accept-language", "en-US,en;q=0.5"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"upgrade-insecure-requests", "1"},
		{"sec-fetch-dest", "document"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-user", "?1"},
		{"priority", "u=0, i"},
		{"te", "trailers"},
	},
}

// safariQUICSpec is a hand-built QUIC + TLS fingerprint for WebKit (Safari 17).
// uquic v0.0.6 does not ship a Safari spec so we construct it from public
// captures (tls.peet.ws / browserleaks.com).
//
// Distinctive Safari characteristics vs Chrome/Firefox:
//   - ec_point_formats extension (Safari sends this even in TLS 1.3)
//   - signed_certificate_timestamp (SCT) request
//   - compress_certificate: zlib only (Chrome uses brotli)
//   - max_idle_timeout: 600 000 ms (10 min) — Chrome uses 30 s
//   - No Google-specific QUIC transport params (no google_quic_version etc.)
var safariQUICSpec = quic.QUICSpec{
	InitialPacketSpec: quic.InitialPacketSpec{
		SrcConnIDLength:        0,
		DestConnIDLength:       8,
		InitPacketNumberLength: 1,
		InitPacketNumber:       0,
		ClientTokenLength:      0,
		FrameBuilder:           quic.QUICFrames{},
	},
	ClientHelloSpec: &tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS13,
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []uint8{0x00},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.SupportedPointsExtension{
				SupportedPoints: []uint8{0x00},
			},
			&tls.SupportedCurvesExtension{
				Curves: []tls.CurveID{
					tls.CurveX25519,
					tls.CurveSECP256R1,
					tls.CurveSECP384R1,
					tls.CurveSECP521R1,
				},
			},
			&tls.ALPNExtension{
				AlpnProtocols: []string{"h3"},
			},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.PSSWithSHA256,
					tls.PKCS1WithSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithSHA1,
					tls.PSSWithSHA384,
					tls.PSSWithSHA384,
					tls.PKCS1WithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA512,
					tls.PKCS1WithSHA1,
				},
			},
			&tls.SCTExtension{},
			&tls.KeyShareExtension{
				KeyShares: []tls.KeyShare{
					{Group: tls.CurveX25519},
				},
			},
			&tls.PSKKeyExchangeModesExtension{
				Modes: []uint8{tls.PskModeDHE},
			},
			&tls.SupportedVersionsExtension{
				Versions: []uint16{tls.VersionTLS13},
			},
			&tls.UtlsCompressCertExtension{
				Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionZlib},
			},
			&tls.ApplicationSettingsExtension{
				SupportedProtocols: []string{"h3"},
			},
			quic.ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{
				TransportParameters: tls.TransportParameters{
					tls.InitialMaxData(10485760),
					tls.InitialMaxStreamDataBidiLocal(1048576),
					tls.InitialMaxStreamDataBidiRemote(1048576),
					tls.InitialMaxStreamDataUni(1048576),
					tls.InitialMaxStreamsBidi(100),
					tls.InitialMaxStreamsUni(100),
					tls.MaxIdleTimeout(600000),
					tls.InitialSourceConnectionID([]byte{}),
					tls.MaxAckDelay(25),
					tls.ActiveConnectionIDLimit(4),
					&tls.DisableActiveMigration{},
					&tls.VersionInformation{
						ChoosenVersion: tls.VERSION_1,
						AvailableVersions: []uint32{
							tls.VERSION_GREASE,
							tls.VERSION_1,
						},
						LegacyID: false,
					},
				},
			}),
			&tls.UtlsPaddingExtension{
				GetPaddingLen: tls.BoringPaddingStyle,
			},
		},
	},
}

const (
	safariVersion = "18.3"
	safariWebKit  = "605.1.15"
)

// safari18 impersonates macOS Safari 18 on macOS Sequoia (WebKit).
var safari17 = Profile{
	Name:      "safari",
	Label:     "Safari " + safariVersion + " (h3, macOS)",
	rawSpec:   &safariQUICSpec,
	ALPN:      []string{"h3"},
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/" + safariWebKit + " (KHTML, like Gecko) Version/" + safariVersion + " Safari/" + safariWebKit,
	Headers: []Header{
		{"user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/" + safariWebKit + " (KHTML, like Gecko) Version/" + safariVersion + " Safari/" + safariWebKit},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"accept-language", "en-US,en;q=0.9"},
		{"accept-encoding", "gzip, deflate, br"},
	},
}

// ios18 impersonates Mobile Safari 18 on iPhone (iOS 18).
var ios17 = Profile{
	Name:      "ios",
	Label:     "Safari 18 (h3, iOS 18)",
	rawSpec:   &safariQUICSpec,
	ALPN:      []string{"h3"},
	UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/" + safariWebKit + " (KHTML, like Gecko) Version/" + safariVersion + " Mobile/15E148 Safari/604.1",
	Headers: []Header{
		{"user-agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/" + safariWebKit + " (KHTML, like Gecko) Version/" + safariVersion + " Mobile/15E148 Safari/604.1"},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"accept-language", "en-US,en;q=0.9"},
		{"accept-encoding", "gzip, deflate, br"},
	},
}

// registry maps profile names to their definitions.
var registry = map[string]Profile{
	chrome.Name:     chrome,
	chrome115.Name:  chrome115,
	firefox116.Name: firefox116,
	safari17.Name:   safari17,
	ios17.Name:      ios17,
}

// Default is the profile used when none is specified.
const Default = "chrome"

// Get returns the profile with the given name, or false if it is unknown.
func Get(name string) (Profile, bool) {
	p, ok := registry[name]
	return p, ok
}

// Names returns the available profile names in display order.
func Names() []string {
	return []string{chrome.Name, chrome115.Name, firefox116.Name, safari17.Name, ios17.Name}
}
