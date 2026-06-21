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
// Profiles are built from real iPhone captures via browserleaks.com.
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
	// Name is the user-facing identifier (e.g. "ios26").
	Name string
	// Label is a human description shown in output.
	Label string
	// rawSpec holds the QUIC spec for this profile.
	rawSpec *quic.QUICSpec
	// ALPN is the negotiated application protocol list.
	ALPN []string
	// UserAgent is the User-Agent header value the browser would send.
	UserAgent string
	// Headers are the default request headers in browser order. The :method,
	// :scheme, :authority and :path pseudo-headers are added by the HTTP/3
	// layer; these are the regular headers that follow.
	Headers []Header
}

// Spec returns the QUIC spec for this profile.
func (p Profile) Spec() (quic.QUICSpec, error) {
	return *p.rawSpec, nil
}

// x25519MLKEM768 is the IANA ID for the X25519+ML-KEM-768 hybrid key exchange
// introduced in iOS 26 / Safari 26. Added to IETF as draft-ietf-tls-hybrid-design.
const x25519MLKEM768 = tls.CurveID(0x11EC)

// ── iOS 18.7 ────────────────────────────────────────────────────────────────

// safariQUICSpec18 is built from a real iPhone iOS 18.7 capture (Safari 18.7.5,
// June 2026). Kept as a legacy profile alongside the newer iOS 26 capture.
var safariQUICSpec18 = quic.QUICSpec{
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
			tls.GREASE_PLACEHOLDER,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []uint8{0x00},
		Extensions: []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.SNIExtension{},
			&tls.SupportedCurvesExtension{
				Curves: []tls.CurveID{
					tls.CurveID(tls.GREASE_PLACEHOLDER),
					tls.CurveX25519,
					tls.CurveSECP256R1,
					tls.CurveSECP384R1,
					tls.CurveSECP521R1,
				},
			},
			&tls.ALPNExtension{AlpnProtocols: []string{"h3"}},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.PSSWithSHA256,
					tls.PKCS1WithSHA256,
					tls.ECDSAWithP384AndSHA384,
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
					{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: tls.CurveX25519},
				},
			},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.SupportedVersionsExtension{
				Versions: []uint16{tls.GREASE_PLACEHOLDER, tls.VersionTLS13},
			},
			&tls.QUICTransportParametersExtension{
				TransportParameters: tls.TransportParameters{
					tls.InitialMaxData(16777216),
					tls.InitialMaxStreamDataBidiLocal(2097152),
					tls.InitialMaxStreamDataBidiRemote(2097152),
					tls.InitialMaxStreamDataUni(2097152),
					tls.InitialMaxStreamsUni(8),
					tls.ActiveConnectionIDLimit(64),
					tls.InitialSourceConnectionID([]byte{}),
					&tls.FakeQUICTransportParameter{Id: 0xFF080808, Val: []byte{0x06}},
				},
			},
			&tls.UtlsCompressCertExtension{
				Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionZlib},
			},
			&tls.UtlsGREASEExtension{},
		},
	},
	UDPDatagramMinSize: 1200,
}

const (
	iosUA18 = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.5 Mobile/15E148 Safari/604.1"
	macUA18 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.5 Safari/605.1.15"
)

var ios18 = Profile{
	Name:      "ios",
	Label:     "Safari 18.7 (h3, iOS 18.7)",
	rawSpec:   &safariQUICSpec18,
	ALPN:      []string{"h3"},
	UserAgent: iosUA18,
	Headers: []Header{
		{"sec-fetch-dest", "document"},
		{"user-agent", iosUA18},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"accept-language", "en-US,en;q=0.9"},
		{"priority", "u=0, i"},
		{"accept-encoding", "gzip, deflate, br"},
	},
}

var safari18 = Profile{
	Name:      "safari",
	Label:     "Safari 18.7 (h3, macOS 15)",
	rawSpec:   &safariQUICSpec18,
	ALPN:      []string{"h3"},
	UserAgent: macUA18,
	Headers: []Header{
		{"sec-fetch-dest", "document"},
		{"user-agent", macUA18},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"accept-language", "en-US,en;q=0.9"},
		{"priority", "u=0, i"},
		{"accept-encoding", "gzip, deflate, br"},
	},
}

// ── iOS 26.5 ────────────────────────────────────────────────────────────────

// safariQUICSpec26 is built from a real iPhone iOS 26.5 capture (Safari 26.5,
// June 2026). Key changes vs iOS 18.7:
//   - Cipher suite order: AES-256 now leads instead of AES-128
//   - X25519MLKEM768 (0x11EC) added to supported_groups and key_share
//     (post-quantum hybrid key exchange, shipping in iOS 26)
//   - QUIC transport params reordered: active_connection_id_limit and
//     initial_source_connection_id moved to the front
//   - Apple vendor param (0xFF080808) not present in capture — omitted
var safariQUICSpec26 = quic.QUICSpec{
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
			tls.GREASE_PLACEHOLDER,
			tls.TLS_AES_256_GCM_SHA384,     // AES-256 now first (was AES-128)
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
		CompressionMethods: []uint8{0x00},
		Extensions: []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.SNIExtension{},
			&tls.SupportedCurvesExtension{
				Curves: []tls.CurveID{
					tls.CurveID(tls.GREASE_PLACEHOLDER),
					x25519MLKEM768,       // new: post-quantum hybrid
					tls.CurveX25519,
					tls.CurveSECP256R1,
					tls.CurveSECP384R1,
					tls.CurveSECP521R1,
				},
			},
			&tls.ALPNExtension{AlpnProtocols: []string{"h3"}},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.PSSWithSHA256,
					tls.PKCS1WithSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.PSSWithSHA384,
					tls.PSSWithSHA384, // Safari sends this twice (verified in capture)
					tls.PKCS1WithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA512,
					tls.PKCS1WithSHA1,
				},
			},
			&tls.SCTExtension{},
			&tls.KeyShareExtension{
				KeyShares: []tls.KeyShare{
					{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: tls.CurveX25519},
				},
			},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.SupportedVersionsExtension{
				Versions: []uint16{tls.GREASE_PLACEHOLDER, tls.VersionTLS13},
			},
			&tls.QUICTransportParametersExtension{
				TransportParameters: tls.TransportParameters{
					// Order from live iOS 26.5 capture (different from iOS 18.7)
					tls.ActiveConnectionIDLimit(64),
					tls.InitialSourceConnectionID([]byte{}),
					tls.InitialMaxData(16777216),
					tls.InitialMaxStreamDataBidiLocal(2097152),
					tls.InitialMaxStreamDataBidiRemote(2097152),
					tls.InitialMaxStreamDataUni(2097152),
					tls.InitialMaxStreamsUni(8),
				},
			},
			&tls.UtlsCompressCertExtension{
				Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionZlib},
			},
			&tls.UtlsGREASEExtension{},
		},
	},
	UDPDatagramMinSize: 1200,
}

// iosUA26 is from the live iOS 26.5 capture. Note: the OS string still reports
// 18_7 — iOS 26 maintains this for web-compat; only the Version token changed.
const iosUA26 = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Mobile/15E148 Safari/604.1"

var ios26 = Profile{
	Name:      "ios26",
	Label:     "Safari 26.5 (h3, iOS 26.5)",
	rawSpec:   &safariQUICSpec26,
	ALPN:      []string{"h3"},
	UserAgent: iosUA26,
	Headers: []Header{
		{"sec-fetch-dest", "document"},
		{"user-agent", iosUA26},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"accept-language", "en-US,en;q=0.9"},
		{"priority", "u=0, i"},
		{"accept-encoding", "gzip, deflate, br, zstd"}, // zstd added in iOS 26
	},
}

// ── Registry ────────────────────────────────────────────────────────────────

var registry = map[string]Profile{
	ios26.Name:  ios26,
	ios18.Name:  ios18,
	safari18.Name: safari18,
}

// Default is the profile used when none is specified.
const Default = "ios26"

// Get returns the profile with the given name, or false if it is unknown.
func Get(name string) (Profile, bool) {
	p, ok := registry[name]
	return p, ok
}

// Names returns the available profile names in display order.
func Names() []string {
	return []string{ios26.Name, ios18.Name, safari18.Name}
}
