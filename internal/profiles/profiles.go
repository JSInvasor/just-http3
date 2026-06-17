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
// Safari profiles are built from a real iPhone capture via browserleaks.com
// (iOS 18.7 / Safari 18.7.5, June 2026).
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
	// Name is the user-facing identifier (e.g. "ios").
	Name string
	// Label is a human description shown in output (e.g. "Safari 18.7 iOS").
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

// safariQUICSpec is built from a real iPhone iOS 18.7 capture via browserleaks.com.
//
// Key Safari/WebKit fingerprint characteristics (verified against live capture):
//   - GREASE cipher suite prefix + GREASE extensions at position 0 and last
//   - NO ec_point_formats, NO ALPS/ApplicationSettings
//   - Extension order: GREASE, SNI, supported_groups, ALPN, status_request,
//     signature_algorithms, SCT, key_share, PSK modes, supported_versions,
//     quic_transport_parameters, compress_certificate, GREASE
//   - compress_certificate: zlib only (Chrome uses brotli)
//   - QUIC transport params in fixed order (no shuffling)
//   - Apple vendor transport param: 0xFF080808 = 6
//   - active_connection_id_limit: 64 (Chrome uses 2, Firefox 8)
//   - initial_max_data: 16 MB; stream data limits: 2 MB each
//   - initial_max_streams_uni: 8 (not 100)
//   - No max_idle_timeout, max_ack_delay, disable_active_migration
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
			&tls.PSKKeyExchangeModesExtension{
				Modes: []uint8{tls.PskModeDHE},
			},
			&tls.SupportedVersionsExtension{
				Versions: []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.VersionTLS13,
				},
			},
			// quic_transport_parameters comes BEFORE compress_certificate in Safari
			// (opposite of what one might expect — verified in capture)
			&tls.QUICTransportParametersExtension{
				TransportParameters: tls.TransportParameters{
					tls.InitialMaxData(16777216),
					tls.InitialMaxStreamDataBidiLocal(2097152),
					tls.InitialMaxStreamDataBidiRemote(2097152),
					tls.InitialMaxStreamDataUni(2097152),
					tls.InitialMaxStreamsUni(8),
					tls.ActiveConnectionIDLimit(64),
					tls.InitialSourceConnectionID([]byte{}),
					// Apple vendor-specific transport parameter (0xFF080808 = 6)
					&tls.FakeQUICTransportParameter{
						Id:  0xFF080808,
						Val: []byte{0x06},
					},
				},
			},
			&tls.UtlsCompressCertExtension{
				Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionZlib},
			},
			&tls.UtlsGREASEExtension{},
		},
	},
	// Pad to 1200 bytes (QUIC RFC 9000 minimum Initial packet size).
	UDPDatagramMinSize: 1200,
}

const (
	// iosUA is the real UA string observed in the browserleaks.com capture.
	iosUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.5 Mobile/15E148 Safari/604.1"

	// macUA mirrors the same WebKit version on macOS Sequoia.
	macUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.5 Safari/605.1.15"
)

// ios is the primary profile: iPhone iOS 18.7 / Mobile Safari 18.7.5.
// Header order and values are adapted from the browserleaks.com capture;
// sec-fetch-* values are for a direct navigation request (not XHR/fetch).
var ios = Profile{
	Name:      "ios",
	Label:     "Safari 18.7 (h3, iOS 18.7)",
	rawSpec:   &safariQUICSpec,
	ALPN:      []string{"h3"},
	UserAgent: iosUA,
	Headers: []Header{
		{"sec-fetch-dest", "document"},
		{"user-agent", iosUA},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"accept-language", "en-US,en;q=0.9"},
		{"priority", "u=0, i"},
		{"accept-encoding", "gzip, deflate, br"},
	},
}

// safari mirrors the iOS profile for macOS Safari 18.7 (same WebKit engine,
// same QUIC fingerprint, different UA and platform string).
var safari = Profile{
	Name:      "safari",
	Label:     "Safari 18.7 (h3, macOS 15)",
	rawSpec:   &safariQUICSpec,
	ALPN:      []string{"h3"},
	UserAgent: macUA,
	Headers: []Header{
		{"sec-fetch-dest", "document"},
		{"user-agent", macUA},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"accept-language", "en-US,en;q=0.9"},
		{"priority", "u=0, i"},
		{"accept-encoding", "gzip, deflate, br"},
	},
}

// registry maps profile names to their definitions.
var registry = map[string]Profile{
	ios.Name:    ios,
	safari.Name: safari,
}

// Default is the profile used when none is specified.
const Default = "ios"

// Get returns the profile with the given name, or false if it is unknown.
func Get(name string) (Profile, bool) {
	p, ok := registry[name]
	return p, ok
}

// Names returns the available profile names in display order.
func Names() []string {
	return []string{ios.Name, safari.Name}
}
