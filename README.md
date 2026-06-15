# just-http3 (`http3-beta`)

Custom **HTTP/3 request sender** written in Go. It fires a single HTTP/3
request while **impersonating a real browser's QUIC + TLS fingerprint**
(the JA3/JA4 hash, QUIC transport parameters, GREASE values and ClientHello
byte layout that sites like [tls.peet.ws](https://tls.peet.ws) inspect), then
prints a timing breakdown.

```
http3-beta https://tls.peet.ws/api/all
```

## Why not "from scratch" QUIC?

Writing a QUIC stack from zero takes months **and still wouldn't match a
browser fingerprint** — which is the whole point here. Instead we build on
[`uquic`](https://github.com/refraction-networking/uquic) (the uTLS equivalent
for QUIC), which lets us control the QUIC Initial packet and the TLS
ClientHello byte-for-byte so the fingerprint matches Chrome/Firefox. The
custom part of this project is the CLI, the timing instrumentation, and the
browser profile layer on top.

## Build

```sh
go build -o http3-beta .
```

> Requires Go 1.25+. The QUIC layer uses **outbound UDP/443** — make sure your
> network/firewall allows it (sandboxed CI runners often block UDP egress,
> which will surface as `timeout: no recent network activity`).

## Usage

```
http3-beta [flags] <url>

  -p, --profile <name>   browser profile: chrome (default), firefox
  -X, --method <method>  HTTP method (default GET)
  -t, --timeout <dur>    overall timeout, e.g. 10s, 1m (default 30s)
  -k, --insecure         skip TLS certificate verification
  -v, --verbose          print response headers
  -b, --body             print response body
      --version          print version
  -h, --help             help
```

### Examples

```sh
# Inspect the fingerprint a server sees (JA4 etc.)
http3-beta -b https://tls.peet.ws/api/all

# Firefox profile, with response headers and timing
http3-beta -p firefox -v https://cloudflare-quic.com

# HEAD request with a short timeout
http3-beta -X HEAD -t 5s https://www.google.com
```

Sample output:

```
→ GET https://cloudflare-quic.com
  profile   Chrome 115 (h3)
  resolved  104.16.132.229:443
  alpn      h3
  tls       TLS 1.3 / TLS_AES_128_GCM_SHA256

  DNS lookup          12.30 ms
  QUIC handshake      48.10 ms
  TTFB               103.40 ms
  download             6.20 ms
  ──────────────────────────────
  total              121.90 ms

  HTTP/3 200 OK  3.2 KB
```

## Browser profiles

Profiles live in `internal/profiles/`. Each bundles:

- the **QUIC fingerprint spec** (from uquic — Initial packet layout, transport
  parameters, GREASE, ClientHello),
- the default **request headers in browser order** (header order is itself
  part of the fingerprint).

Currently shipped: `chrome` (Chrome 115) and `firefox` (Firefox 116).

## Collecting a real browser's H3 fingerprint

Your browser probably **isn't sending H3 yet** for one of these reasons, and
here is how to fix it so you can capture a reference fingerprint:

1. **H3 must be enabled.**
   - Chrome: `chrome://flags` → enable *Experimental QUIC protocol*.
   - Firefox: `about:config` → `network.http.http3.enabled = true`.

2. **Browsers only switch to H3 after discovery (Alt-Svc).** On the first
   visit they use TCP/H2, see the server's `alt-svc: h3=...` header, and only
   use H3 on subsequent requests. To skip that and *force* H3 in Chrome:

   ```sh
   google-chrome \
     --enable-quic \
     --origin-to-force-quic-on=tls.peet.ws:443
   # then open https://tls.peet.ws/api/all
   ```

3. **Read the fingerprint off a reflector.** These return what they observed
   about your client (open them in the H3-forced browser):
   - `https://tls.peet.ws/api/all` → JA3/JA4, HTTP/2 & HTTP/3 fingerprints.
   - `https://quic.tlsfingerprint.io/qfp/?beautify=true` → raw QUIC fingerprint.

   Compare those values against what `http3-beta -b https://tls.peet.ws/api/all`
   produces — they should line up for the matching profile. That is the loop
   for building/validating a new profile in `internal/profiles/`.

## Project layout

```
main.go                  CLI: flags, orchestration, timing output
internal/profiles/       browser fingerprint presets
internal/sender/         builds the uquic round-tripper, runs the request,
                         measures DNS / handshake / TTFB / download
```

## Status

`0.1.0-beta`. Works against live H3 endpoints where UDP egress is permitted.
Next ideas: more profiles (Safari/iOS/Edge), exact request-header ordering at
the QPACK layer, `-n` repeat/benchmark mode, JSON output.
