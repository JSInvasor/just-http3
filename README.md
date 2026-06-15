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

| profile     | UA version | QUIC/TLS spec | notes |
|-------------|------------|---------------|-------|
| `chrome`    | Chrome 131 | Chrome 115    | default; modern client hints |
| `chrome115` | Chrome 115 | Chrome 115    | exact uquic-validated baseline |
| `firefox`   | Firefox 116| Firefox 116   | |

Override the User-Agent on any profile with `-A/--user-agent`.

### About "newer Chrome"

The latest [`uquic`](https://github.com/refraction-networking/uquic) release
(v0.0.6) only ships a **Chrome 115** QUIC spec. That matters more than it
sounds: Chrome **124+** sends a post-quantum key share (Kyber768, now
MLKEM768 — ~1.2 KB) in its TLS ClientHello, which pushes the handshake across
**multiple QUIC Initial packets**. uquic v0.0.6 models a single-packet Initial,
so we *cannot* just bolt the PQ key share onto the 115 spec without producing a
malformed handshake.

So the `chrome` profile uses the **proven Chrome 115 QUIC/TLS fingerprint**
(stable JA4, reads as Chrome) with **refreshed Chrome 131 headers**. What this
gives you and what it doesn't:

- ✅ JA3/JA4 reads as Chrome; QUIC transport params + GREASE match a real Chrome.
- ✅ User-Agent / client hints say Chrome 131 (tweak with `-A`).
- ⚠️ The TLS key share is X25519-only — it lacks the PQ key share that the very
  latest Chrome sends, so a detector that cross-checks UA version against the
  key share could spot the mismatch.

For a byte-exact *latest* Chrome H3 fingerprint we need either a newer uquic
that models the multi-packet PQ Initial, or a hand-built spec from a real
capture (see below). That is the planned next step.

## Browser vs. this tool

Yes — if you only want to **see** your own fingerprint, the browser itself is
the most authentic source: force H3 (below), open `https://tls.peet.ws/api/all`
and the page shows everything the server observed about your real client.

But the browser can only send the requests *you* navigate to, through its own
UI. It can't be scripted to hit arbitrary endpoints, can't run headless on a
server, and won't give you a phase-by-phase timing breakdown. That's what
`http3-beta` is for: sending custom H3 requests, from code/automation, with a
*chosen* fingerprint — and measuring them. Use the browser to capture a
reference; use this tool to reproduce it programmatically.

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
