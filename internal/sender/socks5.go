package sender

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"
)

const (
	socks5Version = 0x05
	authNone      = 0x00
	authPassword  = 0x02
	authNoAccept  = 0xFF
	cmdUDPAssoc   = 0x03
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
)

// socks5UDPConn implements net.PacketConn by routing UDP packets through a
// SOCKS5 UDP ASSOCIATE relay. ctrl is the TCP control connection that must
// stay alive for the duration of the association.
type socks5UDPConn struct {
	ctrl  net.Conn
	udp   *net.UDPConn
	relay *net.UDPAddr
}

func (c *socks5UDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	n, _, err := c.udp.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}
	// SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) ADDR PORT(2) DATA
	if n < 4 {
		return 0, nil, fmt.Errorf("socks5 udp: response too short")
	}
	atyp := buf[3]
	var src net.Addr
	var off int
	switch atyp {
	case atypIPv4:
		if n < 10 {
			return 0, nil, fmt.Errorf("socks5 udp: ipv4 header truncated")
		}
		src = &net.UDPAddr{
			IP:   net.IP(append([]byte(nil), buf[4:8]...)),
			Port: int(binary.BigEndian.Uint16(buf[8:10])),
		}
		off = 10
	case atypIPv6:
		if n < 22 {
			return 0, nil, fmt.Errorf("socks5 udp: ipv6 header truncated")
		}
		src = &net.UDPAddr{
			IP:   net.IP(append([]byte(nil), buf[4:20]...)),
			Port: int(binary.BigEndian.Uint16(buf[20:22])),
		}
		off = 22
	case atypDomain:
		dlen := int(buf[4])
		off = 5 + dlen + 2
		if n < off {
			return 0, nil, fmt.Errorf("socks5 udp: domain header truncated")
		}
		src = &net.UDPAddr{Port: int(binary.BigEndian.Uint16(buf[5+dlen : off]))}
	default:
		return 0, nil, fmt.Errorf("socks5 udp: unknown atyp 0x%02x", atyp)
	}
	return copy(b, buf[off:n]), src, nil
}

func (c *socks5UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("socks5 udp: WriteTo requires *net.UDPAddr, got %T", addr)
	}
	hdr := []byte{0x00, 0x00, 0x00} // RSV, FRAG
	if ip4 := ua.IP.To4(); ip4 != nil {
		hdr = append(hdr, atypIPv4)
		hdr = append(hdr, ip4...)
	} else {
		hdr = append(hdr, atypIPv6)
		hdr = append(hdr, ua.IP.To16()...)
	}
	hdr = append(hdr, byte(ua.Port>>8), byte(ua.Port))

	pkt := make([]byte, len(hdr)+len(b))
	copy(pkt, hdr)
	copy(pkt[len(hdr):], b)
	if _, err := c.udp.WriteTo(pkt, c.relay); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *socks5UDPConn) Close() error {
	c.ctrl.Close()
	return c.udp.Close()
}

func (c *socks5UDPConn) LocalAddr() net.Addr                { return c.udp.LocalAddr() }
func (c *socks5UDPConn) SetDeadline(t time.Time) error      { return c.udp.SetDeadline(t) }
func (c *socks5UDPConn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

// dialSOCKS5UDP negotiates SOCKS5 UDP ASSOCIATE over TCP and returns a
// net.PacketConn that transparently tunnels UDP packets through the proxy.
// proxyURL must use the "socks5" scheme: socks5://[user:pass@]host:port
func dialSOCKS5UDP(proxyURL *url.URL) (net.PacketConn, error) {
	host := proxyURL.Hostname()
	port := proxyURL.Port()
	if port == "" {
		port = "1080"
	}

	ctrl, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("connect to proxy: %w", err)
	}

	// Auth method negotiation.
	hasAuth := proxyURL.User != nil
	if hasAuth {
		ctrl.Write([]byte{socks5Version, 2, authNone, authPassword})
	} else {
		ctrl.Write([]byte{socks5Version, 1, authNone})
	}
	helo := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, helo); err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("auth handshake: %w", err)
	}
	if helo[0] != socks5Version {
		ctrl.Close()
		return nil, fmt.Errorf("not a SOCKS5 proxy (got 0x%02x)", helo[0])
	}
	switch helo[1] {
	case authNone:
		// no-op
	case authPassword:
		if !hasAuth {
			ctrl.Close()
			return nil, fmt.Errorf("proxy requires credentials")
		}
		user := proxyURL.User.Username()
		pass, _ := proxyURL.User.Password()
		pkt := []byte{0x01, byte(len(user))}
		pkt = append(pkt, user...)
		pkt = append(pkt, byte(len(pass)))
		pkt = append(pkt, pass...)
		ctrl.Write(pkt)
		resp := make([]byte, 2)
		if _, err := io.ReadFull(ctrl, resp); err != nil || resp[1] != 0x00 {
			ctrl.Close()
			return nil, fmt.Errorf("proxy auth failed")
		}
	case authNoAccept:
		ctrl.Close()
		return nil, fmt.Errorf("proxy rejected all auth methods")
	default:
		ctrl.Close()
		return nil, fmt.Errorf("proxy chose unknown auth method 0x%02x", helo[1])
	}

	// UDP ASSOCIATE — send 0.0.0.0:0 as our source (proxy will accept any).
	ctrl.Write([]byte{socks5Version, cmdUDPAssoc, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})

	rHdr := make([]byte, 4)
	if _, err := io.ReadFull(ctrl, rHdr); err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("udp assoc response: %w", err)
	}
	if rHdr[1] != 0x00 {
		ctrl.Close()
		return nil, fmt.Errorf("udp assoc rejected (rep=0x%02x)", rHdr[1])
	}

	relayIP, relayPort, err := readSocks5Addr(ctrl, rHdr[3])
	if err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("relay address: %w", err)
	}

	// Some proxies return 0.0.0.0 / :: meaning "use my own IP".
	if relayIP.Equal(net.IPv4zero) || relayIP.Equal(net.IPv6zero) {
		resolved, err := net.LookupHost(host)
		if err != nil || len(resolved) == 0 {
			ctrl.Close()
			return nil, fmt.Errorf("resolve proxy host %q: %w", host, err)
		}
		relayIP = net.ParseIP(resolved[0])
	}

	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("open udp socket: %w", err)
	}

	return &socks5UDPConn{
		ctrl:  ctrl,
		udp:   udp,
		relay: &net.UDPAddr{IP: relayIP, Port: relayPort},
	}, nil
}

func readSocks5Addr(r io.Reader, atyp byte) (net.IP, int, error) {
	switch atyp {
	case atypIPv4:
		b := make([]byte, 6)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, 0, err
		}
		return net.IP(b[:4]), int(binary.BigEndian.Uint16(b[4:])), nil
	case atypIPv6:
		b := make([]byte, 18)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, 0, err
		}
		return net.IP(b[:16]), int(binary.BigEndian.Uint16(b[16:])), nil
	case atypDomain:
		dlen := make([]byte, 1)
		if _, err := io.ReadFull(r, dlen); err != nil {
			return nil, 0, err
		}
		b := make([]byte, int(dlen[0])+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, 0, err
		}
		resolved, err := net.LookupHost(string(b[:dlen[0]]))
		if err != nil || len(resolved) == 0 {
			return nil, 0, fmt.Errorf("resolve %q: %w", string(b[:dlen[0]]), err)
		}
		return net.ParseIP(resolved[0]), int(binary.BigEndian.Uint16(b[dlen[0]:])), nil
	default:
		return nil, 0, fmt.Errorf("unknown atyp 0x%02x", atyp)
	}
}
