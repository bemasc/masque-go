package masque

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// defaultInitialPacketSize is an increased packet size used for the connection to the proxy.
// This allows tunneling QUIC connections, which themselves have a minimum MTU requirement of 1200 bytes.
const defaultInitialPacketSize = 1350

type Connector interface {
	// Connect establishes a proxied UDP connection at the specified expanded template.
	Connect(ctx context.Context, expandedTemplate string, raddr net.Addr) (net.PacketConn, *http.Response, error)

	// ConnectTCP establishes a proxied TCP connection at the specified expanded template.
	ConnectTCP(ctx context.Context, expandedTemplate string, raddr net.Addr) (net.Conn, *http.Response, error)

	// Close closes the connection to the proxy.
	// This immediately shuts down all proxied flows.
	Close() error
}

type Client struct {
	Connector Connector
}

// DialAddr dials a proxied connection to a target server.
// The target address is sent to the proxy, and the DNS resolution is left to the proxy.
// The target must be given as a host:port.
func (c *Client) DialAddr(ctx context.Context, proxyTemplate *uritemplate.Template, target string) (net.PacketConn, *http.Response, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse target: %w", err)
	}
	str, err := proxyTemplate.Expand(uritemplate.Values{
		uriTemplateTargetHost: uritemplate.String(host),
		uriTemplateTargetPort: uritemplate.String(port),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("masque: failed to expand Template: %w", err)
	}
	return c.Connector.Connect(ctx, str, masqueAddr{target})
}

// Dial dials a proxied connection to a target server.
func (c *Client) Dial(ctx context.Context, proxyTemplate *uritemplate.Template, raddr *net.UDPAddr) (net.PacketConn, *http.Response, error) {
	str, err := proxyTemplate.Expand(uritemplate.Values{
		uriTemplateTargetHost: uritemplate.String(escape(raddr.IP.String())),
		uriTemplateTargetPort: uritemplate.String(strconv.Itoa(raddr.Port)),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("masque: failed to expand Template: %w", err)
	}
	return c.Connector.Connect(ctx, str, raddr)
}

// DialTCP dials a proxied TCP connection to a target server.
func (c *Client) DialTCP(ctx context.Context, proxyTemplate *uritemplate.Template, raddr *net.TCPAddr) (net.Conn, *http.Response, error) {
	str, err := proxyTemplate.Expand(uritemplate.Values{
		uriTemplateTargetHost: uritemplate.String(escape(raddr.IP.String())),
		uriTemplateTargetPort: uritemplate.String(strconv.Itoa(raddr.Port)),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("masque: failed to expand Template: %w", err)
	}
	return c.Connector.ConnectTCP(ctx, str, raddr)
}

func (c *Client) Close() error {
	return c.Connector.Close()
}

func makeExtConnectRequest(expandedTemplate string, tcp bool) (*http.Request, error) {
	u, err := url.Parse(expandedTemplate)
	if err != nil {
		return nil, fmt.Errorf("masque: failed to parse URI: %w", err)
	}

	protocol := ConnectUDP
	if tcp {
		protocol = ConnectTCP
	}

	return &http.Request{
		Method: http.MethodConnect,
		Host:   u.Host,
		Proto:  protocol,
		Header: http.Header{
			http3.CapsuleProtocolHeader: []string{capsuleProtocolHeaderValue},
		},
		URL: u,
	}, nil
}

// H3Client establishes proxied UDP connections to remote hosts, using HTTP/3.
// Multiple flows can be proxied via the same connection to the proxy, but all
// requests will be sent to the proxy indicated in the first request.
type H3Client struct {
	// TLSClientConfig is the TLS client config used when dialing the QUIC connection to the proxy.
	// It must set the "h3" ALPN.
	TLSClientConfig *tls.Config

	// QUICConfig is the QUIC config used when dialing the QUIC connection.
	QUICConfig *quic.Config

	dialOnce   sync.Once
	dialErr    error
	conn       *quic.Conn
	clientConn *http3.ClientConn
}

func (c *H3Client) Connect(ctx context.Context, expandedTemplate string, raddr net.Addr) (net.PacketConn, *http.Response, error) {
	rstr, h3Conn, rsp, raddr, err := c.openRequest(ctx, expandedTemplate, raddr, false)
	if err != nil {
		return nil, rsp, err
	}
	laddr := masqueAddr{h3Conn.Conn().LocalAddr().String()}

	var dgs DatagramSendReceiver
	settings := h3Conn.Settings()
	if !settings.EnableDatagrams {
		log.Printf("masque: server didn't enable Datagrams")
	} else if c.QUICConfig.EnableDatagrams {
		dgs = rstr // Both sides have opted in to datagrams
	}

	conn := ProxiedPacketConn(dgs, rstr, rsp.Body, laddr, raddr)
	return conn, rsp, nil

}

func (c *H3Client) ConnectTCP(ctx context.Context, expandedTemplate string, raddr net.Addr) (net.Conn, *http.Response, error) {
	rstr, h3Conn, rsp, raddr, err := c.openRequest(ctx, expandedTemplate, raddr, true)
	if err != nil {
		return nil, nil, err
	}
	laddr := masqueAddr{h3Conn.Conn().LocalAddr().String()}
	conn := ProxiedTCPConn(rstr, rsp.Body, laddr, raddr)
	return conn, rsp, nil

}

func (c *H3Client) openRequest(ctx context.Context, expandedTemplate string, raddr net.Addr, tcp bool) (*http3.RequestStream, *http3.ClientConn, *http.Response, net.Addr, error) {
	req, err := makeExtConnectRequest(expandedTemplate, tcp)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	c.dialOnce.Do(func() {
		quicConf := c.QUICConfig
		if quicConf == nil {
			quicConf = &quic.Config{
				EnableDatagrams:   true,
				InitialPacketSize: defaultInitialPacketSize,
			}
		}
		tlsConf := c.TLSClientConfig
		if tlsConf == nil {
			tlsConf = &tls.Config{NextProtos: []string{http3.NextProtoH3}}
		}
		conn, err := quic.DialAddr(ctx, req.Host, tlsConf, quicConf)
		if err != nil {
			c.dialErr = fmt.Errorf("masque: dialing QUIC connection failed: %w", err)
			return
		}
		c.conn = conn
		tr := &http3.Transport{EnableDatagrams: quicConf.EnableDatagrams}
		c.clientConn = tr.NewClientConn(conn)
	})
	if c.dialErr != nil {
		return nil, nil, nil, nil, c.dialErr
	}
	select {
	case <-ctx.Done():
		return nil, nil, nil, nil, context.Cause(ctx)
	case <-c.clientConn.Context().Done():
		return nil, nil, nil, nil, context.Cause(c.clientConn.Context())
	case <-c.clientConn.ReceivedSettings():
	}
	settings := c.clientConn.Settings()
	if !settings.EnableExtendedConnect {
		return nil, nil, nil, nil, errors.New("masque: server didn't enable Extended CONNECT")
	}

	rstr, err := c.clientConn.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("masque: failed to open request stream: %w", err)
	}
	if err := rstr.SendRequestHeader(req); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("masque: failed to send request: %w", err)
	}
	// TODO: optimistically return the connection
	rsp, err := rstr.ReadResponse()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("masque: failed to read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, nil, rsp, nil, fmt.Errorf("masque: server responded with %d", rsp.StatusCode)
	}

	raddr = updateRemoteAddr(raddr, rsp, tcp)
	return rstr, c.clientConn, rsp, raddr, nil
}

func updateRemoteAddr(raddr net.Addr, rsp *http.Response, tcp bool) net.Addr {
	if !isNativeAddr(raddr, tcp) {
		if nativeAddr := nextHopAddr(rsp, tcp); nativeAddr != nil {
			return nativeAddr
		}
	}
	return raddr
}

func isNativeAddr(addr net.Addr, tcp bool) bool {
	nativeAddr := false
	if tcp {
		_, nativeAddr = addr.(*net.TCPAddr)
	} else {
		_, nativeAddr = addr.(*net.UDPAddr)
	}
	return nativeAddr
}

// Extract the Proxy-Status next-hop value as a UDPAddr or TCPAddr.
func nextHopAddr(rsp *http.Response, tcp bool) net.Addr {
	proxyStatusVals := rsp.Header.Values("Proxy-Status")
	if len(proxyStatusVals) == 0 {
		return nil
	}
	proxyStatus, err := httpsfv.UnmarshalItem(proxyStatusVals)
	if err != nil {
		log.Printf("bad Proxy-Status: %v", err)
		return nil
	}
	nextHop, ok := proxyStatus.Params.Get("next-hop")
	if !ok {
		return nil
	}
	nextHopStr, ok := nextHop.(string)
	if !ok {
		log.Printf("non-string nextHop value")
		return nil
	}
	if nextHopStr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(nextHopStr)
	if err != nil {
		log.Printf("bad next-hop value: %v", err)
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	network := "udp"
	if tcp {
		network = "tcp"
	}
	portNum, err := net.LookupPort(network, port)
	if err != nil {
		log.Printf("bad port: %v", err)
		return nil
	}
	if tcp {
		return &net.TCPAddr{IP: ip, Port: portNum}
	}
	return &net.UDPAddr{IP: ip, Port: portNum}
}

// Close closes the connection to the proxy.
// This immediately shuts down all proxied flows.
func (c *H3Client) Close() error {
	c.dialOnce.Do(func() {}) // wait for existing calls to finish
	if c.conn != nil {
		return c.conn.CloseWithError(0, "")
	}
	return nil
}

// H1Client establishes proxied UDP connections to remote hosts, using HTTP/1.1.
type H1Client struct {
	TLSClientConfig *tls.Config
}

func (c *H1Client) Connect(ctx context.Context, expandedTemplate string, raddr net.Addr) (net.PacketConn, *http.Response, error) {
	httpConn, rsp, raddr, err := c.openRequest(ctx, expandedTemplate, raddr, false)
	if err != nil {
		return nil, rsp, err
	}
	laddr := masqueAddr{httpConn.LocalAddr().String()}
	conn := ProxiedPacketConn(nil, httpConn, httpConn, laddr, raddr)
	return conn, rsp, nil
}

func (c *H1Client) ConnectTCP(ctx context.Context, expandedTemplate string, raddr net.Addr) (net.Conn, *http.Response, error) {
	httpConn, rsp, raddr, err := c.openRequest(ctx, expandedTemplate, raddr, true)
	if err != nil {
		return nil, rsp, err
	}
	laddr := masqueAddr{httpConn.LocalAddr().String()}
	conn := ProxiedTCPConn(httpConn, httpConn, laddr, raddr)
	return conn, rsp, nil
}

func (c *H1Client) openRequest(ctx context.Context, expandedTemplate string, raddr net.Addr, tcp bool) (net.Conn, *http.Response, net.Addr, error) {
	u, err := url.Parse(expandedTemplate)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("masque: failed to parse URI: %w", err)
	}
	var httpConn net.Conn

	authority := u.Host

	switch u.Scheme {
	case "http":
		if u.Port() == "" {
			authority = authority + ":80"
		}
		dialer := &net.Dialer{}
		httpConn, err = dialer.DialContext(ctx, "tcp", authority)

	case "https":
		if u.Port() == "" {
			authority = authority + ":443"
		}
		tlsDialer := &tls.Dialer{
			Config: c.TLSClientConfig,
		}

		httpConn, err = tlsDialer.DialContext(ctx, "tcp", authority)
	default:
		return nil, nil, nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}

	if err != nil {
		return nil, nil, nil, err
	}

	protocol := ConnectUDP
	if tcp {
		protocol = ConnectTCP
	}

	request := &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Header: http.Header{
			"Connection":                {"Upgrade"},
			"Upgrade":                   {protocol},
			http3.CapsuleProtocolHeader: {capsuleProtocolHeaderValue},
		},
	}
	if err := request.Write(httpConn); err != nil {
		return nil, nil, nil, err
	}

	rsp, err := http.ReadResponse(bufio.NewReader(httpConn), request)
	if err != nil {
		return nil, nil, nil, err
	}

	if rsp.StatusCode != http.StatusSwitchingProtocols {
		return nil, rsp, nil, fmt.Errorf("masque: server responded with %d", rsp.StatusCode)
	}

	raddr = updateRemoteAddr(raddr, rsp, tcp)
	return httpConn, rsp, raddr, nil
}

func (c *H1Client) Close() error {
	log.Printf("H1Client.Close is a no-op")
	return nil
}
