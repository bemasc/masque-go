package masque_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"testing"

	"github.com/quic-go/masque-go"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func runTCPEchoServer(t *testing.T, addr *net.TCPAddr) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp", addr)
	require.NoError(t, err)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(conn, conn)
				conn.Close()
			}()
		}
	}()
	return listener
}

func TestTCPProxy(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) { testTCPProxyToIP(t, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}) })
	t.Run("IPv6", func(t *testing.T) { testTCPProxyToIP(t, &net.TCPAddr{IP: net.IPv6loopback, Port: 0}) })
}

func testTCPProxyToIP(t *testing.T, addr *net.TCPAddr) {
	echoServer := runTCPEchoServer(t, addr)
	defer echoServer.Close()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer conn.Close()
	t.Logf("server listening on %s", conn.LocalAddr())
	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", conn.LocalAddr().(*net.UDPAddr).Port))

	mux := http.NewServeMux()
	server := http3.Server{
		TLSConfig:       tlsConf,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	defer server.Close()
	proxy := masque.Proxy{EnableDatagrams: true}
	defer proxy.Close()
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseRequest(r, template)
		if err != nil {
			t.Log("Upgrade failed:", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		err = proxy.Proxy(w, req)
		if err != nil {
			t.Error(err)
		}
	})
	go func() {
		if err := server.Serve(conn); err != nil {
			return
		}
	}()

	cl := masque.Client{
		Connector: &masque.H3Client{
			TLSClientConfig: tlsConfig,
			QUICConfig:      &quic.Config{EnableDatagrams: true},
		},
	}
	defer cl.Close()
	proxiedConn, _, err := cl.DialTCP(
		context.Background(),
		template,
		echoServer.Addr().(*net.TCPAddr),
	)
	require.NoError(t, err)

	_, err = proxiedConn.Write([]byte("foobar"))
	log.Printf("wrote to proxied conn")
	require.NoError(t, err)
	b := make([]byte, 1500)
	n, err := proxiedConn.Read(b)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), b[:n])

	err = proxiedConn.Close()
	require.NoError(t, err)
}
