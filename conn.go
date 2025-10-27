package masque

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type masqueAddr struct{ string }

func (m masqueAddr) Network() string { return "connect-udp" }
func (m masqueAddr) String() string  { return m.string }

var _ net.Addr = masqueAddr{}

// Avoid allocating a buffer for each packet.
var udpBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, maxUDPPayloadSize)
		return &buf
	},
}

// packetConnWrapper converts a [net.Conn] from [net.Pipe]
// into a [net.PacketConn] that can only be used for a single
// destination.  The pipe is presumed to carry writes of
// at most [maxUDPPayloadSize] bytes.
type packetConnWrapper struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (p packetConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.Read(b)
	return n, p.RemoteAddr(), err
}

func (p packetConnWrapper) LocalAddr() net.Addr {
	return p.localAddr
}

func (p packetConnWrapper) RemoteAddr() net.Addr {
	return p.remoteAddr
}

func (p packetConnWrapper) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.Write(b)
}

func (p packetConnWrapper) Read(b []byte) (int, error) {
	if len(b) >= maxUDPPayloadSize {
		return p.Conn.Read(b)
	}
	// Ensure UDP-style truncation behavior when len(b) < maxUDPPayloadSize.
	// Otherwise, large payloads would be fragmented instead of truncated.
	buf := udpBufPool.Get().(*[]byte)
	n, err := p.Conn.Read(*buf)
	n = copy(b, (*buf)[:n])
	udpBufPool.Put(buf)
	return n, err
}

func (p packetConnWrapper) Write(b []byte) (int, error) {
	if len(b) > maxUDPPayloadSize {
		// net.Conn may fragment large writes instead of dropping them.
		log.Printf("Dropping oversize UDP write")
		return len(b), nil
	}
	return p.Conn.Write(b)
}

// ProxiedPacketConn converts an HTTP request and response stream, speaking
// connect-udp, into a synthetic [net.PacketConn] of UDP packets.
//
// `str` is optional, and indicates datagram support if non-nil.
//
// When the PacketConn is closed, the request and response streams will be closed.
func ProxiedPacketConn(str DatagramSendReceiver, req io.WriteCloser, rsp io.ReadCloser, laddr, raddr net.Addr) net.PacketConn {
	left, right := net.Pipe()

	go func() {
		forwardUDP(str, req, rsp, right)
		req.Close()
		if str != nil {
			str.Close()
			str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		}
	}()
	return packetConnWrapper{Conn: left, localAddr: laddr, remoteAddr: raddr}
}

// TCPConn extends net.Conn to provide half-close functionality.
type TCPConn interface {
	net.Conn
	TCPStream
	Lingerer
}

// tcpConnWrapper is an implementation detail of tcpPipe().
// It provides a half-closeable synthetic net.Conn
// by combining two net.Conn's: one for reading and
// the other for writing.
type tcpConnWrapper struct {
	r, w                  net.Conn
	localAddr, remoteAddr net.Addr

	// For SetLinger implementation
	other      *tcpConnWrapper
	lingerZero atomic.Bool
}

var errSimulatedReset error = errors.New("connection reset by peer (simulated)")

var _ TCPConn = &tcpConnWrapper{}

func (t *tcpConnWrapper) Read(b []byte) (int, error) {
	n, err := t.r.Read(b)
	if errors.Is(err, io.EOF) && t.other.lingerZero.Load() {
		// When the remote peer has linger equal to zero,
		// FIN is converted to RST.
		return n, &net.OpError{
			Op:     "read",
			Net:    "tcp",
			Source: t.localAddr,
			Addr:   t.remoteAddr,
			Err:    errSimulatedReset,
		}
	}
	return n, err
}

func (t *tcpConnWrapper) Write(b []byte) (int, error) {
	return t.w.Write(b)
}

func (t *tcpConnWrapper) SetReadDeadline(deadline time.Time) error {
	return t.r.SetReadDeadline(deadline)
}

func (t *tcpConnWrapper) SetWriteDeadline(deadline time.Time) error {
	return t.w.SetWriteDeadline(deadline)
}

func (t *tcpConnWrapper) SetDeadline(deadline time.Time) error {
	return errors.Join(
		t.SetReadDeadline(deadline),
		t.SetWriteDeadline(deadline))
}

func (t *tcpConnWrapper) Close() error {
	return errors.Join(t.CloseWrite(), t.CloseRead())
}

func (t *tcpConnWrapper) LocalAddr() net.Addr {
	return t.localAddr
}

func (t *tcpConnWrapper) RemoteAddr() net.Addr {
	return t.remoteAddr
}

func (t *tcpConnWrapper) CloseRead() error {
	return t.r.Close()
}

func (t *tcpConnWrapper) CloseWrite() error {
	return t.w.Close()
}

func (t *tcpConnWrapper) SetLinger(sec int) error {
	// Linger zero is the only value that must change the
	// behavior of the TCPConn, according to the golang docs.
	t.lingerZero.Store(sec == 0)
	return nil
}

// tcpPipe() is equivalent to net.Pipe(), but with support for
// half-close behaviors.
func tcpPipe(laddr, raddr net.Addr) (TCPConn, TCPConn) {
	leftDown, rightDown := net.Pipe()
	leftUp, rightUp := net.Pipe()

	left := &tcpConnWrapper{r: leftDown, w: leftUp, localAddr: raddr, remoteAddr: laddr}
	right := &tcpConnWrapper{r: rightUp, w: rightDown, localAddr: laddr, remoteAddr: raddr}
	left.other, right.other = right, left
	return left, right
}

// ProxiedTCPConn converts an HTTP request and response stream, speaking
// connect-tcp, into a synthetic TCPConn.
func ProxiedTCPConn(reqStream io.WriteCloser, rspStream io.Reader, laddr, raddr net.Addr) TCPConn {
	left, right := tcpPipe(laddr, raddr)
	go func() {
		forwardTCP(reqStream, rspStream, right)
		reqStream.Close()
	}()
	return left
}
