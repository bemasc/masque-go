package masque_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestUDPToCapsule(t *testing.T) {
	payload := []byte("upstream")
	expectedHeader := []byte{ /* DATAGRAM capsule type */ 0x00 /* varint length */, 8}
	expected := append(expectedHeader, payload...)
	t.Run("simple", func(t *testing.T) { testUDPToCapsule(t, payload, expected) })

	payload = nil
	expected = []byte{ /* DATAGRAM capsule type */ 0x00 /* varint length */, 0}
	t.Run("empty payload", func(t *testing.T) { testUDPToCapsule(t, payload, expected) })

	payload = make([]byte, 1500)
	expected = append([]byte{ /* DATAGRAM capsule type */ 0x00 /* varint length */, 0x45, 0xdc}, payload...)
	t.Run("max size payload", func(t *testing.T) { testUDPToCapsule(t, payload, expected) })

	payload = make([]byte, 1501)
	expected = []byte{}
	t.Run("oversize payload (1501)", func(t *testing.T) { testUDPToCapsule(t, payload, expected) })

	payload = make([]byte, 1502)
	expected = []byte{}
	t.Run("oversize payload (1502)", func(t *testing.T) { testUDPToCapsule(t, payload, expected) })
}

func testUDPToCapsule(t *testing.T, payload, expected []byte) {
	rspReader, rspWriter := io.Pipe()
	reqReader, reqWriter := io.Pipe()

	conn := masque.ProxiedPacketConn(nil, reqWriter, rspReader, nil, nil)

	go func() {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}
		_, err := conn.WriteTo(payload, addr)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
		require.NoError(t, rspWriter.Close())
	}()

	received, err := io.ReadAll(reqReader)
	require.NoError(t, err)
	require.Equal(t, expected, received)
}

func TestUDPToDatagram(t *testing.T) {
	header := [1]byte{0x00} // UDP Context ID

	payload := []byte("upstream")
	expected := append(header[:], payload...)
	t.Run("simple", func(t *testing.T) { testUDPToDatagram(t, payload, expected) })

	payload = nil
	expected = header[:]
	t.Run("empty payload", func(t *testing.T) { testUDPToDatagram(t, payload, expected) })

	payload = make([]byte, 1500)
	expected = append(header[:], payload...)
	t.Run("max size payload", func(t *testing.T) { testUDPToDatagram(t, payload, expected) })
}

func testUDPToDatagram(t *testing.T, payload, expected []byte) {
	// Create a fake httpStreamer implementation
	fakeStream := &fakeH3Stream{
		datagramsSent: make(chan []byte),
	}

	unusedReader, unusedWriter := io.Pipe()

	conn := masque.ProxiedPacketConn(fakeStream, unusedWriter, unusedReader, nil, nil)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}

	// Write upstream data
	_, err := conn.WriteTo(payload, addr)
	require.NoError(t, err)

	// Check that upstream datagram was sent correctly
	datagram := <-fakeStream.datagramsSent
	require.Equal(t, expected, datagram)

	// Clean up
	err = conn.Close()
	require.NoError(t, err)
}

// fakeH3Stream implements DatagramSendReceiver for testing
type fakeH3Stream struct {
	datagramsSent      chan []byte
	datagramsToReceive [][]byte
}

func (f *fakeH3Stream) SendDatagram(b []byte) error {
	f.datagramsSent <- b
	return nil
}

func (f *fakeH3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if len(f.datagramsToReceive) == 0 {
		return nil, io.EOF
	}
	datagram := f.datagramsToReceive[0]
	f.datagramsToReceive = f.datagramsToReceive[1:]
	return datagram, nil
}

func (f *fakeH3Stream) Close() error {
	close(f.datagramsSent)
	return nil
}

func (f *fakeH3Stream) CancelRead(code quic.StreamErrorCode) {}

func TestCapsulesToUDP(t *testing.T) {
	stream := []byte{
		// DATAGRAM capsule type varint (0x00)
		0x00,
		// Payload length varint (8)
		10,
		// Payload ("upstream")
		'd', 'o', 'w', 'n', 's', 't', 'r', 'e', 'a', 'm',
	}
	expected := [][]byte{[]byte("downstream")}
	t.Run("simple", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = []byte{0x00, 0}
	expected = [][]byte{{}}
	t.Run("empty payload", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = []byte{0x00, 0, 0x00, 0, 0x00, 0}
	expected = [][]byte{{}, {}, {}}
	t.Run("empty payload x3", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = []byte{0x00, 1, 1, 0x00, 1, 2, 0x00, 1, 3}
	expected = [][]byte{{1}, {2}, {3}}
	t.Run("received in order", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = append([]byte{0x00, 0x45, 0xdc}, make([]byte, 1500)...)
	expected = [][]byte{make([]byte, 1500)}
	t.Run("max payload", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = append([]byte{0x00, 0x45, 0xdd}, make([]byte, 1501)...)
	expected = [][]byte{} // Dropped
	t.Run("oversize payload (1501)", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = append([]byte{0x00, 0x45, 0xdd}, make([]byte, 1502)...)
	expected = [][]byte{} // Dropped
	t.Run("oversize payload (1502)", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = []byte{
		// DATAGRAM capsule type varint (0x00)
		0x00,
		// Payload length varint (2^62-1)
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		// 7 bytes of actual payload
		'p', 'a', 'y', 'l', 'o', 'a', 'd'}
	expected = [][]byte{}
	// Test that we aren't pre-allocating a buffer of size 2^62-1.
	t.Run("max-size payload (truncated)", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })
}

func testCapsulesToUDP(t *testing.T, stream []byte, expected [][]byte) {
	rspReader, rspWriter := io.Pipe()
	_, reqWriter := io.Pipe()

	conn := masque.ProxiedPacketConn(nil, reqWriter, rspReader, nil, nil)

	go func() {
		_, err := rspWriter.Write(stream)
		require.NoError(t, err)
		require.NoError(t, rspWriter.Close())
	}()

	for _, payload := range expected {
		buf := make([]byte, len(payload)+1)
		n, _, err := conn.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, payload, buf[:n])
	}

	n, _, err := conn.ReadFrom(make([]byte, 1))
	require.Equal(t, io.EOF, err)
	require.Equal(t, 0, n)

	err = conn.Close()
	require.NoError(t, err)
}

func TestDatagramToUDP(t *testing.T) {
	datagram := []byte{
		// DATAGRAM context ID varint (0x00)
		0x00,
		// Payload ("upstream")
		'd', 'o', 'w', 'n', 's', 't', 'r', 'e', 'a', 'm',
	}
	expected := []byte("downstream")
	t.Run("simple", func(t *testing.T) { testDatagramToUDP(t, datagram, expected) })

	datagram = []byte{0x00}
	expected = []byte{}
	t.Run("empty payload", func(t *testing.T) { testDatagramToUDP(t, datagram, expected) })

	datagram = append([]byte{0x00}, make([]byte, 1500)...)
	expected = make([]byte, 1500)
	t.Run("max payload", func(t *testing.T) { testDatagramToUDP(t, datagram, expected) })
}

func testDatagramToUDP(t *testing.T, datagram, expected []byte) {
	// Create a fake httpStreamer implementation
	fakeStream := &fakeH3Stream{
		datagramsSent:      make(chan []byte),
		datagramsToReceive: [][]byte{datagram},
	}

	unusedReader, unusedWriter := io.Pipe()
	conn := masque.ProxiedPacketConn(fakeStream, unusedWriter, unusedReader, nil, nil)

	// Check that the datagram was converted to UDP correctly
	buf := make([]byte, 10*1024)
	n, _, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, expected, buf[:n])

	// Clean up
	err = conn.Close()
	require.NoError(t, err)
}

func TestOversizeDatagramIsDropped(t *testing.T) {
	oversizeDatagram := append([]byte{0x00}, make([]byte, 1501)...)
	// Create a fake httpStreamer implementation
	fakeStream := &fakeH3Stream{
		datagramsSent:      make(chan []byte),
		datagramsToReceive: [][]byte{oversizeDatagram},
	}

	unusedReader, unusedWriter := io.Pipe()
	conn := masque.ProxiedPacketConn(fakeStream, unusedWriter, unusedReader, nil, nil)

	conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))

	// Check that no UDP packets are emitted.
	buf := make([]byte, 10*1024)
	n, _, err := conn.ReadFrom(buf)
	require.Error(t, err)
	require.Equal(t, 0, n)

	require.NoError(t, conn.Close())
}

func TestOversizePacketIsDroppedInDatagramMode(t *testing.T) {
	payload := make([]byte, 1501)

	// Create a fake httpStreamer implementation
	fakeStream := &fakeH3Stream{
		datagramsSent: make(chan []byte),
	}

	unusedReader, unusedWriter := io.Pipe()
	conn := masque.ProxiedPacketConn(fakeStream, unusedWriter, unusedReader, nil, nil)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}

	go func() {
		// Write oversized packet
		_, err := conn.WriteTo(payload, addr)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	}()

	// Check that the datagram channel was closed without sending any
	// datagrams
	_, open := <-fakeStream.datagramsSent
	require.False(t, open)
}

// ProxiedPacketConn has special logic for when the read buffer is smaller
// than the MTU, and implicitly also when the read buffer is smaller than
// the received packet payload.  This test checks both of those cases.
func TestShortReadBuffers(t *testing.T) {
	datagram := []byte{
		// DATAGRAM context ID varint (0x00)
		0x00,
		// Payload ("upstream")
		'd', 'o', 'w', 'n', 's', 't', 'r', 'e', 'a', 'm',
	}
	expected := []byte("downstream")

	// Create a fake httpStreamer implementation
	fakeStream := &fakeH3Stream{
		datagramsSent:      make(chan []byte),
		datagramsToReceive: [][]byte{datagram, datagram},
	}

	unusedReader, unusedWriter := io.Pipe()
	conn := masque.ProxiedPacketConn(fakeStream, unusedWriter, unusedReader, nil, nil)

	// Try a read using a short buffer of exactly the right length.
	// Applications that use fixed-size UDP packets might do this.
	shortBuf := make([]byte, 10)
	n, _, err := conn.ReadFrom(shortBuf)
	require.NoError(t, err)
	require.Equal(t, expected, shortBuf[:n])

	// Try a read using a buffer that is too short.  The data should be
	// truncated.
	veryShortBuf := make([]byte, 4)
	n, _, err = conn.ReadFrom(veryShortBuf)
	require.NoError(t, err)
	require.Equal(t, expected[:4], veryShortBuf[:n])

	// Remote side closed the incoming HTTP stream.
	unusedWriter.Close()

	// Confirm that the remainder of the datagram is not returned by
	// a subsequent read call.
	bigBuf := make([]byte, 10*1024)
	n, _, err = conn.ReadFrom(bigBuf)
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, io.EOF)

	t.Logf("bemasc 2")

	// Clean up
	err = conn.Close()
	require.NoError(t, err)

}

// Connects two proxied UDP connections back-to-back using capsules,
// and confirms that packets flow through and are reconstructed correctly.
func TestUDPConnectionTandem(t *testing.T) {
	conn1, conn2 := setupTandemUDPCapsules()
	t.Run("forward", func(t *testing.T) { testTandemPacketConns(t, conn1, conn2) })
	conn1, conn2 = setupTandemUDPCapsules()
	t.Run("reverse", func(t *testing.T) { testTandemPacketConns(t, conn2, conn1) })
}

func testTandemPacketConns(t *testing.T, conn1, conn2 net.PacketConn) {
	input := []byte{1, 2, 3, 4, 5}

	go func() {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}
		_, err := conn1.WriteTo(input, addr)
		require.NoError(t, err)
	}()

	buf := make([]byte, 1024)
	n, _, err := conn2.ReadFrom(buf)
	require.NoError(t, err)
	output := buf[:n]
	require.Equal(t, input, output)

	conn1.Close()
	conn2.Close()
}

func setupTandemUDPCapsules() (net.PacketConn, net.PacketConn) {
	rspReader, rspWriter := io.Pipe()
	reqReader, reqWriter := io.Pipe()

	conn1 := masque.ProxiedPacketConn(nil, reqWriter, rspReader, nil, nil)
	conn2 := masque.ProxiedPacketConn(nil, rspWriter, reqReader, nil, nil)

	return conn1, conn2
}

func TestTCPCapsules(t *testing.T) {
	rspReader, rspWriter := io.Pipe()
	reqReader, reqWriter := io.Pipe()

	conn := masque.ProxiedTCPConn(reqWriter, rspReader, nil, nil)

	go func() {
		_, err := conn.Write([]byte("upstream"))
		require.NoError(t, err)
		err = conn.CloseWrite()
		require.NoError(t, err)
	}()

	go func() {
		downstream := []byte{
			// FINAL_DATA capsule type varint
			0xa0, 0x28, 0xd7, 0xf1,
			// Payload length varint (10)
			10,
			// Payload ("downstream")
			'd', 'o', 'w', 'n', 's', 't', 'r', 'e', 'a', 'm',
		}

		_, err := rspWriter.Write(downstream)
		require.NoError(t, err)
		err = rspWriter.Close()
		require.NoError(t, err)
	}()

	expectedUpstream := []byte{
		// DATA capsule type varint
		0xa0, 0x28, 0xd7, 0xf0,
		// Payload length varint (8)
		8,
		// Payload ("upstream")
		'u', 'p', 's', 't', 'r', 'e', 'a', 'm',
		// FINAL_DATA capsule type varint
		0xa0, 0x28, 0xd7, 0xf1,
		// Payload length varint (0)
		0,
	}

	receivedUpstream := make([]byte, len(expectedUpstream))
	_, err := io.ReadFull(reqReader, receivedUpstream)
	require.NoError(t, err)
	require.Equal(t, expectedUpstream, receivedUpstream)

	receivedDownstream, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, []byte("downstream"), receivedDownstream)

	postCloseUpstream, err := io.ReadAll(reqReader)
	require.Empty(t, postCloseUpstream)
	require.NoError(t, err)
}

func TestTCPDataCapsuleWithoutFinal(t *testing.T) {
	rspReader, rspWriter := io.Pipe()
	reqReader, reqWriter := io.Pipe()

	conn := masque.ProxiedTCPConn(reqWriter, rspReader, nil, nil)

	go func() {
		downstream := []byte{
			// DATA capsule type varint
			0xa0, 0x28, 0xd7, 0xf0,
			// Payload length varint (10)
			10,
			// Payload ("downstream")
			'd', 'o', 'w', 'n', 's', 't', 'r', 'e', 'a', 'm',
		}

		_, err := rspWriter.Write(downstream)
		require.NoError(t, err)
		err = rspWriter.Close()
		require.NoError(t, err)
	}()

	receivedDownstream := make([]byte, 10)
	n, err := io.ReadFull(conn, receivedDownstream)
	require.NoError(t, err)
	require.Equal(t, 10, n)
	require.Equal(t, []byte("downstream"), receivedDownstream)

	// Verify that the next read returns an error (connection closed without FINAL_DATA)
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	require.ErrorContains(t, err, "reset")

	conn.Close()
	reqReader.Close()
}

func setupTandemTCP() (masque.TCPConn, masque.TCPConn) {
	rspReader, rspWriter := io.Pipe()
	reqReader, reqWriter := io.Pipe()

	conn1 := masque.ProxiedTCPConn(reqWriter, rspReader, nil, nil)
	conn2 := masque.ProxiedTCPConn(rspWriter, reqReader, nil, nil)

	return conn1, conn2
}

func tandemTCPTest(t *testing.T, conn1, conn2 masque.TCPConn, chunks [][]byte) {
	expected := make([]byte, 0)
	go func() {
		for _, chunk := range chunks {
			expected = append(expected, chunk...)
			_, err := conn1.Write(chunk)
			require.NoError(t, err)
		}
		conn1.CloseWrite()
	}()

	output, err := io.ReadAll(conn2)
	require.NoError(t, err)
	require.Equal(t, expected, output)
	conn2.Close()
}

// Connects two proxied TCP connections back-to-back, and confirms that
// data flows through and is reconstructed correctly.
func TestTCPConnectionTandem(t *testing.T) {
	conn1, conn2 := setupTandemTCP()
	t.Run("forward", func(t *testing.T) { tandemTCPTest(t, conn1, conn2, [][]byte{{1, 2, 3, 4, 5}}) })

	conn1, conn2 = setupTandemTCP()
	t.Run("reverse", func(t *testing.T) { tandemTCPTest(t, conn2, conn1, [][]byte{{1, 2, 3, 4, 5}}) })

	conn1, conn2 = setupTandemTCP()
	t.Run("a few tiny writes", func(t *testing.T) { tandemTCPTest(t, conn1, conn2, [][]byte{{1}, {2, 3}, {4, 5}}) })

	const bigN = 100_000 // Bigger than masque.maxTCPChunkSize
	largePayload := make([]byte, bigN)
	for i := range largePayload {
		largePayload[i] = byte(i)
	}

	conn1, conn2 = setupTandemTCP()
	t.Run("one large write", func(t *testing.T) { tandemTCPTest(t, conn2, conn1, [][]byte{largePayload}) })

	tinyWrites := make([][]byte, len(largePayload))
	for i := range tinyWrites {
		tinyWrites[i] = largePayload[i : i+1]
	}
	conn1, conn2 = setupTandemTCP()
	t.Run("a lot of tiny writes", func(t *testing.T) { tandemTCPTest(t, conn2, conn1, tinyWrites) })

	conn1, conn2 = setupTandemTCP()
	t.Run("empty write", func(t *testing.T) { tandemTCPTest(t, conn1, conn2, [][]byte{{}}) })

	conn1, conn2 = setupTandemTCP()
	t.Run("no write", func(t *testing.T) { tandemTCPTest(t, conn1, conn2, nil) })
}

func FuzzTCPConnectionTandem(f *testing.F) {
	// Verify that tandem connect-tcp is equivalent to a byte pipe.
	f.Fuzz(func(t *testing.T, input []byte) {
		// Convert `input` into a sequence of chunks.
		// This "decoding" is a surjection onto all possible chunk sequences,
		// including sequences that may contain empty chunks.
		var chunks [][]byte
		for len(input) > 0 {
			n, L, err := quicvarint.Parse(input)
			if err != nil {
				input = input[1:]
				continue // Peel off one byte and try again
			}
			input = input[L:]
			if n > uint64(len(input)) {
				n = uint64(len(input))
			}
			t.Logf("Chunk %d has size %d", len(chunks), n)
			chunks = append(chunks, input[:n])
			input = input[n:]
		}

		conn1, conn2 := setupTandemTCP()
		tandemTCPTest(t, conn1, conn2, chunks)
	})
}
