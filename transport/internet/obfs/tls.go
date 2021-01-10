package obfs

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"io/ioutil"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

const (
	chunkSize = 1 << 14 // 2 ** 14 == 16 * 1024
)

type obfsTLSConn struct {
	net.Conn
	sync.Mutex
	isServer   bool
	host       string
	rbuf       *buf.MultiBufferContainer
	wbuf       *buf.MultiBufferContainer
	handshaked chan struct{}
}

func (c *obfsTLSConn) Handshaked() bool {
	select {
	case <-c.handshaked:
		return true
	default:
		return false
	}
}

func (c *obfsTLSConn) Handshake(b []byte) (err error) {
	if c.isServer {
		err = c.serverHandshake()
	} else {
		err = c.clientHandshake(b)
	}

	if err != nil {
		return
	}

	close(c.handshaked)
	return
}

func (c *obfsTLSConn) clientHandshake(payload []byte) (err error) {
	mbContainer := &buf.MultiBufferContainer{}
	defer mbContainer.Close()

	random := make([]byte, 28)
	sessionID := make([]byte, 32)
	rand.Read(random)
	rand.Read(sessionID)

	// handshake, TLS 1.0 version, length
	mbContainer.Write([]byte{22})
	mbContainer.Write([]byte{0x03, 0x01})
	length := uint16(212 + len(payload) + len(c.host))
	mbContainer.Write([]byte{byte(length >> 8)})
	mbContainer.Write([]byte{byte(length & 0xff)})

	// clientHello, length, TLS 1.2 version
	mbContainer.Write([]byte{1})
	mbContainer.Write([]byte{0})
	binary.Write(mbContainer, binary.BigEndian, uint16(208+len(payload)+len(c.host)))
	mbContainer.Write([]byte{0x03, 0x03})

	// random with timestamp, sid len, sid
	binary.Write(mbContainer, binary.BigEndian, uint32(time.Now().Unix()))
	mbContainer.Write(random)
	mbContainer.Write([]byte{32})
	mbContainer.Write(sessionID)

	// cipher suites
	mbContainer.Write([]byte{0x00, 0x38})
	mbContainer.Write([]byte{
		0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
		0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
		0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
		0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
	})

	// compression
	mbContainer.Write([]byte{0x01, 0x00})

	// extension length
	binary.Write(mbContainer, binary.BigEndian, uint16(79+len(payload)+len(c.host)))

	// session ticket
	mbContainer.Write([]byte{0x00, 0x23})
	binary.Write(mbContainer, binary.BigEndian, uint16(len(payload)))
	mbContainer.Write(payload)

	// server name
	mbContainer.Write([]byte{0x00, 0x00})
	binary.Write(mbContainer, binary.BigEndian, uint16(len(c.host)+5))
	binary.Write(mbContainer, binary.BigEndian, uint16(len(c.host)+3))
	mbContainer.Write([]byte{0})
	binary.Write(mbContainer, binary.BigEndian, uint16(len(c.host)))
	mbContainer.Write([]byte(c.host))

	// ec_point
	mbContainer.Write([]byte{0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02})

	// groups
	mbContainer.Write([]byte{0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18})

	// signature
	mbContainer.Write([]byte{
		0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05,
		0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
		0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
	})

	// encrypt then mac
	mbContainer.Write([]byte{0x00, 0x16, 0x00, 0x00})

	// extended master secret
	mbContainer.Write([]byte{0x00, 0x17, 0x00, 0x00})

	clientMsg, _ := buf.ReadAllToBytes(mbContainer)
	_, err = c.Conn.Write(clientMsg)
	return
}

func (c *obfsTLSConn) serverHandshake() (err error) {
	buffer := buf.New()
	defer buffer.Release()

	if _, err = buffer.ReadFullFrom(c.Conn, 5); err != nil {
		return
	}
	if buffer.Byte(0) != 22 { // not handshake
		return newError("Bad handshake").AtWarning()
	}

	buffer.Clear()
	if _, err = buffer.ReadFullFrom(c.Conn, 4); err != nil {
		return
	}
	if buffer.Byte(0) != 1 { // not client hello
		return newError("Bad hello").AtWarning()
	}

	length := int(buffer.Byte(1))<<16 | int(buffer.Byte(2))<<8 | int(buffer.Byte(3))
	b := make([]byte, length)
	if _, err = io.ReadFull(c.Conn, b); err != nil {
		return
	}
	tlsVer := binary.BigEndian.Uint16(b[:2])
	if tlsVer < tls.VersionTLS12 {
		return newError("bad version: only TLSv1.2 is supported")
	}

	pos := 34
	sidLen := int(b[pos]) // session id length
	sessionID := b[pos+1 : pos+sidLen]
	pos += sidLen + 1

	nlen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += nlen + 2 // skip cipher suites

	nlen = int(b[pos])
	pos += nlen + 1 // skip compression

	nlen = int(binary.BigEndian.Uint16(b[pos : pos+2])) // extensions length
	pos += 2
	end := pos + nlen
	if nlen > 0 {
		for pos < end {
			extType := int(binary.BigEndian.Uint16(b[pos : pos+2]))
			extLength := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))

			if extType == 0x23 { // session ticket
				c.rbuf.Write(b[pos+4 : pos+4+extLength])
				break
			}

			pos += 4 + extLength
		}
	}

	buffer.Clear()
	random := make([]byte, 28)
	rand.Read(random)

	// handshake, TLS 1.0 version
	buffer.WriteByte(22)
	buffer.Write([]byte{0x03, 0x01})
	binary.Write(buffer, binary.BigEndian, uint16(91)) // hello length

	buffer.WriteByte(2)              // server hello
	buffer.Write([]byte{0, 0, 87})   // payload length
	buffer.Write([]byte{0x03, 0x03}) // tls 1.2

	binary.Write(buffer, binary.BigEndian, uint32(time.Now().Unix()))
	buffer.Write(random)

	buffer.WriteByte(byte(len(sessionID)))
	buffer.Write(sessionID)

	binary.Write(buffer, binary.BigEndian, uint16(0xcca8)) // cipher suite
	buffer.WriteByte(0)                                    // compression

	buffer.Write([]byte{0, 15}) // extensions length
	// RenegotiationInfoExtension
	binary.Write(buffer, binary.BigEndian, uint16(0xff01))
	buffer.Write([]byte{0, 0})
	// ExtendedMasterSecretExtension
	binary.Write(buffer, binary.BigEndian, uint16(0x17))
	buffer.Write([]byte{0, 1, 0})
	// ECPointFormatsExtension
	binary.Write(buffer, binary.BigEndian, uint16(0x0b))
	buffer.Write([]byte{0, 0x02})
	buffer.Write([]byte{0x01, 0x00})

	buffer.WriteByte(20)             // ChangeCipherSpec
	buffer.Write([]byte{0x03, 0x03}) // tls1.2
	buffer.Write([]byte{0x00, 0x01}) // length
	buffer.WriteByte(0x01)

	_, err = c.wbuf.Write(buffer.Bytes())
	return
}

func (c *obfsTLSConn) Read(b []byte) (n int, err error) {
	<-c.handshaked

	if c.rbuf.Len() > 0 {
		return c.rbuf.Read(b)
	}

	var header [5]byte
	if _, err = io.ReadFull(c.Conn, header[:1]); err != nil {
		return
	}

	if header[0] == 22 { // got handshake from server
		// skip all server hello data
		if _, err = io.CopyN(ioutil.Discard, c.Conn, 101); err != nil {
			return
		}

		if _, err = io.ReadFull(c.Conn, header[:]); err != nil {
			return
		}
	}

	if header[0] != 23 {
		return 0, newError("Non-App data received").AtWarning()
	}

	remain := int(header[3])<<8 | int(header[4])
	nlen := len(b)
	if remain <= nlen {
		return io.ReadFull(c.Conn, b[:remain])
	}

	if n, err = io.ReadFull(c.Conn, b[:]); err != nil {
		return
	}

	remain -= nlen
	mb := buf.MultiBuffer{}
	for remain > 0 {
		bLen := buf.Size
		if remain < bLen {
			bLen = remain
		}

		buffer := buf.New()
		mb = append(mb, buffer)
		nn, err := buffer.ReadFullFrom(c.Conn, int32(bLen))
		if err != nil {
			buf.ReleaseMulti(mb)
			return n, err
		}

		remain -= int(nn)
	}

	err = c.rbuf.WriteMultiBuffer(mb)
	return
}

func (c *obfsTLSConn) Write(b []byte) (n int, err error) {
	length := len(b)

	if !c.isServer && !c.Handshaked() {
		c.Lock()
		if !c.Handshaked() {
			err = c.Handshake(b)
			c.Unlock()
			if err != nil {
				return 0, err
			}

			return length, nil
		}
		c.Unlock()
	}

	if c.wbuf.Len() > 0 {
		c.wbuf.Write([]byte{23, 0x03, 0x03}) // type + version
		binary.Write(c.wbuf, binary.BigEndian, uint16(len(b)))
		c.wbuf.Write(b)
		buffer, _ := buf.ReadAllToBytes(c.wbuf)
		_, err = c.Conn.Write(buffer)
		if err != nil {
			return
		}

		return length, nil
	}

	for i := 0; i < length; i += chunkSize {
		end := i + chunkSize
		if end > length {
			end = length
		}

		data := b[i:end]
		nn := len(data)
		c.wbuf.Write([]byte{23, 0x03, 0x03}) // type + version
		binary.Write(c.wbuf, binary.BigEndian, uint16(nn))
		c.wbuf.Write(data)
		buffer, _ := buf.ReadAllToBytes(c.wbuf)
		if _, err = c.Conn.Write(buffer); err != nil {
			return
		}

		n += nn
	}

	return
}

// clientObfsTLSConn creates a connection for obfs-tls client.
func clientObfsTLSConn(conn net.Conn, host string) *obfsTLSConn {
	return &obfsTLSConn{
		Conn:       conn,
		host:       host,
		handshaked: make(chan struct{}),
		rbuf:       &buf.MultiBufferContainer{},
		wbuf:       &buf.MultiBufferContainer{},
	}
}

// serverObfsTLSConn creates a connection for obfs-tls server.
func serverObfsTLSConn(conn net.Conn, host string) *obfsTLSConn {
	return &obfsTLSConn{
		Conn:       conn,
		isServer:   true,
		host:       host,
		handshaked: make(chan struct{}),
		rbuf:       &buf.MultiBufferContainer{},
		wbuf:       &buf.MultiBufferContainer{},
	}
}
