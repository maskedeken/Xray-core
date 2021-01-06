package obfs

import (
	"crypto/rand"
	"crypto/tls"
	"io"
	"io/ioutil"
	"sync"
	"time"

	dissector "github.com/ginuerzh/tls-dissector"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

const (
	chunkSize = 1 << 14 // 2 ** 14 == 16 * 1024
)

var (
	cipherSuites = []uint16{
		0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b, 0xc02f,
		0x009e, 0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067, 0xc00a,
		0xc014, 0x0039, 0xc009, 0xc013, 0x0033, 0x009d, 0x009c, 0x003d,
		0x003c, 0x0035, 0x002f, 0x00ff,
	}

	compressionMethods = []uint8{0x00}

	algorithms = []uint16{
		0x0601, 0x0602, 0x0603, 0x0501, 0x0502, 0x0503, 0x0401, 0x0402,
		0x0403, 0x0301, 0x0302, 0x0303, 0x0201, 0x0202, 0x0203,
	}
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
	clientMsg := &dissector.ClientHelloMsg{
		Version:            tls.VersionTLS12,
		SessionID:          make([]byte, 32),
		CipherSuites:       cipherSuites,
		CompressionMethods: compressionMethods,
		Extensions: []dissector.Extension{
			&dissector.SessionTicketExtension{
				Data: payload,
			},
			&dissector.ServerNameExtension{
				Name: c.host,
			},
			&dissector.ECPointFormatsExtension{
				Formats: []uint8{0x01, 0x00, 0x02},
			},
			&dissector.SupportedGroupsExtension{
				Groups: []uint16{0x001d, 0x0017, 0x0019, 0x0018},
			},
			&dissector.SignatureAlgorithmsExtension{
				Algorithms: algorithms,
			},
			&dissector.EncryptThenMacExtension{},
			&dissector.ExtendedMasterSecretExtension{},
		},
	}
	clientMsg.Random.Time = uint32(time.Now().Unix())
	rand.Read(clientMsg.Random.Opaque[:])
	rand.Read(clientMsg.SessionID)
	b, err := clientMsg.Encode()
	if err != nil {
		return
	}

	record := &dissector.Record{
		Type:    dissector.Handshake,
		Version: tls.VersionTLS10,
		Opaque:  b,
	}
	_, err = record.WriteTo(c.Conn)
	return
}

func (c *obfsTLSConn) serverHandshake() (err error) {
	record := &dissector.Record{}
	if _, err = record.ReadFrom(c.Conn); err != nil {
		return
	}
	if record.Type != dissector.Handshake {
		return dissector.ErrBadType
	}

	clientMsg := &dissector.ClientHelloMsg{}
	if err = clientMsg.Decode(record.Opaque); err != nil {
		return
	}

	sessionID := clientMsg.SessionID
	for _, ext := range clientMsg.Extensions {
		if ext.Type() == dissector.ExtSessionTicket {
			var b []byte
			b, err = ext.Encode()
			if err != nil {
				return
			}

			c.rbuf.Write(b)
			break
		}
	}

	serverMsg := &dissector.ServerHelloMsg{
		Version:           tls.VersionTLS12,
		SessionID:         sessionID,
		CipherSuite:       0xcca8,
		CompressionMethod: 0x00,
		Extensions: []dissector.Extension{
			&dissector.RenegotiationInfoExtension{},
			&dissector.ExtendedMasterSecretExtension{},
			&dissector.ECPointFormatsExtension{
				Formats: []uint8{0x00},
			},
		},
	}

	var helloMsg []byte
	serverMsg.Random.Time = uint32(time.Now().Unix())
	rand.Read(serverMsg.Random.Opaque[:])
	helloMsg, err = serverMsg.Encode()
	if err != nil {
		return
	}

	record = &dissector.Record{
		Type:    dissector.Handshake,
		Version: tls.VersionTLS10,
		Opaque:  helloMsg,
	}

	if _, err = record.WriteTo(c.wbuf); err != nil {
		return
	}

	record = &dissector.Record{
		Type:    dissector.ChangeCipherSpec,
		Version: tls.VersionTLS12,
		Opaque:  []byte{0x01},
	}
	_, err = record.WriteTo(c.wbuf)
	return
}

func (c *obfsTLSConn) Read(b []byte) (n int, err error) {
	<-c.handshaked

	if c.rbuf.Len() > 0 {
		return c.rbuf.Read(b)
	}
	record := &dissector.Record{}
	if _, err = record.ReadFrom(c.Conn); err != nil {
		return
	}

	if record.Type == dissector.Handshake { // got handshake from server
		// type + ver + lensize + 1 = 6
		if _, err = io.CopyN(ioutil.Discard, c.Conn, 6); err != nil {
			return
		}

		if _, err = record.ReadFrom(c.Conn); err != nil {
			return
		}
	}

	n = copy(b, record.Opaque)
	_, err = c.rbuf.Write(record.Opaque[n:])
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

	record := &dissector.Record{
		Type:    dissector.AppData,
		Version: tls.VersionTLS12,
	}

	if c.wbuf.Len() > 0 {
		record.Opaque = b
		record.WriteTo(c.wbuf)
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

		record.Opaque = b[i:end]
		nn := len(record.Opaque)
		if _, err = record.WriteTo(c.Conn); err != nil {
			return
		}

		n += nn
	}

	return
}

// ClientObfsTLSConn creates a connection for obfs-tls client.
func ClientObfsTLSConn(conn net.Conn, host string) *obfsTLSConn {
	return &obfsTLSConn{
		Conn:       conn,
		host:       host,
		handshaked: make(chan struct{}),
		rbuf:       &buf.MultiBufferContainer{},
		wbuf:       &buf.MultiBufferContainer{},
	}
}

// ServerObfsTLSConn creates a connection for obfs-tls server.
func ServerObfsTLSConn(conn net.Conn, host string) *obfsTLSConn {
	return &obfsTLSConn{
		Conn:       conn,
		isServer:   true,
		host:       host,
		handshaked: make(chan struct{}),
		rbuf:       &buf.MultiBufferContainer{},
		wbuf:       &buf.MultiBufferContainer{},
	}
}
