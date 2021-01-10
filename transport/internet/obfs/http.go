package obfs

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

var (
	defaultUserAgent = "Chrome/78.0.3904.106"
	keyGUID          = []byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
)

type obfsHTTPConn struct {
	net.Conn
	sync.Mutex
	host          string
	rbuf          *buf.MultiBufferContainer
	wbuf          *buf.MultiBufferContainer
	isServer      bool
	headerDrained bool
	handshaked    chan struct{}
}

func (c *obfsHTTPConn) Handshaked() bool {
	select {
	case <-c.handshaked:
		return true
	default:
		return false
	}
}

func (c *obfsHTTPConn) Handshake() (err error) {
	if c.isServer {
		err = c.serverHandshake()
	} else {
		err = c.clientHandshake()
	}
	if err != nil {
		return
	}

	close(c.handshaked)
	return
}

func (c *obfsHTTPConn) serverHandshake() (err error) {
	br := bufio.NewReader(c.Conn)
	r, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	b := buf.New()
	defer b.Release()

	if r.Method != http.MethodGet || r.Header.Get("Upgrade") != "websocket" {
		b.WriteString("HTTP/1.1 503 Service Unavailable\r\n")
		b.WriteString("Content-Length: 0\r\n")
		b.WriteString("Date: " + time.Now().Format(time.RFC1123) + "\r\n")
		b.WriteString("\r\n")

		c.Conn.Write(b.Bytes())
		return newError("bad request").AtError()
	}

	if r.ContentLength > 0 {
		_, err = io.Copy(c.rbuf, r.Body)
	} else {
		var b []byte
		b, err = br.Peek(br.Buffered())
		if len(b) > 0 {
			_, err = c.rbuf.Write(b)
		}
	}
	if err != nil {
		return
	}

	b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	b.WriteString("Server: nginx/1.10.0\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123) + "\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString(fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n", computeAcceptKey(r.Header.Get("Sec-WebSocket-Key"))))
	b.WriteString("\r\n")

	c.wbuf.Write(b.Bytes())
	return
}

func (c *obfsHTTPConn) clientHandshake() error {
	r := &http.Request{
		Method:     http.MethodGet,
		ProtoMajor: 1,
		ProtoMinor: 1,
		URL:        &url.URL{Scheme: "http", Host: c.host},
		Header:     make(http.Header),
	}
	r.Header.Set("User-Agent", defaultUserAgent)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	key, _ := generateChallengeKey()
	r.Header.Set("Sec-WebSocket-Key", key)

	// cache the request header
	return r.Write(c.wbuf)
}

func (c *obfsHTTPConn) Read(b []byte) (n int, err error) {
	<-c.handshaked

	if !c.isServer {
		if err = c.drainHeader(); err != nil {
			return
		}
	}

	if c.rbuf.Len() > 0 {
		return c.rbuf.Read(b)
	}
	return c.Conn.Read(b)
}

func (c *obfsHTTPConn) drainHeader() (err error) {
	if c.headerDrained {
		return
	}
	c.headerDrained = true

	br := bufio.NewReader(c.Conn)
	// drain and discard the response header
	var line string
	var buf bytes.Buffer
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			return
		}
		buf.WriteString(line)
		if line == "\r\n" {
			break
		}
	}

	// cache the extra data for next read.
	var b []byte
	b, err = br.Peek(br.Buffered())
	if len(b) > 0 {
		_, err = c.rbuf.Write(b)
	}
	return
}

func (c *obfsHTTPConn) Write(b []byte) (n int, err error) {
	if !c.isServer && !c.Handshaked() {
		c.Lock()
		if !c.Handshaked() {
			err = c.Handshake()
			if err != nil {
				c.Unlock()
				return 0, err
			}
		}
		c.Unlock()
	}

	if c.wbuf.Len() > 0 {
		c.wbuf.Write(b) // append the data to the cached header
		buffer, _ := buf.ReadAllToBytes(c.wbuf)
		_, err = c.Conn.Write(buffer)
		n = len(b) // exclude the header length
		return
	}
	return c.Conn.Write(b)
}

// clientObfsHTTPConn creates a connection for obfs-http client.
func clientObfsHTTPConn(conn net.Conn, host string) *obfsHTTPConn {
	return &obfsHTTPConn{
		Conn:       conn,
		host:       host,
		handshaked: make(chan struct{}),
		rbuf:       &buf.MultiBufferContainer{},
		wbuf:       &buf.MultiBufferContainer{},
	}
}

// serverObfsHTTPConn creates a connection for obfs-http server.
func serverObfsHTTPConn(conn net.Conn, host string) *obfsHTTPConn {
	return &obfsHTTPConn{
		Conn:       conn,
		isServer:   true,
		host:       host,
		handshaked: make(chan struct{}),
		rbuf:       &buf.MultiBufferContainer{},
		wbuf:       &buf.MultiBufferContainer{},
	}
}

func generateChallengeKey() (string, error) {
	p := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, p); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(p), nil
}

func computeAcceptKey(challengeKey string) string {
	h := sha1.New()
	h.Write([]byte(challengeKey))
	h.Write(keyGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
