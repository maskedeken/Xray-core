package websocket

import (
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/xtls/xray-core/transport/internet/stat"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type dialerConf struct {
	net.Destination
	streamSettings *internet.MemoryStreamConfig
}

type muxSession struct {
	conf         dialerConf
	client       *smux.Session
	underlayConn net.Conn
}

type muxPool struct {
	sync.Mutex
	sessions map[dialerConf]*muxSession
}

var pool = muxPool{sessions: make(map[dialerConf]*muxSession)}

//go:embed dialer.html
var webpage []byte
var conns chan *websocket.Conn

func init() {
	if addr := os.Getenv("XRAY_BROWSER_DIALER"); addr != "" {
		conns = make(chan *websocket.Conn, 256)
		go http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/websocket" {
				if conn, err := upgrader.Upgrade(w, r, nil); err == nil {
					conns <- conn
				} else {
					fmt.Println("unexpected error")
				}
			} else {
				w.Write(webpage)
			}
		}))
	}
}

// Dial dials a WebSocket connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	wsSettings := streamSettings.ProtocolSettings.(*Config)
	if !wsSettings.Mux {
		newError("creating connection to ", dest).WriteToLog(session.ExportIDToError(ctx))
		conn, err := dialWebSocket(ctx, dest, streamSettings)
		return stat.Connection(conn), err
	}

	newError("creating mux connection to ", dest).WriteToLog(session.ExportIDToError(ctx))

	createNewMuxConn := func(sess *muxSession) (stat.Connection, error) {
		stream, err := sess.client.OpenStream()
		if err != nil {
			sess.underlayConn.Close()
			sess.client.Close()
			delete(pool.sessions, sess.conf)
			return nil, newError("failed to open mux stream").Base(err)
		}

		return stat.Connection(stream), nil
	}

	pool.Lock()
	defer pool.Unlock()
	conf := dialerConf{dest, streamSettings}
	sess, ok := pool.sessions[conf]
	if ok && !sess.client.IsClosed() {
		return createNewMuxConn(sess)
	}

	conn, err := dialWebSocket(ctx, dest, streamSettings)
	if err != nil {
		return nil, err
	}

	smuxConfig := smux.DefaultConfig()
	client, err := smux.Client(conn, smuxConfig)
	if err != nil {
		return nil, newError("failed to create mux session").Base(err)
	}

	sess = &muxSession{conf: conf, client: client, underlayConn: conn}
	pool.sessions[conf] = sess
	return createNewMuxConn(sess)
}

func dialWebSocket(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	var conn net.Conn
	if streamSettings.ProtocolSettings.(*Config).Ed > 0 {
		ctx, cancel := context.WithCancel(ctx)
		conn = &delayDialConn{
			dialed:         make(chan bool, 1),
			cancel:         cancel,
			ctx:            ctx,
			dest:           dest,
			streamSettings: streamSettings,
		}
	} else {
		var err error
		if conn, err = dialConn(ctx, dest, streamSettings, nil); err != nil {
			return nil, newError("failed to dial WebSocket").Base(err)
		}
	}
	return conn, nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

func dialConn(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, ed []byte) (net.Conn, error) {
	wsSettings := streamSettings.ProtocolSettings.(*Config)

	dialer := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
		},
		ReadBufferSize:   4 * 1024,
		WriteBufferSize:  4 * 1024,
		HandshakeTimeout: time.Second * 8,
	}

	protocol := "ws"

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		protocol = "wss"
		dialer.TLSClientConfig = config.GetTLSConfig(tls.WithDestination(dest), tls.WithNextProto("http/1.1"))
	}

	host := dest.NetAddr()
	if (protocol == "ws" && dest.Port == 80) || (protocol == "wss" && dest.Port == 443) {
		host = dest.Address.String()
	}
	uri := protocol + "://" + host + wsSettings.GetNormalizedPath()

	if conns != nil {
		data := []byte(uri)
		if ed != nil {
			data = append(data, " "+base64.RawURLEncoding.EncodeToString(ed)...)
		}
		var conn *websocket.Conn
		for {
			conn = <-conns
			if conn.WriteMessage(websocket.TextMessage, data) != nil {
				conn.Close()
			} else {
				break
			}
		}
		if _, p, err := conn.ReadMessage(); err != nil {
			conn.Close()
			return nil, err
		} else if s := string(p); s != "ok" {
			conn.Close()
			return nil, newError(s)
		}
		return newConnection(conn, conn.RemoteAddr(), nil), nil
	}

	header := wsSettings.GetRequestHeader()
	if ed != nil {
		header.Set("Sec-WebSocket-Protocol", base64.RawURLEncoding.EncodeToString(ed))
	}

	conn, resp, err := dialer.Dial(uri, header)
	if err != nil {
		var reason string
		if resp != nil {
			reason = resp.Status
		}
		return nil, newError("failed to dial to (", uri, "): ", reason).Base(err)
	}

	return newConnection(conn, conn.RemoteAddr(), nil), nil
}

type delayDialConn struct {
	net.Conn
	closed         bool
	dialed         chan bool
	cancel         context.CancelFunc
	ctx            context.Context
	dest           net.Destination
	streamSettings *internet.MemoryStreamConfig
}

func (d *delayDialConn) Write(b []byte) (int, error) {
	if d.closed {
		return 0, io.ErrClosedPipe
	}
	if d.Conn == nil {
		ed := b
		if len(ed) > int(d.streamSettings.ProtocolSettings.(*Config).Ed) {
			ed = nil
		}
		var err error
		if d.Conn, err = dialConn(d.ctx, d.dest, d.streamSettings, ed); err != nil {
			d.Close()
			return 0, newError("failed to dial WebSocket").Base(err)
		}
		d.dialed <- true
		if ed != nil {
			return len(ed), nil
		}
	}
	return d.Conn.Write(b)
}

func (d *delayDialConn) Read(b []byte) (int, error) {
	if d.closed {
		return 0, io.ErrClosedPipe
	}
	if d.Conn == nil {
		select {
		case <-d.ctx.Done():
			return 0, io.ErrUnexpectedEOF
		case <-d.dialed:
		}
	}
	return d.Conn.Read(b)
}

func (d *delayDialConn) Close() error {
	d.closed = true
	d.cancel()
	if d.Conn == nil {
		return nil
	}
	return d.Conn.Close()
}
