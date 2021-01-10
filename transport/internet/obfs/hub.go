package obfs

import (
	"context"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
)

type Listener struct {
	net.Listener
	locker *internet.FileLocker // for unix domain socket
}

// Close implements net.Listener.Close().
func (ln *Listener) Close() error {
	if ln.locker != nil {
		ln.locker.Release()
	}
	return ln.Listener.Close()
}

func ListenObfs(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	obfsSettings := streamSettings.ProtocolSettings.(*Config)
	switch obfsSettings.Type {
	case ObfsType_HTTP, ObfsType_TLS:
		break
	default:
		return nil, newError("Unknown Obfuscation Type")
	}

	ln := &Listener{}
	if port == net.Port(0) { //unix
		listener, err := internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, newError("failed to listen unix domain socket(for obfuscation) on ", address).Base(err)
		}
		newError("listening unix domain socket(for obfuscation) on ", address).WriteToLog(session.ExportIDToError(ctx))

		ln.Listener = listener
		locker := ctx.Value(address.Domain())
		if locker != nil {
			ln.locker = locker.(*internet.FileLocker)
		}
	} else { //tcp
		listener, err := internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, newError("failed to listen TCP(for obfuscation) on ", address, ":", port).Base(err)
		}
		newError("listening TCP(for obfuscation) on ", address, ":", port).WriteToLog(session.ExportIDToError(ctx))
		ln.Listener = listener
	}

	if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol {
		newError("accepting PROXY protocol").AtWarning().WriteToLog(session.ExportIDToError(ctx))
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				errStr := err.Error()
				if strings.Contains(errStr, "closed") {
					break
				}
				newError("failed to accepted raw connections").Base(err).AtWarning().WriteToLog()
				if strings.Contains(errStr, "too many") {
					time.Sleep(time.Millisecond * 500)
				}
				continue
			}

			go func() {
				if obfsSettings.Type == ObfsType_TLS {
					fakeTLSConn := serverObfsTLSConn(conn, obfsSettings.Host)
					if err := fakeTLSConn.Handshake(nil); err != nil {
						newError("failed to perform tls handshake with ", conn.RemoteAddr().String()).Base(err).AtWarning().WriteToLog()
						return
					}

					addConn(internet.Connection(fakeTLSConn))
					return
				}

				fakeHTTPConn := serverObfsHTTPConn(conn, obfsSettings.Host)
				if err := fakeHTTPConn.Handshake(); err != nil {
					newError("failed to perform http handshake with ", conn.RemoteAddr().String()).Base(err).AtWarning().WriteToLog()
					return
				}

				addConn(internet.Connection(fakeHTTPConn))
			}()

		}
	}()

	return ln, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenObfs))
}
