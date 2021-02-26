package grpc

import (
	context "context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Listener struct {
	listener net.Listener
	server   *grpc.Server
	local    net.Addr
	handler  internet.ConnHandler
	locker   *internet.FileLocker // for unix domain socket
}

func (l *Listener) Addr() net.Addr {
	return l.local
}

func (l *Listener) Close() error {
	if l.locker != nil {
		l.locker.Release()
	}
	return l.listener.Close()
}

// Tun implements GunServiceServer.Tun()
func (l *Listener) Tun(srv GunService_TunServer) error {
	conn := newGunConnection(srv, l.local, nil)
	l.handler(conn)
	<-conn.Done()
	return nil
}

func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	var server *grpc.Server
	config := tls.ConfigFromStreamSettings(streamSettings)
	if config == nil {
		server = grpc.NewServer()
	} else {
		server = grpc.NewServer(grpc.Creds(credentials.NewTLS(config.GetTLSConfig())))
	}

	if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol {
		newError("accepting PROXY protocol").AtWarning().WriteToLog(session.ExportIDToError(ctx))
	}

	l := &Listener{
		server:  server,
		handler: handler,
	}

	var err error
	if port == net.Port(0) { // unix
		l.local = &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}
		l.listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, newError("failed to listen on ", address).Base(err).AtError()
		}
		locker := ctx.Value(address.Domain())
		if locker != nil {
			l.locker = locker.(*internet.FileLocker)
		}
	} else { // tcp
		l.local = &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}
		l.listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, newError("failed to listen on ", address, ":", port).Base(err).AtError()
		}
	}

	RegisterGunServiceServer(server, l)
	go func() {
		err := server.Serve(l.listener)
		if err != nil {
			newError("stopping serving gRPC").Base(err).WriteToLog(session.ExportIDToError(ctx))
		}
	}()

	return l, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
