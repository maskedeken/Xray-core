package grpc

import (
	context "context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
)

var (
	globalDialerMap    map[net.Destination]GunServiceClient
	globalDialerAccess sync.Mutex
)

func getGRPCClient(ctx context.Context, dest net.Destination, tlsSettings *tls.Config) (GunServiceClient, error) {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[net.Destination]GunServiceClient)
	}

	if client, found := globalDialerMap[dest]; found {
		return client, nil
	}

	var dialOption grpc.DialOption
	tlsConfig := tlsSettings.GetTLSConfig(tls.WithDestination(dest))
	dialOption = grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))

	// dial
	conn, err := grpc.Dial(
		dest.NetAddr(),
		dialOption,
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Millisecond,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithDialer(func(string, time.Duration) (net.Conn, error) {
			return internet.DialSystem(ctx, dest, nil)
		}),
	)
	if err != nil {
		return nil, err
	}

	client := NewGunServiceClient(conn)
	globalDialerMap[dest] = client
	return client, nil
}

// Dial dials a new TCP connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (internet.Connection, error) {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, newError("TLS must be enabled for grpc transport.").AtWarning()
	}
	client, err := getGRPCClient(ctx, dest, tlsConfig)
	if err != nil {
		return nil, err
	}

	tun, err := client.Tun(context.Background())
	if err != nil {
		return nil, newError("failed to dial to ", dest).Base(err).AtWarning()
	}

	return newGunConnection(tun, nil, nil), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
