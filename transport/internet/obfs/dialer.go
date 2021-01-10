package obfs

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// Dial implements Transport Dialer
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (internet.Connection, error) {
	obfsSettings := streamSettings.ProtocolSettings.(*Config)
	switch obfsSettings.Type {
	case ObfsType_HTTP, ObfsType_TLS:
		break
	default:
		return nil, newError("Unknown Obfuscation Type")
	}

	conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	if obfsSettings.Type == ObfsType_TLS {
		return clientObfsTLSConn(conn, obfsSettings.Host), nil
	} else {
		return clientObfsHTTPConn(conn, obfsSettings.Host), nil
	}
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
