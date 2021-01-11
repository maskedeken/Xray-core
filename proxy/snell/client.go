package snell

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	protocol "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Client is a inbound handler for snell protocol
type Client struct {
	serverPicker  protocol.ServerPicker
	policyManager policy.Manager
}

// NewClient create a new snell client.
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	serverList := protocol.NewServerList()
	for _, rec := range config.Server {
		s, err := protocol.NewServerSpecFromPB(rec)
		if err != nil {
			return nil, newError("failed to parse server spec").Base(err)
		}
		serverList.AddServer(s)
	}
	if serverList.Size() == 0 {
		return nil, newError("0 server")
	}

	v := core.MustFromContext(ctx)
	client := &Client{
		serverPicker:  protocol.NewRoundRobinServerPicker(serverList),
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}
	return client, nil
}

// Process implements OutboundHandler.Process().
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	var cmd protocol.RequestCommand
	destination := outbound.Target
	if destination.Network == net.Network_UDP {
		cmd = protocol.RequestCommand(CommandUDP)
	} else {
		cmd = protocol.RequestCommand(CommandConnect)
	}

	var server *protocol.ServerSpec
	var conn internet.Connection

	err := retry.ExponentialBackoff(5, 100).On(func() error {
		server = c.serverPicker.PickServer()
		rawConn, err := dialer.Dial(ctx, server.Destination())
		if err != nil {
			return err
		}

		conn = rawConn
		return nil
	})
	if err != nil {
		return newError("failed to find an available destination").AtWarning().Base(err)
	}
	newError("tunneling request to ", destination, " via ", server.Destination()).WriteToLog(session.ExportIDToError(ctx))

	defer conn.Close()

	user := server.PickUser()
	_, ok := user.Account.(*MemoryAccount)
	if !ok {
		return newError("user account is not valid")
	}

	request := &protocol.RequestHeader{
		Version: Version,
		Address: destination.Address,
		Port:    destination.Port,
		User:    user,
		Command: cmd,
	}

	sessionPolicy := c.policyManager.ForLevel(user.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
	bodyWriter, err := WriteRequest(request, bufferedWriter)
	if err != nil {
		return newError("failed to write request").Base(err)
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		// write some request payload to buffer
		if err = buf.CopyOnceTimeout(link.Reader, bodyWriter, time.Millisecond*100); err != nil && err != buf.ErrNotTimeoutReader && err != buf.ErrReadTimeout {
			return newError("failed to write A request payload").Base(err).AtWarning()
		}

		// Flush; bufferWriter.WriteMultiBufer now is bufferWriter.writer.WriteMultiBuffer
		if err = bufferedWriter.SetBuffered(false); err != nil {
			return newError("failed to flush payload").Base(err).AtWarning()
		}

		return buf.Copy(link.Reader, bodyWriter, buf.UpdateActivity(timer))
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		responseReader, err := ReadResponse(user, conn)
		if err != nil {
			return err
		}

		return buf.Copy(responseReader, link.Writer, buf.UpdateActivity(timer))
	}

	var responseDoneAndCloseWriter = task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
