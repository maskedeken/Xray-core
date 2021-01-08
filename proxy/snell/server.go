package snell

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	protocol "github.com/xtls/xray-core/common/protocol"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/udp"
)

type Server struct {
	config        *ServerConfig
	user          *protocol.MemoryUser
	policyManager policy.Manager
}

// NewServer create a new Snell server.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	if config.GetUser() == nil {
		return nil, newError("user is not specified")
	}

	mUser, err := config.User.ToMemoryUser()
	if err != nil {
		return nil, newError("failed to parse user account").Base(err)
	}

	v := core.MustFromContext(ctx)
	s := &Server{
		config:        config,
		user:          mUser,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	return s, nil
}

func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

func (s *Server) Process(ctx context.Context, network net.Network, conn internet.Connection, dispatcher routing.Dispatcher) error {
	sessionPolicy := s.policyManager.ForLevel(s.user.Level)
	conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake))

	bufferedReader := buf.BufferedReader{Reader: buf.NewReader(conn)}
	request, bodyReader, err := ReadRequest(s.user, &bufferedReader)
	if err != nil {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: err,
		})

		errStr := err.Error()
		if strings.Contains(errStr, "snell") {
			return s.handleError(s.user, conn, errStr)
		}

		return newError("failed to create request from: ", conn.RemoteAddr()).Base(err)
	}

	conn.SetReadDeadline(time.Time{})

	if request.Command == protocol.RequestCommand(CommandPing) { // reponse pong if got ping
		conn.Write([]byte{CommandPong})
		return nil
	}

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}
	inbound.User = s.user

	if request.Command == protocol.RequestCommand(CommandUDP) {
		// handle udp request
		return s.handleUDPPayload(ctx, request, bodyReader, conn, dispatcher)
	}

	// handle tcp request
	dest := net.TCPDestination(request.Address, request.Port)
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  request.User.Email,
	})
	newError("tunnelling request to ", dest).WriteToLog(session.ExportIDToError(ctx))

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		responseWriter, err := WriteResponse(request, bufferedWriter)
		if err != nil {
			return newError("failed to write response").Base(err)
		}

		{
			payload, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			if err := responseWriter.WriteMultiBuffer(payload); err != nil {
				return err
			}
		}

		if err := bufferedWriter.SetBuffered(false); err != nil {
			return err
		}

		if err := buf.Copy(link.Reader, responseWriter, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transport all TCP response").Base(err)
		}

		return nil
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		if err := buf.Copy(bodyReader, link.Writer, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transport all TCP request").Base(err)
		}

		return nil
	}

	var requestDoneAndCloseWriter = task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDoneAndCloseWriter, responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return newError("connection ends").Base(err)
	}

	return nil
}

func (s *Server) handleUDPPayload(ctx context.Context, request *protocol.RequestHeader, clientReader buf.Reader, conn internet.Connection, dispatcher routing.Dispatcher) error {
	bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
	clientWriter, err := WriteResponse(request, bufferedWriter)
	if err != nil {
		return err
	}

	buffered := true
	udpServer := udp.NewDispatcher(dispatcher, func(ctx context.Context, packet *udp_proto.Packet) {
		udpPayload := packet.Payload
		udpPayload.UDP = &packet.Source
		common.Must(clientWriter.WriteMultiBuffer(buf.MultiBuffer{udpPayload}))

		if buffered {
			buffered = false
			common.Must(bufferedWriter.SetBuffered(false)) // flush
		}
	})

	inbound := session.InboundFromContext(ctx)
	user := inbound.User

	var dest *net.Destination

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			mb, err := clientReader.ReadMultiBuffer()
			if err != nil {
				if errors.Cause(err) != io.EOF {
					return newError("unexpected EOF").Base(err)
				}
				return nil
			}

			mb2, b := buf.SplitFirst(mb)
			if b == nil {
				continue
			}
			destination := *b.UDP

			currentPacketCtx := ctx
			if inbound.Source.IsValid() {
				currentPacketCtx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
					From:   inbound.Source,
					To:     destination,
					Status: log.AccessAccepted,
					Reason: "",
					Email:  user.Email,
				})
			}
			newError("tunnelling request to ", destination).WriteToLog(session.ExportIDToError(ctx))

			if !buf.Cone || dest == nil {
				dest = &destination
			}

			udpServer.Dispatch(currentPacketCtx, *dest, b) // first packet
			for _, payload := range mb2 {
				udpServer.Dispatch(currentPacketCtx, *dest, payload)
			}
		}
	}
}

func (s *Server) handleError(user *protocol.MemoryUser, conn internet.Connection, errMsg string) error {
	return WriteErrorResponse(user, conn, errMsg)
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
