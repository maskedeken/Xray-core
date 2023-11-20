/*

Some of codes are copied from https://github.com/octeep/wireproxy, license below.

Copyright (c) 2022 Wind T.F. Wong <octeep@pm.me>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

*/

package wireguard

import (
	"context"
	"net/netip"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// Handler is an outbound connection that silently swallow the entire payload.
type Handler struct {
	conf          *DeviceConfig
	net           Tunnel
	bind          *netBindClient
	policyManager policy.Manager
	dns           dns.Client
	// cached configuration
	ipc              string
	endpoints        []netip.Addr
	hasIPv4, hasIPv6 bool
	wgLock           sync.Mutex
}

// New creates a new wireguard handler.
func New(ctx context.Context, conf *DeviceConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)

	endpoints, hasIPv4, hasIPv6, err := parseEndpoints(conf)
	if err != nil {
		return nil, err
	}

	d := v.GetFeature(dns.ClientType()).(dns.Client)
	return &Handler{
		conf:          conf,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		dns:           d,
		ipc:           createIPCRequest(conf),
		endpoints:     endpoints,
		hasIPv4:       hasIPv4,
		hasIPv6:       hasIPv6,
	}, nil
}

func (h *Handler) processWireGuard(dialer internet.Dialer) (err error) {
	h.wgLock.Lock()
	defer h.wgLock.Unlock()

	if h.bind != nil && h.bind.dialer == dialer && h.net != nil {
		return nil
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "switching dialer",
	})

	if h.net != nil {
		_ = h.net.Close()
		h.net = nil
	}
	if h.bind != nil {
		_ = h.bind.Close()
		h.bind = nil
	}

	// bind := conn.NewStdNetBind() // TODO: conn.Bind wrapper for dialer
	bind := &netBindClient{
		netBind: netBind{
			dns: h.dns,
			dnsOption: dns.IPOption{
				IPv4Enable: h.hasIPv4,
				IPv6Enable: h.hasIPv6,
			},
			workers: int(h.conf.NumWorkers),
		},
		dialer:   dialer,
		reserved: h.conf.Reserved,
	}
	defer func() {
		if err != nil {
			_ = bind.Close()
		}
	}()

	h.net, err = h.makeVirtualTun(bind)
	if err != nil {
		return newError("failed to create virtual tun interface").Base(err)
	}
	h.bind = bind
	return nil
}

// Process implements OutboundHandler.Dispatch().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	outbound.Name = "wireguard"
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.SetCanSpliceCopy(3)
	}

	if err := h.processWireGuard(dialer); err != nil {
		return err
	}

	// Destination of the inner request.
	destination := outbound.Target
	command := protocol.RequestCommandTCP
	if destination.Network == net.Network_UDP {
		command = protocol.RequestCommandUDP
	}

	// resolve dns
	addr := destination.Address
	if addr.Family().IsDomain() {
		ips, err := h.dns.LookupIP(addr.Domain(), dns.IPOption{
			IPv4Enable: h.hasIPv4 && h.conf.preferIP4(),
			IPv6Enable: h.hasIPv6 && h.conf.preferIP6(),
		})
		{ // Resolve fallback
			if (len(ips) == 0 || err != nil) && h.conf.hasFallback() {
				ips, err = h.dns.LookupIP(addr.Domain(), dns.IPOption{
					IPv4Enable: h.hasIPv4 && h.conf.fallbackIP4(),
					IPv6Enable: h.hasIPv6 && h.conf.fallbackIP6(),
				})
			}
		}
		if err != nil {
			return newError("failed to lookup DNS").Base(err)
		} else if len(ips) == 0 {
			return dns.ErrEmptyResponse
		}
		addr = net.IPAddress(ips[dice.Roll(len(ips))])
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	p := h.policyManager.ForLevel(0)

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, p.Timeouts.ConnectionIdle)
	addrPort := netip.AddrPortFrom(toNetIpAddr(addr), destination.Port.Value())

	var requestFunc func() error
	var responseFunc func() error

	if command == protocol.RequestCommandTCP {
		conn, err := h.net.DialContextTCPAddrPort(ctx, addrPort)
		if err != nil {
			return newError("failed to create TCP connection").Base(err)
		}
		defer conn.Close()

		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}
	} else if command == protocol.RequestCommandUDP {
		conn, err := h.net.DialUDPAddrPort(netip.AddrPort{}, addrPort)
		if err != nil {
			return newError("failed to create UDP connection").Base(err)
		}
		defer conn.Close()

		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}
	}

	if newCtx != nil {
		ctx = newCtx
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return newError("connection ends").Base(err)
	}

	return nil
}

// creates a tun interface on netstack given a configuration
func (h *Handler) makeVirtualTun(bind *netBindClient) (Tunnel, error) {
	t, err := h.conf.createTun()(h.endpoints, int(h.conf.Mtu), nil)
	if err != nil {
		return nil, err
	}

	bind.dnsOption.IPv4Enable = h.hasIPv4
	bind.dnsOption.IPv6Enable = h.hasIPv6

	if err = t.BuildDevice(h.ipc, bind); err != nil {
		_ = t.Close()
		return nil, err
	}
	return t, nil
}
