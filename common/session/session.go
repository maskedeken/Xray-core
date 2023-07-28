// Package session provides functions for sessions of incoming requests.
package session // import "github.com/xtls/xray-core/common/session"

import (
	"context"
	"math/rand"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal"
)

// ID of a session.
type ID uint32

// NewID generates a new ID. The generated ID is high likely to be unique, but not cryptographically secure.
// The generated ID will never be 0.
func NewID() ID {
	for {
		id := ID(rand.Uint32())
		if id != 0 {
			return id
		}
	}
}

// ExportIDToError transfers session.ID into an error object, for logging purpose.
// This can be used with error.WriteToLog().
func ExportIDToError(ctx context.Context) errors.ExportOption {
	id := IDFromContext(ctx)
	return func(h *errors.ExportOptionHolder) {
		h.SessionID = uint32(id)
	}
}

// Inbound is the metadata of an inbound connection.
type Inbound struct {
	// Source address of the inbound connection.
	Source net.Destination
	// Gateway address.
	Gateway net.Destination
	// Tag of the inbound proxy that handles the connection.
	Tag string
	// Name of the inbound proxy that handles the connection.
	Name string
	// User is the user that authencates for the inbound. May be nil if the protocol allows anounymous traffic.
	User *protocol.MemoryUser
	// Conn is actually internet.Connection. May be nil.
	Conn net.Conn
	// Timer of the inbound buf copier. May be nil.
	Timer *signal.ActivityTimer
}

// Outbound is the metadata of an outbound connection.
type Outbound struct {
	// Target address of the outbound connection.
	Target      net.Destination
	RouteTarget net.Destination
	// Gateway address
	Gateway  net.Address
	Resolved *Resolved
}

// SniffingRequest controls the behavior of content sniffing.
type SniffingRequest struct {
	ExcludeForDomain               []string
	OverrideDestinationForProtocol []string
	Enabled                        bool
	MetadataOnly                   bool
	RouteOnly                      bool
}

// Content is the metadata of the connection content.
type Content struct {
	// Protocol of current content.
	Protocol string

	SniffingRequest SniffingRequest

	Attributes map[string]string

	SkipDNSResolve bool
}

// Sockopt is the settings for socket connection.
type Sockopt struct {
	// Mark of the socket connection.
	Mark int32
}

// SetAttribute attaches additional string attributes to content.
func (c *Content) SetAttribute(name string, value string) {
	if c.Attributes == nil {
		c.Attributes = make(map[string]string)
	}
	c.Attributes[name] = value
}

// Attribute retrieves additional string attributes from content.
func (c *Content) Attribute(name string) string {
	if c.Attributes == nil {
		return ""
	}
	return c.Attributes[name]
}

type Resolved struct {
	IPs    []net.IP
	ipIdx  uint8
	ipLock sync.Mutex
}

// NextIP switch to another resolved result.
// there still be race-condition here if multiple err concurently occured
// may cause idx keep switching,
// but that's an outside error can hardly handled here
func (r *Resolved) NextIP() {
	r.ipLock.Lock()
	defer r.ipLock.Unlock()

	if len(r.IPs) > 1 {
		r.ipIdx++
	} else {
		return
	}

	if r.ipIdx >= uint8(len(r.IPs)) {
		r.ipIdx = 0
	}

	newError("switch to next IP: ", r.IPs[r.ipIdx]).AtDebug().WriteToLog()
}

func (r *Resolved) CurrentIP() net.IP {
	r.ipLock.Lock()
	defer r.ipLock.Unlock()
	if len(r.IPs) > 0 {
		return r.IPs[r.ipIdx]
	}

	return nil
}
