package grpc

import (
	"net"
	"time"
)

type gunService interface {
	Send(*Hunk) error
	Recv() (*Hunk, error)
}

type gunConnection struct {
	gunService
	local  net.Addr
	remote net.Addr
	rb     []byte
	done   chan struct{}
}

func newGunConnection(service gunService, local net.Addr, remote net.Addr) *gunConnection {
	if local == nil {
		local = &net.TCPAddr{
			IP:   []byte{0, 0, 0, 0},
			Port: 0,
		}
	}

	if remote == nil {
		remote = &net.TCPAddr{
			IP:   []byte{0, 0, 0, 0},
			Port: 0,
		}
	}
	return &gunConnection{
		gunService: service,
		local:      local,
		remote:     remote,
		done:       make(chan struct{}),
	}
}

// Read implements net.Conn.Read().
func (c *gunConnection) Read(b []byte) (int, error) {
	if len(c.rb) == 0 {
		hunk, err := c.gunService.Recv()
		if err != nil {
			return 0, err
		}

		c.rb = hunk.Data
	}

	n := copy(b, c.rb)
	c.rb = c.rb[n:]
	return n, nil
}

// Write implements net.Conn.Write().
func (c *gunConnection) Write(b []byte) (int, error) {
	err := c.gunService.Send(&Hunk{Data: b})
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

// Close implements net.Conn.Close().
func (c *gunConnection) Close() error {
	close(c.done)
	return nil
}

// LocalAddr implements net.Conn.LocalAddr().
func (c *gunConnection) LocalAddr() net.Addr {
	return c.local
}

// RemoteAddr implements net.Conn.RemoteAddr().
func (c *gunConnection) RemoteAddr() net.Addr {
	return c.remote
}

// SetDeadline implements net.Conn.SetDeadline().
func (c *gunConnection) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implements net.Conn.SetReadDeadline().
func (c *gunConnection) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline().
func (c *gunConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *gunConnection) Done() <-chan struct{} {
	return c.done
}
