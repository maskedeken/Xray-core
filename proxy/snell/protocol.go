package snell

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"io/ioutil"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	protocol "github.com/xtls/xray-core/common/protocol"
)

const (
	Version byte = 1
)

const (
	CommandPing      byte = 0
	CommandConnect   byte = 1
	CommandUDP       byte = 3
	CommandConnectV2 byte = 5

	CommandTunnel byte = 0
	CommandPong   byte = 1
	CommandError  byte = 2
)

// WriteTCPRequest writes Snell request into the given writer, and returns a writer for body.
func WriteRequest(request *protocol.RequestHeader, writer io.Writer) (buf.Writer, error) {
	user := request.User
	account := user.Account.(*MemoryAccount)

	w, err := initWriter(account, writer)
	if err != nil {
		return nil, newError("failed to create encoding stream").Base(err).AtError()
	}

	header := buf.New()
	defer header.Release()

	cmd := byte(request.Command)
	header.WriteByte(Version)
	header.WriteByte(cmd)

	// clientID length & id
	header.WriteByte(0)
	// host & port
	writeAddressPort(header, request.Address, request.Port)

	if err := w.WriteMultiBuffer(buf.MultiBuffer{header}); err != nil {
		return nil, newError("failed to write header").Base(err)
	}

	if cmd == CommandUDP {
		target := net.UDPDestination(request.Address, request.Port)
		return &PacketWriter{Writer: w, Target: target}, nil
	}

	return w, nil
}

func ReadResponse(user *protocol.MemoryUser, reader io.Reader) (buf.Reader, error) {
	account := user.Account.(*MemoryAccount)

	r, err := initReader(account, reader)
	if err != nil {
		return nil, newError("failed to initialize decoding stream").Base(err).AtError()
	}

	mb, err := r.ReadMultiBuffer()
	if err != nil {
		return nil, err
	}

	var buffer [1]byte
	mbContainer := &buf.MultiBufferContainer{MultiBuffer: mb}
	if _, err := io.ReadFull(mbContainer, buffer[:]); err != nil {
		return nil, err
	}

	cmd := buffer[0]
	switch cmd {
	case CommandTunnel, CommandUDP:
		br := &buf.BufferedReader{
			Reader: r,
			Buffer: mbContainer.MultiBuffer,
		}

		if cmd == CommandTunnel {
			return br, nil
		}

		return &PacketReader{Reader: br}, nil
	default:
	}

	defer mbContainer.Close()

	if buffer[0] != CommandError {
		return nil, newError("command not supported")
	}

	// CommandError
	// 1 byte error code
	if _, err := io.ReadFull(mbContainer, buffer[:]); err != nil {
		return nil, err
	}
	errcode := int(buffer[0])

	// 1 byte error message length
	if _, err := io.ReadFull(mbContainer, buffer[:]); err != nil {
		return nil, err
	}
	length := int(buffer[0])
	msg := make([]byte, length)

	if _, err := io.ReadFull(mbContainer, msg); err != nil {
		return nil, err
	}

	return nil, newError("server reported code: ", errcode, "message: ", string(msg))
}

// ReadRequest reads a Snell TCP session from the given reader, returns its header and remaining parts.
func ReadRequest(user *protocol.MemoryUser, reader io.Reader) (*protocol.RequestHeader, buf.Reader, error) {
	account := user.Account.(*MemoryAccount)

	buffer := buf.New()
	defer buffer.Release()

	r, err := initReader(account, reader)
	if err != nil {
		return nil, nil, newError("failed to initialize decoding stream").Base(err).AtError()
	}

	mb, err := r.ReadMultiBuffer()
	if err != nil {
		return nil, nil, err
	}

	buffer.Clear()
	mbContainer := &buf.MultiBufferContainer{MultiBuffer: mb}
	if _, err := buffer.ReadFullFrom(mbContainer, 3); err != nil {
		return nil, nil, err
	}

	switch buffer.Byte(0) {
	case Version:
	default:
		mbContainer.Close()
		return nil, nil, newError("invalid snell version")
	}

	cmd := buffer.Byte(1)   // command
	idLen := buffer.Byte(2) // user id length
	switch cmd {
	case CommandPing, CommandConnect, CommandUDP:
	default:
		mbContainer.Close()
		return nil, nil, newError("invalid snell command")
	}

	request := &protocol.RequestHeader{
		Version: Version,
		User:    user,
		Command: protocol.RequestCommand(cmd),
	}

	if cmd == CommandPing {
		mbContainer.Close()
		return request, nil, nil
	}

	if idLen > 0 {
		if _, err := io.CopyN(ioutil.Discard, mbContainer, int64(idLen)); err != nil { // just discard user id
			mbContainer.Close()
			return nil, nil, err
		}
	}

	addr, port, err := readAddressPort(mbContainer)
	if err != nil {
		mbContainer.Close()
		return nil, nil, err
	}
	request.Address = addr
	request.Port = port

	br := &buf.BufferedReader{
		Reader: r,
		Buffer: mbContainer.MultiBuffer,
	}

	if cmd == CommandUDP {
		return request, &PacketReader{Reader: br}, nil
	}

	return request, br, nil
}

func WriteResponse(request *protocol.RequestHeader, writer io.Writer) (buf.Writer, error) {
	user := request.User
	account := user.Account.(*MemoryAccount)

	w, err := initWriter(account, writer)
	if err != nil {
		return nil, newError("failed to initialize encoding stream").Base(err).AtError()
	}

	buffer := buf.New()
	if request.Command == protocol.RequestCommand(CommandUDP) {
		target := net.UDPDestination(request.Address, request.Port)
		buffer.WriteByte(CommandUDP)
		w.WriteMultiBuffer(buf.MultiBuffer{buffer})
		return &PacketWriter{Writer: w, Target: target}, nil
	}

	buffer.WriteByte(CommandTunnel)
	w.WriteMultiBuffer(buf.MultiBuffer{buffer})
	return w, nil
}

func WriteErrorResponse(user *protocol.MemoryUser, writer io.Writer, errMsg string) error {
	account := user.Account.(*MemoryAccount)

	w, err := initWriter(account, writer)
	if err != nil {
		return newError("failed to initialize encoding stream").Base(err).AtError()
	}

	buffer := buf.New()
	buffer.WriteByte(CommandError)
	buffer.WriteByte(255)                // error code
	buffer.WriteByte(uint8(len(errMsg))) // error message length
	buffer.WriteString(errMsg)
	w.WriteMultiBuffer(buf.MultiBuffer{buffer})
	return nil
}

func initWriter(account *MemoryAccount, writer io.Writer) (buf.Writer, error) {
	var iv []byte
	if account.Cipher.IVSize() > 0 {
		iv = make([]byte, account.Cipher.IVSize())
		common.Must2(rand.Read(iv))
		if err := buf.WriteAllBytes(writer, iv); err != nil {
			return nil, newError("failed to write IV.").Base(err)
		}
	}

	return account.Cipher.NewEncryptionWriter(account.PSK, iv, writer)
}

func initReader(account *MemoryAccount, reader io.Reader) (buf.Reader, error) {
	var iv []byte
	if account.Cipher.IVSize() > 0 {
		iv = make([]byte, account.Cipher.IVSize())
		if _, err := io.ReadFull(reader, iv); err != nil {
			return nil, newError("failed to read IV").Base(err)
		}
	}

	return account.Cipher.NewDecryptionReader(account.PSK, iv, reader)
}

// PacketWriter UDP Connection Writer Wrapper for snell protocol
type PacketWriter struct {
	buf.Writer
	Target net.Destination
}

// WriteMultiBuffer implements buf.Writer
func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		target := &w.Target
		if b.UDP != nil {
			target = b.UDP
		}
		if _, err := w.writePacket(b.Bytes(), *target); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return nil
}

func (w *PacketWriter) writePacket(payload []byte, dest net.Destination) (int, error) {
	buffer := buf.New()
	mb := buf.MultiBuffer{buffer}

	writeAddressPort(buffer, dest.Address, dest.Port)
	length := len(payload)
	lengthBuf := [2]byte{}
	binary.BigEndian.PutUint16(lengthBuf[:], uint16(length))
	buffer.Write(lengthBuf[:]) // payload length

	err := w.Writer.WriteMultiBuffer(buf.MergeBytes(mb, payload))
	if err != nil {
		return 0, err
	}

	return length, nil
}

// PacketReader is UDP Connection Reader Wrapper for snell protocol
type PacketReader struct {
	io.Reader
}

// ReadMultiBuffer implements buf.Reader
func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	addr, port, err := readAddressPort(r)
	if err != nil {
		return nil, newError("failed to read address and port").Base(err)
	}

	var lengthBuf [2]byte
	if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
		return nil, newError("failed to read payload length").Base(err)
	}

	remain := int(binary.BigEndian.Uint16(lengthBuf[:]))
	dest := net.UDPDestination(addr, port)
	var mb buf.MultiBuffer

	for remain > 0 {
		length := buf.Size
		if remain < length {
			length = remain
		}

		b := buf.New()
		b.UDP = &dest
		mb = append(mb, b)
		n, err := b.ReadFullFrom(r, int32(length))
		if err != nil {
			buf.ReleaseMulti(mb)
			return nil, newError("failed to read payload").Base(err)
		}

		remain -= int(n)
	}

	return mb, nil
}

func writeAddressPort(w io.Writer, addr net.Address, port net.Port) (err error) {
	buffer := buf.New()
	defer buffer.Release()

	// host & port
	buffer.WriteByte(uint8(len(addr.String()))) // address length
	buffer.WriteString(addr.String())
	binary.Write(buffer, binary.BigEndian, uint16(port))
	_, err = w.Write(buffer.Bytes())
	return
}

func readAddressPort(r io.Reader) (addr net.Address, port net.Port, err error) {
	buffer := buf.New()
	defer buffer.Release()
	if _, err = buffer.ReadFullFrom(r, 1); err != nil {
		return
	}

	hlen := int32(buffer.Byte(0))
	buffer.Clear()
	if _, err = buffer.ReadFullFrom(r, hlen+2); err != nil {
		return
	}
	addr = net.ParseAddress(string(buffer.BytesTo(hlen)))
	port = net.Port(binary.BigEndian.Uint16(buffer.BytesRange(hlen, hlen+2)))
	return
}
