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
	CommandConnectV2 byte = 5

	CommandTunnel byte = 0
	CommandPong   byte = 1
	CommandError  byte = 2

	ResponseTunnel byte = 0
	ResponsePong   byte = 1
	ResponseError  byte = 2
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

	header.WriteByte(Version)
	header.WriteByte(CommandConnect)

	// clientID length & id
	header.WriteByte(0)

	// host & port
	header.WriteByte(uint8(len(request.Address.String())))
	header.WriteString(request.Address.String())
	binary.Write(header, binary.BigEndian, uint16(request.Port))

	if err := w.WriteMultiBuffer(buf.MultiBuffer{header}); err != nil {
		return nil, newError("failed to write header").Base(err)
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

	if buffer[0] == CommandTunnel {
		return &buf.BufferedReader{
			Reader: r,
			Buffer: mbContainer.MultiBuffer,
		}, nil
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

	if buffer.Byte(0) != Version {
		mbContainer.Close()
		return nil, nil, newError("invalid snell version")
	}

	cmd := buffer.Byte(1)   // command
	idLen := buffer.Byte(2) // user id length
	if cmd != CommandPing && cmd != CommandConnect {
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

	buffer.Clear()
	if _, err := buffer.ReadFullFrom(mbContainer, 1); err != nil {
		mbContainer.Close()
		return nil, nil, err
	}

	hlen := int32(buffer.Byte(0))
	buffer.Clear()
	if _, err := buffer.ReadFullFrom(mbContainer, hlen+2); err != nil {
		mbContainer.Close()
		return nil, nil, err
	}
	addr := net.ParseAddress(string(buffer.BytesTo(hlen)))
	port := (int(buffer.Byte(hlen)) << 8) | int(buffer.Byte(hlen+1))
	request.Address = addr
	request.Port = net.Port(port)

	br := &buf.BufferedReader{
		Reader: r,
		Buffer: mbContainer.MultiBuffer,
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

	bw := buf.NewBufferedWriter(w)
	bw.WriteByte(CommandTunnel)
	bw.SetBuffered(false)
	return bw, nil
}

func WriteErrorResponse(user *protocol.MemoryUser, writer io.Writer, errMsg []byte) error {
	account := user.Account.(*MemoryAccount)

	w, err := initWriter(account, writer)
	if err != nil {
		return newError("failed to initialize encoding stream").Base(err).AtError()
	}

	bw := buf.NewBufferedWriter(w)
	bw.WriteByte(CommandError)
	bw.WriteByte(255)                // error code
	bw.WriteByte(uint8(len(errMsg))) // error message length
	bw.Write(errMsg)
	bw.SetBuffered(false)
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
