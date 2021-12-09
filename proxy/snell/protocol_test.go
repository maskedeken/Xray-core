package snell_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	protocol "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/snell"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestPing(t *testing.T) {
	account := createSnellAccount()

	mbContainer := &buf.MultiBufferContainer{}
	defer mbContainer.Close()

	writer, err := account.NewEncryptionWriter(mbContainer)
	common.Must(err)
	common.Must(writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte{snell.Version, snell.CommandPing})))

	header, _, err := snell.ReadRequest(mbContainer, account)
	common.Must(err)
	if header.Command != protocol.RequestCommand(snell.CommandPing) {
		t.Error("wrong command: ", header.Command)
	}
}

func TestPong(t *testing.T) {
	account := createSnellAccount()

	mbContainer := &buf.MultiBufferContainer{}
	defer mbContainer.Close()

	writer, err := account.NewEncryptionWriter(mbContainer)
	common.Must(err)
	reader, err := account.NewDecryptionReader(mbContainer)
	common.Must(err)
	common.Must(snell.WriteCommand(writer, snell.CommandPong))

	_, err = snell.ReadResponse(reader)
	if err != nil {
		errStr := err.Error()
		if !strings.Contains(errStr, "supported") {
			t.Error(err)
		}
	}
}

func TestConnect(t *testing.T) {
	account := createSnellAccount()

	mbContainer := &buf.MultiBufferContainer{}
	defer mbContainer.Close()

	writer, err := account.NewEncryptionWriter(mbContainer)
	common.Must(err)

	buffer := buf.New()
	defer buffer.Release()

	destination, _ := net.ParseDestination("tcp:localhost:9968")
	w, err := snell.WriteRequest(&protocol.RequestHeader{
		Version: snell.Version,
		Address: destination.Address,
		Port:    destination.Port,
		User:    nil,
		Command: protocol.RequestCommand(snell.CommandConnect),
	}, writer)
	common.Must(err)

	sendMsg := []byte("123")
	buffer.Write(sendMsg)
	common.Must(w.WriteMultiBuffer(buf.MultiBuffer{buffer}))

	header, r, err := snell.ReadRequest(mbContainer, account)
	common.Must(err)
	if header.Command != protocol.RequestCommand(snell.CommandConnect) {
		t.Error("wrong command: ", header.Command)
	}

	if header.Address != destination.Address {
		t.Error("wrong address: ", header.Address)
	}

	mb, err := r.ReadMultiBuffer()
	common.Must(err)

	defer buf.ReleaseMulti(mb)

	recvMsg := make([]byte, len(sendMsg))
	mb.Copy(recvMsg)

	if r := cmp.Diff(sendMsg, recvMsg); r != "" {
		t.Error("data: ", r)
	}
}

func TestTunnel(t *testing.T) {
	account := createSnellAccount()

	mbContainer := &buf.MultiBufferContainer{}
	defer mbContainer.Close()

	writer, err := account.NewEncryptionWriter(mbContainer)
	common.Must(err)
	reader, err := account.NewDecryptionReader(mbContainer)
	common.Must(err)

	destination, _ := net.ParseDestination("tcp:localhost:9968")
	w, err := snell.WriteResponse(&protocol.RequestHeader{
		Version: snell.Version,
		Address: destination.Address,
		Port:    destination.Port,
		User:    nil,
		Command: protocol.RequestCommand(snell.CommandConnect),
	}, writer)

	buffer := buf.New()
	defer buffer.Release()

	sendMsg := []byte("456")
	buffer.Write(sendMsg)
	common.Must(w.WriteMultiBuffer(buf.MultiBuffer{buffer}))

	r, err := snell.ReadResponse(reader)
	common.Must(err)

	mb, err := r.ReadMultiBuffer()
	common.Must(err)

	defer buf.ReleaseMulti(mb)

	recvMsg := make([]byte, len(sendMsg))
	mb.Copy(recvMsg)

	if r := cmp.Diff(sendMsg, recvMsg); r != "" {
		t.Error("data: ", r)
	}
}

func createSnellAccount() *snell.MemoryAccount {
	return &snell.MemoryAccount{
		PSK: []byte("123456yf"),
		Cipher: &snell.SnellCipher{
			KeyBytes:        32,
			IVBytes:         16,
			AEADAuthCreator: chacha20poly1305.New,
		},
	}
}
