package snell

import (
	"bytes"
	"crypto/cipher"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	protocol "github.com/xtls/xray-core/common/protocol"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// MemoryAccount is an account type converted from Account.
type MemoryAccount struct {
	Cipher *SnellCipher
	PSK    []byte
}

// Equals implements protocol.Account.Equals().
func (a *MemoryAccount) Equals(another protocol.Account) bool {
	if account, ok := another.(*MemoryAccount); ok {
		return bytes.Equal(a.PSK, account.PSK)
	}
	return false
}

// AsAccount implements protocol.AsAccount.
func (a *Account) AsAccount() (protocol.Account, error) {
	cipher := &SnellCipher{
		KeyBytes:        32,
		IVBytes:         16,
		AEADAuthCreator: createChacha20Poly1305,
	}

	return &MemoryAccount{
		Cipher: cipher,
		PSK:    []byte(a.Password),
	}, nil
}

func createChacha20Poly1305(key []byte) cipher.AEAD {
	chacha20, err := chacha20poly1305.New(key)
	common.Must(err)
	return chacha20
}

type SnellCipher struct {
	KeyBytes        int32
	IVBytes         int32
	AEADAuthCreator func(key []byte) cipher.AEAD
}

func (*SnellCipher) IsAEAD() bool {
	return true
}

func (c *SnellCipher) KeySize() int32 {
	return c.KeyBytes
}

func (c *SnellCipher) IVSize() int32 {
	return c.IVBytes
}

func (c *SnellCipher) createAuthenticator(key []byte, iv []byte) *crypto.AEADAuthenticator {
	subkey := snellKDF(key, iv, c.KeySize())
	aead := c.AEADAuthCreator(subkey)
	nonce := crypto.GenerateAEADNonceWithSize(aead.NonceSize())
	return &crypto.AEADAuthenticator{
		AEAD:           aead,
		NonceGenerator: nonce,
	}
}

func (c *SnellCipher) NewEncryptionWriter(key []byte, iv []byte, writer io.Writer) (buf.Writer, error) {
	auth := c.createAuthenticator(key, iv)
	return crypto.NewAuthenticationWriter(auth, &crypto.AEADChunkSizeParser{
		Auth: auth,
	}, writer, protocol.TransferTypeStream, nil), nil
}

func (c *SnellCipher) NewDecryptionReader(key []byte, iv []byte, reader io.Reader) (buf.Reader, error) {
	auth := c.createAuthenticator(key, iv)
	return crypto.NewAuthenticationReader(auth, &crypto.AEADChunkSizeParser{
		Auth: auth,
	}, reader, protocol.TransferTypeStream, nil), nil
}

func (c *SnellCipher) EncodePacket(key []byte, b *buf.Buffer) error {
	ivLen := c.IVSize()
	payloadLen := b.Len()
	auth := c.createAuthenticator(key, b.BytesTo(ivLen))

	b.Extend(int32(auth.Overhead()))
	_, err := auth.Seal(b.BytesTo(ivLen), b.BytesRange(ivLen, payloadLen))
	return err
}

func (c *SnellCipher) DecodePacket(key []byte, b *buf.Buffer) error {
	if b.Len() <= c.IVSize() {
		return newError("insufficient data: ", b.Len())
	}
	ivLen := c.IVSize()
	payloadLen := b.Len()
	auth := c.createAuthenticator(key, b.BytesTo(ivLen))

	bbb, err := auth.Open(b.BytesTo(ivLen), b.BytesRange(ivLen, payloadLen))
	if err != nil {
		return err
	}
	b.Resize(ivLen, int32(len(bbb)))
	return nil
}

func snellKDF(psk, salt []byte, keySize int32) []byte {
	// snell use a special kdf function
	return argon2.IDKey(psk, salt, 3, 8, 1, 32)[:keySize]
}
