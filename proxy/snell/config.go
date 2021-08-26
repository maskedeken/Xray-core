package snell

import (
	"bytes"
	"crypto/rand"
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
		KeyBytes: 32,
		IVBytes:  16,
	}

	return &MemoryAccount{
		Cipher: cipher,
		PSK:    []byte(a.Password),
	}, nil
}

func (a *MemoryAccount) NewEncryptionWriter(writer io.Writer) (buf.Writer, error) {
	var iv []byte
	if a.Cipher.IVSize() > 0 {
		iv = make([]byte, a.Cipher.IVSize())
		common.Must2(rand.Read(iv))
		if err := buf.WriteAllBytes(writer, iv); err != nil {
			return nil, newError("failed to write IV.").Base(err)
		}
	}

	return a.Cipher.NewEncryptionWriter(a.PSK, iv, writer)
}

func (a *MemoryAccount) NewDecryptionReader(reader io.Reader) (buf.Reader, error) {
	var iv []byte
	if a.Cipher.IVSize() > 0 {
		iv = make([]byte, a.Cipher.IVSize())
		if _, err := io.ReadFull(reader, iv); err != nil {
			return nil, newError("failed to read IV").Base(err)
		}
	}

	return a.Cipher.NewDecryptionReader(a.PSK, iv, reader)
}

type SnellCipher struct {
	KeyBytes int32
	IVBytes  int32
}

func (c *SnellCipher) KeySize() int32 {
	return c.KeyBytes
}

func (c *SnellCipher) IVSize() int32 {
	return c.IVBytes
}

func (c *SnellCipher) createAuthenticator(key []byte, iv []byte) (*crypto.AEADAuthenticator, error) {
	subkey := snellKDF(key, iv, c.KeySize())
	aead, err := chacha20poly1305.New(subkey)
	if err != nil {
		return nil, err
	}

	nonce := crypto.GenerateAEADNonceWithSize(aead.NonceSize())
	return &crypto.AEADAuthenticator{
		AEAD:           aead,
		NonceGenerator: nonce,
	}, nil
}

func (c *SnellCipher) NewEncryptionWriter(key []byte, iv []byte, writer io.Writer) (buf.Writer, error) {
	auth, err := c.createAuthenticator(key, iv)
	if err != nil {
		return nil, err
	}

	return crypto.NewAuthenticationWriter(auth, &crypto.AEADChunkSizeParser{
		Auth: auth,
	}, writer, protocol.TransferTypeStream, nil), nil
}

func (c *SnellCipher) NewDecryptionReader(key []byte, iv []byte, reader io.Reader) (buf.Reader, error) {
	auth, err := c.createAuthenticator(key, iv)
	if err != nil {
		return nil, err
	}

	return crypto.NewAuthenticationReader(auth, &crypto.AEADChunkSizeParser{
		Auth: auth,
	}, reader, protocol.TransferTypeStream, nil), nil
}

func snellKDF(psk, salt []byte, keySize int32) []byte {
	// snell use a special kdf function
	return argon2.IDKey(psk, salt, 3, 8, 1, 32)[:keySize]
}
