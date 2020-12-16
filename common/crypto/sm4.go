package crypto

import (
	"crypto/cipher"

	"github.com/tjfoc/gmsm/sm4"
	"v2ray.com/core/common"
)

// NewSm4DecryptionStream creates a new SM4 encryption stream based on given key and IV.
// Caller must ensure the length of key and IV is 16 bytes.
func NewSm4DecryptionStream(key []byte, iv []byte) cipher.Stream {
	return NewSm4StreamMethod(key, iv, cipher.NewCFBDecrypter)
}

// NewSm4EncryptionStream creates a new SM4 description stream based on given key and IV.
// Caller must ensure the length of key and IV is 16 bytes.
func NewSm4EncryptionStream(key []byte, iv []byte) cipher.Stream {
	return NewSm4StreamMethod(key, iv, cipher.NewCFBEncrypter)
}

func NewSm4StreamMethod(key []byte, iv []byte, f func(cipher.Block, []byte) cipher.Stream) cipher.Stream {
	block, err := sm4.NewCipher(key)
	common.Must(err)
	return f(block, iv)
}

// NewSm4CTRStream creates a stream cipher based on SM4-CTR.
func NewSm4CTRStream(key []byte, iv []byte) cipher.Stream {
	return NewSm4StreamMethod(key, iv, cipher.NewCTR)
}

// NewSm4Gcm creates a AEAD cipher based on SM4-GCM.
func NewSm4Gcm(key []byte) cipher.AEAD {
	block, err := sm4.NewCipher(key)
	common.Must(err)
	aead, err := cipher.NewGCM(block)
	common.Must(err)
	return aead
}
