
package machine

import (
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"math/big"
	)


type Factory struct {
	sm2Product
	sm3Product
	sm4Product
}

type sm2Product interface {
	ToPubKey(key *sm2.PrivateKey) (pub *sm2.PublicKey)
	GenerateKey() (*sm2.PrivateKey, error)
	Sm2Encrypt(*sm2.PublicKey, []byte) ([]byte, error)
	Sm2Decrypt(priv *sm2.PrivateKey, data []byte) ([]byte, error)
	Sm2Sign(priv *sm2.PrivateKey, msg, uid []byte) (r, s *big.Int, err error)
	Sm2Verify(pub *sm2.PublicKey, msg, uid []byte, r, s *big.Int) bool
}
type sm3Product interface {
	Sm3Hash(msg ...[]byte) ([]byte)
}
type sm4Product interface {
	Sm4Encrypt(key sm4.SM4Key, data []byte) ([]byte)
	Sm4Decrypt(key sm4.SM4Key, data []byte) ([]byte)
	WriteKeyToPem(FileName string, key sm4.SM4Key, pwd []byte) (bool, error)
	ReadKeyFromPem(FileName string, pwd []byte) (sm4.SM4Key, error)
}

func GetMachine(sm2type sm2Product, sm3type sm3Product, sm4type sm4Product ) (Factory) {
	return Factory{sm2type, sm3type, sm4type}
}

