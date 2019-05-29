
package machine

import (

	"math/big"
	"log"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/sm4"
)

type Software struct {
}


func (p Software) ToPubKey(privp *sm2.PrivateKey) *sm2.PublicKey {
	return &privp.PublicKey
}
func (p Software) GenerateKey() (*sm2.PrivateKey, error) {
	return sm2.GenerateKey()
}
func (p Software) Sm2Encrypt(pub *sm2.PublicKey, data []byte) ([]byte, error) {
	return sm2.Encrypt(pub, data)
}
func (p Software) Sm2Decrypt(priv *sm2.PrivateKey, data []byte) ([]byte, error) {
	return sm2.Decrypt(priv, data)
}
func (p Software) Sm2Sign(priv *sm2.PrivateKey, msg, uid []byte) (r, s *big.Int, err error) {
	return sm2.Sm2Sign(priv, msg,uid)
}
func (p Software) Sm2Verify(pub *sm2.PublicKey, msg, uid []byte, r, s *big.Int) bool {
	return sm2.Sm2Verify(pub, msg,uid, r, s)
}
func (p Software) Sm3Hash(msg ...[]byte)([]byte) {
	sm3 :=&sm3.SM3{}
	sm3.Reset()
	for _, input := range msg {
		sm3.Write(input)
	}
	hash := sm3.Sum(nil)
	return hash
}
func (p Software) Sm4Encrypt(key sm4.SM4Key, data []byte) ([]byte) {
	c, err := sm4.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	d0 := make([]byte, 16)
	c.Encrypt(d0, data)
	return d0
}
func (p Software) Sm4Decrypt(key sm4.SM4Key, data []byte) ([]byte) {
	c, err := sm4.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	d1 := make([]byte, 16)
	c.Decrypt(d1, data)
	return d1

}
func(p Software) WriteKeyToPem(FileName string, key sm4.SM4Key, pwd []byte) (bool, error){
	return sm4.WriteKeyToPem(FileName,key,pwd)
}
func(p Software) ReadKeyFromPem(FileName string, pwd []byte) (sm4.SM4Key, error) {
	return sm4.ReadKeyFromPem(FileName,pwd)
}