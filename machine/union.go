package machine

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

type Union struct {
	Software
}

//加密机套连接地址
const Address string = "127.0.0.1:8087"

func (p Union) ToPubKey(priv *sm2.PrivateKey) *sm2.PublicKey {
	privNum, key, err := AdaptPriv(priv.D)
	if err != nil {
		return nil
	}
	response, err := exportPub(privNum, key)
	if err != nil {
		return nil
	}
	x := response[1:33]
	y := response[33 : 33+32]
	publickey := new(sm2.PublicKey)
	c := sm2.P256Sm2()
	publickey.Curve = c
	publickey.X = BytesToInt(x)
	publickey.Y = BytesToInt(y)
	return publickey

}
func (p Union) GenerateKey() (*sm2.PrivateKey, error) {
	b := big.NewInt(100)
	i, err := rand.Int(rand.Reader, b)
	result := i.Int64()
	privNum := int(result)
	key := []byte("01234567")
	response, err := generateKey(privNum, key)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	privLen := uint(response[0]) << 2
	privLen |= uint(response[1])
	x := response[3+privLen : 3+privLen+32]
	y := response[35+privLen : 35+privLen+32]
	var buffer bytes.Buffer
	buffer.Write(LenTo2byte(privNum))
	buffer.Write(key)
	privateKey := new(sm2.PrivateKey)
	c := sm2.P256Sm2()
	privateKey.PublicKey.Curve = c
	privateKey.D = BytesToInt(buffer.Bytes())
	privateKey.X = BytesToInt(x)
	privateKey.Y = BytesToInt(y)
	return privateKey, nil
}
func (p Union) Sm2Encrypt(pub *sm2.PublicKey, data []byte) ([]byte, error) {
	return sm2EncryPub(pub, data)
}

//私钥D中存放私钥编号与密码
func (p Union) Sm2Decrypt(priv *sm2.PrivateKey, data []byte) ([]byte, error) {
	privNum, key, err := AdaptPriv(priv.D)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return sm2Decrypt(privNum, key, data)
}
func (p Union) Sm2Sign(priv *sm2.PrivateKey, msg, uid []byte) (r, s *big.Int, err error) {
	privNum, key, err := AdaptPriv(priv.D)
	if err != nil {
		return nil, nil, err
	}
	response, err := sm2Sign(privNum, key, uid, msg)
	if err != nil {
		return nil, nil, err
	}
	r = BytesToInt(response[1:33])
	s = BytesToInt(response[33 : 33+32])
	return r, s, nil
}

func (p Union) Sm2Verify(pub *sm2.PublicKey, msg, uid []byte, r, s *big.Int) bool {
	var priv *sm2.PrivateKey
	privNum, key, err := AdaptPriv(priv.D)
	if err != nil {
		fmt.Println(err)
		return false
	}
	var buffer bytes.Buffer
	buffer.Write(r.Bytes())
	buffer.Write(s.Bytes())
	signdata := buffer.Bytes()
	verify, err := sm2Verify(privNum, key, signdata, uid, msg)
	if err != nil {
		fmt.Println(err)
		return false
	}
	return verify
}
func (p Union) Sm3Hash(msg ...[]byte) []byte {
	var buffer bytes.Buffer
	for _, input := range msg {
		buffer.Write(input)
	}
	hash, _ := sm3Hash(buffer.Bytes())
	return hash
}

func exportPub(priNum int, key []byte) ([]byte, error) {
	var err error
	var buffer bytes.Buffer
	buffer.Write([]byte{0xE1, 0xB0, 0x01})
	buffer.Write(LenTo2byte(priNum))
	buffer.Write(key)
	buffer.Write([]byte{0x07})
	response, err := ClientSocket(Address, buffer.Bytes())
	if err != nil {
		return nil, err
	}
	if len(response) == 2 {
		err = errors.New("私钥导出公钥失败")
		return nil, err
	}
	return response, nil
}
func sm2Sign(priNum int, key, uid, data []byte) ([]byte, error) {
	var err error
	var buffer bytes.Buffer
	buffer.Write([]byte{0xD3, 0x06})
	buffer.Write(LenTo2byte(priNum))
	if len(key) != 8 {
		err = errors.New("密钥口令长度不为8")
		return nil, err
	}
	buffer.Write(key)
	buffer.Write([]byte{0x02}) //sm3Hash
	buffer.Write(Length(uid))
	buffer.Write(uid)
	buffer.Write(Length(data))
	buffer.Write(data)
	response, err := ClientSocket(Address, buffer.Bytes())
	if err != nil {
		fmt.Println("签名失败")
		return nil, err
	}
	if len(response) == 2 {

		err = errors.New("签名失败")
		return nil, err
	}
	//TODO
	return response, nil
}
func sm2Verify(privNum int, key, signdata, uid, data []byte) (bool, error) {
	var err error
	var buffer bytes.Buffer
	buffer.Write([]byte{0xD3, 0x07})
	buffer.Write(LenTo2byte(privNum))
	if len(signdata) != 65 {
		err = errors.New("签名数据长度不正确")
		return false, err
	}
	r := signdata[1 : 32+1]
	s := signdata[33 : 33+32]
	if len(key) != 8 {
		err = errors.New("密钥口令长度不为8")
		return false, err
	}
	buffer.Write(key)
	buffer.Write(r)
	buffer.Write(s)
	buffer.Write([]byte{0x02})
	buffer.Write(Length(uid))
	buffer.Write(uid)
	buffer.Write(Length(data))
	buffer.Write(data)
	//TODO
	response, err := ClientSocket(Address, buffer.Bytes())
	if err != nil {
		fmt.Println("验证失败")
		return false, err
	}
	if len(response) == 1 {
		return true, nil
	} else {
		err = errors.New("验证失败")
		return false, err
	}
}
func sm2Encrypt(privNum int, key, data []byte) ([]byte, error) {
	var buffer bytes.Buffer
	var err error
	buffer.Write([]byte{0xD3, 0x08})
	buffer.Write(LenTo2byte(privNum))
	if len(key) != 8 {
		err = errors.New("密钥口令长度不为8")
		return nil, err
	}
	buffer.Write(key)
	buffer.Write(LenTo4byte(len(data)))
	buffer.Write(data)
	//TODO
	response, err := ClientSocket(Address, buffer.Bytes())
	if err != nil {
		fmt.Println("SM2公钥加密失败")
		return nil, err
	}
	if len(response) == 2 {
		err = errors.New("SM2公钥加密失败")
		return nil, err
	}
	return response, nil
}
func sm2EncryPub(pub *sm2.PublicKey, data []byte) ([]byte, error) {
	var buffer bytes.Buffer
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	buffer.Write([]byte{0xD3, 0x08, 0xFF, 0xFF})
	if len(x) != 32 || len(y) != 32 {
		err := errors.New("公钥位数不对")
		return nil, err
	}
	buffer.Write(x)
	buffer.Write(y)
	buffer.Write(LenTo4byte(len(data)))
	buffer.Write(data)
	response, err := ClientSocket(Address, buffer.Bytes())
	if err != nil {
		fmt.Println("SM2私钥解密失败")
		return nil, err
	}
	if len(response) == 2 {
		err := errors.New("SM2公钥加密失败")
		return nil, err
	}
	return response, nil
}
func sm2Decrypt(privNum int, key, data []byte) ([]byte, error) {
	var err error
	var buffer bytes.Buffer
	buffer.Write([]byte{0xD3, 0x09})
	buffer.Write(LenTo2byte(privNum))
	if len(key) != 8 {
		err = errors.New("密钥口令长度不为8")
		return nil, err
	}
	buffer.Write(key)
	buffer.Write(LenTo4byte(len(data)))
	buffer.Write(data)
	//TODO
	response, err := ClientSocket(Address, buffer.Bytes())
	if err != nil {
		fmt.Println("SM2私钥解密失败")
		return nil, err
	}
	if len(response) == 2 {
		err = errors.New("SM2私钥解密失败")
		return nil, err
	}
	return response, nil
}

func generateKey(privNum int, key []byte) ([]byte, error) {
	var buffer bytes.Buffer
	var err error
	buffer.Write([]byte{0xD3, 0x02, 0x07})
	buffer.Write(LenTo2byte(256))
	buffer.Write(LenTo2byte(privNum))
	if len(key) != 8 {
		err = errors.New("密钥口令长度不为8")
		return nil, err
	}
	buffer.Write(key)
	response, err := ClientSocket(Address, buffer.Bytes())
	if err != nil {
		fmt.Println("生成密钥对失败")
		return nil, err
	}
	if len(response) == 2 {
		err = errors.New("生成密钥对失败")
		return nil, err
	}
	return response, nil
}

//前两位为数据长度，之后为hash值
func sm3Hash(data []byte) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.Write([]byte{0xD3, 0x0A, 0x06})
	buffer.Write(Length(data))
	buffer.Write(data)
	fmt.Println(hex.EncodeToString(buffer.Bytes()))
	response, err := ClientSocket(Address, buffer.Bytes())
	if err != nil {
		err := errors.New("sm3哈希失败")
		return nil, err
	}
	a := []byte("chenxutest")
	//	var response []byte
	response = []byte{0x00, 0x0A}
	response = append(response, a...)
	resLen := len(response)
	if resLen == 2 {
		err := errors.New("sm3哈希失败")
		return nil, err
	}
	hashlen := uint(response[0]) << 2
	hashlen |= uint(response[1])
	hash := response[2 : hashlen+2]
	fmt.Println(hex.EncodeToString(hash))
	return hash, nil
}
