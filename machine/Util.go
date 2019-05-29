package machine

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"net"
)

type Client struct {
	addr string
}

func (c *Client) cCoonHandler(data []byte) ([]byte, error) {
	coon, err := net.Dial("tcp", c.addr)
	if err != nil {
		fmt.Println("客户端建立连接失败")
		return nil, err
	}
	buf := make([]byte, 1024)
	defer coon.Close()
	coon.Write(data)
	cnt, err := coon.Read(buf)
	if err != nil {
		fmt.Printf("客户端读取数据失败%s\n", err)
		return nil, err
	}
	fmt.Print("服务器端回复" + string(buf[0:cnt]))
	return buf, nil
}

func ClientSocket(address string, data []byte) (response []byte, err error) {
	Client := &Client{addr: address}
	response, err = Client.cCoonHandler(data)
	return
}

func LenTo2byte(num int) []byte {
	var buffer bytes.Buffer
	var v2 uint32
	b2 := make([]byte, 2)
	v2 = uint32(num)
	b2[1] = uint8(v2)
	b2[0] = uint8(v2 >> 8)
	buffer.Write(b2)
	return buffer.Bytes()
}
func LenTo4byte(num int) []byte {
	var buffer bytes.Buffer
	var v4 uint64
	b4 := make([]byte, 4)
	v4 = uint64(num)
	b4[3] = uint8(v4)
	b4[2] = uint8(v4 >> 8)
	b4[1] = uint8(v4 >> 16)
	b4[0] = uint8(v4 >> 24)
	buffer.Write(b4)
	return buffer.Bytes()
}
func Length(data []byte) []byte {
	return LenTo2byte(len(data))
}
func BytesToInt(b []byte) *big.Int {
	i := new(big.Int)
	i.SetBytes(b)
	return i
}
//加密机无法提供私钥明文，私钥D中存放私钥编号及密钥
func AdaptPriv(privD *big.Int) (int, []byte, error) {
	private := privD.Bytes()
	length := len(private)
	var num int
	var key []byte
	switch length {
	case 10:
		num = int(private[1])
		num += int(private[0]) << 8
		key = private[2:10]
	case 9:
		num = int(private[0])
		key = private[1:9]
	default:
		err := errors.New("传入私钥长度不对")
		return 0, nil, err
	}
	return num, key, nil
}
