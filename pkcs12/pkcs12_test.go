// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"encoding/base64"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"testing"
)


func Test_P12Encrypt(t *testing.T){
	str := "MIICiTCCAi6gAwIBAgIIICAEFwACVjAwCgYIKoEcz1UBg3UwdjEcMBoGA1UEAwwTU21hcnRDQV9UZXN0X1NNMl9DQTEVMBMGA1UECwwMU21hcnRDQV9UZXN0MRAwDgYDVQQKDAdTbWFydENBMQ8wDQYDVQQHDAbljZfkuqwxDzANBgNVBAgMBuaxn+iLjzELMAkGA1UEBhMCQ04wHhcNMjAwNDE3MDYwNjA4WhcNMTkwOTAzMDE1MzE5WjCBrjFGMEQGA1UELQw9YXBpX2NhX1RFU1RfVE9fUEhfUkFfVE9OR0pJX2FlNTA3MGNiY2E4NTQyYzliYmJmOTRmZjcwNThkNmEzMTELMAkGA1UEBhMCQ04xDTALBgNVBAgMBG51bGwxDTALBgNVBAcMBG51bGwxFTATBgNVBAoMDENGQ0FTTTJBR0VOVDENMAsGA1UECwwEbnVsbDETMBEGA1UEAwwKY2hlbnh1QDEwNDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAWeikXULbz1RqgmVzJWtSDMa3f9wirzwnceb1WIWxTqJaY+3xNlsM63oaIKJCD6pZu14EDkLS0FTP1uX3EySOajbTBrMAsGA1UdDwQEAwIGwDAdBgNVHQ4EFgQUbMrrNQDS1B1yjyrkgq2FWGi5zRcwHwYDVR0jBBgwFoAUXPO6JYzCZQzsZ+++3Y1rp16v46wwDAYDVR0TBAUwAwEB/zAOBggqgRzQFAQBAQQCBQAwCgYIKoEcz1UBg3UDSQAwRgIhAMcbwSDvL78qDSoqQh/019EEk4UNHP7zko0t1GueffTnAiEAupHr3k4vWSWV1SEqds+q8u4CbRuuRDvBOQ6od8vGzjM="
	decodeBytes, err := base64.StdEncoding.DecodeString(str)
	x, err := sm2.ParseCertificate(decodeBytes)
	priv, err := sm2.GenerateKey() // 生成密钥对
	if err != nil {
		fmt.Print(err)
		return
	}
	ok, err := sm2.WritePrivateKeytoPem("priv.pem", priv, nil) // 生成密钥文件
	if ok != true {
		fmt.Print(err)
		return
	}
	privKey, err := sm2.ReadPrivateKeyFromPem("priv.pem", nil) // 读取密钥
	if err!=nil{
		fmt.Print(err)
		return
	}
	SM2P12Encrypt(x,"123",privKey,"test.p12")//根据证书与私钥生成带密码的p12证书

}
func Test_P12Dncrypt(t *testing.T){
	certificate,priv,err:=SM2P12Decrypt("test.p12","123")//根据密码读取P12证书
	if err!=nil{
		fmt.Print(err)
		return
	}
	privatekey,err:=sm2.ReadPrivateKeyFromPem("priv.pem",nil)
	if err!=nil{
		fmt.Print(err)
		return
	}
	fmt.Println(certificate.Issuer)
	fmt.Println(privatekey.D.Cmp(priv.D)==0)
	fmt.Println(priv.IsOnCurve(priv.X,priv.Y))
}


