/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sm2

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

func TestSm2(t *testing.T) {
	priv, err := GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	ok, err := WritePrivateKeytoPem("priv.pem", priv, []byte("123456")) // 生成密钥文件
	if ok != true {
		log.Fatal(err)
	}
	data, err := WritePrivateKeytoMem(priv, []byte("123456"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("priv data+++++++++++++++++\n%v\n++++++++++++++\n", data)
	_, err = ReadPrivateKeyFromPem("priv.pem", []byte("123456")) // 读取密钥
	if err != nil {
		log.Fatal(err)
	}
	priv, err = ReadPrivateKeyFromPem("priv.pem", []byte("123456")) // 读取密钥
	if err != nil {
		log.Fatal(err)
	}
	ok, err = WritePublicKeytoPem("pub.pem", priv.Public(), nil) // 生成证书文件
	if ok != true {
		log.Fatal(err)
	}
	data, err = WritePublicKeytoMem(priv.Public(), nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("public data+++++++++++\n%v\n+++++++++++++++\n", data)
	privKey, err := ReadPrivateKeyFromPem("priv.pem", []byte("123456")) // 读取密钥
	if err != nil {
		log.Fatal(err)
	}
	pubKey, err := ReadPublicKeyFromPem("pub.pem", nil) // 读取公钥
	if err != nil {
		log.Fatal(err)
	}
	msg := []byte("test")
	err = ioutil.WriteFile("ifile", msg, os.FileMode(0644)) // 生成测试文件
	if err != nil {
		log.Fatal(err)
	}
	msg, _ = ioutil.ReadFile("ifile")
	sign, err := privKey.Sign(msg) // 签名
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ofile", sign, os.FileMode(0644))
	if err != nil {
		log.Fatal(err)
	}
	signdata, _ := ioutil.ReadFile("ofile")
	ok = privKey.Verify(msg, signdata) // 密钥验证
	if ok != true {
		fmt.Printf("Verify error")
	} else {
		fmt.Printf("Verify ok")
	}
	ok = pubKey.Verify(msg, signdata) // 公钥验证
	if ok != true {
		fmt.Printf("Verify error")
	} else {
		fmt.Printf("Verify ok")
	}
}
