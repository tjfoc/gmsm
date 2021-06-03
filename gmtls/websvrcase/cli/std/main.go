package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

const (
	RSACaCertPath   = "gmtls/websvrcase/certs/RSA_CA.cer"
	RSAAuthCertPath = "gmtls/websvrcase/certs/rsa_auth_cert.cer"
	RSAAuthKeyPath  = "gmtls/websvrcase/certs/rsa_auth_key.pem"
)

// Test Run command to avoid  "certificate relies on legacy Common Name field" Error
// 双向身份认证测试 采用  GODEBUG=x509ignoreCN=0 go run main.go
func main() {
	//// 单向身份认证（只认证服务端）
	//config,err  := singleSideAuthConfig()
	//if err != nil {
	//	panic(err)
	//}
	// 双向身份认证
	config, err := bothAuthConfig()
	if err != nil {
		panic(err)
	}
	conn, err := tls.Dial("tcp", "localhost:443", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	req := []byte("GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	conn.Write(req)

	buff := make([]byte, 1024)
	for {
		n, _ := conn.Read(buff)
		if n <= 0 {
			break
		} else {
			fmt.Printf("%s", buff[0:n])
		}
	}
	fmt.Println()
}

// 获取 客户端服务端双向身份认证 配置
func bothAuthConfig() (*tls.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(RSACaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)
	authKeypair, err := tls.LoadX509KeyPair(RSAAuthCertPath, RSAAuthKeyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MaxVersion:         tls.VersionTLS12,
		RootCAs:            certPool,
		Certificates:       []tls.Certificate{authKeypair},
		InsecureSkipVerify: false,
	}, nil

}

// 获取 单向身份认证（只认证服务端） 配置
func singleSideAuthConfig() (*tls.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(RSACaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &tls.Config{
		MaxVersion: tls.VersionTLS12,
		RootCAs:    certPool,
	}, nil
}
