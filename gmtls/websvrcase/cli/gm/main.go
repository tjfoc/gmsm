package main

import (
	"fmt"
	"github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"
	"io/ioutil"
	"log"
)

const (
	SM2CaCertPath   = "gmtls/websvrcase/certs/SM2_CA.cer"
	SM2AuthCertPath = "gmtls/websvrcase/certs/sm2_auth_cert.cer"
	SM2AuthKeyPath  = "gmtls/websvrcase/certs/sm2_auth_key.pem"
)

func main() {
	// 单向身份认证
	//config,err := singleSideAuthConfig()
	//if err != nil {
	//	log.Fatal(err)
	//}

	// 双向身份认证
	config, err := bothAuthConfig()
	if err != nil {
		log.Fatal(err)
	}
	conn, err := gmtls.Dial("tcp", "localhost:443", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	req := []byte("GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	_, _ = conn.Write(req)
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
func bothAuthConfig() (*gmtls.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)
	authKeypair, err := gmtls.LoadX509KeyPair(SM2AuthCertPath, SM2AuthKeyPath)
	if err != nil {
		return nil, err
	}
	return &gmtls.Config{
		GMSupport:          &gmtls.GMSupport{},
		RootCAs:            certPool,
		Certificates:       []gmtls.Certificate{authKeypair},
		InsecureSkipVerify: false,
	}, nil

}

// 获取 单向身份认证（只认证服务端） 配置
func singleSideAuthConfig() (*gmtls.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &gmtls.Config{
		GMSupport: &gmtls.GMSupport{},
		RootCAs:   certPool,
	}, nil
}
