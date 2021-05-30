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
	sm2SignCertPath = "gmtls/websvrcase/certs/sm2_sign_cert.cer"
	sm2SignKeyPath  = "gmtls/websvrcase/certs/sm2_sign_key.pem"
	sm2EncCertPath  = "gmtls/websvrcase/certs/sm2_enc_cert.cer"
	sm2EncKeyPath   = "gmtls/websvrcase/certs/sm2_enc_key.pem"
)

func main() {

	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)

	config := &gmtls.Config{
		GMSupport: &gmtls.GMSupport{},
		RootCAs:   certPool,
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
