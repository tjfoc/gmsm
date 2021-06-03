package main

import (
	"fmt"
	"github.com/tjfoc/gmsm/gmtls"
	"log"
	"net/http"
)

func main() {
	//config, err := loadRsaConfig()
	//config, err := loadSM2Config()
	//config, err := loadAutoSwitchConfig()
	config, err := loadAutoSwitchConfigClientAuth()
	if err != nil {
		panic(err)
	}

	ln, err := gmtls.Listen("tcp", ":443", config)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "hello\n")
	})
	fmt.Println(">> HTTP Over [GMSSL/TLS] running...\n")
	err = http.Serve(ln, nil)
	if err != nil {
		panic(err)
	}
}

const (
	rsaCertPath = "gmtls/websvrcase/certs/rsa_sign.cer"
	rsaKeyPath  = "gmtls/websvrcase/certs/rsa_sign_key.pem"

	sm2SignCertPath = "gmtls/websvrcase/certs/sm2_sign_cert.cer"
	sm2SignKeyPath  = "gmtls/websvrcase/certs/sm2_sign_key.pem"
	sm2EncCertPath  = "gmtls/websvrcase/certs/sm2_enc_cert.cer"
	sm2EncKeyPath   = "gmtls/websvrcase/certs/sm2_enc_key.pem"
)

// RSA配置
func loadRsaConfig() (*gmtls.Config, error) {
	cert, err := gmtls.LoadX509KeyPair(rsaCertPath, rsaKeyPath)
	if err != nil {
		return nil, err
	}
	return &gmtls.Config{Certificates: []gmtls.Certificate{cert}}, nil
}

// SM2配置
func loadSM2Config() (*gmtls.Config, error) {
	sigCert, err := gmtls.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	if err != nil {
		return nil, err
	}
	encCert, err := gmtls.LoadX509KeyPair(sm2EncCertPath, sm2EncKeyPath)
	if err != nil {
		return nil, err
	}
	return &gmtls.Config{
		GMSupport:    &gmtls.GMSupport{},
		Certificates: []gmtls.Certificate{sigCert, encCert},
	}, nil
}

// 切换GMSSL/TSL
func loadAutoSwitchConfig() (*gmtls.Config, error) {
	rsaKeypair, err := gmtls.LoadX509KeyPair(rsaCertPath, rsaKeyPath)
	if err != nil {
		return nil, err
	}
	sigCert, err := gmtls.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	if err != nil {
		return nil, err
	}
	encCert, err := gmtls.LoadX509KeyPair(sm2EncCertPath, sm2EncKeyPath)
	if err != nil {
		return nil, err

	}
	return gmtls.NewBasicAutoSwitchConfig(&sigCert, &encCert, &rsaKeypair)
}

// 要求客户端身份认证
func loadAutoSwitchConfigClientAuth() (*gmtls.Config, error) {
	config, err := loadAutoSwitchConfig()
	if err != nil {
		return nil, err
	}
	// 设置需要客户端证书请求，标识需要进行客户端的身份认证
	config.ClientAuth = gmtls.RequireAndVerifyClientCert
	return config, nil
}
