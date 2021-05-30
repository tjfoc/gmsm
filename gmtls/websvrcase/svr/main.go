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
	config, err := loadAutoSwitchConfig()
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
	fncGetSignCertKeypair := func(info *gmtls.ClientHelloInfo) (*gmtls.Certificate, error) {
		gmFlag := false
		for _, v := range info.SupportedVersions {
			if v == gmtls.VersionGMSSL {
				gmFlag = true
				break
			}
		}

		if gmFlag {
			return &sigCert, nil
		} else {
			return &rsaKeypair, nil
		}
	}

	fncGetEncCertKeypair := func(info *gmtls.ClientHelloInfo) (*gmtls.Certificate, error) {
		return &encCert, nil
	}
	support := gmtls.NewGMSupport()
	support.EnableMixMode()
	return &gmtls.Config{
		GMSupport:        support,
		GetCertificate:   fncGetSignCertKeypair,
		GetKECertificate: fncGetEncCertKeypair,
	}, nil
}
