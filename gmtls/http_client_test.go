package gmtls

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/tjfoc/gmsm/x509"
)

var _ExpectRawContent = []byte("Hello World!")

// 启动HTTP测试服务器
func bootHttpServer(t *testing.T) {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write(_ExpectRawContent)
	})
	fmt.Println(">> HTTP :50053 running...")
	err := http.ListenAndServe(":50053", serveMux)
	if err != nil {
		t.Fatal(err)
	}
}

// 启动GM HTTPS测试服务器
func bootGMHTTPSServer(t *testing.T) {
	sigCert, err := LoadX509KeyPair(
		"websvr/certs/sm2_sign_cert.cer",
		"websvr/certs/sm2_sign_key.pem")
	if err != nil {
		t.Fatal(err)
	}
	encCert, err := LoadX509KeyPair(
		"websvr/certs/sm2_enc_cert.cer",
		"websvr/certs/sm2_enc_key.pem")
	if err != nil {
		t.Fatal(err)
	}
	config := &Config{
		GMSupport:          &GMSupport{},
		Certificates:       []Certificate{sigCert, encCert},
		InsecureSkipVerify: true,
	}
	if err != nil {
		panic(err)
	}

	ln, err := Listen("tcp", ":50054", config)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write(_ExpectRawContent)
	})
	fmt.Println(">> HTTP :50054 [GMSSL] running...")
	err = http.Serve(ln, serveMux)
	if err != nil {
		t.Fatal(err)
	}
}

// 启动GM HTTPS测试服务器 双向身份认证
func bootGMAuthHTTPSServer(t *testing.T) {
	sigCert, err := LoadX509KeyPair(
		"websvr/certs/sm2_sign_cert.cer",
		"websvr/certs/sm2_sign_key.pem")
	if err != nil {
		t.Fatal(err)
	}
	encCert, err := LoadX509KeyPair(
		"websvr/certs/sm2_enc_cert.cer",
		"websvr/certs/sm2_enc_key.pem")
	if err != nil {
		t.Fatal(err)
	}

	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile("websvr/certs/SM2_CA.cer")
	if err != nil {
		t.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)

	config := &Config{
		GMSupport:    &GMSupport{},
		Certificates: []Certificate{sigCert, encCert},
		ClientAuth:   RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}
	if err != nil {
		panic(err)
	}

	ln, err := Listen("tcp", ":50055", config)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write(_ExpectRawContent)
	})
	fmt.Println(">> HTTP :50055 [GMSSL] Client Auth running...")
	err = http.Serve(ln, serveMux)
	if err != nil {
		t.Fatal(err)
	}
}

// HTTP 客户端连接测试
func TestSimpleNewHTTPSClient1(t *testing.T) {
	go bootHttpServer(t)
	//go bootGMHTTPSServer(t)
	/*
		HTTP 连接测试
	*/
	time.Sleep(time.Second)
	httpClient := NewCustomHTTPSClient(nil)
	response, err := httpClient.Get("http://localhost:50053")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, _ExpectRawContent) {
		t.Fatalf(">> HTTP响应内容与期待内容不符, expect %s, actual: %s", string(_ExpectRawContent), string(raw))
	}
}

// GM HTTPS 客户端连接测试
func TestNewHTTPSClient2(t *testing.T) {
	go bootGMHTTPSServer(t)
	/*
		GM HTTPS 连接测试
	*/
	time.Sleep(time.Second)
	// 信任的根证书

	config, err := createClientGMTLSConfig("", "", []string{"websvr/certs/SM2_CA.cer"})
	if err != nil {
		t.Fatal(err)
	}
	httpClient := NewCustomHTTPSClient(config)
	response, err := httpClient.Get("https://localhost:50054")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, _ExpectRawContent) {
		t.Fatalf(">> GM HTTPS响应内容与期待内容不符, expect %s, actual: %s", string(_ExpectRawContent), string(raw))
	}
}

// GM HTTPS 客户端连接测试 双向身份认证
func TestNewHTTPSClient3(t *testing.T) {
	go bootGMAuthHTTPSServer(t)
	/*
		GM HTTPS 双向身份认证
	*/
	time.Sleep(time.Second)

	config, err := createClientGMTLSConfig("websvr/certs/sm2_auth_key.pem", "websvr/certs/sm2_auth_cert.cer", []string{"websvr/certs/SM2_CA.cer"})
	if err != nil {
		t.Fatal(err)
	}
	httpClient := NewCustomHTTPSClient(config)

	response, err := httpClient.Get("https://localhost:50055")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, _ExpectRawContent) {
		t.Fatalf(">> GM HTTPS响应内容与期待内容不符, expect %s, actual: %s", string(_ExpectRawContent), string(raw))
	}
}

func createClientGMTLSConfig(keyPath string, certPath string, caPaths []string) (*Config, error) {

	cfg := &Config{
		GMSupport: &GMSupport{},
	}
	cfg.Certificates = []Certificate{}
	if keyPath != "" && certPath != "" {
		cert, err := LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load gm X509 keyPair error: %v", err)
		}
		cfg.Certificates = append(cfg.Certificates, cert)
	}

	var pool *x509.CertPool = nil
	if len(caPaths) > 0 {
		pool = x509.NewCertPool()
		for _, certPath := range caPaths {
			caCrt, err := ioutil.ReadFile(certPath)
			if err != nil {
				return nil, err
			}
			ok := pool.AppendCertsFromPEM(caCrt)
			if !ok {
				return nil, fmt.Errorf("append cert to pool fail at %s", certPath)
			}
		}
	}

	cfg.MinVersion = VersionGMSSL
	cfg.MaxVersion = VersionTLS12

	cfg.PreferServerCipherSuites = true
	// cfg.CipherSuites use default value []uint16{GMTLS_SM2_WITH_SM4_SM3, GMTLS_ECDHE_SM2_WITH_SM4_SM3}

	cfg.RootCAs = pool
	// cfg.ServerName = "localhost"
	cfg.InsecureSkipVerify = false

	return cfg, nil

}
