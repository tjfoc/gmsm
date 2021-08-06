package websvr
import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
	"time"
	"github.com/tjfoc/gmsm/x509"

	"github.com/tjfoc/gmsm/gmtls"
)

const (
	// rsaCertPath = "certs/rsa_sign.cer"
	// rsaKeyPath  = "certs/rsa_sign_key.pem"
    rsaCacertPath="certs/rsa_CA.cer"
	// sm2SignCertPath = "certs/sm2_sign_cert.cer"
	// sm2SignKeyPath  = "certs/sm2_sign_key.pem"
	// sm2EncCertPath  = "certs/sm2_enc_cert.cer"
	// sm2EncKeyPath   = "certs/sm2_enc_key.pem"
	// SM2CaCertPath   = "certs/SM2_CA.cer"
	sm2UserCertPath ="certs/sm2_auth_cert.cer"
	sm2UserKeyPath= "certs/sm2_auth_key.pem"
)


func ServerRun() {
	//config, err := loadRsaConfig()
	//config, err := loadSM2Config()
	config, err := loadAutoSwitchConfig()
	//config, err:=loadAutoSwitchConfigClientAuth()
	if err != nil {
		panic(err)
	}

	ln, err := gmtls.Listen("tcp", ":50052", config)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "hello\n")
	})
	fmt.Println(">> HTTP Over [GMSSL/TLS] running...")
	err = http.Serve(ln, nil)
	if err != nil {
		panic(err)
	}
}
func ClientRun() {
	var config = tls.Config{
		MaxVersion:         gmtls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", "localhost:50052", &config)
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
	end <- true
}
func gmClientRun() {

	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	cert, err := gmtls.LoadX509KeyPair(sm2UserCertPath, sm2UserKeyPath)

	config := &gmtls.Config{
		GMSupport: &gmtls.GMSupport{},
		RootCAs:   certPool,
		Certificates: []gmtls.Certificate{cert},
	}

	conn, err := gmtls.Dial("tcp", "localhost:50052", config)
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
	end <- true
}

var end chan bool

func Test_tls(t *testing.T) {
	end = make(chan bool, 64)
	go ServerRun()
	time.Sleep(1000000)
	go ClientRun()
	<-end
	go gmClientRun()
	<-end
}