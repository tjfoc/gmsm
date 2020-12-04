package gmcredentials

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"testing"
	"time"

	"github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/gmtls/gmcredentials/echo"
	"github.com/tjfoc/gmsm/x509"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	port    = ":50051"
	address = "localhost:50051"
)

var end chan bool

type server struct{}

func (s *server) Echo(ctx context.Context, req *echo.EchoRequest) (*echo.EchoResponse, error) {
	return &echo.EchoResponse{Result: req.Req}, nil
}

const ca = "testdata/ca.cert"
const signCert = "testdata/sign.cert"
const signKey = "testdata/sign.key"
const encryptCert = "testdata/encrypt.cert"
const encryptKey = "testdata/encrypt.key"

const userCert = "testdata/user.cert"
const userKey = "testdata/user.key"

func serverRun() {
	signCert, err := gmtls.LoadX509KeyPair(signCert, signKey)
	if err != nil {
		log.Fatal(err)
	}

	encryptCert, err := gmtls.LoadX509KeyPair(encryptCert, encryptKey)
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(ca)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("fail to listen: %v", err)
	}
	creds := NewTLS(&gmtls.Config{
		GMSupport:    &gmtls.GMSupport{},
		ClientAuth:   gmtls.RequireAndVerifyClientCert,
		Certificates: []gmtls.Certificate{signCert, encryptCert},
		ClientCAs:    certPool,
	})
	s := grpc.NewServer(grpc.Creds(creds))
	echo.RegisterEchoServer(s, &server{})
	err = s.Serve(lis)
	if err != nil {
		log.Fatalf("Serve: %v", err)
	}
}

func clientRun() {
	cert, err := gmtls.LoadX509KeyPair(userCert, userKey)
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(ca)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	creds := NewTLS(&gmtls.Config{
		GMSupport:    &gmtls.GMSupport{},
		ServerName:   "test.example.com",
		Certificates: []gmtls.Certificate{cert},
		RootCAs:      certPool,
		ClientAuth:   gmtls.RequireAndVerifyClientCert,
	})
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("cannot to connect: %v", err)
	}
	defer conn.Close()
	c := echo.NewEchoClient(conn)
	echoTest(c)
	end <- true
}

func echoTest(c echo.EchoClient) {
	r, err := c.Echo(context.Background(), &echo.EchoRequest{Req: "hello"})
	if err != nil {
		log.Fatalf("failed to echo: %v", err)
	}
	fmt.Printf("%s\n", r.Result)
}

func Test(t *testing.T) {
	end = make(chan bool, 64)
	go serverRun()
	time.Sleep(1000000)
	go clientRun()
	<-end
}
