package gmtls

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

// SimpleRoundTripper 简单的单次HTTP/HTTPS（国密） 连接往返器
// 每次建立新的连接
type SimpleRoundTripper struct {
	lock      sync.Mutex
	tlsConfig *Config
}

func NewSimpleRoundTripper(cfg *Config) *SimpleRoundTripper {
	return &SimpleRoundTripper{tlsConfig: cfg}
}

func (s *SimpleRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// 加锁保证线程安全
	s.lock.Lock()
	defer s.lock.Unlock()

	scheme := req.URL.Scheme
	isHTTP := scheme == "http" || scheme == "https"
	if !isHTTP {
		return nil, fmt.Errorf("仅支持http/https协议")
	}

	// 获取主机名 和 端口
	hostname := req.URL.Hostname()
	port := req.URL.Port()
	address := net.JoinHostPort(hostname, port)

	var conn io.ReadWriteCloser
	var err error
	// 根据协议建立连接
	if scheme == "http" {
		// HTTP 协议建立TCP连接
		conn, err = net.Dial("tcp", address)
		if err != nil {
			return nil, err
		}
	} else {
		// HTTPS 协议建立TLS连接
		conn, err = Dial("tcp", address, s.tlsConfig)
		if err != nil {
			return nil, err
		}
	}
	defer conn.Close()

	// 把请求写入连接中，发起请求
	err = req.Write(conn)
	if err != nil {
		return nil, err
	}
	// 从连接中读取
	response, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	return response, nil
}
