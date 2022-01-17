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

package gmtls

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"unicode"

	"golang.org/x/net/idna"
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
	address := canonicalAddr(req.URL)

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
	// 协议升级时，替换Body实现
	if response.StatusCode == http.StatusSwitchingProtocols {
		response.Body = conn
	}
	return response, nil
}

var portMap = map[string]string{
	"http":   "80",
	"https":  "443",
	"socks5": "1080",
}

// canonicalAddr returns url.Host but always with a ":port" suffix
// Taken from std
func canonicalAddr(url *url.URL) string {
	addr := url.Hostname()
	if v, err := idnaASCII(addr); err == nil {
		addr = v
	}
	port := url.Port()
	if port == "" {
		port = portMap[url.Scheme]
	}
	return net.JoinHostPort(addr, port)
}

func idnaASCII(v string) (string, error) {
	// TODO: Consider removing this check after verifying performance is okay.
	// Right now punycode verification, length checks, context checks, and the
	// permissible character tests are all omitted. It also prevents the ToASCII
	// call from salvaging an invalid IDN, when possible. As a result it may be
	// possible to have two IDNs that appear identical to the user where the
	// ASCII-only version causes an error downstream whereas the non-ASCII
	// version does not.
	// Note that for correct ASCII IDNs ToASCII will only do considerably more
	// work, but it will not cause an allocation.
	//
	if asciiIs(v) {
		return v, nil
	}
	return idna.Lookup.ToASCII(v)
}

// Is returns whether s is ASCII.
func asciiIs(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}
