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

package gmcredentials

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"
	"golang.org/x/net/context"
	"google.golang.org/grpc/credentials"
)

var (
	// alpnProtoStr are the specified application level protocols for gRPC.
	alpnProtoStr = []string{"h2"}
)

// PerRPCCredentials defines the common interface for the credentials which need to
// attach security information to every RPC (e.g., oauth2).
type PerRPCCredentials interface {
	// GetRequestMetadata gets the current request metadata, refreshing
	// tokens if required. This should be called by the transport layer on
	// each request, and the data should be populated in headers or other
	// context. uri is the URI of the entry point for the request. When
	// supported by the underlying implementation, ctx can be used for
	// timeout and cancellation.
	// TODO(zhaoq): Define the set of the qualified keys instead of leaving
	// it as an arbitrary string.
	GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error)
	// RequireTransportSecurity indicates whether the credentials requires
	// transport security.
	RequireTransportSecurity() bool
}

// ProtocolInfo provides information regarding the gRPC wire protocol version,
// security protocol, security protocol version in use, server name, etc.
type ProtocolInfo struct {
	// ProtocolVersion is the gRPC wire protocol version.
	ProtocolVersion string
	// SecurityProtocol is the security protocol in use.
	SecurityProtocol string
	// SecurityVersion is the security protocol version.
	SecurityVersion string
	// ServerName is the user-configured server name.
	ServerName string
}

// AuthInfo defines the common interface for the auth information the users are interested in.
type AuthInfo interface {
	AuthType() string
}

var (
	// ErrConnDispatched indicates that rawConn has been dispatched out of gRPC
	// and the caller should not close rawConn.
	ErrConnDispatched = errors.New("credentials: rawConn is dispatched out of gRPC")
)

// TLSInfo contains the auth information for a TLS authenticated connection.
// It implements the AuthInfo interface.
type TLSInfo struct {
	State gmtls.ConnectionState
}

// AuthType returns the type of TLSInfo as a string.
func (t TLSInfo) AuthType() string {
	return "tls"
}

// tlsCreds is the credentials required for authenticating a connection using TLS.
type tlsCreds struct {
	// TLS configuration
	config *gmtls.Config
}

func (c tlsCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.2",
		ServerName:       c.config.ServerName,
	}
}

func (c *tlsCreds) ClientHandshake(ctx context.Context, addr string, rawConn net.Conn) (_ net.Conn, _ credentials.AuthInfo, err error) {
	// use local cfg to avoid clobbering ServerName if using multiple endpoints
	cfg := cloneTLSConfig(c.config)
	if cfg.ServerName == "" {
		colonPos := strings.LastIndex(addr, ":")
		if colonPos == -1 {
			colonPos = len(addr)
		}
		cfg.ServerName = addr[:colonPos]
	}
	conn := gmtls.Client(rawConn, cfg)
	errChannel := make(chan error, 1)
	go func() {
		errChannel <- conn.Handshake()
	}()
	select {
	case err := <-errChannel:
		if err != nil {
			return nil, nil, err
		}
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	return conn, TLSInfo{conn.ConnectionState()}, nil
}

func (c *tlsCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn := gmtls.Server(rawConn, c.config)
	if err := conn.Handshake(); err != nil {
		return nil, nil, err
	}
	return conn, TLSInfo{conn.ConnectionState()}, nil
}

func (c *tlsCreds) Clone() credentials.TransportCredentials {
	return NewTLS(c.config)
}

func (c *tlsCreds) OverrideServerName(serverNameOverride string) error {
	c.config.ServerName = serverNameOverride
	return nil
}

// NewTLS uses c to construct a TransportCredentials based on TLS.
func NewTLS(c *gmtls.Config) credentials.TransportCredentials {
	tc := &tlsCreds{cloneTLSConfig(c)}
	tc.config.NextProtos = alpnProtoStr
	return tc
}

// NewClientTLSFromCert constructs TLS credentials from the input certificate for client.
// serverNameOverride is for testing only. If set to a non empty string,
// it will override the virtual host name of authority (e.g. :authority header field) in requests.
func NewClientTLSFromCert(cp *x509.CertPool, serverNameOverride string) credentials.TransportCredentials {
	return NewTLS(&gmtls.Config{GMSupport: &gmtls.GMSupport{}, ServerName: serverNameOverride, RootCAs: cp})
}

// NewClientTLSFromFile constructs TLS credentials from the input certificate file for client.
// serverNameOverride is for testing only. If set to a non empty string,
// it will override the virtual host name of authority (e.g. :authority header field) in requests.
func NewClientTLSFromFile(certFile, serverNameOverride string) (credentials.TransportCredentials, error) {
	b, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("credentials: failed to append certificates")
	}
	return NewTLS(&gmtls.Config{ServerName: serverNameOverride, RootCAs: cp}), nil
}

// NewServerTLSFromCert constructs TLS credentials from the input certificate for server.
func NewServerTLSFromCert(cert *gmtls.Certificate) credentials.TransportCredentials {
	return NewTLS(&gmtls.Config{Certificates: []gmtls.Certificate{*cert}})
}

// NewServerTLSFromFile constructs TLS credentials from the input certificate file and key
// file for server.
func NewServerTLSFromFile(certFile, keyFile string) (credentials.TransportCredentials, error) {
	cert, err := gmtls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return NewTLS(&gmtls.Config{Certificates: []gmtls.Certificate{cert}}), nil
}
