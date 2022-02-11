// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gmtls

import (
	"crypto"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/emmansun/gmsm/sm4"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/x509"
)

const VersionGMSSL = 0x0101 // GM/T 0024-2014
const noncePrefixLength = 4 // RFC 5116 & RFC 5288

var pemCAs = []struct {
	name string
	pem  string
}{
	{
		name: "CFCA",
		pem: `-----BEGIN CERTIFICATE-----
MIICezCCAh6gAwIBAgIQJRABs1dlPn+86pb7bT74wjAMBggqgRzPVQGDdQUAMFgx
CzAJBgNVBAYTAkNOMTAwLgYDVQQKDCdDaGluYSBGaW5hbmNpYWwgQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkxFzAVBgNVBAMMDkNGQ0EgQ1MgU00yIENBMB4XDTE1MDcx
MTAzMTUxM1oXDTM1MDcwNDAzMTUxM1owJTELMAkGA1UEBhMCQ04xFjAUBgNVBAoM
DUNGQ0EgU00yIE9DQTEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAR8mpCijT4m
jIJHLSaxLZibTvrydXWlIu4r261LWKPfyhtYPKarSgxFHBTMMwRAjX0JqOjclSgY
XE6+wD5ha7dco4H6MIH3MB8GA1UdIwQYMBaAFOSO3dSj57YP7h0nls113CUlcmnd
MA8GA1UdEwEB/wQFMAMBAf8wgZMGA1UdHwSBizCBiDBVoFOgUaRPME0xCzAJBgNV
BAYTAkNOMRMwEQYDVQQKDApDRkNBIENTIENBMQwwCgYDVQQLDANDUkwxDDAKBgNV
BAsMA1NNMjENMAsGA1UEAwwEY3JsMTAvoC2gK4YpaHR0cDovL2NybC5jZmNhLmNv
bS5jbi9jc3JjYS9TTTIvY3JsMS5jcmwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQW
BBRck1ggWiRzVhAbZFAQ7OmnygdBETAMBggqgRzPVQGDdQUAA0kAMEYCIQCka+W4
lEDJGbdoQKfMyMIrwkuRjxV4fXu+CQZIsYGFnQIhAKFs1nR4OHFxsdjHPXG0CBx+
1C++KMPnVTWTsfH9fKPf
-----END CERTIFICATE-----`,
	},
	{
		name: "TEST",
		pem: `-----BEGIN CERTIFICATE-----
MIIBgTCCASegAwIBAgIRAJa6ZDaSc3wau4+2sLM2zhMwCgYIKoEcz1UBg3UwJTEL
MAkGA1UEBhMCQ04xFjAUBgNVBAoTDWNhLmNldGNzYy5jb20wHhcNMTgxMjI0MDk1
NDMyWhcNMzgxMjE5MDk1NDMyWjAlMQswCQYDVQQGEwJDTjEWMBQGA1UEChMNY2Eu
Y2V0Y3NjLmNvbTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABNzzDdS5/RMcpbYW
d+hzCdocFpSOynYzalPvPWdyINM/7AP3DKYrYKyfa4jtW5xqYTpufWUabhSkvG3C
DGBbmE6jODA2MA4GA1UdDwEB/wQEAwIChDATBgNVHSUEDDAKBggrBgEFBQcDATAP
BgNVHRMBAf8EBTADAQH/MAoGCCqBHM9VAYN1A0gAMEUCIQCsbtt9tJOtgwO6iavS
NB8Cs3U2so5gFQq6YdtX7d4EtgIgcVu9SQzlDmmmk61AaEES9UJgENmxrdhkon2T
vHTeE7Y=
-----END CERTIFICATE-----`,
	},
	{
		name: "FABRIC",
		pem: `-----BEGIN CERTIFICATE-----
MIICMDCCAdagAwIBAgIRANnwbA2SIB/k0VNSkTi7TYUwCgYIKoEcz1UBg3UwaTEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG
cmFuY2lzY28xFDASBgNVBAoTC2V4YW1wbGUuY29tMRcwFQYDVQQDEw5jYS5leGFt
cGxlLmNvbTAeFw0xODEyMjcwNzE3MzBaFw0yODEyMjQwNzE3MzBaMGkxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMRQwEgYDVQQKEwtleGFtcGxlLmNvbTEXMBUGA1UEAxMOY2EuZXhhbXBsZS5j
b20wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAARAp0oXL9xvWjkipnru0gsuL95g
jpjscT5fQw0bHXPBSzYSq0+hoJf7C3t6tzjnI6pN0156KZg8Y1Bg7fx9xxOHo18w
XTAOBgNVHQ8BAf8EBAMCAaYwDwYDVR0lBAgwBgYEVR0lADAPBgNVHRMBAf8EBTAD
AQH/MCkGA1UdDgQiBCAt1zWEo9mUfmTAZlZthCkppNjgQlpQ9A77ylguCH4tRDAK
BggqgRzPVQGDdQNIADBFAiBFx066bqQswz5eFA6IWZjj7GmdAyypq48IUaI8cs+b
AwIhAPKX+rTHK3IHmZ3MHU2ajoJcGwq0h7aWpcpljF6cld4r
-----END CERTIFICATE-----`,
	},
}

var certCAs []*x509.Certificate

var initonce sync.Once

func getCAs() []*x509.Certificate {
	// mod by syl remove pre insert ca certs
	return nil
	initonce.Do(func() {
		for _, pemca := range pemCAs {
			block, _ := pem.Decode([]byte(pemca.pem))
			ca, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				panic(err)
			}
			certCAs = append(certCAs, ca)
		}
	})
	return certCAs
}

// A list of cipher suite IDs that are, or have been, implemented by this
// package.
const (
	//GM crypto suites ID  Taken from GM/T 0024-2014
	GMTLS_ECDHE_SM2_WITH_SM1_SM3 uint16 = 0xe001
	GMTLS_SM2_WITH_SM1_SM3       uint16 = 0xe003
	GMTLS_IBSDH_WITH_SM1_SM3     uint16 = 0xe005
	GMTLS_IBC_WITH_SM1_SM3       uint16 = 0xe007
	GMTLS_RSA_WITH_SM1_SM3       uint16 = 0xe009
	GMTLS_RSA_WITH_SM1_SHA1      uint16 = 0xe00a
	GMTLS_ECDHE_SM2_WITH_SM4_SM3 uint16 = 0xe011
	GMTLS_ECDHE_SM4_CBC_SM3      uint16 = 0xe011
	GMTLS_ECDHE_SM4_GCM_SM3      uint16 = 0xe051
	GMTLS_SM2_WITH_SM4_SM3       uint16 = 0xe013
	GMTLS_ECC_SM4_CBC_SM3        uint16 = 0xe013
	GMTLS_ECC_SM4_GCM_SM3        uint16 = 0xe053
	GMTLS_IBSDH_WITH_SM4_SM3     uint16 = 0xe015
	GMTLS_IBC_WITH_SM4_SM3       uint16 = 0xe017
	GMTLS_RSA_WITH_SM4_SM3       uint16 = 0xe019
	GMTLS_RSA_WITH_SM4_SHA1      uint16 = 0xe01a
)

var gmCipherSuites = []*cipherSuite{
	{GMTLS_ECC_SM4_CBC_SM3, 16, 32, 16, eccGMKA, suiteECDSA, cipherSM4, macSM3, nil},
	{GMTLS_ECC_SM4_GCM_SM3, 16, 0, 4, eccGMKA, suiteECDSA, nil, nil, aeadSM4GCM},

	{GMTLS_ECDHE_SM4_CBC_SM3, 16, 32, 16, ecdheGMKA, suiteECDHE | suiteECDSA, cipherSM4, macSM3, nil},
	{GMTLS_ECDHE_SM4_GCM_SM3, 16, 0, 4, ecdheGMKA, suiteECDHE | suiteECDSA, nil, nil, aeadSM4GCM},
}

// aeadSM4GCM SM4 GCM向前加解密函数
// key: 对称密钥
// nonce: 隐式随机数 (implicit nonce 4 Byte)
func aeadSM4GCM(key []byte, nonce []byte) cipher.AEAD {
	if len(nonce) != noncePrefixLength {
		panic("tls: internal error: wrong implicit nonce length")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		panic(err)
	}
	// AEAD 使用的随机数应由显式和隐式两部分构成，
	// 显式部分即 nonce explicit，客户端和服务端使用隐式部分
	// 分别来自 client_write_iv 和 server_write_iv。
	// AEAD使用的随机数和计数器的构造参见 RFC 5116
	ret := &fixedNonceAEAD{aead: aead}
	copy(ret.nonce[:], nonce)
	return ret
}

func getCipherSuites(c *Config) []uint16 {
	s := c.CipherSuites
	if s == nil {
		s = []uint16{
			GMTLS_ECC_SM4_CBC_SM3,
			GMTLS_ECC_SM4_GCM_SM3,
			GMTLS_ECDHE_SM4_CBC_SM3,
			GMTLS_ECDHE_SM4_GCM_SM3,
		}
	}
	return s
}

func cipherSM4(key, iv []byte, isRead bool) interface{} {
	block, _ := sm4.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

// macSHA1 returns a macFunction for the given protocol version.
func macSM3(version uint16, key []byte) macFunction {
	return tls10MAC{hmac.New(sm3.New, key)}
}

//used for adapt the demand of finishHash write
type nilMD5Hash struct{}

func (nilMD5Hash) Write(p []byte) (n int, err error) {
	return 0, nil
}

func (nilMD5Hash) Sum(b []byte) []byte {
	return nil
}

func (nilMD5Hash) Reset() {
}

func (nilMD5Hash) Size() int {
	return 0
}

func (nilMD5Hash) BlockSize() int {
	return 0
}

func newFinishedHashGM(cipherSuite *cipherSuite) finishedHash {
	return finishedHash{sm3.New(), sm3.New(), new(nilMD5Hash), new(nilMD5Hash), []byte{}, VersionGMSSL, prf12(sm3.New)}
}

func ecdheGMKA(version uint16) keyAgreement {
	return &ecdheKeyAgreementGM{
		version: version,
	}
}

func eccGMKA(version uint16) keyAgreement {
	return &eccKeyAgreementGM{
		version: version,
	}
}

// mutualCipherSuite returns a cipherSuite given a list of supported
// ciphersuites and the id requested by the peer.
func mutualCipherSuiteGM(have []uint16, want uint16) *cipherSuite {
	for _, id := range have {
		if id == want {
			for _, suite := range gmCipherSuites {
				if suite.id == want {
					return suite
				}
			}
			return nil
		}
	}
	return nil
}

const (
	ModeGMSSLOnly  = "GMSSLOnly"  // 仅支持 国密SSL模式
	ModeAutoSwitch = "AutoSwitch" // GMSSL/TLS 自动切换模式
)

type GMSupport struct {
	WorkMode string // 工作模式
}

func NewGMSupport() *GMSupport {
	return &GMSupport{WorkMode: ModeGMSSLOnly}
}

func (support *GMSupport) GetVersion() uint16 {
	return VersionGMSSL
}

func (support *GMSupport) IsAvailable() bool {
	return true
}

func (support *GMSupport) cipherSuites() []*cipherSuite {
	return gmCipherSuites
}

// EnableMixMode 启用 GMSSL/TLS 自动切换的工作模式
func (support *GMSupport) EnableMixMode() {
	support.WorkMode = ModeAutoSwitch
}

// IsAutoSwitchMode 是否处于混合工作模式
// return true - GMSSL/TLS 均支持, false - 不处于混合模式
func (support *GMSupport) IsAutoSwitchMode() bool {
	return support.WorkMode == ModeAutoSwitch
}

// LoadGMX509KeyPairs reads and parses two public/private key pairs from pairs
// of files. The files must contain PEM encoded data. The certificate file
// may contain intermediate certificates following the leaf certificate to
// form a certificate chain. On successful return, Certificate.Leaf will
// be nil because the parsed form of the certificate is not retained.
func LoadGMX509KeyPairs(certFile, keyFile, encCertFile, encKeyFile string) (Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}
	encCertPEMBlock, err := ioutil.ReadFile(encCertFile)
	if err != nil {
		return Certificate{}, err
	}
	encKeyPEMBlock, err := ioutil.ReadFile(encKeyFile)
	if err != nil {
		return Certificate{}, err
	}

	return GMX509KeyPairs(certPEMBlock, keyPEMBlock, encCertPEMBlock, encKeyPEMBlock)
}

// add by syl add sigle key pair sitiation
func LoadGMX509KeyPair(certFile, keyFile string) (Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}

	return GMX509KeyPairsSingle(certPEMBlock, keyPEMBlock)
}

////load sign/enc certs and sign/enc privatekey from one single file respectively
//func LoadGMX509KeyPairs2(certFile, keyFile string) (Certificate, error) {
//	certPEMBlock, err := ioutil.ReadFile(certFile)
//	if err != nil {
//		return Certificate{}, err
//	}
//	keyPEMBlock, err := ioutil.ReadFile(keyFile)
//	if err != nil {
//		return Certificate{}, err
//	}
//	encCertPEMBlock, err := ioutil.ReadFile(encCertFile)
//	if err != nil {
//		return Certificate{}, err
//	}
//	encKeyPEMBlock, err := ioutil.ReadFile(encKeyFile)
//	if err != nil {
//		return Certificate{}, err
//	}
//
//	return GMX509KeyPairs(certPEMBlock, keyPEMBlock, encCertPEMBlock, encKeyPEMBlock)
//}

func getCert(certPEMBlock []byte) ([][]byte, error) {

	var certs [][]byte
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			certs = append(certs, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(certs) == 0 {
		if len(skippedBlockTypes) == 0 {
			return nil, errors.New("tls: failed to find any PEM data in certificate input")
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return nil, errors.New("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched")
		}
		return nil, fmt.Errorf("tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes)
	}
	return certs, nil
}

func getKey(keyPEMBlock []byte) (*pem.Block, error) {
	var skippedBlockTypes []string
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return nil, errors.New("tls: failed to find any PEM data in key input")
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return nil, errors.New("tls: found a certificate rather than a key in the PEM for the private key")
			}
			return nil, fmt.Errorf("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes)
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}
	return keyDERBlock, nil
}

func matchKeyCert(keyDERBlock *pem.Block, certDERBlock []byte) (crypto.PrivateKey, error) {
	// We don't need to parse the public key for TLS, but we so do anyway
	// to check that it looks sane and matches the private key.
	x509Cert, err := x509.ParseCertificate(certDERBlock)
	if err != nil {
		return nil, err
	}

	privateKey, err := parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *sm2.PublicKey:
		priv, ok := privateKey.(*sm2.PrivateKey)
		if !ok {
			return nil, errors.New("tls: private key type does not match public key type")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return nil, errors.New("tls: private key does not match public key")
		}
	default:
		return nil, errors.New("tls: unknown public key algorithm")
	}
	return privateKey, nil
}

// X509KeyPair parses a public/private key pair from a pair of
// PEM encoded data. On successful return, Certificate.Leaf will be nil because
// the parsed form of the certificate is not retained.
func GMX509KeyPairs(certPEMBlock, keyPEMBlock, encCertPEMBlock, encKeyPEMBlock []byte) (Certificate, error) {
	fail := func(err error) (Certificate, error) { return Certificate{}, err }

	var certificate Certificate

	signCerts, err := getCert(certPEMBlock)
	if err != nil {
		return certificate, err
	}
	if len(signCerts) == 0 {
		return certificate, errors.New("tls: failed to find any sign cert PEM data in cert input")
	}
	certificate.Certificate = append(certificate.Certificate, signCerts[0])

	encCerts, err := getCert(encCertPEMBlock)
	if err != nil {
		return certificate, err
	}
	if len(encCerts) == 0 {
		return certificate, errors.New("tls: failed to find any enc cert PEM data in cert input")
	}
	certificate.Certificate = append(certificate.Certificate, encCerts[0])

	keyDERBlock, err := getKey(keyPEMBlock)
	if err != nil {
		return certificate, err
	}

	certificate.PrivateKey, err = matchKeyCert(keyDERBlock, certificate.Certificate[0])
	if err != nil {
		return fail(err)
	}

	return certificate, nil
}

//one cert for enc and sign
func GMX509KeyPairsSingle(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	fail := func(err error) (Certificate, error) { return Certificate{}, err }

	var certificate Certificate

	certs, err := getCert(certPEMBlock)
	if err != nil {
		return certificate, err
	}
	if len(certs) == 0 {
		return certificate, errors.New("tls: failed to find any sign cert PEM data in cert input")
	}
	checkCert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return certificate, errors.New("tls: failed to parse certificate")
	}

	//if cert is not for GM, use default X509KeyPair
	if checkCert.PublicKeyAlgorithm != x509.SM2 {
		return X509KeyPair(certPEMBlock, keyPEMBlock)
	}

	certificate.Certificate = append(certificate.Certificate, certs[0]) //this is for sign and env

	keyDERBlock, err := getKey(keyPEMBlock)
	if err != nil {
		return certificate, err
	}

	certificate.PrivateKey, err = matchKeyCert(keyDERBlock, certificate.Certificate[0])
	if err != nil {
		return fail(err)
	}

	return certificate, nil
}
