package x509

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

func ReadPrivateKeyFromPem(privateKeyPem []byte, pwd []byte) (*sm2.PrivateKey, error) {
	var block *pem.Block
	block, _ = pem.Decode(privateKeyPem)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}
	priv, err := ParsePKCS8PrivateKey(block.Bytes, pwd)
	return priv, err
}

func WritePrivateKeyToPem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	var block *pem.Block
	der, err := MarshalSm2PrivateKey(key, pwd) //Convert private key to DER format
	if err != nil {
		return nil, err
	}
	if pwd != nil {
		block = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: der,
		}
	} else {
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}

func ReadPublicKeyFromPem(publicKeyPem []byte) (*sm2.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPem)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}
	return ParseSm2PublicKey(block.Bytes)
}

func WritePublicKeyToPem(key *sm2.PublicKey) ([]byte, error) {
	der, err := MarshalSm2PublicKey(key) //Convert publick key to DER format
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}

//DHex是sm2私钥的真正关键数值
func ReadPrivateKeyFromDhex(privateKeyFromDhex string) (*sm2.PrivateKey) {
	c := sm2.P256Sm2()
	k, _ := new(big.Int).SetString(privateKeyFromDhex, 16)
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv
}


//DHex是sm2私钥的关键数值
func WritePrivateKeyToDhex(key *sm2.PrivateKey) string {
	return key.D.Text(16)
}

//QHex是sm2公钥的关键数值，由04+pub.X+pub.Y组成
func ReadPublicKeyFromQhex(publicKeyFromQhex string) (*sm2.PublicKey, error) {
	if len(publicKeyFromQhex) == 130{
		publicKeyFromQhex = publicKeyFromQhex[2:]
	} else {
		return nil, errors.New("Decrypt: failed to decrypt")
	}
	pub := new(sm2.PublicKey)
	pub.Curve = sm2.P256Sm2()
	pub.X, _ = new(big.Int).SetString(publicKeyFromQhex[:64], 16)
	pub.Y, _ = new(big.Int).SetString(publicKeyFromQhex[64:], 16)
	return pub, nil
}

//QHex是sm2公钥的关键数值，由04+pub.X+pub.Y组成
func WritePublicKeyToQhex(key *sm2.PublicKey) string {
	x := key.X.Text(16)
	y := key.Y.Text(16)
	for len(x) < 64 {
		x = "0" + x;
	}
	for len(y) < 64 {
		y = "0" + y;
	}
	return "04" + x + y
}

//kxz:为了和openssl互通而设立的，该pem是p8格式的一部分，openssl命令行参考：openssl ecparam -genkey -name SM2 -out priv.key
func ReadPrivateKeyFromOpenSSLPem(privateKeyPem []byte) (*sm2.PrivateKey, error) {
	var block *pem.Block
	block, _ = pem.Decode(privateKeyPem)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}
	priv, err := ParseSm2PrivateKey(block.Bytes)
	return priv, err
}

//kxz:为了和openssl互通而设立的，该pem是p8格式的一部分，openssl命令行参考：openssl ecparam -genkey -name SM2 -out priv.key
func WritePrivateKeyToOpenSSLPem(key *sm2.PrivateKey) ([]byte, error) {
	//x509\pkcs8.go中没有相关代码，这里直接进行实现
	var priv sm2PrivateKey
	priv.Version = 1
	priv.NamedCurveOID = oidNamedCurveP256SM2
	priv.PublicKey = asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)}
	priv.PrivateKey = key.D.Bytes()
	der, err := asn1.Marshal(priv)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}



func ReadCertificateRequestFromPem(certPem []byte) (*CertificateRequest, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificateRequest(block.Bytes)
}

func CreateCertificateRequestToPem(template *CertificateRequest, signer crypto.Signer) ([]byte, error) {
	der, err := CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}

func ReadCertificateFromPem(certPem []byte) (*Certificate, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificate(block.Bytes)
}

// CreateCertificate creates a new certificate based on a template. The
// following members of template are used: SerialNumber, Subject, NotBefore,
// NotAfter, KeyUsage, ExtKeyUsage, UnknownExtKeyUsage, BasicConstraintsValid,
// IsCA, MaxPathLen, SubjectKeyId, DNSNames, PermittedDNSDomainsCritical,
// PermittedDNSDomains, SignatureAlgorithm.
//
// The certificate is signed by parent. If parent is equal to template then the
// certificate is self-signed. The parameter pub is the public key of the
// signee and priv is the private key of the signer.
//
// The returned slice is the certificate in DER encoding.
//
// All keys types that are implemented via crypto.Signer are supported (This
// includes *rsa.PublicKey and *ecdsa.PublicKey.)
func CreateCertificate(template, parent *Certificate, publicKey *sm2.PublicKey, signer crypto.Signer) ([]byte, error) {
	if template.SerialNumber == nil {
		return nil, errors.New("x509: no SerialNumber given")
	}

	hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(signer.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return nil, err
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
		template.AuthorityKeyId = parent.SubjectKeyId
	}

	extensions, err := buildExtensions(template)
	if err != nil {
		return nil, err
	}
	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	c := tbsCertificate{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: signatureAlgorithm,
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
		Extensions:         extensions,
	}

	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return nil, err
	}

	c.Raw = tbsCertContents

	digest := tbsCertContents
	switch template.SignatureAlgorithm {
	case SM2WithSM3, SM2WithSHA1, SM2WithSHA256:
		break
	default:
		h := hashFunc.New()
		h.Write(tbsCertContents)
		digest = h.Sum(nil)
	}

	var signerOpts crypto.SignerOpts
	signerOpts = hashFunc
	if template.SignatureAlgorithm != 0 && template.SignatureAlgorithm.isRSAPSS() {
		signerOpts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.Hash(hashFunc),
		}
	}

	var signature []byte
	signature, err = signer.Sign(rand.Reader, digest, signerOpts)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(certificate{
		nil,
		c,
		signatureAlgorithm,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// CreateCertificateToPem creates a new certificate based on a template and
// encodes it to PEM format. It uses CreateCertificate to create certificate
// and returns its PEM format.
func CreateCertificateToPem(template, parent *Certificate, pubKey *sm2.PublicKey, signer crypto.Signer) ([]byte, error) {
	der, err := CreateCertificate(template, parent, pubKey, signer)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}

func ParseSm2CertifateToX509(asn1data []byte) (*x509.Certificate, error) {
	sm2Cert, err := ParseCertificate(asn1data)
	if err != nil {
		return nil, err
	}
	return sm2Cert.ToX509Certificate(), nil
}
