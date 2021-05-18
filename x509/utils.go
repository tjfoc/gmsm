package x509

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
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
func ReadPrivateKeyFromHex(Dhex string) (*sm2.PrivateKey,error) {
	c := sm2.P256Sm2()
	d,err:=hex.DecodeString(Dhex)
	if err!=nil{
		return nil,err
	}
	k:= new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n)>=0{
      return nil,errors.New("privateKey's D is overflow.")
	}
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv,nil
}



func WritePrivateKeyToHex(key *sm2.PrivateKey) string {
	return key.D.Text(16)
}

func ReadPublicKeyFromHex(Qhex string) (*sm2.PublicKey, error) {
	q,err:=hex.DecodeString(Qhex)
	if err!=nil{
		return nil,err
	}
	if len(q)==65&&q[0]==byte(0x04){
		q=q[1:]
	}
	if len(q)!=64{
		return nil,errors.New("publicKey is not uncompressed.")
	}
	pub := new(sm2.PublicKey)
	pub.Curve = sm2.P256Sm2()
	pub.X = new(big.Int).SetBytes(q[:32])
	pub.Y = new(big.Int).SetBytes(q[32:])
	return pub, nil
}


func WritePublicKeyToHex(key *sm2.PublicKey) string {
	x := key.X.Bytes()
	y := key.Y.Bytes()
	if n := len(x); n < 32 {
		x = append(zeroByteSlice()[:32-n], x...)
	}
	if n := len(y); n < 32 {
		y = append(zeroByteSlice()[:32-n], y...)
	}
	c := []byte{}
	c = append(c, x...)
	c = append(c, y...)
	c = append([]byte{0x04}, c...)
	return hex.EncodeToString(c)
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
// 32byte
func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}
