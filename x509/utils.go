package x509

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"io/ioutil"
	"os"
)
//read private key from PEM format
func ReadPrivateKeyFromPem(privateKeyPem []byte, pwd []byte) (*sm2.PrivateKey, error) {
	var block *pem.Block
	block, _ = pem.Decode(privateKeyPem)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}
	priv, err := ParsePKCS8PrivateKey(block.Bytes, pwd)
	return priv, err
}
//Convert private key to PEM format
func WritePrivateKeytoPem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	var block *pem.Block
	der, err := MarshalSm2PrivateKey(key, pwd)  //Convert private key to DER format
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
//read publick key from PEM format
func ReadPublicKeyFromPem(FileName string) (*sm2.PublicKey, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}
	return ParseSm2PublicKey(block.Bytes)
}
//Convert public key to PEM format
func WritePublicKeytoPem(FileName string, key *sm2.PublicKey) error {
	der, err := MarshalSm2PublicKey(key) //Convert publick key to DER format
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	certPem := pem.EncodeToMemory(block)
	file, err := os.Create(FileName)
	defer func() {
		err = file.Close()
	}()
	if err != nil {
		return err
	}
	_, err = file.Write(certPem)
	if err != nil {
		return err
	}
	return nil
}

func ReadCertificateRequestFromPem(FileName string) (*CertificateRequest, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificateRequest(block.Bytes)
}

func CreateCertificateRequestToPem(FileName string, template *CertificateRequest, privKey *sm2.PrivateKey) error {
	der, err := CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}
	file, err := os.Create(FileName)
	if err != nil {
		return err
	}
	defer func() {
		err = file.Close()
	}()
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

func ReadCertificateFromPem(FileName string) (*Certificate, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificate(block.Bytes)
}

func CreateCertificateToPem(FileName string, template, parent *Certificate, pubKey *sm2.PublicKey, privKey *sm2.PrivateKey) error {
	if template.SerialNumber == nil {
		return errors.New("x509: no SerialNumber given")
	}

	hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(privKey.Public(), template.SignatureAlgorithm)
	if err != nil {
		return err
	}

	publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(pubKey)
	if err != nil {
		return err
	}

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return err
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return err
	}

	if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
		template.AuthorityKeyId = parent.SubjectKeyId
	}

	extensions, err := buildExtensions(template)
	if err != nil {
		return err
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
		return err
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
	signature, err = privKey.Sign(rand.Reader, digest, signerOpts)
	if err != nil {
		return err
	}
	der, err := asn1.Marshal(certificate{
		nil,
		c,
		signatureAlgorithm,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})

	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	certPem := pem.EncodeToMemory(block)
	file, err := os.Create(FileName)
	if err != nil {
		return err
	}
	defer func() {
		err = file.Close()
	}()
	_, err = file.Write(certPem)
	if err != nil {
		return err
	}
	return nil
}
