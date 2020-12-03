// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gmtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"

	"golang.org/x/crypto/curve25519"
)

//// hashForServerKeyExchange hashes the given slices and returns their digest
//// using the given hash function (for >= TLS 1.2) or using a default based on
//// the sigType (for earlier TLS versions).
//func hashForServerKeyExchange(sigType uint8, hashFunc crypto.Hash, version uint16, slices ...[]byte) ([]byte, error) {
//	if version >= VersionTLS12 {
//		h := hashFunc.New()
//		for _, slice := range slices {
//			h.Write(slice)
//		}
//		digest := h.Sum(nil)
//		return digest, nil
//	}
//	if sigType == signatureECDSA {
//		return sha1Hash(slices), nil
//	}
//	return md5SHA1Hash(slices), nil
//}
//
//func curveForCurveID(id CurveID) (elliptic.Curve, bool) {
//	switch id {
//	case CurveP256:
//		return elliptic.P256(), true
//	case CurveP384:
//		return elliptic.P384(), true
//	case CurveP521:
//		return elliptic.P521(), true
//	default:
//		return nil, false
//	}
//
//}

// ecdheKeyAgreementGM implements a TLS key agreement where the server
// generates an ephemeral SM2 public/private key pair and signs it. The
// pre-master secret is then calculated using ECDH.
type ecdheKeyAgreementGM struct {
	version    uint16
	privateKey []byte
	curveid    CurveID

	// publicKey is used to store the peer's public value when X25519 is
	// being used.
	publicKey []byte
	// x and y are used to store the peer's public value when one of the
	// NIST curves is being used.
	x, y *big.Int
}

func (ka *ecdheKeyAgreementGM) generateServerKeyExchange(config *Config, signCert, cipherCert *Certificate,
	clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	panic("")
	//	preferredCurves := config.curvePreferences()
	//
	//NextCandidate:
	//	for _, candidate := range preferredCurves {
	//		for _, c := range clientHello.supportedCurves {
	//			if candidate == c {
	//				ka.curveid = c
	//				break NextCandidate
	//			}
	//		}
	//	}
	//
	//	if ka.curveid == 0 {
	//		return nil, errors.New("tls: no supported elliptic curves offered")
	//	}
	//
	//	var ecdhePublic []byte
	//
	//	if ka.curveid == X25519 {
	//		var scalar, public [32]byte
	//		if _, err := io.ReadFull(config.rand(), scalar[:]); err != nil {
	//			return nil, err
	//		}
	//
	//		curve25519.ScalarBaseMult(&public, &scalar)
	//		ka.privateKey = scalar[:]
	//		ecdhePublic = public[:]
	//	} else {
	//		curve, ok := curveForCurveID(ka.curveid)
	//		if !ok {
	//			return nil, errors.New("tls: preferredCurves includes unsupported curve")
	//		}
	//
	//		var x, y *big.Int
	//		var err error
	//		ka.privateKey, x, y, err = elliptic.GenerateKey(curve, config.rand())
	//		if err != nil {
	//			return nil, err
	//		}
	//		ecdhePublic = elliptic.Marshal(curve, x, y)
	//	}
	//
	//	// https://tools.ietf.org/html/rfc4492#section-5.4
	//	serverECDHParams := make([]byte, 1+2+1+len(ecdhePublic))
	//	serverECDHParams[0] = 3 // named curve
	//	serverECDHParams[1] = byte(ka.curveid >> 8)
	//	serverECDHParams[2] = byte(ka.curveid)
	//	serverECDHParams[3] = byte(len(ecdhePublic))
	//	copy(serverECDHParams[4:], ecdhePublic)
	//
	//	priv, ok := cert.PrivateKey.(crypto.Signer)
	//	if !ok {
	//		return nil, errors.New("tls: certificate private key does not implement crypto.Signer")
	//	}
	//
	//	signatureAlgorithm, sigType, hashFunc, err := pickSignatureAlgorithm(priv.Public(), clientHello.supportedSignatureAlgorithms, supportedSignatureAlgorithms, ka.version)
	//	if err != nil {
	//		return nil, err
	//	}
	//	if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
	//		return nil, errors.New("tls: certificate cannot be used with the selected cipher suite")
	//	}
	//
	//	digest, err := hashForServerKeyExchange(sigType, hashFunc, ka.version, clientHello.random, hello.random, serverECDHParams)
	//	if err != nil {
	//		return nil, err
	//	}
	//
	//	signOpts := crypto.SignerOpts(hashFunc)
	//	if sigType == signatureRSAPSS {
	//		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hashFunc}
	//	}
	//	sig, err := priv.Sign(config.rand(), digest, signOpts)
	//	if err != nil {
	//		return nil, errors.New("tls: failed to sign ECDHE parameters: " + err.Error())
	//	}
	//
	//	skx := new(serverKeyExchangeMsg)
	//	sigAndHashLen := 0
	//	if ka.version >= VersionTLS12 {
	//		sigAndHashLen = 2
	//	}
	//	skx.key = make([]byte, len(serverECDHParams)+sigAndHashLen+2+len(sig))
	//	copy(skx.key, serverECDHParams)
	//	k := skx.key[len(serverECDHParams):]
	//	if ka.version >= VersionTLS12 {
	//		k[0] = byte(signatureAlgorithm >> 8)
	//		k[1] = byte(signatureAlgorithm)
	//		k = k[2:]
	//	}
	//	k[0] = byte(len(sig) >> 8)
	//	k[1] = byte(len(sig))
	//	copy(k[2:], sig)
	//
	//	return skx, nil
}

func (ka *ecdheKeyAgreementGM) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	panic("")
	//	if len(ckx.ciphertext) == 0 || int(ckx.ciphertext[0]) != len(ckx.ciphertext)-1 {
	//		return nil, errClientKeyExchange
	//	}
	//
	//	if ka.curveid == X25519 {
	//		if len(ckx.ciphertext) != 1+32 {
	//			return nil, errClientKeyExchange
	//		}
	//
	//		var theirPublic, sharedKey, scalar [32]byte
	//		copy(theirPublic[:], ckx.ciphertext[1:])
	//		copy(scalar[:], ka.privateKey)
	//		curve25519.ScalarMult(&sharedKey, &scalar, &theirPublic)
	//		return sharedKey[:], nil
	//	}
	//
	//	curve, ok := curveForCurveID(ka.curveid)
	//	if !ok {
	//		panic("internal error")
	//	}
	//	x, y := elliptic.Unmarshal(curve, ckx.ciphertext[1:]) // Unmarshal also checks whether the given point is on the curve
	//	if x == nil {
	//		return nil, errClientKeyExchange
	//	}
	//	x, _ = curve.ScalarMult(x, y, ka.privateKey)
	//	preMasterSecret := make([]byte, (curve.Params().BitSize+7)>>3)
	//	xBytes := x.Bytes()
	//	copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)
	//
	//	return preMasterSecret, nil
}

func (ka *ecdheKeyAgreementGM) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}
	if skx.key[0] != 3 { // named curve
		return errors.New("tls: server selected unsupported curve")
	}
	ka.curveid = CurveID(skx.key[1])<<8 | CurveID(skx.key[2])

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	serverECDHParams := skx.key[:4+publicLen]
	publicKey := serverECDHParams[4:]

	sig := skx.key[4+publicLen:]
	if len(sig) < 2 {
		return errServerKeyExchange
	}

	//according to GMT0024, we don't care about
	curve := sm2.P256Sm2()
	ka.x, ka.y = elliptic.Unmarshal(curve, publicKey) // Unmarshal also checks whether the given point is on the curve
	if ka.x == nil {
		return errServerKeyExchange
	}

	var signatureAlgorithm SignatureScheme
	_, sigType, hashFunc, err := pickSignatureAlgorithm(cert.PublicKey, []SignatureScheme{signatureAlgorithm}, clientHello.supportedSignatureAlgorithms, ka.version)

	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return errServerKeyExchange
	}
	sig = sig[2:]

	digest, err := hashForServerKeyExchange(sigType, hashFunc, ka.version, clientHello.random, serverHello.random, serverECDHParams)
	if err != nil {
		return err
	}
	return verifyHandshakeSignature(sigType, cert.PublicKey, hashFunc, digest, sig)
}

func (ka *ecdheKeyAgreementGM) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.curveid == 0 {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}

	var serialized, preMasterSecret []byte

	if ka.curveid == X25519 {
		var ourPublic, theirPublic, sharedKey, scalar [32]byte

		if _, err := io.ReadFull(config.rand(), scalar[:]); err != nil {
			return nil, nil, err
		}

		copy(theirPublic[:], ka.publicKey)
		curve25519.ScalarBaseMult(&ourPublic, &scalar)
		curve25519.ScalarMult(&sharedKey, &scalar, &theirPublic)
		serialized = ourPublic[:]
		preMasterSecret = sharedKey[:]
	} else {
		curve, ok := curveForCurveID(ka.curveid)
		if !ok {
			panic("internal error")
		}
		priv, mx, my, err := elliptic.GenerateKey(curve, config.rand())
		if err != nil {
			return nil, nil, err
		}
		x, _ := curve.ScalarMult(ka.x, ka.y, priv)
		preMasterSecret = make([]byte, (curve.Params().BitSize+7)>>3)
		xBytes := x.Bytes()
		copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

		serialized = elliptic.Marshal(curve, mx, my)
	}

	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, 1+len(serialized))
	ckx.ciphertext[0] = byte(len(serialized))
	copy(ckx.ciphertext[1:], serialized)

	return preMasterSecret, ckx, nil
}

// eccKeyAgreementGM implements a TLS key agreement where the server
// generates an ephemeral SM2 public/private key pair and signs it. The
// pre-master secret is then calculated using ECDH.
type eccKeyAgreementGM struct {
	version    uint16
	privateKey []byte
	curveid    CurveID

	// publicKey is used to store the peer's public value when X25519 is
	// being used.
	publicKey []byte
	// x and y are used to store the peer's public value when one of the
	// NIST curves is being used.
	x, y *big.Int

	//cert for encipher referred to GMT0024
	encipherCert *x509.Certificate
}

func (ka *eccKeyAgreementGM) generateServerKeyExchange(config *Config, signCert, cipherCert *Certificate,
	clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	// mod by syl only one cert
	//digest := ka.hashForServerKeyExchange(clientHello.random, hello.random, cert.Certificate[1])
	digest := ka.hashForServerKeyExchange(clientHello.random, hello.random, cipherCert.Certificate[0])

	priv, ok := signCert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Signer")
	}
	sig, err := priv.Sign(config.rand(), digest, nil)
	if err != nil {
		return nil, err
	}

	len := len(sig)

	ske := new(serverKeyExchangeMsg)
	ske.key = make([]byte, len+2)
	ske.key[0] = byte(len >> 8)
	ske.key[1] = byte(len)
	copy(ske.key[2:], sig)

	return ske, nil
}

func (ka *eccKeyAgreementGM) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) == 0 {
		return nil, errClientKeyExchange
	}

	if int(ckx.ciphertext[0]<<8|ckx.ciphertext[1]) != len(ckx.ciphertext)-2 {
		return nil, errClientKeyExchange
	}

	cipher := ckx.ciphertext[2:]

	decrypter, ok := cert.PrivateKey.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Decrypter")
	}

	plain, err := decrypter.Decrypt(config.rand(), cipher, nil)
	if err != nil {
		return nil, err
	}

	if len(plain) != 48 {
		return nil, errClientKeyExchange
	}

	//we do not examine the version here according to openssl practice
	return plain, nil
}

func (ka *eccKeyAgreementGM) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) <= 2 {
		return errServerKeyExchange
	}
	sigLen := int(skx.key[0]<<8 | skx.key[1])
	if sigLen+2 != len(skx.key) {
		return errServerKeyExchange
	}
	sig := skx.key[2:]
	//sig := skx.key[:]

	digest := ka.hashForServerKeyExchange(clientHello.random, serverHello.random, ka.encipherCert.Raw)

	//verify
	pubKey, _ := cert.PublicKey.(*ecdsa.PublicKey)
	if pubKey.Curve != sm2.P256Sm2() {
		return errors.New("tls: sm2 signing requires a sm2 public key")
	}

	ecdsaSig := new(ecdsaSignature)
	rest, err := asn1.Unmarshal(sig, ecdsaSig)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("tls:processServerKeyExchange: sm2 get signature failed")
	}
	if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
		return errors.New("tls: processServerKeyExchange: sm2 signature contained zero or negative values")
	}

	sm2PubKey := sm2.PublicKey{
		Curve: pubKey.Curve,
		X:     pubKey.X,
		Y:     pubKey.Y,
	}

	if !sm2PubKey.Verify(digest, sig) {
		return errors.New("tls: processServerKeyExchange: sm2 verification failure")
	}

	return nil
}

func (ka *eccKeyAgreementGM) hashForServerKeyExchange(slices ...[]byte) []byte {
	buffer := new(bytes.Buffer)
	for i, slice := range slices {
		if i == 2 {
			buffer.Write([]byte{byte(len(slice) >> 16), byte(len(slice) >> 8), byte(len(slice))})
		}
		buffer.Write(slice)
	}
	return buffer.Bytes()
}

func (ka *eccKeyAgreementGM) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(clientHello.vers >> 8)
	preMasterSecret[1] = byte(clientHello.vers)
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		return nil, nil, err
	}
	pubKey := ka.encipherCert.PublicKey.(*ecdsa.PublicKey)
	sm2PubKey := &sm2.PublicKey{Curve: pubKey.Curve, X: pubKey.X, Y: pubKey.Y}
	encrypted, err := sm2.Encrypt(sm2PubKey, preMasterSecret, config.rand())
	if err != nil {
		return nil, nil, err
	}
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, len(encrypted)+2)
	ckx.ciphertext[0] = byte(len(encrypted) >> 8)
	ckx.ciphertext[1] = byte(len(encrypted))
	copy(ckx.ciphertext[2:], encrypted)
	return preMasterSecret, ckx, nil
}
