package x509

import (
	"encoding/pem"
	"errors"
	"github.com/Hyperledger-TWGC/tj-gmsm/sm2"
	"io/ioutil"
	"os"
)

func ReadPrivateKeyFromMem(data []byte, pwd []byte) (*sm2.PrivateKey, error) {
	var block *pem.Block

	block, _ = pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}
	priv, err := ParsePKCS8PrivateKey(block.Bytes, pwd)
	return priv, err
}

func ReadPrivateKeyFromPem(FileName string, pwd []byte) (*sm2.PrivateKey, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadPrivateKeyFromMem(data, pwd)
}

func WritePrivateKeytoMem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	var block *pem.Block

	der, err := MarshalSm2PrivateKey(key, pwd)
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
	return pem.EncodeToMemory(block), nil
}

func WritePrivateKeytoPem(FileName string, key *sm2.PrivateKey, pwd []byte) (err error) {
	certPem, err := WritePrivateKeytoMem(key, pwd)
	if err != nil {
		return err
	}

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

func ReadPublicKeyFromMem(data []byte) (*sm2.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}
	pub, err := ParseSm2PublicKey(block.Bytes)
	return pub, err
}

func ReadPublicKeyFromPem(FileName string) (*sm2.PublicKey, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadPublicKeyFromMem(data)
}

func WritePublicKeytoMem(key *sm2.PublicKey) ([]byte, error) {
	der, err := MarshalSm2PublicKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

func WritePublicKeytoPem(FileName string, key *sm2.PublicKey) (err error) {
	certPem, err := WritePublicKeytoMem(key)
	if err != nil {
		return err
	}

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

