package sm4

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)



func ReadKeyFromPem(FileName string, pwd []byte) (SM4Key, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("SM4: pem decode failed")
	}
	if x509.IsEncryptedPEMBlock(block) {
		if block.Type != "SM4 ENCRYPTED KEY" {
			return nil, errors.New("SM4: unknown type")
		}
		if pwd == nil {
			return nil, errors.New("SM4: need passwd")
		}
		data, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	if block.Type != "SM4 KEY" {
		return nil, errors.New("SM4: unknown type")
	}
	return block.Bytes, nil
}

func WriteKeyToPem(FileName string, key SM4Key, pwd []byte) error {
	var block *pem.Block
	var err error
	if pwd != nil {
		block, err = x509.EncryptPEMBlock(rand.Reader,
			"SM4 ENCRYPTED KEY", key, pwd, x509.PEMCipherAES256)
		if err != nil {
			return err
		}
	} else {
		block = &pem.Block{
			Type:  "SM4 KEY",
			Bytes: key,
		}
	}
	pemBytes := pem.EncodeToMemory(block)
	err = ioutil.WriteFile(FileName, pemBytes, 0666)
	if err != nil {
		return err
	}
	return nil
}
