/* +build cgo */
package gmssl

/*
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

func GetPublicKeyTypes(aliases bool) []string {
	return []string{"RSA", "DH", "DSA"}
}

func GetSignatureSchemes(publicKeyType string, aliases bool) []string {
	return []string{"RSA", "DSA", "ECDSA", "SM2"}
}

func GetPublicKeyEncryptions(publicKeyType string, aliases bool) []string {
	return []string{"RSA", "ECIES", "SM2"}
}

func GetKeyExchanges(publicKeyType string, aliases bool) []string {
	return []string{"DH", "ECDH", "SM2"}
}

type PublicKey struct {
	pkey *C.EVP_PKEY
}

type PrivateKey struct {
	pkey *C.EVP_PKEY
}

func GenerateKeyPair(publicKeyType string, args map[string]string, bits int) (*PublicKey, *PrivateKey, error) {
	fmt.Println("in GenerateKeyPair")
	
	key_file := "/root/work/prk.der"
	ckey_file := C.CString(key_file)
	defer C.free(unsafe.Pointer(ckey_file))



	key := C.BIO_new(C.BIO_s_file())

	//key来自file
	//C.BIO_read_filename(key, ckey_file)
	//格式转换   der
	pkey := C.d2i_PrivateKey_bio(key, nil)
	prk := &PublicKey{pkey}
	fmt.Println(prk)

	//	ctxpr := C.EVP_PKEY_new()
	//	fmt.Println(ctxpr)
	//	prk := &PrivateKey{ctxpr}
	//	fmt.Println(prk)
	//	cname := C.CString(name)
	//	defer C.free(unsafe.Pointer(cname))
	//	md := C.EVP_get_digestbyname(cname)
	//	ctxpr := C.d2i_PrivateKey(C.EVP_PKEY_EC,nil,)
	//	prk := &PrivateKey{ctxpr}
	//	ctxpu := C.d2i_PublicKey()
	//	puk := &PublicKey{ctxpu}
	///

	fmt.Println("xxxxxxxxxx exit GenerateKeyPair")
	return nil, nil, errors.New("Not implemented")
}

func LoadPublicKey(publicKeyType string, args map[string]string, data []byte) (*PublicKey, error) {
	return nil, errors.New("Not implemented")
}

func LoadPrivateKey(publicKeyType string, args map[string]string, data []byte) (*PrivateKey, error) {
	return nil, errors.New("Not implemented")
}

func (pkey *PublicKey) Save(args map[string]string) ([]byte, error) {
	return nil, errors.New("Not implemented")
}

func (pkey *PrivateKey) Save(args map[string]string) ([]byte, error) {
	return nil, errors.New("Not implemented")
}

func (pkey *PublicKey) GetAttributes(args map[string]string) (map[string]string, error) {
	return nil, errors.New("Not implemented")
}

func (pkey *PrivateKey) GetAttributes(args map[string]string) (map[string]string, error) {
	return nil, errors.New("Not implemented")
}

func (pkey *PublicKey) Encrypt(scheme string, args map[string]string, in []byte) ([]byte, error) {
	ctx := C.EVP_PKEY_CTX_new(pkey.pkey, nil)
	if ctx == nil {
		return nil, errors.New("Failure")
	}
	if 1 != C.EVP_PKEY_encrypt_init(ctx) {
		return nil, errors.New("Failurew")
	}
	outbuf := make([]byte, len(in)+1024)
	outlen := C.size_t(len(outbuf))
	if 1 != C.EVP_PKEY_encrypt(ctx, (*C.uchar)(&outbuf[0]), &outlen,
		(*C.uchar)(&in[0]), C.size_t(len(in))) {
		return nil, errors.New("Failurew")
	}
	return outbuf[:outlen], nil
}

func (pkey *PrivateKey) Decrypt(scheme string, args map[string]string, in []byte) ([]byte, error) {
	ctx := C.EVP_PKEY_CTX_new(pkey.pkey, nil)
	if ctx == nil {
		return nil, errors.New("Failure")
	}
	if 1 != C.EVP_PKEY_decrypt_init(ctx) {
		return nil, errors.New("Failure")
	}
	outbuf := make([]byte, len(in))
	outlen := C.size_t(len(outbuf))
	if 1 != C.EVP_PKEY_decrypt(ctx, (*C.uchar)(&outbuf[0]), &outlen,
		(*C.uchar)(&in[0]), C.size_t(len(in))) {
		return nil, errors.New("Failure")
	}
	return outbuf[:outlen], nil
}

func (pkey *PrivateKey) Sign(scheme string, args map[string]string, data []byte) ([]byte, error) {

	fmt.Println("---------------- in Sign")
	fmt.Println(pkey)

	ctx := C.EVP_PKEY_CTX_new(pkey.pkey, nil)
	fmt.Println("xxxxxxxxxxxxxxxxxxxx")
	if ctx == nil {
		return nil, errors.New("Failure")
	}
	if 1 != C.EVP_PKEY_sign_init(ctx) {
		return nil, errors.New("Failure")
	}
	outbuf := make([]byte, C.EVP_PKEY_size(pkey.pkey))
	outlen := C.size_t(len(outbuf))
	if 1 != C.EVP_PKEY_sign(ctx, (*C.uchar)(&outbuf[0]), &outlen,
		(*C.uchar)(&data[0]), C.size_t(len(data))) {
		return nil, errors.New("Failure")
	}
	return outbuf[:outlen], nil
}

func (pkey *PublicKey) Verify(scheme string, args map[string]string, data, signature []byte) error {
	ctx := C.EVP_PKEY_CTX_new(pkey.pkey, nil)
	if ctx == nil {
		return errors.New("Failure")
	}
	if 1 != C.EVP_PKEY_sign_init(ctx) {
		return errors.New("Failure")
	}
	ret := C.EVP_PKEY_verify(ctx, (*C.uchar)(&signature[0]), C.size_t(len(signature)),
		(*C.uchar)(&data[0]), C.size_t(len(data)))
	if ret != 1 {
		return errors.New("Failure")
	}
	return nil
}

func (pkey *PrivateKey) DeriveKey(scheme string, args map[string]string, publicKey PublicKey) ([]byte, error) {
	ctx := C.EVP_PKEY_CTX_new(pkey.pkey, nil)
	if ctx == nil {
		return nil, errors.New("Failure")
	}
	if 1 != C.EVP_PKEY_derive_init(ctx) {
	}
	/*
		if 1 != C.EVP_PKEY_derive_set_peer(ctx, PublicKey.pkey) {
		}
	*/

	outbuf := make([]byte, C.EVP_PKEY_size(pkey.pkey))
	outlen := C.size_t(len(outbuf))
	if 1 != C.EVP_PKEY_derive(ctx, (*C.uchar)(&outbuf[0]), &outlen) {
	}
	return nil, errors.New("Not implemented")
}
