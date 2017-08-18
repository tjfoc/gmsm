package main

/*
#
#cgo pkg-config: openssl
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

static int BN_num_bytes_not_a_macro(BIGNUM* arg) {
	return BN_num_bytes(arg);
}
*/
import "C"

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/ioutil"
	"unsafe"
)

type (
	Curve     int16
	PublicKey struct {
		Curve
		X, Y []byte
	}
	PrivateKey struct {
		PublicKey
		Key []byte
	}
)

func ParsePublicKeyByDerEncode(curve Curve, der []byte) (*PublicKey, error) {
	pukInfo := struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{}
	_, err := asn1.Unmarshal(der, &pukInfo)
	if err != nil {
		return nil, err
	}
	raw := pukInfo.PublicKey.Bytes
	if raw[0] != byte(0x04) || len(raw)%2 != 1 {
		return nil, errors.New("not uncompressed format")
	}
	raw = raw[1:]
	intLength := int(len(raw) / 2)
	key := new(PublicKey)
	key.Curve = curve
	key.X = make([]byte, intLength)
	key.Y = make([]byte, intLength)
	copy(key.X, raw[:intLength])
	copy(key.Y, raw[intLength:])
	return key, nil
}

func ParsePrivateKeyByDerEncode(curve Curve, der []byte) (*PrivateKey, error) {
	prkInfo := struct {
		Version       int
		PrivateKey    []byte
		NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}{}
	_, err := asn1.Unmarshal(der, &prkInfo)
	if err != nil {
		return nil, err
	}
	raw := prkInfo.PrivateKey
	key := new(PrivateKey)
	key.Curve = curve
	key.Key = raw
	k := C.EC_KEY_new_by_curve_name(C.int(key.Curve))
	defer C.EC_KEY_free(k)
	group := C.EC_KEY_get0_group(k)
	pub_key := C.EC_POINT_new(group)
	defer C.EC_POINT_free(pub_key)
	priv_key := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&key.Key[0])),
		C.int(len(key.Key)), nil)
	defer C.BN_free(priv_key)
	pub_key_x := C.BN_new()
	defer C.BN_free(pub_key_x)
	pub_key_y := C.BN_new()
	defer C.BN_free(pub_key_y)
	// the actual step which does the conversion from private to public key
	if C.EC_POINT_mul(group, pub_key, priv_key, nil, nil, nil) == C.int(0) {
		return nil, errors.New("EC_POINT_mul error")
	}
	if C.EC_KEY_set_private_key(k, priv_key) == C.int(0) {
		return nil, errors.New("EC_KEY_set_private_key")
	}
	if C.EC_KEY_set_public_key(k, pub_key) == C.int(0) {
		return nil, errors.New("EC_KEY_set_public_key")
	}
	// get X and Y coords from pub_key
	if C.EC_POINT_get_affine_coordinates_GFp(group, pub_key, pub_key_x,
		pub_key_y, nil) == C.int(0) {
		return nil, errors.New("EC_POINT_get_affine_coordinates_GFp")
	}
	key.PublicKey.X = make([]byte, C.BN_num_bytes_not_a_macro(pub_key_x))
	key.PublicKey.Y = make([]byte, C.BN_num_bytes_not_a_macro(pub_key_y))
	C.BN_bn2bin(pub_key_x, (*C.uchar)(unsafe.Pointer(&key.PublicKey.X[0])))
	C.BN_bn2bin(pub_key_y, (*C.uchar)(unsafe.Pointer(&key.PublicKey.Y[0])))
	return key, nil
}

func getEC_KEY(curve Curve, pubkey *PublicKey, privkey *PrivateKey) (*C.EC_KEY,
	error) {
	// initialization
	key := C.EC_KEY_new_by_curve_name(C.int(curve))
	if key == nil {
		return nil, errors.New("EC_KEY_new_by_curve_name")
	}
	// convert bytes to BIGNUMs
	pub_key_x := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&pubkey.X[0])),
		C.int(len(pubkey.X)), nil)
	defer C.BN_free(pub_key_x)
	pub_key_y := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&pubkey.Y[0])),
		C.int(len(pubkey.Y)), nil)
	defer C.BN_free(pub_key_y)
	// also add private key if it exists
	if privkey != nil {
		priv_key := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&privkey.Key[0])),
			C.int(len(privkey.Key)), nil)
		defer C.BN_free(priv_key)
		if C.EC_KEY_set_private_key(key, priv_key) == C.int(0) {
			return nil, errors.New("EC_KEY_set_private_key")
		}
	}
	group := C.EC_KEY_get0_group(key)
	pub_key := C.EC_POINT_new(group)
	defer C.EC_POINT_free(pub_key)
	// set coordinates to get pubkey and then set pubkey
	if C.EC_POINT_set_affine_coordinates_GFp(group, pub_key, pub_key_x,
		pub_key_y, nil) == C.int(0) {
		return nil, errors.New("EC_POINT_set_affine_coordinates_GFp")
	}
	if C.EC_KEY_set_public_key(key, pub_key) == C.int(0) {
		return nil, errors.New("EC_KEY_set_public_key")
	}
	// validate the key
	if C.EC_KEY_check_key(key) == C.int(0) {
		return nil, errors.New("EC_KEY_check_key")
	}
	return key, nil
}

// func (key *PrivateKey) Sign(rawData []byte) ([]byte, error) {
// 	k, err := getEC_KEY(key.Curve, &key.PublicKey, key)
// 	defer C.EC_KEY_free(k)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// create EVP context
// 	md_ctx := C.EVP_MD_CTX_create()
// 	defer C.EVP_MD_CTX_destroy(md_ctx)
// 	C.EVP_MD_CTX_init(md_ctx)
// 	if C.EVP_DigestInit(md_ctx, C.EVP_ecdsa()) == C.int(0) {
// 		return nil, errors.New("EVP_DigestInit")
// 	}
// 	if C.EVP_DigestUpdate(md_ctx, unsafe.Pointer(&rawData[0]),
// 		C.size_t(len(rawData))) == C.int(0) {
// 		return nil, errors.New("EVP_DigestUpdate")
// 	}
// 	digest := make([]byte, C.EVP_MAX_MD_SIZE)
// 	var digest_len uint
// 	// get the digest
// 	if C.EVP_DigestFinal(md_ctx, (*C.uchar)(unsafe.Pointer(&digest[0])),
// 		(*C.uint)(unsafe.Pointer(&digest_len))) == C.int(0) {
// 		return nil, errors.New("EVP_DigestFinal")
// 	}
// 	sig := make([]byte, C.ECDSA_size(k)) // get max signature length
// 	var sig_len uint
// 	// get the signature
// 	if C.ECDSA_sign(C.int(0), (*C.uchar)(unsafe.Pointer(&digest[0])),
// 		C.int(digest_len), (*C.uchar)(unsafe.Pointer(&sig[0])),
// 		(*C.uint)(unsafe.Pointer(&sig_len)), k) == C.int(0) {
// 		return nil, errors.New("ECDSA_sign")
// 	}
// 	return sig[:sig_len], nil
// }

//func (key *PublicKey) VerifySignature(sig, rawData []byte) (bool, error) {
//	k, err := getEC_KEY(key.Curve, key, nil)
//	defer C.EC_KEY_free(k)
//	if err != nil {
//		return false, err
//	}
//	// create EVP context
//	md_ctx := C.EVP_MD_CTX_create()
//	defer C.EVP_MD_CTX_destroy(md_ctx)
//	C.EVP_MD_CTX_init(md_ctx)
//	if C.EVP_DigestInit(md_ctx, C.EVP_ecdsa()) == C.int(0) {
//		return false, errors.New("EVP_DigestInit")
//	}
//	if C.EVP_DigestUpdate(md_ctx, unsafe.Pointer(&rawData[0]),
//		C.size_t(len(rawData))) == C.int(0) {
//		return false, errors.New("EVP_DigestUpdate")
//	}
//	digest := make([]byte, C.EVP_MAX_MD_SIZE)
//	var digest_len uint
//	// get the digest
//	if C.EVP_DigestFinal(md_ctx, (*C.uchar)(unsafe.Pointer(&digest[0])),
//		(*C.uint)(unsafe.Pointer(&digest_len))) == C.int(0) {
//		return false, errors.New("EVP_DigestFinal")
//	}
//	// check signature
//	ret := int(C.ECDSA_verify(C.int(0), (*C.uchar)(unsafe.Pointer(&digest[0])),
//		C.int(digest_len), (*C.uchar)(unsafe.Pointer(&sig[0])),
//		C.int(len(sig)), k))
//	switch ret {
//	case -1:
//		return false, errors.New("ECDSA_verify")
//	case 1:
//		return true, nil
//	case 0:
//		return false, nil
//	}
//	return false, errors.New("lolwut? unknown error")
//}

func main() {
	sm2p256v1 := Curve(C.NID_sm2p256v1)
	prkDer, err := ioutil.ReadFile("prk.der")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("私钥: %x \n",prkDer)
	prk, err := ParsePrivateKeyByDerEncode(sm2p256v1, prkDer)
	if err != nil {
		fmt.Println(err)
	}
//	signRaw, err := prk.Sign([]byte("123456"))
//	if err != nil {
//		fmt.Println(err)
//	}
	pukDer, err := ioutil.ReadFile("puk.der")
	fmt.Printf("公钥: %x \n",pukDer)
	if err != nil {
		fmt.Println(err)
	}
	puk, err := ParsePublicKeyByDerEncode(sm2p256v1, pukDer)
	if err != nil {
		fmt.Println(err)
	}
//	ok, err := puk.VerifySignature(signRaw, []byte("123456"))
//	if err != nil {
//		fmt.Println(err)
//	}
//	if ok {
//		fmt.Println("验证成功！")
//	}
	fmt.Println("--------------------------")
	fmt.Printf("prk: %+v \n",prk)
	fmt.Printf("puk: %+v \n",puk)
	fmt.Println("over")
}
