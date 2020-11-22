package sm4

import (
	"bytes"
	"crypto/cipher"
)

// From https://studygolang.com/articles/22233
// @HollowKnight

// PKCS#7 填充模式填充待加密原文
// ciphertext: 待填充的明文
// blockSize: 加密组长度
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS#7 模式去填充
// origData: 被PKCS#7填充的明文
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// ECB 无填充加密
// data: 待加密明文
// block: 分组加密密码算法
func EcbEncrypt(data []byte, block cipher.Block) []byte {
	decrypted := make([]byte, len(data))
	size := block.BlockSize()

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Encrypt(decrypted[bs:be], data[bs:be])
	}
	return decrypted
}

// ECB 无填充解密
// data: 密文数据
// block: 分组加密密码算法
func EcbDecrypt(data []byte, block cipher.Block) []byte {
	decrypted := make([]byte, len(data))
	size := block.BlockSize()

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Decrypt(decrypted[bs:be], data[bs:be])
	}
	return decrypted
}
