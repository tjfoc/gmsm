package main

import (
	"fmt"
	"gmssl"
)

func testSm2() {
	fmt.Println("////////////// in testSm2 func  /////////")
	gmssl.Sm2Test()
	fmt.Println("end testSm2 func\n")
}

func testSm3() {
	fmt.Println("////////////// in testSm3 func  /////////")
	data1 := []byte("ab")
	data2 := []byte("c")
	sm3, err := gmssl.NewDigestContext("SM3", nil)
	err = sm3.Update(data1)
	err = sm3.Update(data2)
	sm3digest, err := sm3.Final()
	if err != nil {
		fmt.Println("ERROR")
	}
	fmt.Printf("sm3digest： %x \n", sm3digest)
	fmt.Println("end testSm3 func\n")
}

func testSm4() {
	fmt.Println("////////////// in testSm4 func  /////////")

	iv := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	//plaintext := []byte("hello")
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	
	fmt.Printf("plaintext: %x \n", plaintext)
	sms4, err := gmssl.NewCipherContext("SMS4", nil, key, iv, true)
	if err != nil {
		fmt.Println("sm4 ERROR!!")
		fmt.Println(err)
		return
	}
	ciphertext1, err := sms4.Update(plaintext)
	fmt.Printf("ciphertext1: %x \n", ciphertext1)

	ciphertext2, err := sms4.Final()
	fmt.Printf("ciphertext2: %x \n", ciphertext2)

	ciphertext := make([]byte, 0, len(ciphertext1)+len(ciphertext2))
	ciphertext = append(ciphertext, ciphertext1...)
	ciphertext = append(ciphertext, ciphertext2...)
	fmt.Printf("ciphertext:%x \n", ciphertext)

	fmt.Println("----------开始解密-----------------")
	sms4d, err := gmssl.NewCipherContext("SMS4", nil, key, iv, false)
	if err != nil {
		fmt.Println("sms4d ERROR!!")
		fmt.Println(err)
		return
	}
	plaintext1, err := sms4d.Update(ciphertext)
	fmt.Printf("plaintext1: %x \n", plaintext1)

	plaintext2, err := sms4d.Final()
	fmt.Printf("plaintext2: %x \n", plaintext2)

	dplaintext := make([]byte, 0, len(plaintext1)+len(plaintext2))
	dplaintext = append(dplaintext, plaintext1...)
	dplaintext = append(dplaintext, plaintext2...)
	fmt.Printf("dplaintext:%x \n", dplaintext)

	fmt.Println("end testSm4 func\n")
}

func main() {

	fmt.Println("\nGMSSL 版本信息")
	versions := gmssl.GetVersion()
	for _, version := range versions {
		fmt.Println(version)
	}

	fmt.Println("\n摘要算法")
	digests := gmssl.GetDigests(false)
	for _, digest := range digests {
		fmt.Println(digest)
	}

	fmt.Println("\nciphers")
	ciphers := gmssl.GetCiphers(false)
	for _, cipher := range ciphers {
		fmt.Println(cipher)
	}

	fmt.Println("\nGetMacs")
	macs := gmssl.GetMacs(false)
	for _, mac := range macs {
		fmt.Println(mac)
	}

	testSm3()

	testSm4()

	testSm2()

}
