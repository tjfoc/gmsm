package machine

import (
	"fmt"
	"log"
	"reflect"
	"testing"

	"github.com/tjfoc/gmsm/sm4"
)

func Test_SoftwareSM3(t *testing.T) {
	soft := Software{}
	a := GetMachine(soft, soft, soft)
	msg := []byte("abc")
	fmt.Println(len(a.Sm3Hash(msg)))
	fmt.Println(a.Sm3Hash(msg))

}
func Test_SoftwareSM2(t *testing.T) {
	msg := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	soft := Software{}
	machine := GetMachine(soft, soft, soft)
	pri, _ := machine.GenerateKey()
	pub := machine.ToPubKey(pri)
	d0, _ := machine.Sm2Encrypt(pub, msg)
	d1, _ := machine.Sm2Decrypt(pri, d0)
	if sa := testCompare(msg, d1); sa != true {
		fmt.Printf("Error data!")
	}
	r, s, _ := machine.Sm2Sign(pri, msg, nil)
	IsVerify := machine.Sm2Verify(pub, msg, nil, r, s)
	fmt.Println("IsVerify：", IsVerify)

}
func Test_SoftwareSM4(t *testing.T) {
	soft := Software{}
	encryMachine := GetMachine(soft, soft, soft)
	key := []byte("1234567890abcdef")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	sm4.WriteKeyToPem("key.pem", key, nil)
	key, err := sm4.ReadKeyFromPem("key.pem", nil)
	if err != nil {
		log.Fatal(err)
	}
	d0 := encryMachine.Sm4Encrypt(key, data)
	fmt.Printf("d0 = %x\n", d0)
	d1 := encryMachine.Sm4Decrypt(key, d0)
	fmt.Printf("d1 = %x\n", d1)
	if sa := testCompare(data, d1); sa != true {
		fmt.Printf("Error data!")
	}
}
func Test_UnionSM2(t *testing.T) {
	msg := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	union := Union{}
	machine := GetMachine(union, union, union)
	pri, _ := machine.GenerateKey()
	pub := machine.ToPubKey(pri)
	d0, _ := machine.Sm2Encrypt(pub, msg)
	d1, _ := machine.Sm2Decrypt(pri, d0)
	if sa := testCompare(msg, d1); sa != true {
		fmt.Printf("Error data!")
	}
	r, s, _ := machine.Sm2Sign(pri, msg, nil)
	fmt.Println(r, s)
	//	IsVerify := machine.Sm2Verify(pub, msg, nil, r, s)
	//	fmt.Println("IsVerify：", IsVerify)

}

func Test_UnionSM3(t *testing.T) {
	union := Union{}
	a := GetMachine(union, union, union)
	msg := []byte("abc")
	fmt.Println(len(a.Sm3Hash(msg)))
	fmt.Println(a.Sm3Hash(msg))

}
func Test_UnionSM4(t *testing.T) {
	union := Union{}
	encryMachine := GetMachine(union, union, union)
	key := []byte("1234567890abcdef")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	sm4.WriteKeyToPem("key.pem", key, nil)
	key, err := sm4.ReadKeyFromPem("key.pem", nil)
	if err != nil {
		log.Fatal(err)
	}
	d0 := encryMachine.Sm4Encrypt(key, data)
	fmt.Printf("d0 = %x\n", d0)
	d1 := encryMachine.Sm4Decrypt(key, d0)
	fmt.Printf("d1 = %x\n", d1)
	if sa := testCompare(data, d1); sa != true {
		fmt.Printf("Error data!")
	}
}

func testCompare(key1, key2 []byte) bool {
	if len(key1) != len(key2) {
		return false
	}
	for i, v := range key1 {
		if i == 1 {
			fmt.Println("type of v", reflect.TypeOf(v))
		}
		a := key2[i]
		if a != v {
			return false
		}
	}
	return true
}
