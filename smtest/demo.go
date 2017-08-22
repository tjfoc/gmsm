package smtest

import (
	"fmt"
	"gmsm/sm3"
	"gmsm/sm4"
)


func Sm3(plainText string) string{
	mLen := len([]rune(plainText)) 
	buffer := make([]byte, mLen)
	//trueVal := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

	copy(buffer[:], plainText)
	hw := sm3.NewSM3()
	hw.Write(buffer[:])

	uhash := make([]uint8, 32)
	hw.Sum(uhash[:0])
	calcVal := Byte2String(uhash)
	return calcVal
}


func Sm4(){
	sm4.TestcryptBlock()
}



func Byte2String(b []byte) string {
	ret := ""
	for i := 0; i < len(b); i++ {
		ret += fmt.Sprintf("%02x", b[i])
	}
	return ret
}


