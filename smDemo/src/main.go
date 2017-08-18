package main

import(
	"fmt"
	"strings"
	"sm3"
	"sm4"
)
func main() {
	//sm4 test
	sm4.TestcryptBlock()
	
	//sm3 test
	test("123456")
	TestSM3_1()
	TestSM3_2()
	TestSM3_3()
}


func test(msg string){
	var mLen int= strings.Count(msg,"")-1 
	buffer := make([]byte, mLen)
	
	copy(buffer[:], msg)
	hw := sm3.NewSM3()
	hw.Write(buffer[:])

	uhash := make([]uint8, 32)
	hw.Sum(uhash[:0])
	calcVal := Byte2String(uhash)

	fmt.Println("msg:"+msg+"\tcalcVal:" + calcVal)
}

func TestSM3_1() {
	fmt.Println("in TestSM3_1 fun")
	msg := "abc"
	var buffer [3]byte
	trueVal := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

	copy(buffer[:], msg)
	hw := sm3.NewSM3()
	hw.Write(buffer[:])

	uhash := make([]uint8, 32)
	hw.Sum(uhash[:0])
	calcVal := Byte2String(uhash)

	fmt.Println("trueVal:" + trueVal)
	fmt.Println("calcVal:" + calcVal)
	if calcVal != trueVal {
		fmt.Println("false")
	}else{
		fmt.Println("true")
	}
	fmt.Println("exit TestSM3_1 fun\n")
}


func TestSM3_2() {
	msg := "abcd"
	var buffer [4]byte
	trueVal := "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"

	copy(buffer[:], msg)
	hw := sm3.NewSM3()
	for i := 0; i < 16; i++ {
		hw.Write(buffer[:])
	}

	uhash := make([]uint8, 32)
	hw.Sum(uhash[:0])
	calcVal := Byte2String(uhash)

	fmt.Println("trueVal:" + trueVal)
	fmt.Println("calcVal:" + calcVal)
	if calcVal != trueVal {
		fmt.Println("false")
	}else{
		fmt.Println("true")
	}
}

func TestSM3_3() {
	msg := "abcd"
	var buffer [4]byte
	trueVal := "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"

	copy(buffer[:], msg)
	hw := sm3.NewSM3()
	for i := 0; i < 15; i++ {
		hw.Write(buffer[:])
	}

	uhash := make([]uint8, 32)
	hw.Sum(uhash[:0])

	// Continue write, the result still the same,
	// for hw.Sum() not change the hash state
	hw.Write(buffer[:])
	uhash = make([]uint8, 32)
	hw.Sum(uhash[:0])
	calcVal := Byte2String(uhash)

	fmt.Println("trueVal:" + trueVal)
	fmt.Println("calcVal:" + calcVal)
	if calcVal != trueVal {
		fmt.Println("false")
	}else{
		fmt.Println("true")
	}
	fmt.Println("exit TestSM3_3 fun\n")
}




func Byte2String(b []byte) string {
	ret := ""
	for i := 0; i < len(b); i++ {
		ret += fmt.Sprintf("%02x", b[i])
	}
	return ret
}

