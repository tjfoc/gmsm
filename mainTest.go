package main

import(
	"fmt"
	"sm3"
	"strings"
	"sm4"
)

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


func main() {

	
	sm4.TestcryptBlock()
	//test("123456")
	//TestSM3_1()
	//TestSM3_2()
	//TestSM3_3()
	//[-249460999, 1097214817, 1516941722, 2074681463, 913531124, 2003438689, -1229223501, 611725649, -1524617092, -1218949699, -1022929939, 2128960343, 1770545292, 819500471, 1153045679, 272930209, -786385880, 1941266339, -863549082, -1843116999, -392272865, -1731591846, -954888096, -1713242834, -1214523380, 488707504, 237144811, -243790719, 1116550740, 1646867606, 30372581, -1859870702]

//		int mid = 2;
//		int[] x = new int[] { 1, 2, 3, 4 };
//		int[] CK = new int[] { 
//				1, 2, 3, 4, 5, 6, 7, 8, 
//				1, 2, 3, 4, 5, 6, 7, 8,
//				1, 2, 3, 4, 5, 6, 7, 8,
//				1, 2, 3, 4, 5, 6, 7, 8
//		};
//		int[] rk = new int[32];
//[19, 38, 67, 132, 225, 8, 59, 108, 141, 238, 33, 56, 397, 334, 299, 470, 77, 398, 271, 256, 479, 106, 463, 384, 493, 452, 119, 488, 385, 482, 493, 124]


	var mid uint32 = 10256
	var x  =[] uint32 {1,2,3,4}
	var ck  =[] uint32 {
		1, 2, 3, 4, 5, 6, 7, 8, 
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8}
	
	var rk = make([]uint32, 32)
	
	for r := 0; r<32; r+=4 {
		mid = x[1] ^ x[2] ^ x[3] ^ ck[r + 0]
		mid = p(mid)
		x[0] ^= l1(mid)
		rk[r + 0] = x[0]

		mid = x[2] ^ x[3] ^ x[0] ^ ck[r + 1]
		mid = p(mid)
		x[1] ^= l1(mid) 
		rk[r + 1] = x[1]

		mid = x[3] ^ x[0] ^ x[1] ^ ck[r + 2]
		mid = p(mid)
		x[2] ^= l1(mid) 
		rk[r + 2] =x[2]

		mid = x[0] ^ x[1] ^ x[2] ^ ck[r + 3]
		mid = p(mid)
		x[3] ^= l1(mid) 
		rk[r + 3] = x[3]
	}
	
	fmt.Println("--------------------------------")
	fmt.Printf("rk: %d", rk)

}

	func l1(a uint32) uint32{
		return a*2
	}

	func p(a uint32) uint32 {
		return a + 2
	}
