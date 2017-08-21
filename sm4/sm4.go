package sm4

import (
	"fmt"
)

//S 盒为固定的 8 比特输入 8 比特输出的置换,记为Sbox
var sbox = [256]byte{
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48}

//密钥及密钥参量
//FK = (FK0,FK1,FK2,FK3)为系统参数，CK = (CK0>,CK1,⋯,CK31)
var fk = []uint32{0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc}

var ck = []uint32{
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279}

//函数
//左旋运算<<<
func rl(x uint32, n uint32) uint32 {
	n %= 32
	return (x<<n | x>>(32-n))
}

//线性变换L
//C=L(B)=B ^ (B<<<2 )^ (B<<<10) ^ (B<<<18) ^ (B<<<24)
func l0(x uint32) uint32 {
	return x ^ rl(x, 2) ^ rl(x, 10) ^ rl(x, 18) ^ rl(x, 24)
}

//线性变换L' C=L'(B)=B ^ (B<<<13) ^ (B<<<23)
func l1(x uint32) uint32 {
	return x ^ rl(x, 13) ^ rl(x, 23)
}

//非线性变换τ(.)
func p(a uint32) uint32 {
	return (uint32(sbox[a>>24]) << 24) ^ (uint32(sbox[(a>>16)&0xff]) << 16) ^ (uint32(sbox[(a>>8)&0xff]) << 8) ^ uint32(sbox[(a)&0xff])
}

//可逆变换T,由非线性变换 τ 和线性变换 L 复合而成,即 T(.)=L(τ(.))
func t0(r uint32) uint32 {
	return l0(p(r))
}

//可逆变换TN,由非线性变换 τ 和线性变换 L' 复合而成,即 T(.)=L'(τ(.))
func t1(r uint32) uint32 {
	return l1(p(r))
}

func f0(x0, x1, x2, x3, rk uint32) uint32 {

	//return (x0^l0(x1^x2^x3^rk))

	return x0
}

func f1(x0, x1, x2, x3, rk uint32) uint32 {

	// return (x0^l1(x1^x2^x3^rk))
	return x1
}

// 加密算法由32次迭代运算和1次反序变换组成;解密变换与加密变换结构相同,不同的仅是轮密钥的使用顺序。解密时,使用轮密钥序 rk42 , rk40, ⋯ , rk0
// 算法描述
func cryptBlock(subkeys, dst, src []byte, decrypt bool) {
	var (
		k0, k1, k2, k3 uint32
		d0, d1, d2, d3 uint32
		y0, y1, y2, y3 uint32
		rk             = make([]uint32, 32)
	)
	k0 = getu32(subkeys, 0)
	k1 = getu32(subkeys, 4)
	k2 = getu32(subkeys, 8)
	k3 = getu32(subkeys, 12)
	d0 = getu32(src, 0)
	d1 = getu32(src, 4)
	d2 = getu32(src, 8)
	d3 = getu32(src, 12)
	k0 = k0 ^ fk[0]
	k1 = k1 ^ fk[1]
	k2 = k2 ^ fk[2]
	k3 = k3 ^ fk[3]
	for i := 0; i < 32; i++ {
		rk[i] = f1(k0, k1, k2, k3, ck[i])
		k0 = k1
		k1 = k2
		k2 = k3
		k3 = rk[i]
		if !decrypt {
			t := f0(d0, d1, d2, d3, rk[i])
			d0 = d1
			d1 = d2
			d2 = d3
			d3 = t
		}
	}
	if decrypt {
		for i := 0; i < 32; i++ {
			t := f0(d0, d1, d2, d3, rk[31-i])
			d0 = d1
			d1 = d2
			d2 = d3
			d3 = t
		}
	}
	y0 = d3
	y1 = d2
	y2 = d1
	y3 = d0
	putu32(dst, y0, 0)
	putu32(dst, y1, 4)
	putu32(dst, y2, 8)
	putu32(dst, y3, 12)
}

func getu32(b []byte, i uint32) uint32 {
	return (uint32(b[i]) << 24) | (uint32(b[i+1]) << 16) | (uint32(b[i+2]) << 8) | uint32(b[i+3])
}

func putu32(b []byte, n, i uint32) {
	b[i] = byte(n >> 24)
	b[i+1] = byte(n >> 16)
	b[i+2] = byte(n >> 8)
	b[i+3] = byte(n)
}

func TestcryptBlock() {
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	//加密
	fmt.Println("--------------------------------------")
	var en = make([]byte, 16)
	sms4(data, 16, key, en, 1)
	fmt.Println("加密结果：")
	fmt.Printf("en: %x \n", en)

	//解密
	fmt.Println("--------------------------------------")
	var dc = make([]byte, 16)
	sms4(en, 16, key, dc, 0)
	fmt.Println("解密结果：")
	fmt.Printf("en: %x \n", dc)

}

//da : 0123456789abcdeffedcba9876543210
//en : 681edf34d206965e86b3e94f536e4246
//de : 0123456789abcdeffedcba9876543210

func sms4(in []byte, inLen uint32, key []byte, out []byte, CryptFlag uint32) uint32 {

	var round_key = make([]uint32, 32)
	SMS4KeyExt(key, round_key, CryptFlag)

	fmt.Printf("ck: %d \n", ck)
	fmt.Printf("round_key: %d \n", round_key)

	SMS4Crypt(in, out, round_key)
	return 0
}

func SMS4KeyExt(Key []byte, rk []uint32, CryptFlag uint32) {
	var mid uint32
	var x = make([]uint32, 4)
	var tmp = make([]uint32, 4)
	for i := 0; i < 4; i++ {
		tmp[0] = uint32(Key[0+4*i] & 0xff)
		tmp[1] = uint32(Key[1+4*i] & 0xff)
		tmp[2] = uint32(Key[2+4*i] & 0xff)
		tmp[3] = uint32(Key[3+4*i] & 0xff)
		x[i] = tmp[0]<<24 | tmp[1]<<16 | tmp[2]<<8 | tmp[3]
	}
	x[0] ^= fk[0]
	x[1] ^= fk[1]
	x[2] ^= fk[2]
	x[3] ^= fk[3]
	for r := 0; r < 32; r += 4 {
		mid = x[1] ^ x[2] ^ x[3] ^ ck[r+0]
		mid = p(mid)
		x[0] ^= l1(mid)
		rk[r+0] = x[0]

		mid = x[2] ^ x[3] ^ x[0] ^ ck[r+1]
		mid = p(mid)
		x[1] ^= l1(mid)
		rk[r+1] = x[1]

		mid = x[3] ^ x[0] ^ x[1] ^ ck[r+2]
		mid = p(mid)
		x[2] ^= l1(mid)
		rk[r+2] = x[2]

		mid = x[0] ^ x[1] ^ x[2] ^ ck[r+3]
		mid = p(mid)
		x[3] ^= l1(mid)
		rk[r+3] = x[3]
	}

	if CryptFlag == 0 {
		for r := 0; r < 16; r++ {
			mid = rk[r]
			rk[r] = rk[31-r]
			rk[31-r] = mid
		}
	}
}

func SMS4Crypt(Input []byte, Output []byte, rk []uint32) {

	fmt.Printf("input %x \n", Input)
	fmt.Printf("Otput %x \n", Output)

	var mid uint32
	var x = make([]uint32, 4)
	var tmp = make([]uint32, 4)
	for i := 0; i < 4; i++ {
		tmp[0] = uint32(Input[0+4*i] & 0xff)
		tmp[1] = uint32(Input[1+4*i] & 0xff)
		tmp[2] = uint32(Input[2+4*i] & 0xff)
		tmp[3] = uint32(Input[3+4*i] & 0xff)
		x[i] = tmp[0]<<24 | tmp[1]<<16 | tmp[2]<<8 | tmp[3]
	}

	for r := 0; r < 32; r += 4 {
		mid = x[1] ^ x[2] ^ x[3] ^ rk[r+0]
		mid = p(mid)
		x[0] = x[0] ^ l0(mid)

		mid = x[2] ^ x[3] ^ x[0] ^ rk[r+1]
		mid = p(mid)
		x[1] = x[1] ^ l0(mid)

		mid = x[3] ^ x[0] ^ x[1] ^ rk[r+2]
		mid = p(mid)
		x[2] = x[2] ^ l0(mid)

		mid = x[0] ^ x[1] ^ x[2] ^ rk[r+3]
		mid = p(mid)
		x[3] = x[3] ^ l0(mid)
	}

	// Reverse
	for j := 0; j < 16; j += 4 {
		Output[j] = (byte)(x[3-j/4] >> 24 & 0xFF)
		Output[j+1] = (byte)(x[3-j/4] >> 16 & 0xFF)
		Output[j+2] = (byte)(x[3-j/4] >> 8 & 0xFF)
		Output[j+3] = (byte)(x[3-j/4] & 0xFF)
	}
}
