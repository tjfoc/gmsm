package sm3
//
//import (
//	"encoding/binary"
//)
//
//// 初始值
//// IV = 7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e，具体定义如下代码片段：
//// 用于确定压缩函数寄存器的初态
//const (
//	iv0 = 0x7380166f
//	iv1 = 0x4914b2b9
//	iv2 = 0x172442d7
//	iv3 = 0xda8a0600
//	iv4 = 0xa96f30bc
//	iv5 = 0x163138aa
//	iv6 = 0xe38dee4d
//	iv7 = 0xb0fb0e4e
//	
//	BlockSize int =1
//)
//
//// 常量
//// Tj={ 79cc4519 0≤j≤15；7a879d8a 16≤j≤63}, 随j的变化取不同的值，具体定义如下代码片段：
//const (
//	// 取t0值时，j范围是： 0 < j < 15
//	t0 = 0x79cc4519
//	// 取t1值时，j范围是: 16 < j < 63
//	t1 = 0x7a879d8a
//)
//
//// 布尔函数
//// FFj(X,Y,Z)={X ^ Y ^ Z 0≤j≤15；(X & Y)|(X&Z)|(Y&Z) 16≤j≤63},随j的变化取不同表达式，具体定义如下代码片段
//// 执行ff0函数时，j的范围是: 0 < j < 15
//func ff0(x, y, z uint32) uint32 {
//	return x ^ y ^ z
//}
//
//// 执行ff1函数时，j的范围是: 16 < j < 63
//func ff1(x, y, z uint32) uint32 {
//	return (x & y) | (x & z) | (y & z)
//}
//
//// GGj(X,Y,Z)={X ^ Y ^ Z 0≤j≤15；（X & Y）|（~X&Z）16≤j≤63},随j的变化取不同表达式，具体定义如下代码片段
//// 执行gg0函数时，j的范围是: 0 < j < 15
//func gg0(x, y, z uint32) uint32 {
//	return x ^ y ^ z
//}
//
//// 执行gg1函数时，j的范围是: 16 < j < 63
//func gg1(x, y, z uint32) uint32 {
//	return (x & y) | (^x & z)
//}
//
//// 左旋运算函数
//func rl(x uint32, n uint32) uint32 {
//	n %= 32
//	return (x<<n | x>>(32-n))
//}
//
//// 置换函数
//// P0（X）= X ^ (X<<<9) ^ （X<<<17)，压缩函数中的置换函数，具体定义如下代码片段
//func p0(x uint32) uint32 {
//	return x ^ rl(x, 9) ^ rl(x, 17)
//}
//
//// P1（X）= X ^ (X<<<15) ^ （X<<<23)，消息扩展中的置换函数，具体定义如下代码片段
//func p1(x uint32) uint32 {
//	return x ^ rl(x, 15) ^ rl(x, 23)
//}
//
//	
//
//// sm3 结构体
//type sm3_ctx struct {
//	digest [8]uint32 //初始值为IV
//	num    uint64
//	block  []byte
//}
//
//
//func (self *sm3_ctx) padding() []byte {
//	msg := self.block
//	msg = append(msg, 0x80)
//	for len(msg)%BlockSize != 56 {
//		msg = append(msg, 0x00)
//	}
//	msg = append(msg, uint8(self.num>>56&0xff))
//	msg = append(msg, uint8(self.num>>48&0xff))
//	msg = append(msg, uint8(self.num>>40&0xff))
//	msg = append(msg, uint8(self.num>>32&0xff))
//	msg = append(msg, uint8(self.num>>24&0xff))
//	msg = append(msg, uint8(self.num>>16&0xff))
//	msg = append(msg, uint8(self.num>>8&0xff))
//	msg = append(msg, uint8(self.num>>0&0xff))
//	if len(msg)%BlockSize != 0 {
//		panic("padding error block length is " + string(len(msg)))
//	}
//	return msg
//}
//
//
//func (self *sm3_ctx) update(msg []byte, nblocks int) {
//	for i := 0; i < nblocks; i++ {
//		start := i * BlockSize
//		w, w1 := extend(msg[start : start+BlockSize])
//		self.cf(w, w1)
//	}
//}
//
//func extend(data []byte) (w [68]uint32, w1 [64]uint32) {
//	for i := 0; i < 16; i++ {
//		//大端序
//		w[i] = binary.BigEndian.Uint32(data[4*i : 4*(i+1)])
//	}
//	for i := 16; i < 68; i++ {
//		w[i] = p1(w[i-16]^w[i-9]^rl(w[i-3], 15)) ^ rl(w[i-13], 7) ^ w[i-6]
//	}
//	for i := 0; i < 64; i++ {
//		w1[i] = w[i] ^ w[i+4]
//	}
//	return w, w1
//}
//
//
//func (self *sm3_ctx) cf(w [68]uint32, w1 [64]uint32) {
//	a := self.digest[0] //iv0
//	b := self.digest[1] //iv1
//	c := self.digest[2] //iv2
//	d := self.digest[3] //iv3
//	e := self.digest[4] //iv4
//	f := self.digest[5] //iv5
//	g := self.digest[6] //iv6
//	h := self.digest[7] //iv7
//	for i := 0; i < 16; i++ {
//		ss1 := rl(rl(a, 12)+e+rl(t0, uint32(i)), 7)
//		ss2 := ss1 ^ rl(a, 12)
//		tt1 := ff0(a, b, c) + d + ss2 + w1[i]
//		tt2 := gg0(e, f, g) + h + ss1 + w[i]
//		d = c
//		c = rl(b, 9)
//		b = a
//		a = tt1
//		h = g
//		g = rl(f, 19)
//		f = e
//		e = p0(tt2)
//	}
//	for i := 16; i < 64; i++ {
//		ss1 := rl(rl(a, 12)+e+rl(t1, uint32(i)), 7)
//		ss2 := ss1 ^ rl(a, 12)
//		tt1 := ff1(a, b, c) + d + ss2 + w1[i]
//		tt2 := gg1(e, f, g) + h + ss1 + w[i]
//		d = c
//		c = rl(b, 9)
//		b = a
//		a = tt1
//		h = g
//		g = rl(f, 19)
//		f = e
//		e = p0(tt2)
//	}
//	self.digest[0] ^= a
//	self.digest[1] ^= b
//	self.digest[2] ^= c
//	self.digest[3] ^= d
//	self.digest[4] ^= e
//	self.digest[5] ^= f
//	self.digest[6] ^= g
//	self.digest[7] ^= h
//}
//
//
//// 写入要计算hash的数据
//func (self *sm3_ctx) Write(p []byte) (n int, err error) {
//	n = len(p)
//	self.num += uint64(n * 8)
//	msg := append(self.block, p...)
//	nblocks := len(msg) / BlockSize
//	self.update(msg, nblocks)
//	self.block = msg[nblocks*BlockSize:]
//	return n, nil
//}
//
//
//// 计算hash 结果
//func (self *sm3_ctx) Sum(in []byte) []byte {
//	sm3 := clone(self)
//	msg := sm3.padding()
//	nblocks := len(msg) / BlockSize
//	sm3.update(msg, nblocks)
//	needed := Size
//	if cap(in)-len(in) < needed {
//		newIn := make([]byte, len(in), len(in)+needed)
//		copy(newIn, in)
//		in = newIn
//	}
//	out := in[len(in) : len(in)+needed]
//	for i := 0; i < 8; i++ {
//		//大端序
//		binary.BigEndian.PutUint32(out[i*4:], sm3.digest[i])
//	}
//	return out
//}
//
//// 测试
//func Test_Hash() {
//	h := &sm3_ctx{}
//	h.Write([]byte("123456"))
//	hashData := h.Sum(nil)
//	//t.Logf("%x \n", hashData)
//}
//
//
