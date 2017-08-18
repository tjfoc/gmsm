package sm3

import (
	"encoding/binary"
	"fmt"
	"hash"
)

type SM3 struct {
	digest      [8]uint32  // digest represents the partial evaluation of V
	T           [64]uint32 // constant
	length      uint64     // length of the message
	unhandleMsg []byte     // uint8  //
}

func NewSM3() hash.Hash {
	sm3 := &SM3{length: 0}
	sm3.digest[0] = 0x7380166f
	sm3.digest[1] = 0x4914b2b9
	sm3.digest[2] = 0x172442d7
	sm3.digest[3] = 0xda8a0600
	sm3.digest[4] = 0xa96f30bc
	sm3.digest[5] = 0x163138aa
	sm3.digest[6] = 0xe38dee4d
	sm3.digest[7] = 0xb0fb0e4e

	// Set T[i]
	for i := 0; i < 16; i++ {
		sm3.T[i] = 0x79cc4519
	}
	for i := 16; i < 64; i++ {
		sm3.T[i] = 0x7a879d8a
	}
	return sm3
}

func CopySM3(sm3 *SM3) *SM3 {
	cpsm3 := &SM3{length: sm3.length}

	cpsm3.digest[0] = sm3.digest[0]
	cpsm3.digest[1] = sm3.digest[1]
	cpsm3.digest[2] = sm3.digest[2]
	cpsm3.digest[3] = sm3.digest[3]
	cpsm3.digest[4] = sm3.digest[4]
	cpsm3.digest[5] = sm3.digest[5]
	cpsm3.digest[6] = sm3.digest[6]
	cpsm3.digest[7] = sm3.digest[7]

	cpsm3.unhandleMsg = make([]byte, len(sm3.unhandleMsg))
	copy(cpsm3.unhandleMsg, sm3.unhandleMsg)

	// Set T[i]
	for i := 0; i < 16; i++ {
		cpsm3.T[i] = 0x79cc4519
	}
	for i := 16; i < 64; i++ {
		cpsm3.T[i] = 0x7a879d8a
	}
	return cpsm3
}

// Reset clears the internal state by zeroing bytes in the state buffer.
// This can be skipped for a newly-created hash state; the default zero-allocated state is correct.
func (sm3 *SM3) Reset() {
	// Reset digest
	sm3.digest[0] = 0x7380166f
	sm3.digest[1] = 0x4914b2b9
	sm3.digest[2] = 0x172442d7
	sm3.digest[3] = 0xda8a0600
	sm3.digest[4] = 0xa96f30bc
	sm3.digest[5] = 0x163138aa
	sm3.digest[6] = 0xe38dee4d
	sm3.digest[7] = 0xb0fb0e4e

	// Reset numberic states
	sm3.length = 0

	sm3.unhandleMsg = []byte{}
}

// BlockSize, required by the hash.Hash interface.
// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (sm3 *SM3) BlockSize() int {
	// Here return the number of byte
	return 64
}

// Size, required by the hash.Hash interface.
// Size returns the number of bytes Sum will return.
func (sm3 *SM3) Size() int {
	return 32
}

func (sm3 *SM3) ff0(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

func (sm3 *SM3) ff1(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func (sm3 *SM3) gg0(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

func (sm3 *SM3) gg1(x, y, z uint32) uint32 {
	return (x & y) | (^x & z)
}

func (sm3 *SM3) p0(x uint32) uint32 {
	return x ^ sm3.leftRotate(x, 9) ^ sm3.leftRotate(x, 17)
}

func (sm3 *SM3) p1(x uint32) uint32 {
	return x ^ sm3.leftRotate(x, 15) ^ sm3.leftRotate(x, 23)
}

func (sm3 *SM3) messageExtend(data []byte) (W [68]uint32, W1 [64]uint32) {
	fmt.Println("messageExtend--------->")

	// big endian
	for i := 0; i < 16; i++ {
		W[i] = binary.BigEndian.Uint32(data[4*i : 4*(i+1)])
	}
	for i := 16; i < 68; i++ {
		W[i] = sm3.p1(W[i-16]^W[i-9]^sm3.leftRotate(W[i-3], 15)) ^ sm3.leftRotate(W[i-13], 7) ^ W[i-6]
	}
	for i := 0; i < 64; i++ {
		W1[i] = W[i] ^ W[i+4]
	}
	return W, W1
}

func (sm3 *SM3) leftRotate(x uint32, i uint32) uint32 {
	i %= 32
	return (x<<i | x>>(32-i))
}

// cf is compress function
func (sm3 *SM3) cf(W [68]uint32, W1 [64]uint32) {
	fmt.Println("cf------->")

	A := sm3.digest[0]
	B := sm3.digest[1]
	C := sm3.digest[2]
	D := sm3.digest[3]
	E := sm3.digest[4]
	F := sm3.digest[5]
	G := sm3.digest[6]
	H := sm3.digest[7]

	for i := 0; i < 16; i++ {
		SS1 := sm3.leftRotate(sm3.leftRotate(A, 12)+E+sm3.leftRotate(sm3.T[i], uint32(i)), 7)
		SS2 := SS1 ^ sm3.leftRotate(A, 12)
		TT1 := sm3.ff0(A, B, C) + D + SS2 + W1[i]
		TT2 := sm3.gg0(E, F, G) + H + SS1 + W[i]
		D = C
		C = sm3.leftRotate(B, 9)
		B = A
		A = TT1
		H = G
		G = sm3.leftRotate(F, 19)
		F = E
		E = sm3.p0(TT2)

		// // debug
		// fmt.Printf("%02d: ", i)
		// fmt.Printf("%08x ", A)
		// fmt.Printf("%08x ", B)
		// fmt.Printf("%08x ", C)
		// fmt.Printf("%08x ", D)
		// fmt.Printf("%08x ", E)
		// fmt.Printf("%08x ", F)
		// fmt.Printf("%08x ", G)
		// fmt.Printf("%08x\n", H)
	}

	for i := 16; i < 64; i++ {
		SS1 := sm3.leftRotate(sm3.leftRotate(A, 12)+E+sm3.leftRotate(sm3.T[i], uint32(i)), 7)
		SS2 := SS1 ^ sm3.leftRotate(A, 12)
		TT1 := sm3.ff1(A, B, C) + D + SS2 + W1[i]
		TT2 := sm3.gg1(E, F, G) + H + SS1 + W[i]
		D = C
		C = sm3.leftRotate(B, 9)
		B = A
		A = TT1
		H = G
		G = sm3.leftRotate(F, 19)
		F = E
		E = sm3.p0(TT2)

		// debug
		// fmt.Printf("%02d: ", i)
		// fmt.Printf("%08x ", A)
		// fmt.Printf("%08x ", B)
		// fmt.Printf("%08x ", C)
		// fmt.Printf("%08x ", D)
		// fmt.Printf("%08x ", E)
		// fmt.Printf("%08x ", F)
		// fmt.Printf("%08x ", G)
		// fmt.Printf("%08x\n", H)
	}

	sm3.digest[0] ^= A
	sm3.digest[1] ^= B
	sm3.digest[2] ^= C
	sm3.digest[3] ^= D
	sm3.digest[4] ^= E
	sm3.digest[5] ^= F
	sm3.digest[6] ^= G
	sm3.digest[7] ^= H
}

// update, iterative compress, update digests
func (sm3 *SM3) update(msg []byte, nblocks int) {
	for i := 0; i < nblocks; i++ {
		startPos := i * sm3.BlockSize()
		W, W1 := sm3.messageExtend(msg[startPos : startPos+sm3.BlockSize()])

		// debug
		// printUint32Slice(W[:])
		// printUint32Slice(W1[:])

		sm3.cf(W, W1)
	}
}

// Write, required by the hash.Hash interface.
// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (sm3 *SM3) Write(p []byte) (int, error) {
	// fmt.Println("Write---------------->")
	toWrite := len(p)
	sm3.length += uint64(len(p) * 8)
	// fmt.Println("new len:", sm3.length)

	msg := append(sm3.unhandleMsg, p...)
	nblocks := len(msg) / sm3.BlockSize()
	sm3.update(msg, nblocks)

	// Update unhandleMsg
	sm3.unhandleMsg = msg[nblocks*sm3.BlockSize():]

	return toWrite, nil
}

func (sm3 *SM3) pad() []byte {
	fmt.Println("pad------->")
	fmt.Println("message length:", sm3.length, "bits")

	// Debug
	// fmt.Println("Before padding:")
	// sm3.printMsg()

	// Make a copy not using unhandleMsg
	msg := sm3.unhandleMsg

	// Append '1'
	msg = append(msg, 0x80)

	// Append until the resulting message length (in bits) is congruent to 448 (mod 512)
	blockSize := 64
	for len(msg)%blockSize != 56 {
		msg = append(msg, 0x00)
	}

	// append message length
	msg = append(msg, uint8(sm3.length>>56&0xff))
	msg = append(msg, uint8(sm3.length>>48&0xff))
	msg = append(msg, uint8(sm3.length>>40&0xff))
	msg = append(msg, uint8(sm3.length>>32&0xff))
	msg = append(msg, uint8(sm3.length>>24&0xff))
	msg = append(msg, uint8(sm3.length>>16&0xff))
	msg = append(msg, uint8(sm3.length>>8&0xff))
	msg = append(msg, uint8(sm3.length>>0&0xff))

	if len(msg)%64 != 0 {
		fmt.Println("------pad: Error, msgLen =", len(msg))
	}

	// fmt.Println("After padding:")
	// print msg
	return msg
}

// Sum, required by the hash.Hash interface.
// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (sm3 *SM3) Sum(in []byte) []byte {
	cpsm3 := CopySM3(sm3)

	// Debug
	// fmt.Println("Copy deug -------------------------------------------------->")
	// cpsm3.printValues()
	// sm3.printValues()
	// cpsm3.printMsg()
	// sm3.printMsg()

	msg := cpsm3.pad()

	// Finialize
	cpsm3.update(msg, len(msg)/cpsm3.BlockSize())

	// save hash to in
	needed := cpsm3.Size()
	if cap(in)-len(in) < needed {
		fmt.Println("---------------------Should not happen here.")
		newIn := make([]byte, len(in), len(in)+needed)
		copy(newIn, in)
		in = newIn
	}
	out := in[len(in) : len(in)+needed]

	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(out[i*4:], cpsm3.digest[i])
	}

	// debug
	// sm3.printValues()

	return out
}

//------------------ ALL debug functions
func (sm3 *SM3) printMsg() {
	for i := 0; i < len(sm3.unhandleMsg); i++ {
		fmt.Printf("%02x", sm3.unhandleMsg[i])
		if i%4 == 3 {
			fmt.Printf(" ")
		}
		if i%(4*8) == 31 {
			fmt.Println("")
		}
	}
	fmt.Println("")
}

func printUint32Slice(list []uint32) {
	for i := 0; i < len(list); i++ {
		fmt.Printf("%08x ", list[i])
		if i%8 == 7 {
			fmt.Println("")
		}
	}
	fmt.Println("")
}

func (sm3 *SM3) printValues() {
	for i := 0; i < 8; i++ {
		fmt.Printf("%x ", sm3.digest[i])
	}
	fmt.Printf("\n")
	// fmt.Println(sm3.hashcode)
}
