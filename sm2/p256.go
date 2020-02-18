/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sm2

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

/** 学习标准库p256的优化方法实现sm2的快速版本
 * 标准库的p256的代码实现有些晦涩难懂，当然sm2的同样如此，有兴趣的大家可以研究研究，最后神兽压阵。。。
 *
 * ━━━━━━animal━━━━━━
 * 　　　┏┓　　　┏┓
 * 　　┏┛┻━━━┛┻┓
 * 　　┃　　　　　　　┃
 * 　　┃　　　━　　　┃
 * 　　┃　┳┛　┗┳　┃
 * 　　┃　　　　　　　┃
 * 　　┃　　　┻　　　┃
 * 　　┃　　　　　　　┃
 * 　　┗━┓　　　┏━┛
 * 　　　┃　　　┃
 *　　 　┃　　　┃
 *　　　 ┃　　　┗━━━┓
 *	   　┃　　　　　┣┓
 *   　　┃　　　　　┏┛
 *　　 　┗┓┓┏━┳┓┏┛
 *　　　　┃┫┫ ┃┫┫
 *　　　　┗┻┛ ┗┻┛
 *
 * ━━━━━Kawaii ━━━━━━
 */

type sm2P256Curve struct {
	RInverse *big.Int
	*elliptic.CurveParams
	a, b, gx, gy sm2P256FieldElement
}

var initonce sync.Once
var sm2P256 sm2P256Curve

type sm2P256FieldElement [9]uint32
type sm2P256LargeFieldElement [17]uint64

const (
	bottom28Bits = 0xFFFFFFF
	bottom29Bits = 0x1FFFFFFF
)

func initP256Sm2() {
	sm2P256.CurveParams = &elliptic.CurveParams{Name: "SM2-P-256"} // sm2
	A, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	//SM2椭	椭 圆 曲 线 公 钥 密 码 算 法 推 荐 曲 线 参 数
	sm2P256.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2P256.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2P256.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2P256.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2P256.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2P256.RInverse, _ = new(big.Int).SetString("7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002", 16)
	sm2P256.BitSize = 256
	sm2P256FromBig(&sm2P256.a, A)
	sm2P256FromBig(&sm2P256.gx, sm2P256.Gx)
	sm2P256FromBig(&sm2P256.gy, sm2P256.Gy)
	sm2P256FromBig(&sm2P256.b, sm2P256.B)
}

func P256Sm2() elliptic.Curve {
	initonce.Do(initP256Sm2)
	return sm2P256
}

func (curve sm2P256Curve) Params() *elliptic.CurveParams {
	return sm2P256.CurveParams
}

// y^2 = x^3 + ax + b
func (curve sm2P256Curve) IsOnCurve(X, Y *big.Int) bool {
	var a, x, y, y2, x3 sm2P256FieldElement

	sm2P256FromBig(&x, X)
	sm2P256FromBig(&y, Y)

	sm2P256Square(&x3, &x)       // x3 = x ^ 2
	sm2P256Mul(&x3, &x3, &x)     // x3 = x ^ 2 * x
	sm2P256Mul(&a, &curve.a, &x) // a = a * x
	sm2P256Add(&x3, &x3, &a)
	sm2P256Add(&x3, &x3, &curve.b)

	sm2P256Square(&y2, &y) // y2 = y ^ 2
	return sm2P256ToBig(&x3).Cmp(sm2P256ToBig(&y2)) == 0
}

func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

func (curve sm2P256Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	var X1, Y1, Z1, X2, Y2, Z2, X3, Y3, Z3 sm2P256FieldElement

	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	sm2P256FromBig(&X1, x1)
	sm2P256FromBig(&Y1, y1)
	sm2P256FromBig(&Z1, z1)
	sm2P256FromBig(&X2, x2)
	sm2P256FromBig(&Y2, y2)
	sm2P256FromBig(&Z2, z2)
	sm2P256PointAdd(&X1, &Y1, &Z1, &X2, &Y2, &Z2, &X3, &Y3, &Z3)
	return sm2P256ToAffine(&X3, &Y3, &Z3)
}

func (curve sm2P256Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	var X1, Y1, Z1 sm2P256FieldElement

	z1 := zForAffine(x1, y1)
	sm2P256FromBig(&X1, x1)
	sm2P256FromBig(&Y1, y1)
	sm2P256FromBig(&Z1, z1)
	sm2P256PointDouble(&X1, &Y1, &Z1, &X1, &Y1, &Z1)
	return sm2P256ToAffine(&X1, &Y1, &Z1)
}

func (curve sm2P256Curve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	var X, Y, Z, X1, Y1 sm2P256FieldElement
	sm2P256FromBig(&X1, x1)
	sm2P256FromBig(&Y1, y1)
	scalar := sm2GenrateWNaf(k)
	scalarReversed := WNafReversed(scalar)
	sm2P256ScalarMult(&X, &Y, &Z, &X1, &Y1, scalarReversed)
	return sm2P256ToAffine(&X, &Y, &Z)
}

func (curve sm2P256Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	var scalarReversed [32]byte
	var X, Y, Z sm2P256FieldElement

	sm2P256GetScalar(&scalarReversed, k)
	sm2P256ScalarBaseMult(&X, &Y, &Z, &scalarReversed)
	return sm2P256ToAffine(&X, &Y, &Z)
}

var sm2P256Precomputed = [9 * 2 * 15 * 2]uint32{
	0x830053d, 0x328990f, 0x6c04fe1, 0xc0f72e5, 0x1e19f3c, 0x666b093, 0x175a87b, 0xec38276, 0x222cf4b,
	0x185a1bba, 0x354e593, 0x1295fac1, 0xf2bc469, 0x47c60fa, 0xc19b8a9, 0xf63533e, 0x903ae6b, 0xc79acba,
	0x15b061a4, 0x33e020b, 0xdffb34b, 0xfcf2c8, 0x16582e08, 0x262f203, 0xfb34381, 0xa55452, 0x604f0ff,
	0x41f1f90, 0xd64ced2, 0xee377bf, 0x75f05f0, 0x189467ae, 0xe2244e, 0x1e7700e8, 0x3fbc464, 0x9612d2e,
	0x1341b3b8, 0xee84e23, 0x1edfa5b4, 0x14e6030, 0x19e87be9, 0x92f533c, 0x1665d96c, 0x226653e, 0xa238d3e,
	0xf5c62c, 0x95bb7a, 0x1f0e5a41, 0x28789c3, 0x1f251d23, 0x8726609, 0xe918910, 0x8096848, 0xf63d028,
	0x152296a1, 0x9f561a8, 0x14d376fb, 0x898788a, 0x61a95fb, 0xa59466d, 0x159a003d, 0x1ad1698, 0x93cca08,
	0x1b314662, 0x706e006, 0x11ce1e30, 0x97b710, 0x172fbc0d, 0x8f50158, 0x11c7ffe7, 0xd182cce, 0xc6ad9e8,
	0x12ea31b2, 0xc4e4f38, 0x175b0d96, 0xec06337, 0x75a9c12, 0xb001fdf, 0x93e82f5, 0x34607de, 0xb8035ed,
	0x17f97924, 0x75cf9e6, 0xdceaedd, 0x2529924, 0x1a10c5ff, 0xb1a54dc, 0x19464d8, 0x2d1997, 0xde6a110,
	0x1e276ee5, 0x95c510c, 0x1aca7c7a, 0xfe48aca, 0x121ad4d9, 0xe4132c6, 0x8239b9d, 0x40ea9cd, 0x816c7b,
	0x632d7a4, 0xa679813, 0x5911fcf, 0x82b0f7c, 0x57b0ad5, 0xbef65, 0xd541365, 0x7f9921f, 0xc62e7a,
	0x3f4b32d, 0x58e50e1, 0x6427aed, 0xdcdda67, 0xe8c2d3e, 0x6aa54a4, 0x18df4c35, 0x49a6a8e, 0x3cd3d0c,
	0xd7adf2, 0xcbca97, 0x1bda5f2d, 0x3258579, 0x606b1e6, 0x6fc1b5b, 0x1ac27317, 0x503ca16, 0xa677435,
	0x57bc73, 0x3992a42, 0xbab987b, 0xfab25eb, 0x128912a4, 0x90a1dc4, 0x1402d591, 0x9ffbcfc, 0xaa48856,
	0x7a7c2dc, 0xcefd08a, 0x1b29bda6, 0xa785641, 0x16462d8c, 0x76241b7, 0x79b6c3b, 0x204ae18, 0xf41212b,
	0x1f567a4d, 0xd6ce6db, 0xedf1784, 0x111df34, 0x85d7955, 0x55fc189, 0x1b7ae265, 0xf9281ac, 0xded7740,
	0xf19468b, 0x83763bb, 0x8ff7234, 0x3da7df8, 0x9590ac3, 0xdc96f2a, 0x16e44896, 0x7931009, 0x99d5acc,
	0x10f7b842, 0xaef5e84, 0xc0310d7, 0xdebac2c, 0x2a7b137, 0x4342344, 0x19633649, 0x3a10624, 0x4b4cb56,
	0x1d809c59, 0xac007f, 0x1f0f4bcd, 0xa1ab06e, 0xc5042cf, 0x82c0c77, 0x76c7563, 0x22c30f3, 0x3bf1568,
	0x7a895be, 0xfcca554, 0x12e90e4c, 0x7b4ab5f, 0x13aeb76b, 0x5887e2c, 0x1d7fe1e3, 0x908c8e3, 0x95800ee,
	0xb36bd54, 0xf08905d, 0x4e73ae8, 0xf5a7e48, 0xa67cb0, 0x50e1067, 0x1b944a0a, 0xf29c83a, 0xb23cfb9,
	0xbe1db1, 0x54de6e8, 0xd4707f2, 0x8ebcc2d, 0x2c77056, 0x1568ce4, 0x15fcc849, 0x4069712, 0xe2ed85f,
	0x2c5ff09, 0x42a6929, 0x628e7ea, 0xbd5b355, 0xaf0bd79, 0xaa03699, 0xdb99816, 0x4379cef, 0x81d57b,
	0x11237f01, 0xe2a820b, 0xfd53b95, 0x6beb5ee, 0x1aeb790c, 0xe470d53, 0x2c2cfee, 0x1c1d8d8, 0xa520fc4,
	0x1518e034, 0xa584dd4, 0x29e572b, 0xd4594fc, 0x141a8f6f, 0x8dfccf3, 0x5d20ba3, 0x2eb60c3, 0x9f16eb0,
	0x11cec356, 0xf039f84, 0x1b0990c1, 0xc91e526, 0x10b65bae, 0xf0616e8, 0x173fa3ff, 0xec8ccf9, 0xbe32790,
	0x11da3e79, 0xe2f35c7, 0x908875c, 0xdacf7bd, 0x538c165, 0x8d1487f, 0x7c31aed, 0x21af228, 0x7e1689d,
	0xdfc23ca, 0x24f15dc, 0x25ef3c4, 0x35248cd, 0x99a0f43, 0xa4b6ecc, 0xd066b3, 0x2481152, 0x37a7688,
	0x15a444b6, 0xb62300c, 0x4b841b, 0xa655e79, 0xd53226d, 0xbeb348a, 0x127f3c2, 0xb989247, 0x71a277d,
	0x19e9dfcb, 0xb8f92d0, 0xe2d226c, 0x390a8b0, 0x183cc462, 0x7bd8167, 0x1f32a552, 0x5e02db4, 0xa146ee9,
	0x1a003957, 0x1c95f61, 0x1eeec155, 0x26f811f, 0xf9596ba, 0x3082bfb, 0x96df083, 0x3e3a289, 0x7e2d8be,
	0x157a63e0, 0x99b8941, 0x1da7d345, 0xcc6cd0, 0x10beed9a, 0x48e83c0, 0x13aa2e25, 0x7cad710, 0x4029988,
	0x13dfa9dd, 0xb94f884, 0x1f4adfef, 0xb88543, 0x16f5f8dc, 0xa6a67f4, 0x14e274e2, 0x5e56cf4, 0x2f24ef,
	0x1e9ef967, 0xfe09bad, 0xfe079b3, 0xcc0ae9e, 0xb3edf6d, 0x3e961bc, 0x130d7831, 0x31043d6, 0xba986f9,
	0x1d28055, 0x65240ca, 0x4971fa3, 0x81b17f8, 0x11ec34a5, 0x8366ddc, 0x1471809, 0xfa5f1c6, 0xc911e15,
	0x8849491, 0xcf4c2e2, 0x14471b91, 0x39f75be, 0x445c21e, 0xf1585e9, 0x72cc11f, 0x4c79f0c, 0xe5522e1,
	0x1874c1ee, 0x4444211, 0x7914884, 0x3d1b133, 0x25ba3c, 0x4194f65, 0x1c0457ef, 0xac4899d, 0xe1fa66c,
	0x130a7918, 0x9b8d312, 0x4b1c5c8, 0x61ccac3, 0x18c8aa6f, 0xe93cb0a, 0xdccb12c, 0xde10825, 0x969737d,
	0xf58c0c3, 0x7cee6a9, 0xc2c329a, 0xc7f9ed9, 0x107b3981, 0x696a40e, 0x152847ff, 0x4d88754, 0xb141f47,
	0x5a16ffe, 0x3a7870a, 0x18667659, 0x3b72b03, 0xb1c9435, 0x9285394, 0xa00005a, 0x37506c, 0x2edc0bb,
	0x19afe392, 0xeb39cac, 0x177ef286, 0xdf87197, 0x19f844ed, 0x31fe8, 0x15f9bfd, 0x80dbec, 0x342e96e,
	0x497aced, 0xe88e909, 0x1f5fa9ba, 0x530a6ee, 0x1ef4e3f1, 0x69ffd12, 0x583006d, 0x2ecc9b1, 0x362db70,
	0x18c7bdc5, 0xf4bb3c5, 0x1c90b957, 0xf067c09, 0x9768f2b, 0xf73566a, 0x1939a900, 0x198c38a, 0x202a2a1,
	0x4bbf5a6, 0x4e265bc, 0x1f44b6e7, 0x185ca49, 0xa39e81b, 0x24aff5b, 0x4acc9c2, 0x638bdd3, 0xb65b2a8,
	0x6def8be, 0xb94537a, 0x10b81dee, 0xe00ec55, 0x2f2cdf7, 0xc20622d, 0x2d20f36, 0xe03c8c9, 0x898ea76,
	0x8e3921b, 0x8905bff, 0x1e94b6c8, 0xee7ad86, 0x154797f2, 0xa620863, 0x3fbd0d9, 0x1f3caab, 0x30c24bd,
	0x19d3892f, 0x59c17a2, 0x1ab4b0ae, 0xf8714ee, 0x90c4098, 0xa9c800d, 0x1910236b, 0xea808d3, 0x9ae2f31,
	0x1a15ad64, 0xa48c8d1, 0x184635a4, 0xb725ef1, 0x11921dcc, 0x3f866df, 0x16c27568, 0xbdf580a, 0xb08f55c,
	0x186ee1c, 0xb1627fa, 0x34e82f6, 0x933837e, 0xf311be5, 0xfedb03b, 0x167f72cd, 0xa5469c0, 0x9c82531,
	0xb92a24b, 0x14fdc8b, 0x141980d1, 0xbdc3a49, 0x7e02bb1, 0xaf4e6dd, 0x106d99e1, 0xd4616fc, 0x93c2717,
	0x1c0a0507, 0xc6d5fed, 0x9a03d8b, 0xa1d22b0, 0x127853e3, 0xc4ac6b8, 0x1a048cf7, 0x9afb72c, 0x65d485d,
	0x72d5998, 0xe9fa744, 0xe49e82c, 0x253cf80, 0x5f777ce, 0xa3799a5, 0x17270cbb, 0xc1d1ef0, 0xdf74977,
	0x114cb859, 0xfa8e037, 0xb8f3fe5, 0xc734cc6, 0x70d3d61, 0xeadac62, 0x12093dd0, 0x9add67d, 0x87200d6,
	0x175bcbb, 0xb29b49f, 0x1806b79c, 0x12fb61f, 0x170b3a10, 0x3aaf1cf, 0xa224085, 0x79d26af, 0x97759e2,
	0x92e19f1, 0xb32714d, 0x1f00d9f1, 0xc728619, 0x9e6f627, 0xe745e24, 0x18ea4ace, 0xfc60a41, 0x125f5b2,
	0xc3cf512, 0x39ed486, 0xf4d15fa, 0xf9167fd, 0x1c1f5dd5, 0xc21a53e, 0x1897930, 0x957a112, 0x21059a0,
	0x1f9e3ddc, 0xa4dfced, 0x8427f6f, 0x726fbe7, 0x1ea658f8, 0x2fdcd4c, 0x17e9b66f, 0xb2e7c2e, 0x39923bf,
	0x1bae104, 0x3973ce5, 0xc6f264c, 0x3511b84, 0x124195d7, 0x11996bd, 0x20be23d, 0xdc437c4, 0x4b4f16b,
	0x11902a0, 0x6c29cc9, 0x1d5ffbe6, 0xdb0b4c7, 0x10144c14, 0x2f2b719, 0x301189, 0x2343336, 0xa0bf2ac,
}

func sm2P256GetScalar(b *[32]byte, a []byte) {
	var scalarBytes []byte

	n := new(big.Int).SetBytes(a)
	if n.Cmp(sm2P256.N) >= 0 {
		n.Mod(n, sm2P256.N)
		scalarBytes = n.Bytes()
	} else {
		scalarBytes = a
	}
	for i, v := range scalarBytes {
		b[len(scalarBytes)-(1+i)] = v
	}
}

func sm2P256PointAddMixed(xOut, yOut, zOut, x1, y1, z1, x2, y2 *sm2P256FieldElement) {
	var z1z1, z1z1z1, s2, u2, h, i, j, r, rr, v, tmp sm2P256FieldElement

	sm2P256Square(&z1z1, z1)
	sm2P256Add(&tmp, z1, z1)

	sm2P256Mul(&u2, x2, &z1z1)
	sm2P256Mul(&z1z1z1, z1, &z1z1)
	sm2P256Mul(&s2, y2, &z1z1z1)
	sm2P256Sub(&h, &u2, x1)
	sm2P256Add(&i, &h, &h)
	sm2P256Square(&i, &i)
	sm2P256Mul(&j, &h, &i)
	sm2P256Sub(&r, &s2, y1)
	sm2P256Add(&r, &r, &r)
	sm2P256Mul(&v, x1, &i)

	sm2P256Mul(zOut, &tmp, &h)
	sm2P256Square(&rr, &r)
	sm2P256Sub(xOut, &rr, &j)
	sm2P256Sub(xOut, xOut, &v)
	sm2P256Sub(xOut, xOut, &v)

	sm2P256Sub(&tmp, &v, xOut)
	sm2P256Mul(yOut, &tmp, &r)
	sm2P256Mul(&tmp, y1, &j)
	sm2P256Sub(yOut, yOut, &tmp)
	sm2P256Sub(yOut, yOut, &tmp)
}

// sm2P256CopyConditional sets out=in if mask = 0xffffffff in constant time.
//
// On entry: mask is either 0 or 0xffffffff.
func sm2P256CopyConditional(out, in *sm2P256FieldElement, mask uint32) {
	for i := 0; i < 9; i++ {
		tmp := mask & (in[i] ^ out[i])
		out[i] ^= tmp
	}
}

// sm2P256SelectAffinePoint sets {out_x,out_y} to the index'th entry of table.
// On entry: index < 16, table[0] must be zero.
func sm2P256SelectAffinePoint(xOut, yOut *sm2P256FieldElement, table []uint32, index uint32) {
	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}

	for i := uint32(1); i < 16; i++ {
		mask := i ^ index
		mask |= mask >> 2
		mask |= mask >> 1
		mask &= 1
		mask--
		for j := range xOut {
			xOut[j] |= table[0] & mask
			table = table[1:]
		}
		for j := range yOut {
			yOut[j] |= table[0] & mask
			table = table[1:]
		}
	}
}

// sm2P256SelectJacobianPoint sets {out_x,out_y,out_z} to the index'th entry of
// table.
// On entry: index < 16, table[0] must be zero.
func sm2P256SelectJacobianPoint(xOut, yOut, zOut *sm2P256FieldElement, table *[16][3]sm2P256FieldElement, index uint32) {
	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}
	for i := range zOut {
		zOut[i] = 0
	}

	// The implicit value at index 0 is all zero. We don't need to perform that
	// iteration of the loop because we already set out_* to zero.
	for i := uint32(1); i < 16; i++ {
		mask := i ^ index
		mask |= mask >> 2
		mask |= mask >> 1
		mask &= 1
		mask--
		for j := range xOut {
			xOut[j] |= table[i][0][j] & mask
		}
		for j := range yOut {
			yOut[j] |= table[i][1][j] & mask
		}
		for j := range zOut {
			zOut[j] |= table[i][2][j] & mask
		}
	}
}

// sm2P256GetBit returns the bit'th bit of scalar.
func sm2P256GetBit(scalar *[32]uint8, bit uint) uint32 {
	return uint32(((scalar[bit>>3]) >> (bit & 7)) & 1)
}

// sm2P256ScalarBaseMult sets {xOut,yOut,zOut} = scalar*G where scalar is a
// little-endian number. Note that the value of scalar must be less than the
// order of the group.
func sm2P256ScalarBaseMult(xOut, yOut, zOut *sm2P256FieldElement, scalar *[32]uint8) {
	nIsInfinityMask := ^uint32(0)
	var px, py, tx, ty, tz sm2P256FieldElement
	var pIsNoninfiniteMask, mask, tableOffset uint32

	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}
	for i := range zOut {
		zOut[i] = 0
	}

	// The loop adds bits at positions 0, 64, 128 and 192, followed by
	// positions 32,96,160 and 224 and does this 32 times.
	for i := uint(0); i < 32; i++ {
		if i != 0 {
			sm2P256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
		}
		tableOffset = 0
		for j := uint(0); j <= 32; j += 32 {
			bit0 := sm2P256GetBit(scalar, 31-i+j)
			bit1 := sm2P256GetBit(scalar, 95-i+j)
			bit2 := sm2P256GetBit(scalar, 159-i+j)
			bit3 := sm2P256GetBit(scalar, 223-i+j)
			index := bit0 | (bit1 << 1) | (bit2 << 2) | (bit3 << 3)

			sm2P256SelectAffinePoint(&px, &py, sm2P256Precomputed[tableOffset:], index)
			tableOffset += 30 * 9

			// Since scalar is less than the order of the group, we know that
			// {xOut,yOut,zOut} != {px,py,1}, unless both are zero, which we handle
			// below.
			sm2P256PointAddMixed(&tx, &ty, &tz, xOut, yOut, zOut, &px, &py)
			// The result of pointAddMixed is incorrect if {xOut,yOut,zOut} is zero
			// (a.k.a.  the point at infinity). We handle that situation by
			// copying the point from the table.
			sm2P256CopyConditional(xOut, &px, nIsInfinityMask)
			sm2P256CopyConditional(yOut, &py, nIsInfinityMask)
			sm2P256CopyConditional(zOut, &sm2P256Factor[1], nIsInfinityMask)

			// Equally, the result is also wrong if the point from the table is
			// zero, which happens when the index is zero. We handle that by
			// only copying from {tx,ty,tz} to {xOut,yOut,zOut} if index != 0.
			pIsNoninfiniteMask = nonZeroToAllOnes(index)
			mask = pIsNoninfiniteMask & ^nIsInfinityMask
			sm2P256CopyConditional(xOut, &tx, mask)
			sm2P256CopyConditional(yOut, &ty, mask)
			sm2P256CopyConditional(zOut, &tz, mask)
			// If p was not zero, then n is now non-zero.
			nIsInfinityMask &^= pIsNoninfiniteMask
		}
	}
}

func sm2P256PointToAffine(xOut, yOut, x, y, z *sm2P256FieldElement) {
	var zInv, zInvSq sm2P256FieldElement

	zz := sm2P256ToBig(z)
	zz.ModInverse(zz, sm2P256.P)
	sm2P256FromBig(&zInv, zz)

	sm2P256Square(&zInvSq, &zInv)
	sm2P256Mul(xOut, x, &zInvSq)
	sm2P256Mul(&zInv, &zInv, &zInvSq)
	sm2P256Mul(yOut, y, &zInv)
}

func sm2P256ToAffine(x, y, z *sm2P256FieldElement) (xOut, yOut *big.Int) {
	var xx, yy sm2P256FieldElement

	sm2P256PointToAffine(&xx, &yy, x, y, z)
	return sm2P256ToBig(&xx), sm2P256ToBig(&yy)
}

var sm2P256Factor = []sm2P256FieldElement{
	sm2P256FieldElement{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
	sm2P256FieldElement{0x2, 0x0, 0x1FFFFF00, 0x7FF, 0x0, 0x0, 0x0, 0x2000000, 0x0},
	sm2P256FieldElement{0x4, 0x0, 0x1FFFFE00, 0xFFF, 0x0, 0x0, 0x0, 0x4000000, 0x0},
	sm2P256FieldElement{0x6, 0x0, 0x1FFFFD00, 0x17FF, 0x0, 0x0, 0x0, 0x6000000, 0x0},
	sm2P256FieldElement{0x8, 0x0, 0x1FFFFC00, 0x1FFF, 0x0, 0x0, 0x0, 0x8000000, 0x0},
	sm2P256FieldElement{0xA, 0x0, 0x1FFFFB00, 0x27FF, 0x0, 0x0, 0x0, 0xA000000, 0x0},
	sm2P256FieldElement{0xC, 0x0, 0x1FFFFA00, 0x2FFF, 0x0, 0x0, 0x0, 0xC000000, 0x0},
	sm2P256FieldElement{0xE, 0x0, 0x1FFFF900, 0x37FF, 0x0, 0x0, 0x0, 0xE000000, 0x0},
	sm2P256FieldElement{0x10, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x0, 0x01},
}

func sm2P256Scalar(b *sm2P256FieldElement, a int) {
	sm2P256Mul(b, b, &sm2P256Factor[a])
}

// (x3, y3, z3) = (x1, y1, z1) + (x2, y2, z2)
func sm2P256PointAdd(x1, y1, z1, x2, y2, z2, x3, y3, z3 *sm2P256FieldElement) {
	var u1, u2, z22, z12, z23, z13, s1, s2, h, h2, r, r2, tm sm2P256FieldElement

	if sm2P256ToBig(z1).Sign() == 0 {
		sm2P256Dup(x3, x2)
		sm2P256Dup(y3, y2)
		sm2P256Dup(z3, z2)
		return
	}

	if sm2P256ToBig(z2).Sign() == 0 {
		sm2P256Dup(x3, x1)
		sm2P256Dup(y3, y1)
		sm2P256Dup(z3, z1)
		return
	}

	sm2P256Square(&z12, z1) // z12 = z1 ^ 2
	sm2P256Square(&z22, z2) // z22 = z2 ^ 2

	sm2P256Mul(&z13, &z12, z1) // z13 = z1 ^ 3
	sm2P256Mul(&z23, &z22, z2) // z23 = z2 ^ 3

	sm2P256Mul(&u1, x1, &z22) // u1 = x1 * z2 ^ 2
	sm2P256Mul(&u2, x2, &z12) // u2 = x2 * z1 ^ 2

	sm2P256Mul(&s1, y1, &z23) // s1 = y1 * z2 ^ 3
	sm2P256Mul(&s2, y2, &z13) // s2 = y2 * z1 ^ 3

	if sm2P256ToBig(&u1).Cmp(sm2P256ToBig(&u2)) == 0 &&
		sm2P256ToBig(&s1).Cmp(sm2P256ToBig(&s2)) == 0 {
		sm2P256PointDouble(x1, y1, z1, x1, y1, z1)
	}

	sm2P256Sub(&h, &u2, &u1) // h = u2 - u1
	sm2P256Sub(&r, &s2, &s1) // r = s2 - s1

	sm2P256Square(&r2, &r) // r2 = r ^ 2
	sm2P256Square(&h2, &h) // h2 = h ^ 2

	sm2P256Mul(&tm, &h2, &h) // tm = h ^ 3
	sm2P256Sub(x3, &r2, &tm)
	sm2P256Mul(&tm, &u1, &h2)
	sm2P256Scalar(&tm, 2)   // tm = 2 * (u1 * h ^ 2)
	sm2P256Sub(x3, x3, &tm) // x3 = r ^ 2 - h ^ 3 - 2 * u1 * h ^ 2

	sm2P256Mul(&tm, &u1, &h2) // tm = u1 * h ^ 2
	sm2P256Sub(&tm, &tm, x3)  // tm = u1 * h ^ 2 - x3
	sm2P256Mul(y3, &r, &tm)
	sm2P256Mul(&tm, &h2, &h)  // tm = h ^ 3
	sm2P256Mul(&tm, &tm, &s1) // tm = s1 * h ^ 3
	sm2P256Sub(y3, y3, &tm)   // y3 = r * (u1 * h ^ 2 - x3) - s1 * h ^ 3

	sm2P256Mul(z3, z1, z2)
	sm2P256Mul(z3, z3, &h) // z3 = z1 * z3 * h
}

// (x3, y3, z3) = (x1, y1, z1)- (x2, y2, z2)
func sm2P256PointSub(x1, y1, z1, x2, y2, z2, x3, y3, z3 *sm2P256FieldElement) {
	var u1, u2, z22, z12, z23, z13, s1, s2, h, h2, r, r2, tm sm2P256FieldElement
	y:=sm2P256ToBig(y2)
	zero:=new(big.Int).SetInt64(0)
	y.Sub(zero,y)
	sm2P256FromBig(y2,y)

	if sm2P256ToBig(z1).Sign() == 0 {
		sm2P256Dup(x3, x2)
		sm2P256Dup(y3, y2)
		sm2P256Dup(z3, z2)
		return
	}

	if sm2P256ToBig(z2).Sign() == 0 {
		sm2P256Dup(x3, x1)
		sm2P256Dup(y3, y1)
		sm2P256Dup(z3, z1)
		return
	}

	sm2P256Square(&z12, z1) // z12 = z1 ^ 2
	sm2P256Square(&z22, z2) // z22 = z2 ^ 2

	sm2P256Mul(&z13, &z12, z1) // z13 = z1 ^ 3
	sm2P256Mul(&z23, &z22, z2) // z23 = z2 ^ 3

	sm2P256Mul(&u1, x1, &z22) // u1 = x1 * z2 ^ 2
	sm2P256Mul(&u2, x2, &z12) // u2 = x2 * z1 ^ 2

	sm2P256Mul(&s1, y1, &z23) // s1 = y1 * z2 ^ 3
	sm2P256Mul(&s2, y2, &z13) // s2 = y2 * z1 ^ 3

	if sm2P256ToBig(&u1).Cmp(sm2P256ToBig(&u2)) == 0 &&
		sm2P256ToBig(&s1).Cmp(sm2P256ToBig(&s2)) == 0 {
		sm2P256PointDouble(x1, y1, z1, x1, y1, z1)
	}

	sm2P256Sub(&h, &u2, &u1) // h = u2 - u1
	sm2P256Sub(&r, &s2, &s1) // r = s2 - s1

	sm2P256Square(&r2, &r) // r2 = r ^ 2
	sm2P256Square(&h2, &h) // h2 = h ^ 2

	sm2P256Mul(&tm, &h2, &h) // tm = h ^ 3
	sm2P256Sub(x3, &r2, &tm)
	sm2P256Mul(&tm, &u1, &h2)
	sm2P256Scalar(&tm, 2)   // tm = 2 * (u1 * h ^ 2)
	sm2P256Sub(x3, x3, &tm) // x3 = r ^ 2 - h ^ 3 - 2 * u1 * h ^ 2

	sm2P256Mul(&tm, &u1, &h2) // tm = u1 * h ^ 2
	sm2P256Sub(&tm, &tm, x3)  // tm = u1 * h ^ 2 - x3
	sm2P256Mul(y3, &r, &tm)
	sm2P256Mul(&tm, &h2, &h)  // tm = h ^ 3
	sm2P256Mul(&tm, &tm, &s1) // tm = s1 * h ^ 3
	sm2P256Sub(y3, y3, &tm)   // y3 = r * (u1 * h ^ 2 - x3) - s1 * h ^ 3

	sm2P256Mul(z3, z1, z2)
	sm2P256Mul(z3, z3, &h) // z3 = z1 * z3 * h
}

func sm2P256PointDouble(x3, y3, z3, x, y, z *sm2P256FieldElement) {
	var s, m, m2, x2, y2, z2, z4, y4, az4 sm2P256FieldElement

	sm2P256Square(&x2, x) // x2 = x ^ 2
	sm2P256Square(&y2, y) // y2 = y ^ 2
	sm2P256Square(&z2, z) // z2 = z ^ 2

	sm2P256Square(&z4, z)   // z4 = z ^ 2
	sm2P256Mul(&z4, &z4, z) // z4 = z ^ 3
	sm2P256Mul(&z4, &z4, z) // z4 = z ^ 4

	sm2P256Square(&y4, y)   // y4 = y ^ 2
	sm2P256Mul(&y4, &y4, y) // y4 = y ^ 3
	sm2P256Mul(&y4, &y4, y) // y4 = y ^ 4
	sm2P256Scalar(&y4, 8)   // y4 = 8 * y ^ 4

	sm2P256Mul(&s, x, &y2)
	sm2P256Scalar(&s, 4) // s = 4 * x * y ^ 2

	sm2P256Dup(&m, &x2)
	sm2P256Scalar(&m, 3)
	sm2P256Mul(&az4, &sm2P256.a, &z4)
	sm2P256Add(&m, &m, &az4) // m = 3 * x ^ 2 + a * z ^ 4

	sm2P256Square(&m2, &m) // m2 = m ^ 2

	sm2P256Add(z3, y, z)
	sm2P256Square(z3, z3)
	sm2P256Sub(z3, z3, &z2)
	sm2P256Sub(z3, z3, &y2) // z' = (y + z) ^2 - z ^ 2 - y ^ 2

	sm2P256Sub(x3, &m2, &s)
	sm2P256Sub(x3, x3, &s) // x' = m2 - 2 * s

	sm2P256Sub(y3, &s, x3)
	sm2P256Mul(y3, y3, &m)
	sm2P256Sub(y3, y3, &y4) // y' = m * (s - x') - 8 * y ^ 4
}

// p256Zero31 is 0 mod p.
var sm2P256Zero31 = sm2P256FieldElement{0x7FFFFFF8, 0x3FFFFFFC, 0x800003FC, 0x3FFFDFFC, 0x7FFFFFFC, 0x3FFFFFFC, 0x7FFFFFFC, 0x37FFFFFC, 0x7FFFFFFC}

// c = a + b
func sm2P256Add(c, a, b *sm2P256FieldElement) {
	carry := uint32(0)
	for i := 0; ; i++ {
		c[i] = a[i] + b[i]
		c[i] += carry
		carry = c[i] >> 29
		c[i] &= bottom29Bits
		i++
		if i == 9 {
			break
		}
		c[i] = a[i] + b[i]
		c[i] += carry
		carry = c[i] >> 28
		c[i] &= bottom28Bits
	}
	sm2P256ReduceCarry(c, carry)
}

// c = a - b
func sm2P256Sub(c, a, b *sm2P256FieldElement) {
	var carry uint32

	for i := 0; ; i++ {
		c[i] = a[i] - b[i]
		c[i] += sm2P256Zero31[i]
		c[i] += carry
		carry = c[i] >> 29
		c[i] &= bottom29Bits
		i++
		if i == 9 {
			break
		}
		c[i] = a[i] - b[i]
		c[i] += sm2P256Zero31[i]
		c[i] += carry
		carry = c[i] >> 28
		c[i] &= bottom28Bits
	}
	sm2P256ReduceCarry(c, carry)
}

// c = a * b
func sm2P256Mul(c, a, b *sm2P256FieldElement) {
	var tmp sm2P256LargeFieldElement

	tmp[0] = uint64(a[0]) * uint64(b[0])
	tmp[1] = uint64(a[0])*(uint64(b[1])<<0) +
		uint64(a[1])*(uint64(b[0])<<0)
	tmp[2] = uint64(a[0])*(uint64(b[2])<<0) +
		uint64(a[1])*(uint64(b[1])<<1) +
		uint64(a[2])*(uint64(b[0])<<0)
	tmp[3] = uint64(a[0])*(uint64(b[3])<<0) +
		uint64(a[1])*(uint64(b[2])<<0) +
		uint64(a[2])*(uint64(b[1])<<0) +
		uint64(a[3])*(uint64(b[0])<<0)
	tmp[4] = uint64(a[0])*(uint64(b[4])<<0) +
		uint64(a[1])*(uint64(b[3])<<1) +
		uint64(a[2])*(uint64(b[2])<<0) +
		uint64(a[3])*(uint64(b[1])<<1) +
		uint64(a[4])*(uint64(b[0])<<0)
	tmp[5] = uint64(a[0])*(uint64(b[5])<<0) +
		uint64(a[1])*(uint64(b[4])<<0) +
		uint64(a[2])*(uint64(b[3])<<0) +
		uint64(a[3])*(uint64(b[2])<<0) +
		uint64(a[4])*(uint64(b[1])<<0) +
		uint64(a[5])*(uint64(b[0])<<0)
	tmp[6] = uint64(a[0])*(uint64(b[6])<<0) +
		uint64(a[1])*(uint64(b[5])<<1) +
		uint64(a[2])*(uint64(b[4])<<0) +
		uint64(a[3])*(uint64(b[3])<<1) +
		uint64(a[4])*(uint64(b[2])<<0) +
		uint64(a[5])*(uint64(b[1])<<1) +
		uint64(a[6])*(uint64(b[0])<<0)
	tmp[7] = uint64(a[0])*(uint64(b[7])<<0) +
		uint64(a[1])*(uint64(b[6])<<0) +
		uint64(a[2])*(uint64(b[5])<<0) +
		uint64(a[3])*(uint64(b[4])<<0) +
		uint64(a[4])*(uint64(b[3])<<0) +
		uint64(a[5])*(uint64(b[2])<<0) +
		uint64(a[6])*(uint64(b[1])<<0) +
		uint64(a[7])*(uint64(b[0])<<0)
	// tmp[8] has the greatest value but doesn't overflow. See logic in
	// p256Square.
	tmp[8] = uint64(a[0])*(uint64(b[8])<<0) +
		uint64(a[1])*(uint64(b[7])<<1) +
		uint64(a[2])*(uint64(b[6])<<0) +
		uint64(a[3])*(uint64(b[5])<<1) +
		uint64(a[4])*(uint64(b[4])<<0) +
		uint64(a[5])*(uint64(b[3])<<1) +
		uint64(a[6])*(uint64(b[2])<<0) +
		uint64(a[7])*(uint64(b[1])<<1) +
		uint64(a[8])*(uint64(b[0])<<0)
	tmp[9] = uint64(a[1])*(uint64(b[8])<<0) +
		uint64(a[2])*(uint64(b[7])<<0) +
		uint64(a[3])*(uint64(b[6])<<0) +
		uint64(a[4])*(uint64(b[5])<<0) +
		uint64(a[5])*(uint64(b[4])<<0) +
		uint64(a[6])*(uint64(b[3])<<0) +
		uint64(a[7])*(uint64(b[2])<<0) +
		uint64(a[8])*(uint64(b[1])<<0)
	tmp[10] = uint64(a[2])*(uint64(b[8])<<0) +
		uint64(a[3])*(uint64(b[7])<<1) +
		uint64(a[4])*(uint64(b[6])<<0) +
		uint64(a[5])*(uint64(b[5])<<1) +
		uint64(a[6])*(uint64(b[4])<<0) +
		uint64(a[7])*(uint64(b[3])<<1) +
		uint64(a[8])*(uint64(b[2])<<0)
	tmp[11] = uint64(a[3])*(uint64(b[8])<<0) +
		uint64(a[4])*(uint64(b[7])<<0) +
		uint64(a[5])*(uint64(b[6])<<0) +
		uint64(a[6])*(uint64(b[5])<<0) +
		uint64(a[7])*(uint64(b[4])<<0) +
		uint64(a[8])*(uint64(b[3])<<0)
	tmp[12] = uint64(a[4])*(uint64(b[8])<<0) +
		uint64(a[5])*(uint64(b[7])<<1) +
		uint64(a[6])*(uint64(b[6])<<0) +
		uint64(a[7])*(uint64(b[5])<<1) +
		uint64(a[8])*(uint64(b[4])<<0)
	tmp[13] = uint64(a[5])*(uint64(b[8])<<0) +
		uint64(a[6])*(uint64(b[7])<<0) +
		uint64(a[7])*(uint64(b[6])<<0) +
		uint64(a[8])*(uint64(b[5])<<0)
	tmp[14] = uint64(a[6])*(uint64(b[8])<<0) +
		uint64(a[7])*(uint64(b[7])<<1) +
		uint64(a[8])*(uint64(b[6])<<0)
	tmp[15] = uint64(a[7])*(uint64(b[8])<<0) +
		uint64(a[8])*(uint64(b[7])<<0)
	tmp[16] = uint64(a[8]) * (uint64(b[8]) << 0)
	sm2P256ReduceDegree(c, &tmp)
}

// b = a * a
func sm2P256Square(b, a *sm2P256FieldElement) {
	var tmp sm2P256LargeFieldElement

	tmp[0] = uint64(a[0]) * uint64(a[0])
	tmp[1] = uint64(a[0]) * (uint64(a[1]) << 1)
	tmp[2] = uint64(a[0])*(uint64(a[2])<<1) +
		uint64(a[1])*(uint64(a[1])<<1)
	tmp[3] = uint64(a[0])*(uint64(a[3])<<1) +
		uint64(a[1])*(uint64(a[2])<<1)
	tmp[4] = uint64(a[0])*(uint64(a[4])<<1) +
		uint64(a[1])*(uint64(a[3])<<2) +
		uint64(a[2])*uint64(a[2])
	tmp[5] = uint64(a[0])*(uint64(a[5])<<1) +
		uint64(a[1])*(uint64(a[4])<<1) +
		uint64(a[2])*(uint64(a[3])<<1)
	tmp[6] = uint64(a[0])*(uint64(a[6])<<1) +
		uint64(a[1])*(uint64(a[5])<<2) +
		uint64(a[2])*(uint64(a[4])<<1) +
		uint64(a[3])*(uint64(a[3])<<1)
	tmp[7] = uint64(a[0])*(uint64(a[7])<<1) +
		uint64(a[1])*(uint64(a[6])<<1) +
		uint64(a[2])*(uint64(a[5])<<1) +
		uint64(a[3])*(uint64(a[4])<<1)
	// tmp[8] has the greatest value of 2**61 + 2**60 + 2**61 + 2**60 + 2**60,
	// which is < 2**64 as required.
	tmp[8] = uint64(a[0])*(uint64(a[8])<<1) +
		uint64(a[1])*(uint64(a[7])<<2) +
		uint64(a[2])*(uint64(a[6])<<1) +
		uint64(a[3])*(uint64(a[5])<<2) +
		uint64(a[4])*uint64(a[4])
	tmp[9] = uint64(a[1])*(uint64(a[8])<<1) +
		uint64(a[2])*(uint64(a[7])<<1) +
		uint64(a[3])*(uint64(a[6])<<1) +
		uint64(a[4])*(uint64(a[5])<<1)
	tmp[10] = uint64(a[2])*(uint64(a[8])<<1) +
		uint64(a[3])*(uint64(a[7])<<2) +
		uint64(a[4])*(uint64(a[6])<<1) +
		uint64(a[5])*(uint64(a[5])<<1)
	tmp[11] = uint64(a[3])*(uint64(a[8])<<1) +
		uint64(a[4])*(uint64(a[7])<<1) +
		uint64(a[5])*(uint64(a[6])<<1)
	tmp[12] = uint64(a[4])*(uint64(a[8])<<1) +
		uint64(a[5])*(uint64(a[7])<<2) +
		uint64(a[6])*uint64(a[6])
	tmp[13] = uint64(a[5])*(uint64(a[8])<<1) +
		uint64(a[6])*(uint64(a[7])<<1)
	tmp[14] = uint64(a[6])*(uint64(a[8])<<1) +
		uint64(a[7])*(uint64(a[7])<<1)
	tmp[15] = uint64(a[7]) * (uint64(a[8]) << 1)
	tmp[16] = uint64(a[8]) * uint64(a[8])
	sm2P256ReduceDegree(b, &tmp)
}

// nonZeroToAllOnes returns:
//   0xffffffff for 0 < x <= 2**31
//   0 for x == 0 or x > 2**31.
func nonZeroToAllOnes(x uint32) uint32 {
	return ((x - 1) >> 31) - 1
}

var sm2P256Carry = [8 * 9]uint32{
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x2, 0x0, 0x1FFFFF00, 0x7FF, 0x0, 0x0, 0x0, 0x2000000, 0x0,
	0x4, 0x0, 0x1FFFFE00, 0xFFF, 0x0, 0x0, 0x0, 0x4000000, 0x0,
	0x6, 0x0, 0x1FFFFD00, 0x17FF, 0x0, 0x0, 0x0, 0x6000000, 0x0,
	0x8, 0x0, 0x1FFFFC00, 0x1FFF, 0x0, 0x0, 0x0, 0x8000000, 0x0,
	0xA, 0x0, 0x1FFFFB00, 0x27FF, 0x0, 0x0, 0x0, 0xA000000, 0x0,
	0xC, 0x0, 0x1FFFFA00, 0x2FFF, 0x0, 0x0, 0x0, 0xC000000, 0x0,
	0xE, 0x0, 0x1FFFF900, 0x37FF, 0x0, 0x0, 0x0, 0xE000000, 0x0,
}

// carry < 2 ^ 3
func sm2P256ReduceCarry(a *sm2P256FieldElement, carry uint32) {
	a[0] += sm2P256Carry[carry*9+0]
	a[2] += sm2P256Carry[carry*9+2]
	a[3] += sm2P256Carry[carry*9+3]
	a[7] += sm2P256Carry[carry*9+7]
}

// 这代码真是丑比了，我也是对自己醉了。。。
// 你最好别改这个代码，不然你会死的很惨。。
func sm2P256ReduceDegree(a *sm2P256FieldElement, b *sm2P256LargeFieldElement) {
	var tmp [18]uint32
	var carry, x, xMask uint32

	// tmp
	// 0  | 1  | 2  | 3  | 4  | 5  | 6  | 7  | 8  |  9 | 10 ...
	// 29 | 28 | 29 | 28 | 29 | 28 | 29 | 28 | 29 | 28 | 29 ...
	tmp[0] = uint32(b[0]) & bottom29Bits
	tmp[1] = uint32(b[0]) >> 29
	tmp[1] |= (uint32(b[0]>>32) << 3) & bottom28Bits
	tmp[1] += uint32(b[1]) & bottom28Bits
	carry = tmp[1] >> 28
	tmp[1] &= bottom28Bits
	for i := 2; i < 17; i++ {
		tmp[i] = (uint32(b[i-2] >> 32)) >> 25
		tmp[i] += (uint32(b[i-1])) >> 28
		tmp[i] += (uint32(b[i-1]>>32) << 4) & bottom29Bits
		tmp[i] += uint32(b[i]) & bottom29Bits
		tmp[i] += carry
		carry = tmp[i] >> 29
		tmp[i] &= bottom29Bits

		i++
		if i == 17 {
			break
		}
		tmp[i] = uint32(b[i-2]>>32) >> 25
		tmp[i] += uint32(b[i-1]) >> 29
		tmp[i] += ((uint32(b[i-1] >> 32)) << 3) & bottom28Bits
		tmp[i] += uint32(b[i]) & bottom28Bits
		tmp[i] += carry
		carry = tmp[i] >> 28
		tmp[i] &= bottom28Bits
	}
	tmp[17] = uint32(b[15]>>32) >> 25
	tmp[17] += uint32(b[16]) >> 29
	tmp[17] += uint32(b[16]>>32) << 3
	tmp[17] += carry

	for i := 0; ; i += 2 {

		tmp[i+1] += tmp[i] >> 29
		x = tmp[i] & bottom29Bits
		tmp[i] = 0
		if x > 0 {
			set4 := uint32(0)
			set7 := uint32(0)
			xMask = nonZeroToAllOnes(x)
			tmp[i+2] += (x << 7) & bottom29Bits
			tmp[i+3] += x >> 22
			if tmp[i+3] < 0x10000000 {
				set4 = 1
				tmp[i+3] += 0x10000000 & xMask
				tmp[i+3] -= (x << 10) & bottom28Bits
			} else {
				tmp[i+3] -= (x << 10) & bottom28Bits
			}
			if tmp[i+4] < 0x20000000 {
				tmp[i+4] += 0x20000000 & xMask
				tmp[i+4] -= set4 // 借位
				tmp[i+4] -= x >> 18
				if tmp[i+5] < 0x10000000 {
					tmp[i+5] += 0x10000000 & xMask
					tmp[i+5] -= 1 // 借位
					if tmp[i+6] < 0x20000000 {
						set7 = 1
						tmp[i+6] += 0x20000000 & xMask
						tmp[i+6] -= 1 // 借位
					} else {
						tmp[i+6] -= 1 // 借位
					}
				} else {
					tmp[i+5] -= 1
				}
			} else {
				tmp[i+4] -= set4 // 借位
				tmp[i+4] -= x >> 18
			}
			if tmp[i+7] < 0x10000000 {
				tmp[i+7] += 0x10000000 & xMask
				tmp[i+7] -= set7
				tmp[i+7] -= (x << 24) & bottom28Bits
				tmp[i+8] += (x << 28) & bottom29Bits
				if tmp[i+8] < 0x20000000 {
					tmp[i+8] += 0x20000000 & xMask
					tmp[i+8] -= 1
					tmp[i+8] -= x >> 4
					tmp[i+9] += ((x >> 1) - 1) & xMask
				} else {
					tmp[i+8] -= 1
					tmp[i+8] -= x >> 4
					tmp[i+9] += (x >> 1) & xMask
				}
			} else {
				tmp[i+7] -= set7 // 借位
				tmp[i+7] -= (x << 24) & bottom28Bits
				tmp[i+8] += (x << 28) & bottom29Bits
				if tmp[i+8] < 0x20000000 {
					tmp[i+8] += 0x20000000 & xMask
					tmp[i+8] -= x >> 4
					tmp[i+9] += ((x >> 1) - 1) & xMask
				} else {
					tmp[i+8] -= x >> 4
					tmp[i+9] += (x >> 1) & xMask
				}
			}

		}

		if i+1 == 9 {
			break
		}

		tmp[i+2] += tmp[i+1] >> 28
		x = tmp[i+1] & bottom28Bits
		tmp[i+1] = 0
		if x > 0 {
			set5 := uint32(0)
			set8 := uint32(0)
			set9 := uint32(0)
			xMask = nonZeroToAllOnes(x)
			tmp[i+3] += (x << 7) & bottom28Bits
			tmp[i+4] += x >> 21
			if tmp[i+4] < 0x20000000 {
				set5 = 1
				tmp[i+4] += 0x20000000 & xMask
				tmp[i+4] -= (x << 11) & bottom29Bits
			} else {
				tmp[i+4] -= (x << 11) & bottom29Bits
			}
			if tmp[i+5] < 0x10000000 {
				tmp[i+5] += 0x10000000 & xMask
				tmp[i+5] -= set5 // 借位
				tmp[i+5] -= x >> 18
				if tmp[i+6] < 0x20000000 {
					tmp[i+6] += 0x20000000 & xMask
					tmp[i+6] -= 1 // 借位
					if tmp[i+7] < 0x10000000 {
						set8 = 1
						tmp[i+7] += 0x10000000 & xMask
						tmp[i+7] -= 1 // 借位
					} else {
						tmp[i+7] -= 1 // 借位
					}
				} else {
					tmp[i+6] -= 1 // 借位
				}
			} else {
				tmp[i+5] -= set5 // 借位
				tmp[i+5] -= x >> 18
			}
			if tmp[i+8] < 0x20000000 {
				set9 = 1
				tmp[i+8] += 0x20000000 & xMask
				tmp[i+8] -= set8
				tmp[i+8] -= (x << 25) & bottom29Bits
			} else {
				tmp[i+8] -= set8
				tmp[i+8] -= (x << 25) & bottom29Bits
			}
			if tmp[i+9] < 0x10000000 {
				tmp[i+9] += 0x10000000 & xMask
				tmp[i+9] -= set9 // 借位
				tmp[i+9] -= x >> 4
				tmp[i+10] += (x - 1) & xMask
			} else {
				tmp[i+9] -= set9 // 借位
				tmp[i+9] -= x >> 4
				tmp[i+10] += x & xMask
			}
		}
	}

	carry = uint32(0)
	for i := 0; i < 8; i++ {
		a[i] = tmp[i+9]
		a[i] += carry
		a[i] += (tmp[i+10] << 28) & bottom29Bits
		carry = a[i] >> 29
		a[i] &= bottom29Bits

		i++
		a[i] = tmp[i+9] >> 1
		a[i] += carry
		carry = a[i] >> 28
		a[i] &= bottom28Bits
	}
	a[8] = tmp[17]
	a[8] += carry
	carry = a[8] >> 29
	a[8] &= bottom29Bits
	sm2P256ReduceCarry(a, carry)
}

// b = a
func sm2P256Dup(b, a *sm2P256FieldElement) {
	*b = *a
}

// X = a * R mod P
func sm2P256FromBig(X *sm2P256FieldElement, a *big.Int) {
	x := new(big.Int).Lsh(a, 257)
	x.Mod(x, sm2P256.P)
	for i := 0; i < 9; i++ {
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom29Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 29)
		i++
		if i == 9 {
			break
		}
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom28Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 28)
	}
}

// X = r * R mod P
// r = X * R' mod P
func sm2P256ToBig(X *sm2P256FieldElement) *big.Int {
	r, tm := new(big.Int), new(big.Int)
	r.SetInt64(int64(X[8]))
	for i := 7; i >= 0; i-- {
		if (i & 1) == 0 {
			r.Lsh(r, 29)
		} else {
			r.Lsh(r, 28)
		}
		tm.SetInt64(int64(X[i]))
		r.Add(r, tm)
	}
	r.Mul(r, sm2P256.RInverse)
	r.Mod(r, sm2P256.P)
	return r
}
func WNafReversed(wnaf []int8) []int8 {
	wnafRev := make([]int8, len(wnaf), len(wnaf))
	for i, v := range wnaf {
		wnafRev[len(wnaf)-(1+i)] = v
	}
	return wnafRev
}
func sm2GenrateWNaf(b []byte) []int8 {
	n:= new(big.Int).SetBytes(b)
	var k *big.Int
	if n.Cmp(sm2P256.N) >= 0 {
		n.Mod(n, sm2P256.N)
		k = n
	} else {
		k = n
	}
	wnaf := make([]int8, k.BitLen()+1, k.BitLen()+1)
	if k.Sign() == 0 {
		return wnaf
	}
	var width, pow2, sign int
	width, pow2, sign = 4, 16, 8
	var mask int64 = 15
	var carry bool
	var length, pos int
	for pos <= k.BitLen() {
		if k.Bit(pos) == boolToUint(carry) {
			pos++
			continue
		}
		k.Rsh(k, uint(pos))
		var digit int
		digit = int(k.Int64() & mask)
		if carry {
			digit++
		}
		carry = (digit & sign) != 0
		if carry {
			digit -= pow2
		}
		length += pos
		wnaf[length] = int8(digit)
		pos = int(width)
	}
	if len(wnaf) > length+1 {
		t := make([]int8, length+1, length+1)
		copy(t, wnaf[0:length+1])
		wnaf = t
	}
	return wnaf
}
func boolToUint(b bool) uint {
	if b {
		return 1
	}
	return 0
}
func abs(a int8) uint32{
	if a<0 {
		return uint32(-a)
	}
	return uint32(a)
}

func sm2P256ScalarMult(xOut, yOut, zOut, x, y *sm2P256FieldElement, scalar []int8) {
	var precomp [16][3]sm2P256FieldElement
	var px, py, pz, tx, ty, tz sm2P256FieldElement
	var nIsInfinityMask, index, pIsNoninfiniteMask, mask uint32

	// We precompute 0,1,2,... times {x,y}.
	precomp[1][0] = *x
	precomp[1][1] = *y
	precomp[1][2] = sm2P256Factor[1]

	for i := 2; i < 8; i += 2 {
		sm2P256PointDouble(&precomp[i][0], &precomp[i][1], &precomp[i][2], &precomp[i/2][0], &precomp[i/2][1], &precomp[i/2][2])
		sm2P256PointAddMixed(&precomp[i+1][0], &precomp[i+1][1], &precomp[i+1][2], &precomp[i][0], &precomp[i][1], &precomp[i][2], x, y)
	}

	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}
	for i := range zOut {
		zOut[i] = 0
	}
	nIsInfinityMask = ^uint32(0)
	var zeroes int16
	for i := 0; i<len(scalar); i++ {
		if scalar[i] ==0{
			zeroes++
			continue
		}
		if(zeroes>0){
			for  ;zeroes>0;zeroes-- {
				sm2P256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
			}
		}
		index = abs(scalar[i])
		sm2P256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
		sm2P256SelectJacobianPoint(&px, &py, &pz, &precomp, index)
		if scalar[i] > 0 {
			sm2P256PointAdd(xOut, yOut, zOut, &px, &py, &pz, &tx, &ty, &tz)
		} else {
			sm2P256PointSub(xOut, yOut, zOut, &px, &py, &pz, &tx, &ty, &tz)
		}
		sm2P256CopyConditional(xOut, &px, nIsInfinityMask)
		sm2P256CopyConditional(yOut, &py, nIsInfinityMask)
		sm2P256CopyConditional(zOut, &pz, nIsInfinityMask)
		pIsNoninfiniteMask = nonZeroToAllOnes(index)
		mask = pIsNoninfiniteMask & ^nIsInfinityMask
		sm2P256CopyConditional(xOut, &tx, mask)
		sm2P256CopyConditional(yOut, &ty, mask)
		sm2P256CopyConditional(zOut, &tz, mask)
		nIsInfinityMask &^= pIsNoninfiniteMask
	}
	if(zeroes>0){
		for  ;zeroes>0;zeroes-- {
			sm2P256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
		}
	}
}
