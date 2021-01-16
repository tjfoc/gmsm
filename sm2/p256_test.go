package sm2

import (
	"math/big"
	"testing"
)

var D1, _ = new(big.Int).SetString("97153678362774365860518296860216916279301843162955384675219110984034112393364", 10)
var X1, _ = new(big.Int).SetString("81559001704489008611741997348618820642479401221867240515072006477593208045921", 10)
var Y1, _ = new(big.Int).SetString("105685721488865364715150074413737068448843435072992986905863178779624898367976", 10)
var D2, _ = new(big.Int).SetString("76269306548769423512710976991507498403146014322096542349980929950411330320194", 10)
var X2, _ = new(big.Int).SetString("5850494457019939964881771577879025876322504184365127998719889651254172251216", 10)
var Y2, _ = new(big.Int).SetString("92742215369818124071137610493966149923994619293047546123917692804642003570952", 10)
var K, _ = new(big.Int).SetString("77451026430882257753057970668982810995024789586896471499062124473824578625446", 10)

func BenchmarkZForAffine(t *testing.B) {
	t.ReportAllocs()
	x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	y, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		zForAffine(x, y)
	}
}

func BenchmarkSm2P256GetScalar(t *testing.B) {
	initP256Sm2()
	t.ReportAllocs()
	var scalarReversed [32]byte
	//a := big.NewInt(1).Bytes()
	a := K.Bytes()
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256GetScalar(&scalarReversed, a)
	}
}

func BenchmarkSm2P256PointAddMixed(t *testing.B) {
	t.ReportAllocs()
	initP256Sm2()
	var x1, y1, z1, x2, y2 sm2P256FieldElement
	x1 = sm2P256FromBig(X1)
	y1 = sm2P256FromBig(Y1)
	x2 = sm2P256FromBig(X2)
	y2 = sm2P256FromBig(Y2)
	z1 = sm2P256FromBig(new(big.Int).SetInt64(1))
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256PointAddMixed(x1, y1, z1, x2, y2)
	}
}

func BenchmarkSm2P256CopyConditional(t *testing.B) {
	t.ReportAllocs()
	initP256Sm2()
	var x1, y1 sm2P256FieldElement
	var mask uint32
	x1 = sm2P256FromBig(X1)
	y1 = sm2P256FromBig(Y1)
	mask = uint32(K.Uint64())
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256CopyConditional(x1, y1, mask)
	}
}

func BenchmarkSm2P256SelectAffinePoint(t *testing.B) {
	t.ReportAllocs()
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
	var index uint32
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256SelectAffinePoint(sm2P256Precomputed[0:], index)
	}
}

func BenchmarkSm2P256SelectJacobianPoint(t *testing.B) {
	var scalar uint32
	t.ReportAllocs()
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
	t.ResetTimer()
	initP256Sm2()
	scalar = uint32(K.Uint64())
	for i := 0; i < t.N; i++ {
		sm2P256SelectAffinePoint(sm2P256Precomputed[0:], scalar)
	}
}

func BenchmarkSm2P256GetBit(t *testing.B) {
	var scalar [32]uint8
	var bit uint
	t.ReportAllocs()
	initP256Sm2()
	var b [32]byte
	scalarBytes := K.Bytes()
	for i, v := range scalarBytes {
		b[len(scalarBytes)-(1+i)] = v
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256GetBit(scalar, bit)
	}
}

func BenchmarkSm2P256ScalarBaseMult(t *testing.B) {
	t.ReportAllocs()
	initP256Sm2()
	var b [32]byte
	scalarBytes := K.Bytes()
	for i, v := range scalarBytes {
		b[len(scalarBytes)-(1+i)] = v
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256ScalarBaseMult(b)
	}
}

func BenchmarkSm2P256PointToAffine(t *testing.B) {
	var x, y, z sm2P256FieldElement
	t.ReportAllocs()
	initP256Sm2()

	x = sm2P256FromBig(X1)
	y = sm2P256FromBig(Y1)
	z = sm2P256FromBig(new(big.Int).SetInt64(1))
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256PointToAffine(x, y, z)
	}
}

func BenchmarkSm2P256ToAffine(t *testing.B) {
	var x, y, z sm2P256FieldElement
	t.ReportAllocs()
	initP256Sm2()
	x = sm2P256FromBig(X1)
	y = sm2P256FromBig(Y1)
	z = sm2P256FromBig(new(big.Int).SetInt64(1))
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256ToAffine(x, y, z)
	}
}

func BenchmarkSm2P256PointAdd(t *testing.B) {
	var x1, y1, z1, x2, y2, z2 sm2P256FieldElement
	t.ReportAllocs()
	initP256Sm2()
	x1 = sm2P256FromBig(X1)
	y1 = sm2P256FromBig(Y1)
	x2 = sm2P256FromBig(X2)
	y2 = sm2P256FromBig(Y2)
	z1 = sm2P256FromBig(new(big.Int).SetInt64(1))
	z2 = sm2P256FromBig(new(big.Int).SetInt64(1))
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256PointAdd(x1, y1, z1, x2, y2, z2)
	}
}

func BenchmarkSm2P256PointSub(t *testing.B) {
	var x1, y1, z1, x2, y2, z2 sm2P256FieldElement
	t.ReportAllocs()
	initP256Sm2()
	x1 = sm2P256FromBig(X1)
	y1 = sm2P256FromBig(Y1)
	x2 = sm2P256FromBig(X2)
	y2 = sm2P256FromBig(Y2)
	z1 = sm2P256FromBig(new(big.Int).SetInt64(1))
	z2 = sm2P256FromBig(new(big.Int).SetInt64(1))
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256PointSub(x1, y1, z1, x2, y2, z2)
	}
}

func BenchmarkSm2P256Cal(t *testing.B) {
	var x1, y1, z1, x2, y2, z2 sm2P256FieldElement
	t.ReportAllocs()
	initP256Sm2()
	x1 = sm2P256FromBig(X1)
	y1 = sm2P256FromBig(Y1)
	x2 = sm2P256FromBig(X2)
	y2 = sm2P256FromBig(Y2)
	z1 = sm2P256FromBig(new(big.Int).SetInt64(1))
	z2 = sm2P256FromBig(new(big.Int).SetInt64(1))
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256Cal(x1, y1, z1, x2, y2, z2)
	}
}

func BenchmarkSm256PointDouble(t *testing.B) {
	var x1, y1, z1 sm2P256FieldElement
	t.ReportAllocs()
	initP256Sm2()
	x1 = sm2P256FromBig(X1)
	y1 = sm2P256FromBig(Y1)
	z1 = sm2P256FromBig(new(big.Int).SetInt64(1))
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256PointDouble(x1, y1, z1)
	}
}

func BenchmarkSm2P256Add(t *testing.B) {
	var x1, y1 sm2P256FieldElement
	t.ReportAllocs()
	initP256Sm2()
	x1 = sm2P256FromBig(X1)
	y1 = sm2P256FromBig(Y1)

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256Add(x1, y1)
	}
}

func BenchmarkSm2P256Sub(t *testing.B) {
	var x1, y1 sm2P256FieldElement
	t.ReportAllocs()
	initP256Sm2()
	x1 = sm2P256FromBig(X1)
	y1 = sm2P256FromBig(Y1)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256Sub(x1, y1)
	}
}

func BenchmarkSm2P256Mul(t *testing.B) {
	var x1, y1 sm2P256FieldElement
	t.ReportAllocs()
	initP256Sm2()
	x1 = sm2P256FromBig(X1)
	y1 = sm2P256FromBig(Y1)

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256Mul(x1, y1)
	}
}

func BenchmarkSm2P256Square(t *testing.B) {
	var x1 sm2P256FieldElement
	t.ReportAllocs()
	initP256Sm2()
	x1 = sm2P256FromBig(X1)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256Square(x1)
	}
}

func BenchmarkSm2P256ReduceCarry(t *testing.B) {
	var x1 sm2P256FieldElement
	var carry uint32
	t.ReportAllocs()
	initP256Sm2()
	x1 = sm2P256FromBig(X1)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256ReduceCarry(x1, carry)
	}
}

func BenchmarkSm2P256ReduceDegree(t *testing.B) {
	var x1 sm2P256FieldElement
	var y1 sm2P256LargeFieldElement
	t.ReportAllocs()
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256ReduceDegree(x1, y1)
	}
}

func BenchmarkSm2P256FromBig(t *testing.B) {
	var a *big.Int
	initP256Sm2()
	a = new(big.Int).Set(K)
	t.ReportAllocs()

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256FromBig(a)
	}
}

func BenchmarkSm2P256ToBig(t *testing.B) {
	var X sm2P256FieldElement
	t.ReportAllocs()
	initP256Sm2()
	X = sm2P256FromBig(K)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256ToBig(X)
	}
}

func BenchmarkSm2P256ScalarMult(t *testing.B) {
	var X, Y sm2P256FieldElement
	var scalar []int8
	t.ReportAllocs()
	initP256Sm2()
	X = sm2P256FromBig(X1)
	Y = sm2P256FromBig(Y2)

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256ScalarMult(X, Y, scalar)
	}
}

func BenchmarkBigIntAdd(t *testing.B) {
	x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	y, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	initP256Sm2()

	t.ReportAllocs()

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		x.Add(x, y)
	}
}

func BenchmarkBigIntMul(t *testing.B) {
	x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	y, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	initP256Sm2()

	t.ReportAllocs()

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		x.Mul(x, y)
	}
}

func BenchmarkBigIntMulWithTransToArray(t *testing.B) {
	x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	y, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	initP256Sm2()

	t.ReportAllocs()

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		xa := sm2P256FromBig(x)
		xb := sm2P256FromBig(y)
		xz := sm2P256Mul(xa, xb)
		sm2P256ToBig(xz)
	}
}

func BenchmarkBigIntSub(t *testing.B) {
	x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	y, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	initP256Sm2()

	t.ReportAllocs()

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		x.Sub(x, y)
	}
}
func BenchmarkScalar3(t *testing.B) {
	initP256Sm2()
	t.ReportAllocs()
	initP256Sm2()
	d := sm2P256FromBig(D1)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256Scalar3(d)
	}
}
func BenchmarkScalar4(t *testing.B) {
	initP256Sm2()
	t.ReportAllocs()
	initP256Sm2()
	d := sm2P256FromBig(D1)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256Scalar4(d)
	}
}
func BenchmarkScalar8(t *testing.B) {
	initP256Sm2()
	t.ReportAllocs()
	initP256Sm2()
	d := sm2P256FromBig(D1)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sm2P256Scalar8(d)
	}
}

// func Test_Scalar(t *testing.T) {
// 	initP256Sm2()
// 	d := sm2P256FromBig(D1)
// 	scalar3 := p256Scalar3(d)
// 	scalar4 := p256Scalar4(d)
// 	scalar8 := p256Scalar8(d)
// 	out3 := sm2P256Scalar(d, 3)
// 	out4 := sm2P256Scalar(d, 4)
// 	out8 := sm2P256Scalar(d, 8)
// 	s3 := sm2P256ToBig(scalar3)
// 	s4 := sm2P256ToBig(scalar4)
// 	s8 := sm2P256ToBig(scalar8)
// 	o3 := sm2P256ToBig(out3)
// 	o4 := sm2P256ToBig(out4)
// 	o8 := sm2P256ToBig(out8)
// 	if s3.Cmp(o3) != 0 {
// 		t.Errorf("Scalar3 error")
// 	}
// 	if s4.Cmp(o4) != 0 {
// 		t.Errorf("Scalar4 error")
// 	}
// 	if s8.Cmp(o8) != 0 {
// 		t.Errorf("Scalar8 error")
// 	}

// }
