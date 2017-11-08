/*
Author: billhan
Mail: hanxueyang@sansec.com.cn, warm3snow@gmail.com
Date: 2017/11/8
*/

package sm2

import (
	"crypto/elliptic"
	"math/big"
)

var preComputedBigInt = [2 * 15 * 2]string{
	"22963146547237050559479531362550074578802567295341616970375194840604139615431", "85132369209828568825618990617112496413088388631904505083283536607588877201568",
	"67705117572652837114471349525499634045614794997337890197046851983230464312599", "105231369456097397661386898492232980821817614166177179504943077059142844337611",
	"59085058512652262766744473634923081986036205385486894268141155278033732483669", "109091573048984472073089738700806795212297391679525613544153843136436839439305",
	"82580483505579888048248891498041876314786199024995590273835293449129297593069", "73029124966741147116568609485132862990712545849247788159814994149391419696555",
	"86848041686756723114584433308299608942636941729527524331542225209405118928267", "54921675316658680818388274484536285985620228771232775428701918326977374721529",
	"53209117963129755799540629530870949355596187090964143013579869346335355383829", "45310597926631255378856870098738145979682050257252233157641454365038168970041",
	"98567493925580762823069255045984118054797882661099345921668929848869459512328", "110336070580595011796555767631269242586466863542034033617751385756889574188365",
	"54842370261918212924648761054027838747829661419062947173569851166254391481878", "101426701570716438575530100482748050191536102803600044520927466495781527040827",
	"12269061587400982443539020516506469528566294741841090734900028672205580665746", "16529702793016095588534532837075850571549425155399206504289122598772051188685",
	"64434573173236480969138577404833282673523627011536882749755581097703792374498", "38739535235004306990435750688164009769761761056360970669716744546640331203293",
	"34527691700877729035117129267209078061476481175212747565893731231603176390121", "4057743830030335104756212222018194631112125931021813403712247080186416358025",
	"113019814001216926601167366326200148303289071208068658154223316262167530671662", "65771162203637495562352007069135952168431207244049062569251477870437195461279",
	"98806970682279766809788238647846303670311504174553780897122205688916923498009", "80258702523420980907564925663081481092346280892548128526246151985709225657322",
	"75015959162397789281735403142210955999780934098796070639937316793192444562854", "102622446084784894172630081175370402215434615166783993228004681223075583073513",
	"98290966315732394635804879472297552049863842953830735255423745352015426579195", "86045662416818120197860942815200917482442774209509364262885407182405740581028",
	"27656645740463688420011061666403150467724038752015205298141582508658173133289", "61304494158713143023459198820689120461809067114069644647956890469746089234482",
	"108139344675098469275811847961873270439384029870138508931592770477395992987795", "91247607565653826025006790553252720052512946813134830989326271521410331996106",
	"85359681153702576556883230634214742275789753451618925904919914550988377036333", "66873501300530853990980802553524376253118396437397699315984027838391462443243",
	"106457195765868536364301857874523844785410252372179228253876364442002381813742", "107558665886644582134143013748434047802917171807264665288908076345410766984360",
	"11995388783463527963161320235598011443133654281944223275845079091542421530356", "45091550567191095463633359227681865179223863396298882402218668148298619203168",
	"65680916170291054634978247076940207069084334509599166206181389158183842445169", "93601325927595405085934542000529005602143735667699607636748977760611906258815",
	"101589270325472078746176225938550908594042745532146702365107714989046225324559", "113684684209056633113510565116378904222453305320567142458414464003889688617411",
	"36796040157371402779777568491897504700018912309863314106301510062917872921119", "33802998356492310275031089417234972039148157891410161300315932567884179249254",
	"66488641277053852730302653660870225029881480477562028952882483979720874598220", "99743473681205441932168817033637494197049301615605530110432679356592041584126",
	"70864763812423826357624068784164251476901347076767930905614106456205281982106", "73541401817033626647357686253595872603029551111349278805929932338267627495469",
	"97051910126062360804685778785862815989968717704058425286926543016103008215504", "78980949781813977431531298580258272721702876234975805785157623012510397909518",
	"58116726195830150431978735967973133414545434092024546936076840239708566145733", "79590880309700856083792654844611904801820246021494422125788789091600826507188",
	"113507193978715085869764764456228544548713455748597849005156375003692341976321", "7995840820734240198944361443325383476316681539831095849598291951368115094190",
	"103747715251198567781280760790998494461126321874995293887400558681164610724761", "47261842213255175620960057316697558921664252110384882339850628875527359721111",
	"64715719199968089545068383275043113115131965984698509435186423212657452236699", "37861092312862231610700917336955293410732275606119045543189054690171468843413",
}

func BigInt2Uint32Bytes(k *big.Int) [8]uint32 {
	kb := k.Bytes()
	//fmt.Println("k bytes len= ", len(kb))
	var scalar [8]uint32
	for i := 0; i < len(scalar); i++ {
		scalar[i] = uint32(0)
	}
	//big-endien, []byte -> [8]uint32
	var i = 0
	var scalarI = 0
	for ; i < len(kb)-3; i += 4 {
		var z uint32
		for j := 0; j < 4; j++ {
			if j != 0 {
				z <<= 8
			}
			z += uint32(kb[i+j])
		}
		scalar[scalarI] = z
		scalarI++
	}
	//residue < 4 bytes
	r := len(kb) - i
	//fmt.Println("lenOfKbytes=", len(kb), "i=", i, "r=", r, "scalarI=", scalarI)
	if r != 0 {
		var z uint32
		for j := 0; j < r; j++ {
			if j != 0 {
				z <<= 8
			}
			z += uint32(kb[i+j])
		}
		scalar[scalarI] = z
	}

	return scalar
}
func ScalarBaseMult(curve elliptic.Curve, k *big.Int) (r, s *big.Int) {
	var scalar = BigInt2Uint32Bytes(k)
	//Gx, Gy := curve.Params().Gx, curve.Params().Gy
	bz := new(big.Int).SetInt64(1)

	//fmt.Printf("scalar: %v\n", scalar)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)
	for i := uint(0); i < 32; i++ {
		//x, y = curve.Double(x, y)
		x, y, z = doubleJacobian(curve.Params(), x, y, z)

		a0 := (scalar[0] >> (31 - i)) & 1
		a1 := (scalar[1] >> (31 - i)) & 1
		a2 := (scalar[2] >> (31 - i)) & 1
		a3 := (scalar[3] >> (31 - i)) & 1
		a4 := (scalar[4] >> (31 - i)) & 1
		a5 := (scalar[5] >> (31 - i)) & 1
		a6 := (scalar[6] >> (31 - i)) & 1
		a7 := (scalar[7] >> (31 - i)) & 1

		index0 := (a1 << 3) + (a3 << 2) + (a5 << 1) + a7
		index1 := (a0 << 3) + (a2 << 2) + (a4 << 1) + a6

		//omit all zeros
		if index0 != 0 {
			x1, _ := new(big.Int).SetString(preComputedBigInt[(index0-1)*2], 10)
			y1, _ := new(big.Int).SetString(preComputedBigInt[(index0-1)*2+1], 10)
			//x, y = curve.Add(x, y, x1, y1)
			x, y, z = addJacobian(curve.Params(), x1, y1, bz, x, y, z)
		}

		if index1 != 0 {
			x2, _ := new(big.Int).SetString(preComputedBigInt[15*2+(index1-1)*2], 10)
			y2, _ := new(big.Int).SetString(preComputedBigInt[15*2+(index1-1)*2+1], 10)
			//x, y = curve.Add(x, y, x2, y2)
			x, y, z = addJacobian(curve.Params(), x2, y2, bz, x, y, z)
		}

		//fmt.Printf("index0=%d, index1=%d\n", index0, index1)
	}

	//return x, y
	return affineFromJacobian(curve.Params(), x, y, z)
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func doubleJacobian(curve *elliptic.CurveParams, x, y, z *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
	delta := new(big.Int).Mul(z, z)
	delta.Mod(delta, curve.P)
	gamma := new(big.Int).Mul(y, y)
	gamma.Mod(gamma, curve.P)
	alpha := new(big.Int).Sub(x, delta)
	if alpha.Sign() == -1 {
		alpha.Add(alpha, curve.P)
	}
	alpha2 := new(big.Int).Add(x, delta)
	alpha.Mul(alpha, alpha2)
	alpha2.Set(alpha)
	alpha.Lsh(alpha, 1)
	alpha.Add(alpha, alpha2)

	beta := alpha2.Mul(x, gamma)

	x3 := new(big.Int).Mul(alpha, alpha)
	beta8 := new(big.Int).Lsh(beta, 3)
	x3.Sub(x3, beta8)
	for x3.Sign() == -1 {
		x3.Add(x3, curve.P)
	}
	x3.Mod(x3, curve.P)

	z3 := new(big.Int).Add(y, z)
	z3.Mul(z3, z3)
	z3.Sub(z3, gamma)
	if z3.Sign() == -1 {
		z3.Add(z3, curve.P)
	}
	z3.Sub(z3, delta)
	if z3.Sign() == -1 {
		z3.Add(z3, curve.P)
	}
	z3.Mod(z3, curve.P)

	beta.Lsh(beta, 2)
	beta.Sub(beta, x3)
	if beta.Sign() == -1 {
		beta.Add(beta, curve.P)
	}
	y3 := alpha.Mul(alpha, beta)

	gamma.Mul(gamma, gamma)
	gamma.Lsh(gamma, 3)
	gamma.Mod(gamma, curve.P)

	y3.Sub(y3, gamma)
	if y3.Sign() == -1 {
		y3.Add(y3, curve.P)
	}
	y3.Mod(y3, curve.P)

	return x3, y3, z3
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func addJacobian(curve *elliptic.CurveParams, x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return x3, y3, z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return x3, y3, z3
	}

	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, curve.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, curve.P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, curve.P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, curve.P)
	h := new(big.Int).Sub(u2, u1)
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(h, curve.P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)

	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, curve.P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, curve.P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, curve.P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		return doubleJacobian(curve, x1, y1, z1)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3.Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, curve.P)

	y3.Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, curve.P)

	z3.Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	z3.Mod(z3, curve.P)

	return x3, y3, z3
}

// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file. If the point is ∞ it returns 0, 0.
func affineFromJacobian(curve *elliptic.CurveParams, x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	zinv := new(big.Int).ModInverse(z, curve.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, curve.P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, curve.P)
	return
}