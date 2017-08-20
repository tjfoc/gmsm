package gmssl

/*
#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -lcrypto

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "e_os.h"
# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/engine.h>
# include <openssl/sm2.h>
# include "sm2_lcl.h"



# define VERBOSE 1

RAND_METHOD fake_rand;
const RAND_METHOD *old_rand;

static const char rnd_seed[] =
	"string to make the random number generator think it has entropy";
static const char *rnd_number = NULL;

static int fbytes(unsigned char *buf, int num)
{
	int ret = 0;
	BIGNUM *bn = NULL;

	if (!BN_hex2bn(&bn, rnd_number)) {
		goto end;
	}
	if (BN_num_bytes(bn) > num) {
		goto end;
	}
	memset(buf, 0, num);
	if (!BN_bn2bin(bn, buf + num - BN_num_bytes(bn))) {
		goto end;
	}
	ret = 1;
end:
	BN_free(bn);
	return ret;
}

static int change_rand(const char *hex)
{
	if (!(old_rand = RAND_get_rand_method())) {
		return 0;
	}

	fake_rand.seed		= old_rand->seed;
	fake_rand.cleanup	= old_rand->cleanup;
	fake_rand.add		= old_rand->add;
	fake_rand.status	= old_rand->status;
	fake_rand.bytes		= fbytes;
	fake_rand.pseudorand	= old_rand->bytes;

	if (!RAND_set_rand_method(&fake_rand)) {
		return 0;
	}

	rnd_number = hex;
	return 1;
}

static int restore_rand(void)
{
	rnd_number = NULL;
	if (!RAND_set_rand_method(old_rand))
		return 0;
	else	return 1;
}

static int hexequbin(const char *hex, const unsigned char *bin, size_t binlen)
{
	int ret = 0;
	char *buf = NULL;
	int i = 0;
	size_t buflen = binlen * 2 + 1;


	if (binlen * 2 != strlen(hex)) {
		return 0;
	}
	if (!(buf = malloc(binlen * 2 + 1))) {
		return 0;
	}
	for (i = 0; i < binlen; i++) {
		sprintf(buf + i*2, "%02X", bin[i]);
	}
	buf[buflen - 1] = 0;

	if (memcmp(hex, buf, binlen * 2) == 0) {
		ret = 1;
	}

	free(buf);
	return ret;
}

static EC_GROUP *new_ec_group(int is_prime_field,
	const char *p_hex, const char *a_hex, const char *b_hex,
	const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex)
{
	int ok = 0;
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	EC_POINT *G = NULL;
	point_conversion_form_t form = SM2_DEFAULT_POINT_CONVERSION_FORM;
	int flag = 0;

	if (!(ctx = BN_CTX_new())) {
		goto err;
	}

	if (!BN_hex2bn(&p, p_hex) ||
	    !BN_hex2bn(&a, a_hex) ||
	    !BN_hex2bn(&b, b_hex) ||
	    !BN_hex2bn(&x, x_hex) ||
	    !BN_hex2bn(&y, y_hex) ||
	    !BN_hex2bn(&n, n_hex) ||
	    !BN_hex2bn(&h, h_hex)) {
		goto err;
	}

	if (is_prime_field) {
		if (!(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))) {
			goto err;
		}
		if (!(G = EC_POINT_new(group))) {
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GFp(group, G, x, y, ctx)) {
			goto err;
		}
	} else {
		if (!(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))) {
			goto err;
		}
		if (!(G = EC_POINT_new(group))) {
			goto err;
		}
		if (!EC_POINT_set_affine_coordinates_GF2m(group, G, x, y, ctx)) {
			goto err;
		}
	}

	if (!EC_GROUP_set_generator(group, G, n, h)) {
		goto err;
	}

	EC_GROUP_set_asn1_flag(group, flag);
	EC_GROUP_set_point_conversion_form(group, form);

	ok = 1;
err:
	BN_CTX_free(ctx);
	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(x);
	BN_free(y);
	BN_free(n);
	BN_free(h);
	EC_POINT_free(G);
	if (!ok && group) {
		ERR_print_errors_fp(stderr);
		EC_GROUP_free(group);
		group = NULL;
	}

	return group;
}

static EC_KEY *new_ec_key(const EC_GROUP *group,
	const char *sk, const char *xP, const char *yP,
	const char *id, const EVP_MD *id_md)
{
	int ok = 0;
	EC_KEY *ec_key = NULL;
	BIGNUM *d = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;

	OPENSSL_assert(group);
	OPENSSL_assert(xP);
	OPENSSL_assert(yP);

	if (!(ec_key = EC_KEY_new())) {
		goto end;
	}
	if (!EC_KEY_set_group(ec_key, group)) {
		goto end;
	}

	if (sk) {
		if (!BN_hex2bn(&d, sk)) {
			goto end;
		}
		if (!EC_KEY_set_private_key(ec_key, d)) {
			goto end;
		}
	}

	if (xP && yP) {
		if (!BN_hex2bn(&x, xP)) {
			goto end;
		}
		if (!BN_hex2bn(&y, yP)) {
			goto end;
		}
		if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
			goto end;
		}
	}
	ok = 1;
end:
	if (d) BN_free(d);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (!ok && ec_key) {
		ERR_print_errors_fp(stderr);
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}
	return ec_key;
}

static int test_sm2_sign(const EC_GROUP *group,
	const char *sk, const char *xP, const char *yP,
	const char *id, const char *Z,
	const char *M, const char *e,
	const char *k, const char *r, const char *s)
{
	int ret = 0;
	int verbose = VERBOSE;
	const EVP_MD *id_md = EVP_sm3();
	const EVP_MD *msg_md = EVP_sm3();
	int type = NID_undef;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	size_t dgstlen;
	unsigned char sig[256];
	unsigned int siglen;
	const unsigned char *p;
	EC_KEY *ec_key = NULL;
	EC_KEY *pubkey = NULL;
	ECDSA_SIG *sm2sig = NULL;
	BIGNUM *rr = NULL;
	BIGNUM *ss = NULL;
	const BIGNUM *sig_r;
	const BIGNUM *sig_s;

	change_rand(k);

	if (!(ec_key = new_ec_key(group, sk, xP, yP, id, id_md))) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	if (verbose > 1) {
		EC_KEY_print_fp(stdout, ec_key, 4);
	}

	dgstlen = sizeof(dgst);
	if (!SM2_compute_id_digest(id_md, id, strlen(id), dgst, &dgstlen, ec_key)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	if (verbose > 1) {
		int j;
		printf("id=%s\n", id);
		printf("zid(xx):");
		for (j = 0; j < dgstlen; j++) { printf("%02x", dgst[j]); } printf("\n");
	}

	if (!hexequbin(Z, dgst, dgstlen)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	dgstlen = sizeof(dgst);
	if (!SM2_compute_message_digest(id_md, msg_md,
		(const unsigned char *)M, strlen(M), id, strlen(id),
		dgst, &dgstlen, ec_key)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}
	if (!hexequbin(e, dgst, dgstlen)) {
		int i;
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);

		printf("%s\n", e);
		printf(" my: "); for (i = 0; i < dgstlen; i++) { printf("%02x", dgst[i]); } printf("\n");

		goto err;
	}


	
	siglen = sizeof(sig);
	if (!SM2_sign(type, dgst, dgstlen, sig, &siglen, ec_key)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	p = sig;
	if (!(sm2sig = d2i_ECDSA_SIG(NULL, &p, siglen))) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}
	if (!BN_hex2bn(&rr, r) || !BN_hex2bn(&ss, s)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	ECDSA_SIG_get0(sm2sig, &sig_r, &sig_s);

	if (BN_cmp(sig_r, rr) || BN_cmp(sig_s, ss)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}


	
	if (!(pubkey = new_ec_key(group, NULL, xP, yP, id, id_md))) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	if (1 != SM2_verify(type, dgst, dgstlen, sig, siglen, pubkey)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		goto err;
	}

	ret = 1;
err:
	restore_rand();
	if (ec_key) EC_KEY_free(ec_key);
	if (pubkey) EC_KEY_free(pubkey);
	if (sm2sig) ECDSA_SIG_free(sm2sig);
	if (rr) BN_free(rr);
	if (ss) BN_free(ss);
	return ret;
}


static int test_sm2_enc(const EC_GROUP *group, const EVP_MD *md,
	const char *d, const char *xP, const char *yP,
	const char *M, const char *k, const char *C)
{
	int ret = 0;
	EC_KEY *pub_key = NULL;
	EC_KEY *pri_key = NULL;
	SM2CiphertextValue *cv = NULL;
	unsigned char *tbuf = NULL;
	long tlen;
	unsigned char mbuf[128] = {0};
	unsigned char cbuf[sizeof(mbuf) + 256] = {0};
	size_t mlen, clen;
	unsigned char *p;

	
	if (!(pub_key = new_ec_key(group, NULL, xP, yP, NULL, NULL))) {
		goto end;
	}

	change_rand(k);
	if (!(cv = SM2_do_encrypt(md, (unsigned char *)M, strlen(M), pub_key))) {
		goto end;
	}

	p = cbuf;
	if ((clen = i2o_SM2CiphertextValue(group, cv, &p)) <= 0) {
		goto end;
	}

	if (!(tbuf = OPENSSL_hexstr2buf(C, &tlen))) {
		EXIT(1);
	}

	if (tlen != clen || memcmp(tbuf, cbuf, clen) != 0) {
		goto end;
	}

	
	if (!(pri_key = new_ec_key(group, d, xP, yP, NULL, NULL))) {
		goto end;
	}

	mlen = sizeof(mbuf);
	if (!SM2_do_decrypt(md, cv, mbuf, &mlen, pri_key)) {
		goto end;
	}

	if (mlen != strlen(M) || memcmp(mbuf, M, strlen(M))) {
		goto end;
	}

	ret = 1;

end:
	ERR_print_errors_fp(stderr);
	restore_rand();
	EC_KEY_free(pub_key);
	EC_KEY_free(pri_key);
	SM2CiphertextValue_free(cv);
	OPENSSL_free(tbuf);
	return ret;
}

*/
import "C"

import (
	"fmt"
)



func Sm2Test(){
	fmt.Println("in Sm2Test..")
	
	sm2p256test := C.new_ec_group(1,
		C.CString("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"),
		C.CString("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"),
		C.CString("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"),
		C.CString("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"),
		C.CString("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"),
		C.CString("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"),
		C.CString("1"));
	
	ca := C.test_sm2_sign(
		sm2p256test,
		C.CString("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263"),
		C.CString("0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A"),
		C.CString("7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857"),
		C.CString("ALICE123@YAHOO.COM"),
		C.CString("F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A"),
		C.CString("message digest"),
		C.CString("B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76"),
		C.CString("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F"),
		C.CString("40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1"),
		C.CString("6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7"))
	signRes := int32(ca)
	if signRes==0 {
		fmt.Println("sign/verify failed")
	}else{
		fmt.Println("sign/verify success")
	}
	
	
	cb := C.test_sm2_enc(
		sm2p256test, C.EVP_sm3(),
		C.CString("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0"),
		C.CString("435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A"),
		C.CString("75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42"),
		C.CString("encryption standard"),
		C.CString("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F"),
		C.CString("04"+
		"245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252E7"+
		"76CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01B8"+
		"650053A89B41C418B0C3AAD00D886C00286467"+
		"9C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E07480653426D"))
	encRes := int32(cb)
	if encRes==0 {
		fmt.Println("encrypt/decrypt failed")
	}else{
		fmt.Println("encrypt/decrypt success")
	}
	fmt.Println("exit Sm2Test..")
}

