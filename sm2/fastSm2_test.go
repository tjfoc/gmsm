package sm2

import (
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
	"testing"
)

func TestSign(t *testing.T) {
	msg := []byte("hello bill")
	h := sha256.New()
	h.Write(msg)
	digest := h.Sum(nil)

	key, _ := GenerateKey()
	for i := 0; i < int(math.Pow(2, 32)); i++ {
		fmt.Printf("This is the %d'th test\n", i)
		r, s, err := Sign(key, digest)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("r=%v, s=%v\n", r, s)
		fmt.Printf("PubKey: %v\n", key.PublicKey)

		ok := Verify(&key.PublicKey, digest, r, s)
		if !ok {
			t.Fatal("Failed to verify fastSm2 signature")
		}
		fmt.Printf("verify=%t\n", ok)
	}
}

func TestFixedSign(t *testing.T) {
	r, _ := new(big.Int).SetString("65473572484904001011019370389951858794206472403907338451504535741863058150710", 10)
	s, _ := new(big.Int).SetString("12651708508422169783472469495687536057371499424944423848244178061496366500213", 10)
	_, _ = r, s

	//ok := sm2.Verify("&")
}
