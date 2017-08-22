package smtest

import (
	"testing"
)

func TestSm3_1(t *testing.T) {
	plainText := "abc"
	trueVal := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	decryptVal := Sm3(plainText)
	if decryptVal != trueVal {
		t.Errorf("plainText:" + plainText)
		t.Errorf("trueVal:" + trueVal)
		t.Errorf("decryptVal:" + decryptVal)
		t.Error("SM3 加密解密不一致")
	} else {
		t.Log("passed")
	}
}

func TestSm3_2(t *testing.T) {
	plainText := "abcd"
	trueVal := "82ec580fe6d36ae4f81cae3c73f4a5b3b5a09c943172dc9053c69fd8e18dca1e"
	decryptVal := Sm3(plainText)
	if decryptVal != trueVal {
		t.Errorf("plainText:" + plainText)
		t.Errorf("trueVal:" + trueVal)
		t.Errorf("decryptVal:" + decryptVal)
		t.Error("SM3 加密解密不一致")
	} else {
		t.Log("passed")
	}
}


func TestSm4(t *testing.T) {
	t.Log("passed")
}
