package x509

import (
	"testing"
)

func TestLoadFromPKUGM(t *testing.T) {
	var privKeyPem = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgELPz2EG+YY2QcdqF
PMgqUC93FH9BiAq3XbLnT7C2KLmhRANCAAQqsrdHSoNTOLHNHaKrzb+9a2dbTIgZ
skZ8Abgw90kUUkSk4zGTLgyHbYhxUuZbW5daOwC8DOpruHqBW5TvoNfe
-----END PRIVATE KEY-----
	`
	_, err := ReadPrivateKeyFromPem([]byte(privKeyPem), nil)
	if err != nil {
		t.Fatal(err)
	}
}
