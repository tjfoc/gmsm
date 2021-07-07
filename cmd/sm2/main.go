package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/pedroalbanese/gmsm/sm2"
)

var (
	dec     = flag.Bool("sm2dec", false, "Decrypt with asymmetric SM2 PrivateKey.")
	enc     = flag.Bool("sm2enc", false, "Encrypt with asymmetric SM2 Publickey.")
	gen     = flag.Bool("keygen", false, "Generate asymmetric key pair.")
	key     = flag.String("key", "", "Private/Public key.")
	sig     = flag.Bool("sign", false, "Sign with PrivateKey.")
	sign    = flag.String("signature", "", "Input signature. (for verification only)")
	verify  = flag.Bool("verify", false, "Verify with PublicKey.")
)

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "GMSM Cipher Suite - Chinese National Standard Toolkit")
		fmt.Fprintln(os.Stderr, "Copyright (c) 2020-2021 Pedro Albanese. All rights reserved.\n")
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *gen == true {
		priv, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		pub := &priv.PublicKey

		fmt.Println("Private= " + WritePrivateKeyToHex(priv))
		fmt.Println("Public= " + WritePublicKeyToHex(pub))
	}

	if *enc {
		pub, err := ReadPublicKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Printf("Failed to read: %v", scanner.Err())
			return
		}
		line := scanner.Bytes()
		ciphertxt, err := pub.EncryptAsn1([]byte(line), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", ciphertxt)
	}

	if *dec {
		priv, err := ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Printf("Failed to read: %v", scanner.Err())
			return
		}
		line := scanner.Bytes()
		str, _ := hex.DecodeString(string(line))
		plaintxt, err := priv.DecryptAsn1([]byte(str))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", plaintxt)
	}

	if *sig {
		priv, err := ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Printf("Failed to read: %v", scanner.Err())
			return
		}
		line := scanner.Bytes()
		sign, err := priv.Sign(rand.Reader, []byte(line), nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", sign)
	}

	if *verify {
		pub, err := ReadPublicKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Printf("Failed to read: %v", scanner.Err())
			return
		}
		line := scanner.Bytes()
		signature, _ := hex.DecodeString(*sign)
		isok := pub.Verify([]byte(line), []byte(signature))
		if isok == true {
			fmt.Printf("Verified: %v\n", isok)
			os.Exit(0)
		} else {
			fmt.Printf("Verified: %v\n", isok)
			os.Exit(1)
		}
	}
}
