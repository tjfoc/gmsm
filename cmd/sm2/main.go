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
	dec  = flag.Bool("dec", false, "Decrypt with PrivateKey.")
	enc  = flag.Bool("enc", false, "Encrypt with Publickey.")
	gen  = flag.Bool("gen", false, "Generate asymmetric key pair.")
	key  = flag.String("key", "", "Private/Public key.")
	sgn  = flag.Bool("sgn", false, "Sign with PrivateKey.")
	sig  = flag.String("sig", "", "Input signature.")
	vfy  = flag.Bool("vfy", false, "Verify with PublicKey.")
)

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
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

	if *sgn {
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

	if *vfy {
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
		signature, _ := hex.DecodeString(*sig)
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
