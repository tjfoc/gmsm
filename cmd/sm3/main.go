package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/pedroalbanese/gmsm/sm3"
)

func main() {
	flag.Parse()
	h := sm3.New()
	if _, err := io.Copy(h, os.Stdin); err != nil {
		panic(err)
	}
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
}