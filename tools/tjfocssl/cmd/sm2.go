package cmd

import (
	"fmt"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/urfave/cli"
)

func init() {
	sm2Command = cli.Command{
		Name:  "sm2",
		Usage: "SM2 private key resolution command",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:        "out",
				Usage:       "public or private key file name (required)",
				Required:    true,
				Destination: &filename,
			},
			cli.StringFlag{
				Name:        "in",
				Usage:       "private key path (required)",
				Required:    true,
				Destination: &privfilepath,
			},
			cli.BoolFlag{
				Name:        "pubout",
				Usage:       "whether to output public key",
				Destination: &pubout,
			},
			cli.StringFlag{
				Name:        "password,pwd",
				Usage:       "private key password",
				Destination: &pwd,
			},
		},
		Action: MigrateFlags(sm2Parser),
	}

}

func sm2Parser(ctx *cli.Context) error {
	p := []byte(pwd)
	if pwd == "" {
		p = nil
	}
	priv, err := sm2.ReadPrivateKeyFromPem(privfilepath, p)
	if err != nil {
		fmt.Println(err)
		return err
	}
	if pubout {
		pub := priv.PublicKey
		_, err = sm2.WritePublicKeytoPem(filename, &pub, nil)
		if err != nil {
			fmt.Println(err)
			return err
		}
		fmt.Println("generate sm2 public key success ! ")
	} else {
		_, err = sm2.WritePrivateKeytoPem(filename, priv, nil)
		if err != nil {
			fmt.Println(err)
			return err
		}
		fmt.Println("copy sm2 private key success ! ")
	}
	data, _ := readAll(filename)
	fmt.Printf("%s", data)
	return nil
}
