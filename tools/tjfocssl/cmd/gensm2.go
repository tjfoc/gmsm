package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/urfave/cli"
)

func init() {
	gensm2Command = cli.Command{
		Name:  "gensm2",
		Usage: "SM2 private key generation command",
		// Category: "曲线选择",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:        "out",                                        // 配置名称
				Usage:       "public or private key file name (required)", // 配置描述
				Required:    true,                                         //是否必要命令
				Destination: &filename,                                    // 保存配置值
			},
			cli.StringFlag{
				Name:        "password,pwd",
				Usage:       "private key password",
				Destination: &pwd,
			},
		},
		Action: MigrateFlags(gensm2),
	}

}

func gensm2(ctx *cli.Context) error {
	p := []byte(pwd)
	if pwd == "" {
		p = nil
	}
	priv, err := sm2.GenerateKey()
	if err != nil {
		fmt.Println(err)
		return err
	}
	_, err = sm2.WritePrivateKeytoPem(filename, priv, p)
	if err != nil {
		fmt.Println(err)
		return err
	}
	data, _ := readAll(filename)
	fmt.Println("generate sm2 private key success ! ")
	fmt.Printf("%s", data)
	return nil
}

//读取文件内容
func readAll(filePth string) ([]byte, error) {
	f, err := os.Open(filePth)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(f)
}
