package cmd

import (
	"os"

	"github.com/urfave/cli"
)

//filename 公私钥文件名
var filename string

//pwd 私钥密码
var pwd string

//privfilepath 私钥路径
var privfilepath string

//pubout 输出公钥标识
var pubout bool

var sm2Command cli.Command
var gensm2Command cli.Command

//Excute 添加所有子命令
func Excute() {
	app := cli.NewApp()
	app.Version = "1.0.0"
	app.Name = "tjfocssl"                      // 指定程序名称
	app.Usage = "SM2 key pair generation tool" //  程序功能描述
	app.Commands = []cli.Command{
		gensm2Command,
		sm2Command,
	}
	app.Run(os.Args)
}

//MigrateFlags action方法注册器
func MigrateFlags(action func(ctx *cli.Context) error) func(*cli.Context) error {
	return func(ctx *cli.Context) error {
		for _, name := range ctx.FlagNames() {
			if ctx.IsSet(name) {
				ctx.GlobalSet(name, ctx.String(name))
			}
		}
		return action(ctx)
	}
}
