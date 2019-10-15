## tjfocssl-1.0.0使用说明

tjfocssl-1.0.0目前一共提供了两个命令：gensm2和sm2

### gensm2

这是用于生成sm2相关文件的命令，目前能够用于生成私钥，相关命令操作：

```go
NAME:
   tjfocssl gensm2 - SM2 private key generation command

USAGE:
   tjfocssl gensm2 [command options] [arguments...]

OPTIONS:
   --out value                    public or private key file name (required)
   --password value, --pwd value  private key password
```

一共两个参数：

​				-out 输入将生成的文件名，为必填参数。

​				-password/pwd 为私钥密码，可以不带，不带就是没密码。

使用示例：

```go
.\tjfocssl gensm2 -out privkey.pem -pwd 123
```

使用以上命令就会生成一个密码为123的私钥。以下为输出结果：

```
generate sm2 private key success !
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH8MFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAiNKdDIbkwMBwICCAAw
DAYIKoZIhvcNAgcFADAdBglghkgBZQMEASoEEKgJkkg8Svmnug5+nZpQTGAEgaCn
cJRfe1Rrd9Ef9pfGBCWI4yNQTBSplsXpaJ6Rrw6Jn8FxK8ClNCviP4Xj2Pm1APr6
nF6dA1XtKemgZrt5dSS6+5rRB95IZs/35GH0jjV5eSy4t0T6DgzOoIcNV7IsXopf
U/IfkX61GqeVunLLrSEdVJXl1pf96vOEPgtPdBCiMS0aix5WSL249b4MOJ6h0A+J
CbRqoNIU4VZvWhAatit2
-----END ENCRYPTED PRIVATE KEY-----
```

### sm2

这是用于解析sm2相关文件的命令，目前能够用于解析私钥，输出公钥，相关命令操作：

```go
NAME:
   tjfocssl sm2 - SM2 private key resolution command

USAGE:
   tjfocssl sm2 [command options] [arguments...]

OPTIONS:
   --out value                    public or private key file name (required)
   --in value                     private key path (required)
   --pubout                       whether to output public key
   --password value, --pwd value  private key password
```

一共四个参数：

​				-out 输入将生成的文件名，为必填参数。

​				-in 输入想要解析的私钥文件名，为必填参数。

​				-pubout 为公钥输出标识，有该标识，则解析私钥输出公钥

​				-password/pwd 为私钥密码，若私钥无密码，则不用使用该参数

使用示例：

```go
 .\tjfocssl sm2 -in privkey.pem -pubout -out pubkey.pem -pwd 123
```

以上命令就是解析一个密码为123的私钥，输出它的公钥。以下为输出结果：

```
generate sm2 public key success !
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEIzU8zUHIPoG2FqKsZ+mrAZcfgawg
DPvu+bS7/Gs1NQy4QXFKzgKQt3xb0TCAV5nwvNGiJoK/qEQABGq/6XMnzQ==
-----END PUBLIC KEY-----
```

