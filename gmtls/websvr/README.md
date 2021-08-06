# TLS/GMSSL 服务端协议自适应

目录结构说明:

```
├─certs        // 证书以及密钥
├─websvr_test   //HTTP服务端/客户端测试Demo
└─websvr          //协议自适应实现
```

## 服务端 GMTLS/TLS 工作逻辑

![autoswitchlogic](./img/autoswitchlogic.png)


通过配置`gmtls.Config` 对象提供自动切换相关的配置，创建`gmtls.Conn`。

在对`gmtls.Conn`的`Read/Wirte`时将会触发握手行为`HandShake`。

`HandShake`会根据用户配置参数，判断需要使用 GMSSL、TLS、GMSSL/TLS 三种工作模式中的哪一种，
然后进入到相应的工作模式中运行。

- **TLS工作模式**:
    - 运行`serverHandshake` 进入TLS握手。
    - 创建TLS握手上下文`serverHandshakeState`。
    - 读取并处理 来自于客户端的ClientHello 消息。
    - 进入 TLS握手流程。
- **GMSSL工作模式**:
    - 运行`serverHandshakeGM` 进入GMSSL握手。
    - 创建TLS握手上下文`serverHandshakeStateGM`。
    - 读取并处理 来自于客户端的ClientHello 消息。
    - 进入 GMSSL握手流程。
- **GMSSL/TLS工作模式**:
    - 运行`serverHandshakeAutoSwitch` 进入自动切换的握手模式。
    - 读取来自于客户端的ClientHello 消息。
    - 分析处理ClientHello，根据客户端协议版本。
    - 根据协议版本，选择使用具体握手方式：
      - GMSSL: 创建上下文`serverHandshakeStateGM`，进入GMSSL握手流程。
      - TLS: 创建上下文`serverHandshakeState`，进入TLS握手流程。


在GMSSL/TLS模式的服务端运行过程中，如何根据客户端版本选择需要使用的证书以及密钥？

自动切换模式，同时需要为服务端提供2份证书与密钥对（一份用于标准的TLS、一份用于GMSSL）,
在运行过程需要使用到`gmtls.Config#GetCertificate`方法来根据客户端的版本选择出合适的
证书密钥对，即在客户端版本是GMSSL的时候返回SM2签名证书密钥对；在客户端版本是标准的TLS时
返还RSA/ECC的证书密钥对，以次来动态适应不同客户端的连接需求。
针对于GMSSL特殊的双证书需求，特别为`gmtls.Config`增加了一个方法`gmtls.Config#GetKECertificate`
通过该方法来提供GMSSL密钥交换过程中使用密钥对。

更多细节实现见: [auto_handshake_server](../auto_handshake_server.go)

## GMSSL/TLS 自动切换模式

快速开始：

1. 准备 RSA、SM2签名、SM2加密，证书以及密钥对。
2. 调用`gmtls.NewBasicAutoSwitchConfig`构造基础的配置对象。
3. Use it.

```go
func main() {
	config, err := gmtls.NewBasicAutoSwitchConfig(&sigCert, &encCert, &rsaKeypair)
	if err != nil {
		panic(err)
	}

	ln, err := gmtls.Listen("tcp", ":443", config)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "hello\n")
	})
	err = http.Serve(ln, nil)
	if err != nil {
		panic(err)
	}
}	
```


详细服务端的配置流程如下：

1. 准备：
   - SM2签名密钥对、证书：`sigCert`
   - SM2加密密钥对、证书：`encCert`
   - RSA/ECC加密密钥对、证书：`rsaKeypair`
2. 创建一个实现`gmtls.Config#GetCertificate`方法签名的方法，方法需要根据支持的签名类型：
    - 含有GMSSL版本：返回SM2签名证书密钥对(`sigCert`)。
    - 不含有GMSSL版本：返回RSA签名证书密钥对(`rsaKeypair`)。
3. 创建一个实现`gmtls.Config#GetKECertificate`方法签名的方法，固定返回SM2加密证书密钥对(`encCert`)。
4. 创建`GMSupport`并启用，自动切换模式。
5. 创建`gmtls.Config`对象，接下就可以启动服务端实现自动切换功能。

```go
// Step 1:
fncGetSignCertKeypair := func(info *gmtls.ClientHelloInfo) (*gmtls.Certificate, error) {
    gmFlag := false
    // 检查支持协议中是否包含GMSSL
    for _, v := range info.SupportedVersions {
        if v == gmtls.VersionGMSSL {
        gmFlag = true
        break
        }
    }
    if gmFlag {
        return &sigCert, nil
    } else {
        return &rsaKeypair, nil
    }
}

fncGetEncCertKeypair := func(info *gmtls.ClientHelloInfo) (*gmtls.Certificate, error) {
    return &encCert, nil
}
support := gmtls.NewGMSupport()
support.EnableMixMode()
config := &gmtls.Config{
    GMSupport:        support,
    GetCertificate:   fncGetSignCertKeypair,
    GetKECertificate: fncGetEncCertKeypair,
}
```

> 更多细节请参考： [HTTP over GMTLS/TLS Server Demo](./websvr.go)


## 双向身份认证

服务端开启双向身份认证，需要配置而外参数`ClientAuth`。

建议使用`gmtls.RequireAndVerifyClientCert`表明服务端需要客户端证书请求且需要验证客户端证书。

```go
config, err := gmtls.NewBasicAutoSwitchConfig(&sigCert, &encCert, &rsaKeypair)
if err != nil {
	panic(err)
}

// 开启客户端的身份认证
config.ClientAuth = gmtls.RequireAndVerifyClientCert
```

> 更多细节请参考：
> 
> - [自适应Web服务端 Demo websvr.go #loadAutoSwitchConfigClientAuth](./websvr.go)



客户端的启用双向身份认证也需要配置，只需要提供认证所使用的证书密钥对就可以。

例如：

```go
config ,err = &gmtls.Config{
		GMSupport:          &gmtls.GMSupport{},
		RootCAs:            certPool,
		Certificates:       []gmtls.Certificate{authKeypair},
		InsecureSkipVerify: false,
}
```

> 更多细节请参考：
>
> - [国际算法标准 客户端 Demo websvr.go #bothAuthConfig](./websvr.go)
