# TLS/GMSSL 服务端协议自适应

<!-- TOC -->

- [TLS/GMSSL 服务端协议自适应](#tlsgmssl-服务端协议自适应)
    - [服务端 GMSSL/TLS 工作逻辑](#服务端-gmssltls-工作逻辑)
    - [GMSSL/TLS 自动切换模式](#gmssltls-自动切换模式)
    - [TCLP 双向身份认证](#tclp-双向身份认证)
        - [服务端配置](#服务端配置)
        - [客户端配置](#客户端配置)
    - [国密HTTPS客户端](#国密https客户端)
        - [HTTPS 单向身份认证](#https-单向身份认证)
        - [HTTPS 双向身份认证](#https-双向身份认证)
    - [TLCP GCM模式](#tlcp-gcm模式)
        - [客户端 GCM配置](#客户端-gcm配置)
        - [关于 TLCP AEAD随机数](#关于-tlcp-aead随机数)

<!-- /TOC -->


目录结构说明:

```
├─certs        // 证书以及密钥
├─websvr_test   //HTTP服务端/客户端测试Demo
└─websvr          //协议自适应实现
```

## 服务端 GMSSL/TLS 工作逻辑

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


## TCLP 双向身份认证

### 服务端配置

1. 设置启用国密TLCP支持。
2. 配置服务端签名证书密钥和加密证书密钥。
3. 设置服务端开启双向身份认证，并要求验证客户端证书。
4. 配置根证书链，用于验证客户端证书。

```go
config := &gmtls.Config{
    GMSupport:    gmtls.NewGMSupport(),
    Certificates: []gmtls.Certificate{sigCert, encCert},
    ClientAuth:   gmtls.RequireAndVerifyClientCert,
    ClientCAs:    certPool,
}
```

> 更多细节请参考：
> 
> - [TLCP服务端 双向身份认证配置 Demo websvr.go #loadServerMutualTLCPAuthConfig](./websvr.go)


### 客户端配置

1. 设置启用国密TLCP支持。
2. 配置双向身份认证的客户端方的签名证书和密钥对。
3. 提供验证服务端证书的根证书链。
4. 设置需要进行安全校验。

例如：

```go
config := &gmtls.Config{
    GMSupport:          gmtls.NewGMSupport(),
    RootCAs:            certPool,
    Certificates:       []gmtls.Certificate{authKeypair},
    InsecureSkipVerify: false,
}
```

> 更多细节请参考：
>
> - [TLCP客户端 双向身份认证配置 Demo websvr.go #bothAuthConfig](./websvr.go)


## 国密HTTPS客户端

为了简化HTTPS客户端的构造`gmtls`包提供下面构造方法：

- 创建单向身份认证HTTPS客户端：`gmtls.NewHTTPSClient(*x509.CertPool)` 
- 创建双向身份认证HTTPS客户端：`gmtls.NewAuthHTTPSClient(*x509.CertPool, *gmtls.Certificate)`
- 创建定制化的TLS连接的HTTPS客户端：`gmtls.NewCustomHTTPSClient(*gmtls.Config)`

### HTTPS 单向身份认证

单向身份认证客户端，只只验证服务器证书有效性，服务端不对客户端进行身份认证。

该模式下进行国密HTTPS的调用你需要：

1. 提供根证书链。
2. 构造HTTP客户端。
3. 调用API访问HTTPS。

```go
package main

import (
	"github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"
	"io/ioutil"
)

func main() {
	// 1. 提供根证书链
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile("websvr/certs/SM2_CA.cer")
	if err != nil {
		panic(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	// 2. 构造HTTP客户端
	httpClient := gmtls.NewHTTPSClient(certPool)
	// 3. 调用API访问HTTPS
	response, err := httpClient.Get("https://localhost:443")
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	// 使用 response 做你需要的事情...
}
```

更多细节见 [gmsm/http_client_test.go#TestNewHTTPSClient2](../http_client_test.go)

### HTTPS 双向身份认证

双向身份认证，在服务端开启了对客户端的身份认证情况下，国密SSL通行就需要进行双向身份认证。

该模式下进行国密HTTPS的调用你需要：

1. 提供根证书链。
2. 提供客户端认证证书、密钥对。
3. 构造HTTP客户端。
4. 调用API访问HTTPS。

```go
package main

import (
	"github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"
	"io/ioutil"
)

func main() {
	// 1. 提供根证书链
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile("websvr/certs/SM2_CA.cer")
	if err != nil {
		panic(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	// 2. 提供客户端认证证书、密钥对。
	clientAuthCert, err := gmtls.LoadX509KeyPair("websvr/certs/sm2_auth_cert.cer", "websvr/certs/sm2_auth_key.pem")
	// 3. 构造HTTP客户端。
	httpClient := gmtls.NewAuthHTTPSClient(certPool, &clientAuthCert)
	// 4. 调用API访问HTTPS。
	response, err := httpClient.Get("https://localhost:443")
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	// 使用 response 做你需要的事情...
}
```

更多细节见 [gmsm/http_client_test.go#TestSimpleNewAuthHTTPSClient](../http_client_test.go)

## TLCP GCM模式

《GBT 38636-2020 信息安全技术 传输层密码协议（TLCP）》协议中增加了GCM可鉴别加密模式相关的系列密码套件。

以`ECC_SM4_GCM_SM3` 密码套件为例，该套件使用SM4算法GCM可鉴别加密模式，替换了“SM4 CBC模式 + SM3 HMAC”，其余保持不变。

GCM模式下：

- 密文数据结构和生成规则详见: 《GBT 38636-2020》 6.3.3.4.4 认证加密算法的数据处理
- 实现随机数实现细节见：RFC 5116 (AES_GCM 参考 RFC 5288)


如何使用？

- 目前客户端和服务端均支持 `ECC_SM4_GCM_SM3` 与 `ECC_SM4_CBC_SM3` 密码套件。
- 服务端：无需而外配置。
- 客户端：目前客户单默认使用`ECC_SM4_CBC_SM3`密码套件，需要手动配置才可以使用 `ECC_SM4_GCM_SM3`套件。

目前支持TLCP密码套件：

- `ECC_SM4_GCM_SM3`
- `ECC_SM4_CBC_SM3`
- `ECDHE_SM4_CBC_SM3`
- `ECDHE_SM4_GCM_SM3`

### 客户端 GCM配置

以单向身份认证举例，只需要在连接配置中增加响应的算法，将GCM模式套件放在数组较前面的位置就可以。

示例如下：

```go
package main

import (
	"github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"
	"io/ioutil"
	"log"
)

func main() {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile("root.cer")
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	cert, err := gmtls.LoadX509KeyPair("sm2_cli.cer", "sm2_cli.pem")

	config := &gmtls.Config{
		GMSupport:    &gmtls.GMSupport{},
		RootCAs:      certPool,
		Certificates: []gmtls.Certificate{cert},
		// 设置GCM模式套件放在前面
		CipherSuites: []uint16{gmtls.GMTLS_ECC_SM4_GCM_SM3, gmtls.GMTLS_ECC_SM4_CBC_SM3},
	}

	conn, err := gmtls.Dial("tcp", "localhost:50052", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// 对 conn 读取或写入
}
```

### 关于 TLCP AEAD随机数

该套件采用 显式 和 隐式 随机数构造，AEAD随机数（Nonce），总长12字节，4字节隐式随机数、8字节显式部分。

```txt
      +---------------------+----------------------------------+
      |      Fixed(4byte)   |          Counter(8byte)          |
      +---------------------+----------------------------------+
      <----  隐式随机数  ---> <------------ 显式部分 ------------>
```

- 隐式随机数为： 工作密钥中的 客户端写IV(`client_write_IV `) 或 服务端写IV(`server_write_IV`)。
- 显式部分为： 数据包序号(`seq_num`)，也就是`GenericAEADCipher.nonce_explicit`字段。

> 详见 RFC 5116 3.2.  Recommended Nonce Formation

AEAD SM4 与 AEAD AES 128 实现一致。

