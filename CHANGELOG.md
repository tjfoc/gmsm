## 更新日志

主要更新:
- 添加以下oid
    SM3WithSM2 1.2.156.10197.1.501
    SHA1WithSM2 1.2.156.10197.1.502
    SHA256WithSM2 1.2.156.10197.1.503

- x509生成的证书如今可以使用SM3作为hash算法

- 引入了以下hash算法
    RIPEMD160
    SHA3_256
    SHA3_384
    SHA3_512
    SHA3_SM3
  用户需要自己安装golang.org/x/crypto
