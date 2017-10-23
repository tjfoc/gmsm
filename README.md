
GM SM2/3/4 library based on Golang

Process Results
[![Build Status](https://travis-ci.org/tjfoc/gmsm.svg?branch=master)](https://travis-ci.org/tjfoc/gmsm)

基于Go语言的国密SM2/SM3/SM4加密算法库

版权所有 苏州同济区块链研究院有限公司(http://www.tj-fintech.com)


Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

See the License for the specific language governing permissions and limitations under the License.


GMSM包含以下主要功能

    SM2: 国密椭圆曲线算法库
        . 支持Generate Key, Sign, Verify基础操作
        . 支持加密和不加密的pem文件格式(加密方法参见RFC5958, 具体实现参加代码)
        . 支持证书的生成，证书的读写(接口兼容rsa和ecdsa的证书)
        . 支持证书链的操作(接口兼容rsa和ecdsa)
        . 支持crypto.Signer接口

    SM3: 国密hash算法库
       . 支持基础的sm3Sum操作
       . 支持hash.Hash接口

    SM4: 国密分组密码算法库
        . 支持Generate Key, Encrypt, Decrypt基础操作
        . 提供Cipher.Block接口
        . 支持加密和不加密的pem文件格式(加密方法为pem block加密, 具体函数为x509.EncryptPEMBlock)


关于GMSM交流： [![Join the chat at https://gitter.im/tjfoc/gmsm](https://badges.gitter.im/tjfoc/gmsm.svg)](https://gitter.im/tjfoc/gmsm?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

### sm4 加速
| | 测试环境 |
| --- | :--- |
| CPU | Intel(TM) i5-4570 @ 3.20GHz |
| OS | Ubuntu 16.04.3 LTS |
| Go ver. | 1.7.3 linux/amd64 |

* [原版 by tjfoc](https://github.com/tjfoc/gmsm):
```
BenchmarkSM4-4   	 2000000	       651 ns/op	      32 B/op	       2 allocs/op
PASS
ok  	github.com/tjfoc/gmsm/sm4	1.992s
```
* [加速版 by QwertyJack](https://github.com/QwertyJack/gmsm.git):
```
BenchmarkSM4-4   	 3000000	       404 ns/op	      32 B/op	       2 allocs/op
PASS
ok  	github.com/QwertyJack/gmsm/sm4	1.638s
```
