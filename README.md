
# tjfoc-gm
GM SM2/3/4 library based on Golang
=======



[![Build Status](https://travis-ci.com/Hyperledger-TWGC/tjfoc-gm.svg?branch=dev-fabric)](https://travis-ci.com/Hyperledger-TWGC/tjfoc-gm)
[![Build Status](https://dev.azure.com/Hyperledger/TWGC/_apis/build/status/Hyperledger-TWGC.tjfoc-gm?branchName=dev-fabric)](https://dev.azure.com/Hyperledger/TWGC/_build/latest?definitionId=127&branchName=dev-fabric)
## Feature
tjfoc-gm包含以下主要功能

## Feature 功能支持列表



|  SM2功能   | 支持范围  | 
|  ----  | ----  |
| Generate KeyPair  | `是` |
| Sign  | `是` |
| Verify | `是` |
| PEM格式导出 | `私钥/公钥/CSR/证书`|
| PEM格式导入 | `私钥/公钥/CSR/证书` |
| PEM文件加密 | RFC5958 |  

|  SM4功能   | 支持范围  | 
|  ----  | ----  |
| Generate Key |  `是` |
| Encrypt, Decrypt | `是` |
| PEM格式导出 | `是`  |
| PEM文件加密 | golang: `x509.EncryptPEMBlock` |
| 分组模式 | ECB/CBC/CFB/OFB/CTR |


|  SM3功能   | 支持范围  | 
|  ----  | ----  |
| 当前语言Hash接口兼容 | `是` |

## Terminology 术语
- SM2: 国密椭圆曲线算法库
- SM3: 国密hash算法库
- SM4: 国密分组密码算法库
    - **注意**：CBC模式在国际范围内正逐渐弃用，此安全最佳实践也适用于国密

## [Usage 使用说明](./API使用说明.md)

## Communication
tjfoc国密交流 
   
[![Join the chat at https://gitter.im/tjfoc/gmsm](https://badges.gitter.im/tjfoc/gmsm.svg)](https://gitter.im/tjfoc/gmsm?utm_source=badge&utm_medium=badge&utm_campaign=-badge&utm_content=badge)


- 如果你对国密算法开源技术及应用感兴趣，欢迎添加“苏州同济区块链研究院·小助手“微信，回复“国密算法进群”，加入“同济区块链国密算法交流群”。微信二维码如下:  
     ![微信二维码](https://github.com/tjfoc/wutongchian-public/blob/master/wutongchain.png)

- 发送邮件到tj@wutongchain.com
 
 
 ## License
 版权所有 苏州同济区块链研究院有限公司(http://www.wutongchain.com/)
 
 Copyright 2017- Suzhou Tongji Fintech Research Institute. All Rights Reserved.
 Licensed under the Apache License, Version 2.0 (the "License");
 
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 
 See the License for the specific language governing permissions and limitations under the License.


