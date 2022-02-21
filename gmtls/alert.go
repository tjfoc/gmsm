/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gmtls

import "strconv"

type alert uint8

const (
	// alert level
	alertLevelWarning = 1
	alertLevelError   = 2
)

const (
	alertCloseNotify            alert = 0
	alertUnexpectedMessage      alert = 10
	alertBadRecordMAC           alert = 20
	alertDecryptionFailed       alert = 21
	alertRecordOverflow         alert = 22
	alertDecompressionFailure   alert = 30
	alertHandshakeFailure       alert = 40
	alertBadCertificate         alert = 42
	alertUnsupportedCertificate alert = 43
	alertCertificateRevoked     alert = 44
	alertCertificateExpired     alert = 45
	alertCertificateUnknown     alert = 46
	alertIllegalParameter       alert = 47
	alertUnknownCA              alert = 48
	alertAccessDenied           alert = 49
	alertDecodeError            alert = 50
	alertDecryptError           alert = 51
	alertProtocolVersion        alert = 70
	alertInsufficientSecurity   alert = 71
	alertInternalError          alert = 80
	alertInappropriateFallback  alert = 86
	alertUserCanceled           alert = 90
	alertNoRenegotiation        alert = 100
	alertNoApplicationProtocol  alert = 120
	//GMT0024
	alertUnspporttedSite2Site alert = 200
	alertNoArea               alert = 201
	alertUnspportedAreaType   alert = 202
	alertBadIBCParam          alert = 203
	alertUnspportedIBCParam   alert = 204
	alertIdentityNeed         alert = 205
)

var alertText = map[alert]string{
	alertCloseNotify:            "close notify",
	alertUnexpectedMessage:      "unexpected message",
	alertBadRecordMAC:           "bad record MAC",
	alertDecryptionFailed:       "decryption failed",
	alertRecordOverflow:         "record overflow",
	alertDecompressionFailure:   "decompression failure",
	alertHandshakeFailure:       "handshake failure",
	alertBadCertificate:         "bad certificate",
	alertUnsupportedCertificate: "unsupported certificate",
	alertCertificateRevoked:     "revoked certificate",
	alertCertificateExpired:     "expired certificate",
	alertCertificateUnknown:     "unknown certificate",
	alertIllegalParameter:       "illegal parameter",
	alertUnknownCA:              "unknown certificate authority",
	alertAccessDenied:           "access denied",
	alertDecodeError:            "error decoding message",
	alertDecryptError:           "error decrypting message",
	alertProtocolVersion:        "protocol version not supported",
	alertInsufficientSecurity:   "insufficient security level",
	alertInternalError:          "internal error",
	alertInappropriateFallback:  "inappropriate fallback",
	alertUserCanceled:           "user canceled",
	alertNoRenegotiation:        "no renegotiation",
	alertNoApplicationProtocol:  "no application protocol",
	//GMT0024
	alertUnspporttedSite2Site: "不支持site2site",
	alertNoArea:               "没有保护域",
	alertUnspportedAreaType:   "不支持的保护域类型",
	alertBadIBCParam:          "接收到一个无效的ibc公共参数",
	alertUnspportedIBCParam:   "不支持ibc参数中定义的信息",
	alertIdentityNeed:         "缺少对方的ibc标识",
}

// 错误中文描述
var alertText_CN = map[alert]string{
	alertCloseNotify:            "关闭通知",
	alertUnexpectedMessage:      "接收到一个不符合上下文关系的消息",
	alertBadRecordMAC:           "MAC校验错误或解密错误",
	alertDecryptionFailed:       "解密失败",
	alertRecordOverflow:         "报文过长",
	alertDecompressionFailure:   "解压缩失败",
	alertHandshakeFailure:       "协商失败",
	alertBadCertificate:         "证书破坏",
	alertUnsupportedCertificate: "不支持证书类型",
	alertCertificateRevoked:     "证书被撤销",
	alertCertificateExpired:     "证书过期或未生效",
	alertCertificateUnknown:     "未知证书错误",
	alertIllegalParameter:       "非法参数",
	alertUnknownCA:              "根证书不可信",
	alertAccessDenied:           "拒绝访问",
	alertDecodeError:            "消息解码失败",
	alertDecryptError:           "消息解密失败",
	alertProtocolVersion:        "版本不匹配",
	alertInsufficientSecurity:   "安全性不足",
	alertInternalError:          "内部错误",
	alertUserCanceled:           "用户取消操作",
	alertNoRenegotiation:        "拒绝重新协商",
	alertUnspporttedSite2Site:   "不支持 site2site",
	alertNoArea:                 "没有保护域",
	alertUnspportedAreaType:     "不支持的保护域类型",
	alertBadIBCParam:            "接收到一个无效的ibc公共参数",
	alertUnspportedIBCParam:     "不支持ibc公共参数中定义的信息",
	alertIdentityNeed:           "缺少对方的ibc标识",
}

func (e alert) String() string {
	s, ok := alertText[e]
	if ok {
		return "tls: " + s
	}
	return "tls: alert(" + strconv.Itoa(int(e)) + ")"
}

func (e alert) Error() string {
	return e.String()
}

// AlertDespCN 报警消息中文意义
func AlertDespCN(e uint8) string {
	s, ok := alertText_CN[alert(e)]
	if ok {
		return s
	}
	return "报警(" + strconv.Itoa(int(e)) + ")"
}
