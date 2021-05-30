package gmtls

// NewBasicAutoSwitchConfig 返回一个实现了GMSSL/TLS自动切换的配置
//
// sm2SigCert: SM2 签名密钥对、证书
// sm2EncCert: SM2 加密密钥对、证书
// stdCert: RSA/ECC 标准的密钥对、证书
//
// return: 最基础的Config对象
func NewBasicAutoSwitchConfig(sm2SigCert, sm2EncCert, stdCert *Certificate) (*Config, error) {
	fncGetSignCertKeypair := func(info *ClientHelloInfo) (*Certificate, error) {
		gmFlag := false
		// 检查支持协议中是否包含GMSSL
		for _, v := range info.SupportedVersions {
			if v == VersionGMSSL {
				gmFlag = true
				break
			}
		}

		if gmFlag {
			return sm2SigCert, nil
		} else {
			return stdCert, nil
		}
	}

	fncGetEncCertKeypair := func(info *ClientHelloInfo) (*Certificate, error) {
		return sm2EncCert, nil
	}
	support := NewGMSupport()
	support.EnableMixMode()
	return &Config{
		GMSupport:        support,
		GetCertificate:   fncGetSignCertKeypair,
		GetKECertificate: fncGetEncCertKeypair,
	}, nil
}
