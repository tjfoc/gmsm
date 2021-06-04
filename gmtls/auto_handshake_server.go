// GMTLS 和 TLS 自动切换

package gmtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// 服务服务端的混合握手
// 根据客户端协议类型自动选择GMSSL协议或TLS系列协议
func (c *Conn) serverHandshakeAutoSwitch() error {
	// If this is the first server handshake, we generate a random key to
	// encrypt the tickets with.
	c.config.serverInitOnce.Do(func() { c.config.serverInit(nil) })

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError("Client Hello Msg", msg)
	}

	//
	// 根据客户端Hello消息的版本选择使用的
	// GMSSL协议 或 TLS 协议
	//
	switch clientHello.vers {
	case VersionGMSSL:
		// 构造 国密SSL握手 状态上下文
		hs := &serverHandshakeStateGM{
			c:           c,
			clientHello: clientHello,
		}
		// 处理读取到 客户端Hello 消息
		isResume, err := processClientHelloGM(c, hs)
		if err != nil {
			return err
		}
		// 运行 GMSSL 握手流程
		return runServerHandshakeGM(c, hs, isResume)
	case VersionSSL30, VersionTLS10, VersionTLS11, VersionTLS12:
		// SSL v3.0 - TLS 1.3
		// 构造 国密SSL握手 状态上下文
		hs := &serverHandshakeState{
			c:           c,
			clientHello: clientHello,
		}
		// 处理读取到 客户端Hello 消息
		isResume, err := processClientHello(c, hs)
		if err != nil {
			return err
		}
		// 运行 GMSSL 握手流程
		return runServerHandshake(c, hs, isResume)
	default:
		_ = c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: mix server handshake unsupport client protocol version: %X", clientHello.vers)
	}
}

// 处理 GMSSL 客户端 Hello消息
// Code segment copy from: gmtls/gm_handshake_server_double.go:114
//
// c: 连接对象
// hs: GMSSL服务端握手状态
//
// return:
// 			是否重用会话，true/false 重用/不重用
//			错误信息
func processClientHelloGM(c *Conn, hs *serverHandshakeStateGM) (isResume bool, err error) {
	if c.config.GetConfigForClient != nil {
		if newConfig, err := c.config.GetConfigForClient(hs.clientHelloInfo()); err != nil {
			_ = c.sendAlert(alertInternalError)
			return false, err
		} else if newConfig != nil {
			newConfig.serverInitOnce.Do(func() { newConfig.serverInit(c.config) })
			c.config = newConfig
		}
	}
	var ok bool
	c.vers, ok = c.config.mutualVersion(hs.clientHello.vers)
	if !ok {
		_ = c.sendAlert(alertProtocolVersion)
		return false, fmt.Errorf("tls: client offered an unsupported, maximum protocol version of %x", hs.clientHello.vers)
	}
	c.haveVers = true

	hs.hello = new(serverHelloMsg)

	foundCompression := false
	// We only support null compression, so check that the client offered it.
	for _, compression := range hs.clientHello.compressionMethods {
		if compression == compressionNone {
			foundCompression = true
			break
		}
	}

	if !foundCompression {
		_ = c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: client does not support uncompressed connections")
	}

	hs.hello.vers = c.vers
	hs.hello.random = make([]byte, 32)
	_, err = io.ReadFull(c.config.rand(), hs.hello.random)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return false, err
	}
	// Edit: 根据 GMT 0024 6.4.4.1.1 Client Hello 消息 b) random 描述
	// 客户端产生的随机信息，其内容包括时钟和随机数。
	gmtRandom(&(hs.hello.random))

	if len(hs.clientHello.secureRenegotiation) != 0 {
		_ = c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
	}

	hs.hello.secureRenegotiationSupported = hs.clientHello.secureRenegotiationSupported
	hs.hello.compressionMethod = compressionNone
	if len(hs.clientHello.serverName) > 0 {
		c.serverName = hs.clientHello.serverName
	}

	if len(hs.clientHello.alpnProtocols) > 0 {
		if selectedProto, fallback := mutualProtocol(hs.clientHello.alpnProtocols, c.config.NextProtos); !fallback {
			hs.hello.alpnProtocol = selectedProto
			c.clientProtocol = selectedProto
		}
	} else {
		// Although sending an empty NPN extension is reasonable, Firefox has
		// had a bug around this. Best to send nothing at all if
		// c.config.NextProtos is empty. See
		// https://golang.org/issue/5445.
		if hs.clientHello.nextProtoNeg && len(c.config.NextProtos) > 0 {
			hs.hello.nextProtoNeg = true
			hs.hello.nextProtos = c.config.NextProtos
		}
	}

	// Edit:
	//		通过获取证书方法获取 签名证书(含私钥)
	//		通过获取证书方法获取 加密证书(含私钥)
	sigCert, err := c.config.getCertificate(hs.clientHelloInfo())
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return false, err
	}
	encCert, err := c.config.GetKECertificate(hs.clientHelloInfo())
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return false, err
	}
	// GMT0024
	if encCert == nil || sigCert == nil {
		_ = c.sendAlert(alertInternalError)
		return false, fmt.Errorf("tls: amount of server certificates must be greater than 2, which will sign and encipher respectively")
	}
	// 第1张证书为 签名证书、第2张为加密证书（用于密钥交换）
	hs.cert = []Certificate{*sigCert, *encCert}

	if hs.clientHello.scts {
		hs.hello.scts = hs.cert[0].SignedCertificateTimestamps
	}

	if hs.checkForResumption() {
		return true, nil
	}

	var preferenceList, supportedList []uint16
	if c.config.PreferServerCipherSuites {
		preferenceList = getCipherSuites(c.config)
		supportedList = hs.clientHello.cipherSuites
	} else {
		preferenceList = hs.clientHello.cipherSuites
		supportedList = getCipherSuites(c.config)
	}

	for _, id := range preferenceList {
		if hs.setCipherSuite(id, supportedList, c.vers) {
			break
		}
	}

	if hs.suite == nil {
		_ = c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: no cipher suite supported by both client and server")
	}

	// See https://tools.ietf.org/html/rfc7507.
	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// The client is doing a fallback connection.
			if hs.clientHello.vers < c.config.maxVersion() {
				_ = c.sendAlert(alertInappropriateFallback)
				return false, errors.New("tls: client using inappropriate protocol fallback")
			}
			break
		}
	}
	return false, nil
}

// 运行GMSSL服务端握手流程
// Code segment copy from: gmtls/gm_handshake_server_double.go:39
//
// c: 连接对象
// hs: GMSSL服务端握手状态
// isResume: 是否重新启用会话
//
// return:
//			错误信息
func runServerHandshakeGM(c *Conn, hs *serverHandshakeStateGM, isResume bool) error {
	// For an overview of TLS handshaking, see https://tools.ietf.org/html/rfc5246#section-7.3
	c.buffering = true
	if isResume {
		// The client has included a session ticket and so we do an abbreviated handshake.
		if err := hs.doResumeHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		// ticketSupported is set in a resumption handshake if the
		// ticket from the client was encrypted with an old session
		// ticket key and thus a refreshed ticket should be sent.
		if hs.hello.ticketSupported {
			if err := hs.sendSessionTicket(); err != nil {
				return err
			}
		}
		if err := hs.sendFinished(c.serverFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		if err := hs.readFinished(nil); err != nil {
			return err
		}
		c.didResume = true
	} else {
		// The client didn't include a session ticket, or it wasn't
		// valid so we do a full handshake.
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readFinished(c.clientFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		c.buffering = true
		if err := hs.sendSessionTicket(); err != nil {
			return err
		}
		if err := hs.sendFinished(nil); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	}

	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random)
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

// 处理 TLS 客户端 Hello消息
// Code segment copy from: gmtls/handshake_server.go:122
//
// c: 连接对象
// hs: TLS服务端握手状态
//
// return:
// 			是否重用会话，true/false 重用/不重用
//			错误信息
func processClientHello(c *Conn, hs *serverHandshakeState) (bool, error) {
	if c.config.GetConfigForClient != nil {
		if newConfig, err := c.config.GetConfigForClient(hs.clientHelloInfo()); err != nil {
			_ = c.sendAlert(alertInternalError)
			return false, err
		} else if newConfig != nil {
			newConfig.serverInitOnce.Do(func() { newConfig.serverInit(c.config) })
			c.config = newConfig
		}
	}
	var ok bool
	var err error
	c.vers, ok = c.config.mutualVersion(hs.clientHello.vers)
	if !ok {
		_ = c.sendAlert(alertProtocolVersion)
		return false, fmt.Errorf("tls: client offered an unsupported, maximum protocol version of %x", hs.clientHello.vers)
	}
	c.haveVers = true

	hs.hello = new(serverHelloMsg)

	supportedCurve := false
	preferredCurves := c.config.curvePreferences()
Curves:
	for _, curve := range hs.clientHello.supportedCurves {
		for _, supported := range preferredCurves {
			if supported == curve {
				supportedCurve = true
				break Curves
			}
		}
	}

	supportedPointFormat := false
	for _, pointFormat := range hs.clientHello.supportedPoints {
		if pointFormat == pointFormatUncompressed {
			supportedPointFormat = true
			break
		}
	}
	hs.ellipticOk = supportedCurve && supportedPointFormat

	foundCompression := false
	// We only support null compression, so check that the client offered it.
	for _, compression := range hs.clientHello.compressionMethods {
		if compression == compressionNone {
			foundCompression = true
			break
		}
	}

	if !foundCompression {
		_ = c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: client does not support uncompressed connections")
	}

	hs.hello.vers = c.vers
	hs.hello.random = make([]byte, 32)
	_, err = io.ReadFull(c.config.rand(), hs.hello.random)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return false, err
	}

	if len(hs.clientHello.secureRenegotiation) != 0 {
		_ = c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
	}

	hs.hello.secureRenegotiationSupported = hs.clientHello.secureRenegotiationSupported
	hs.hello.compressionMethod = compressionNone
	if len(hs.clientHello.serverName) > 0 {
		c.serverName = hs.clientHello.serverName
	}

	if len(hs.clientHello.alpnProtocols) > 0 {
		if selectedProto, fallback := mutualProtocol(hs.clientHello.alpnProtocols, c.config.NextProtos); !fallback {
			hs.hello.alpnProtocol = selectedProto
			c.clientProtocol = selectedProto
		}
	} else {
		// Although sending an empty NPN extension is reasonable, Firefox has
		// had a bug around this. Best to send nothing at all if
		// c.config.NextProtos is empty. See
		// https://golang.org/issue/5445.
		if hs.clientHello.nextProtoNeg && len(c.config.NextProtos) > 0 {
			hs.hello.nextProtoNeg = true
			hs.hello.nextProtos = c.config.NextProtos
		}
	}

	hs.cert, err = c.config.getCertificate(hs.clientHelloInfo())
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return false, err
	}
	if hs.clientHello.scts {
		hs.hello.scts = hs.cert.SignedCertificateTimestamps
	}

	if priv, ok := hs.cert.PrivateKey.(crypto.Signer); ok {
		switch priv.Public().(type) {
		case *ecdsa.PublicKey:
			hs.ecdsaOk = true
		case *rsa.PublicKey:
			hs.rsaSignOk = true
		default:
			_ = c.sendAlert(alertInternalError)
			return false, fmt.Errorf("tls: unsupported signing key type (%T)", priv.Public())
		}
	}
	if priv, ok := hs.cert.PrivateKey.(crypto.Decrypter); ok {
		switch priv.Public().(type) {
		case *rsa.PublicKey:
			hs.rsaDecryptOk = true
		default:
			_ = c.sendAlert(alertInternalError)
			return false, fmt.Errorf("tls: unsupported decryption key type (%T)", priv.Public())
		}
	}

	if hs.checkForResumption() {
		return true, nil
	}

	var preferenceList, supportedList []uint16
	if c.config.PreferServerCipherSuites {
		preferenceList = c.config.cipherSuites()
		supportedList = hs.clientHello.cipherSuites
	} else {
		preferenceList = hs.clientHello.cipherSuites
		supportedList = c.config.cipherSuites()
	}

	for _, id := range preferenceList {
		if hs.setCipherSuite(id, supportedList, c.vers) {
			break
		}
	}

	if hs.suite == nil {
		_ = c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: no cipher suite supported by both client and server")
	}

	// See https://tools.ietf.org/html/rfc7507.
	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// The client is doing a fallback connection.
			if hs.clientHello.vers < c.config.maxVersion() {
				_ = c.sendAlert(alertInappropriateFallback)
				return false, errors.New("tls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	return false, nil
}

// 运行TLS服务端握手流程
// Code segment copy from: gmtls/handshake_server.go:51
//
// c: 连接对象
// hs: TLS服务端握手状态
// isResume: 是否重新启用会话
//
// return:
//			错误信息
func runServerHandshake(c *Conn, hs *serverHandshakeState, isResume bool) error {
	// For an overview of TLS handshaking, see https://tools.ietf.org/html/rfc5246#section-7.3
	c.buffering = true
	if isResume {
		// The client has included a session ticket and so we do an abbreviated handshake.
		if err := hs.doResumeHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		// ticketSupported is set in a resumption handshake if the
		// ticket from the client was encrypted with an old session
		// ticket key and thus a refreshed ticket should be sent.
		if hs.hello.ticketSupported {
			if err := hs.sendSessionTicket(); err != nil {
				return err
			}
		}
		if err := hs.sendFinished(c.serverFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		if err := hs.readFinished(nil); err != nil {
			return err
		}
		c.didResume = true
	} else {
		// The client didn't include a session ticket, or it wasn't
		// valid so we do a full handshake.
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readFinished(c.clientFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		c.buffering = true
		if err := hs.sendSessionTicket(); err != nil {
			return err
		}
		if err := hs.sendFinished(nil); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	}

	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random)
	atomic.StoreUint32(&c.handshakeStatus, 1)
	return nil
}

// 国密类型的随机数 4 byte unix time 28 byte random
func gmtRandom(raw *[]byte) uint32 {
	rd := *raw
	unixTime := time.Now().Unix()
	rd[0] = uint8(unixTime >> 24)
	rd[1] = uint8(unixTime >> 16)
	rd[2] = uint8(unixTime >> 8)
	rd[3] = uint8(unixTime)
	return uint32(unixTime)
}
