// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build single_cert

package gmtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"io"
	"strconv"
	"sync/atomic"
)

type clientHandshakeStateGM struct {
	c            *Conn
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
	session      *ClientSessionState
}

func makeClientHelloGM(config *Config) (*clientHelloMsg, error) {
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		return nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	hello := &clientHelloMsg{
		vers:               config.GMSupport.GetVersion(),
		compressionMethods: []uint8{compressionNone},
		random:             make([]byte, 32),
	}
	possibleCipherSuites := getCipherSuites(config)
	hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

NextCipherSuite:
	for _, suiteId := range possibleCipherSuites {
		for _, suite := range config.GMSupport.cipherSuites() {
			if suite.id != suiteId {
				continue
			}
			hello.cipherSuites = append(hello.cipherSuites, suiteId)
			continue NextCipherSuite
		}
	}

	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	return hello, nil
}

// Does the handshake, either a full one or resumes old session.
// Requires hs.c, hs.hello, and, optionally, hs.session to be set.
func (hs *clientHandshakeStateGM) handshake() error {
	c := hs.c

	// send ClientHello
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	var ok bool
	if hs.serverHello, ok = msg.(*serverHelloMsg); !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(hs.serverHello, msg)
	}

	if hs.serverHello.vers != VersionGMSSL {
		hs.c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x, while expecting %x", hs.serverHello.vers, VersionGMSSL)
	}

	if err = hs.pickCipherSuite(); err != nil {
		return err
	}

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHashGM(hs.suite)

	// No signatures of the handshake are needed in a resumption.
	// Otherwise, in a full handshake, if we don't have any certificates
	// configured then we will never send a CertificateVerify message and
	// thus no signatures are needed in that case either.
	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}

	hs.finishedHash.Write(hs.hello.marshal())
	hs.finishedHash.Write(hs.serverHello.marshal())

	c.buffering = true
	if isResume {
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}

	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random)
	c.didResume = isResume
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (hs *clientHandshakeStateGM) pickCipherSuite() error {
	if hs.suite = mutualCipherSuiteGM(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		hs.c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}

	hs.c.cipherSuite = hs.suite.id
	return nil
}

func (hs *clientHandshakeStateGM) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}

	// mod by syl only one cert
	// Thanks to dual certificates mechanism, length of certificates in GMT0024 must great than 2
	//if len(certMsg.certificates) < 2{
	//	c.sendAlert(alertInsufficientSecurity)
	//	return fmt.Errorf("tls: length of certificates in GMT0024 must great than 2")
	//}

	hs.finishedHash.Write(certMsg.marshal())

	if c.handshakes == 0 {
		// If this is the first handshake on a connection, process and
		// (optionally) verify the server's certificates.
		certs := make([]*x509.Certificate, len(certMsg.certificates))
		for i, asn1Data := range certMsg.certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				c.sendAlert(alertBadCertificate)
				return errors.New("tls: failed to parse certificate from server: " + err.Error())
			}

			// mod by syl below
			//if cert.SignatureAlgorithm != x509.SM2WithSM3{
			//	c.sendAlert(alertUnsupportedCertificate)
			//	return fmt.Errorf("tls: SignatureAlgorithm of the certificate[%d] is not supported, actual:%s, expect:SM2WITHSM3", i, cert.SignatureAlgorithm.String())
			//}
			//if cert.PublicKeyAlgorithm != x509.SM2 {
			//	c.sendAlert(alertUnsupportedCertificate)
			//	return fmt.Errorf("tls: PublicKeyAlgorithm of the certificate[%d] is not supported, actual:%s, expect:SM2", i, []string{"unkown", "RSA", "DSA", "ECDSA", "SM2"}[int(cert.PublicKeyAlgorithm)])
			//}
			////cert[0] is for signature while cert[1] is for encipher, refer to  GMT0024
			////check key usage
			//switch i {
			//case 0:
			//	if cert.KeyUsage == 0 || (cert.KeyUsage & (x509.KeyUsageDigitalSignature | cert.KeyUsage&x509.KeyUsageContentCommitment)) == 0{
			//		c.sendAlert(alertInsufficientSecurity)
			//		return fmt.Errorf("tls: the keyusage of cert[0] does not exist or is not for KeyUsageDigitalSignature/KeyUsageContentCommitment, value:%d", cert.KeyUsage)
			//	}
			//case 1:
			//	if cert.KeyUsage == 0 || (cert.KeyUsage & (x509.KeyUsageDataEncipherment | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement))==0{
			//		c.sendAlert(alertInsufficientSecurity)
			//		return fmt.Errorf("tls: the keyusage of cert[1] does not exist or is not for KeyUsageDataEncipherment/KeyUsageKeyEncipherment/KeyUsageKeyAgreement, value:%d", cert.KeyUsage)
			//	}
			//}

			certs[i] = cert
		}

		if !c.config.InsecureSkipVerify {
			opts := x509.VerifyOptions{
				Roots:         c.config.RootCAs,
				CurrentTime:   c.config.time(),
				DNSName:       c.config.ServerName,
				Intermediates: x509.NewCertPool(),
			}
			if opts.Roots == nil {
				opts.Roots = x509.NewCertPool()
			}

			for _, rootca := range getCAs() {
				opts.Roots.AddCert(rootca)
			}
			for i, cert := range certs {
				if i == 0 {
					continue
				}
				opts.Intermediates.AddCert(cert)
			}

			c.verifiedChains, err = certs[0].Verify(opts)
			if err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}

		if c.config.VerifyPeerCertificate != nil {
			if err := c.config.VerifyPeerCertificate(certMsg.certificates, c.verifiedChains); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}

		switch certs[0].PublicKey.(type) {
		case *sm2.PublicKey, *ecdsa.PublicKey, *rsa.PublicKey:
			break
		default:
			c.sendAlert(alertUnsupportedCertificate)
			return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
		}

		c.peerCertificates = certs
	} else {
		// This is a renegotiation handshake. We require that the
		// server's identity (i.e. leaf certificate) is unchanged and
		// thus any previous trust decision is still valid.
		//
		// See https://mitls.org/pages/attacks/3SHAKE for the
		// motivation behind this requirement.
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: server's identity changed during renegotiation")
		}
	}

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	keyAgreement := hs.suite.ka(c.vers)
	if ka, ok := keyAgreement.(*eccKeyAgreementGM); ok {
		// mod by syl only one cert
		//ka.encipherCert = c.peerCertificates[1]
		ka.encipherCert = c.peerCertificates[0]
	}

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		hs.finishedHash.Write(skx.marshal())
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, c.peerCertificates[0], skx)
		if err != nil {
			c.sendAlert(alertUnexpectedMessage)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsgGM)
	if ok {
		certRequested = true
		hs.finishedHash.Write(certReq.marshal())

		if chainToSend, err = hs.getCertificate(certReq); err != nil || chainToSend.Certificate == nil {
			c.sendAlert(alertInternalError)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}
	hs.finishedHash.Write(shd.marshal())

	// If the server requested a certificate then we have to send a
	// Certificate message, even if it's empty because we don't have a
	// certificate to send.
	if certRequested {
		certMsg = new(certificateMsg)
		certMsg.certificates = chainToSend.Certificate
		hs.finishedHash.Write(certMsg.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
			return err
		}
	}

	// mod by syl only one cert
	//preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates[1])
	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates[0])
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if ckx != nil {
		hs.finishedHash.Write(ckx.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, ckx.marshal()); err != nil {
			return err
		}
	}

	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{}

		key, ok := chainToSend.PrivateKey.(crypto.Signer)
		if !ok {
			c.sendAlert(alertInternalError)
			return fmt.Errorf("tls: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey)
		}

		digest := hs.finishedHash.client.Sum(nil)

		certVerify.signature, err = key.Sign(c.config.rand(), digest, nil)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		hs.finishedHash.Write(certVerify.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certVerify.marshal()); err != nil {
			return err
		}
	}

	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.random)
	if err := c.config.writeKeyLog(hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to write to key log: " + err.Error())
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *clientHandshakeStateGM) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(c.vers, clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(c.vers, serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeStateGM) serverResumedSession() bool {
	// If the server responded with the same sessionId then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionId != nil &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

func (hs *clientHandshakeStateGM) processServerHello() (bool, error) {
	c := hs.c

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertUnexpectedMessage)
		return false, errors.New("tls: server selected unsupported compression format")
	}

	if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.serverHello.secureRenegotiation) != 0 {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
		}
	}

	if c.handshakes > 0 && c.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], c.clientFinished[:])
		copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
		if !bytes.Equal(hs.serverHello.secureRenegotiation, expectedSecureRenegotiation[:]) {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: incorrect renegotiation extension contents")
		}
	}

	clientDidNPN := hs.hello.nextProtoNeg
	clientDidALPN := len(hs.hello.alpnProtocols) > 0
	serverHasNPN := hs.serverHello.nextProtoNeg
	serverHasALPN := len(hs.serverHello.alpnProtocol) > 0

	if !clientDidNPN && serverHasNPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised unrequested NPN extension")
	}

	if !clientDidALPN && serverHasALPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised unrequested ALPN extension")
	}

	if serverHasNPN && serverHasALPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised both NPN and ALPN extensions")
	}

	if serverHasALPN {
		c.clientProtocol = hs.serverHello.alpnProtocol
		c.clientProtocolFallback = false
	}
	c.scts = hs.serverHello.scts

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.vers != c.vers {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different cipher suite")
	}

	// Restore masterSecret and peerCerts from previous state
	hs.masterSecret = hs.session.masterSecret
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	return true, nil
}

func (hs *clientHandshakeStateGM) readFinished(out []byte) error {
	c := hs.c

	c.readRecord(recordTypeChangeCipherSpec)
	if c.in.err != nil {
		return c.in.err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server's Finished message was incorrect")
	}
	hs.finishedHash.Write(serverFinished.marshal())
	copy(out, verify)
	return nil
}

func (hs *clientHandshakeStateGM) readSessionTicket() error {
	if !hs.serverHello.ticketSupported {
		return nil
	}

	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(sessionTicketMsg, msg)
	}
	hs.finishedHash.Write(sessionTicketMsg.marshal())

	hs.session = &ClientSessionState{
		sessionTicket:      sessionTicketMsg.ticket,
		vers:               c.vers,
		cipherSuite:        hs.suite.id,
		masterSecret:       hs.masterSecret,
		serverCertificates: c.peerCertificates,
		verifiedChains:     c.verifiedChains,
	}

	return nil
}

func (hs *clientHandshakeStateGM) sendFinished(out []byte) error {
	c := hs.c

	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	if hs.serverHello.nextProtoNeg {
		nextProto := new(nextProtoMsg)
		proto, fallback := mutualProtocol(c.config.NextProtos, hs.serverHello.nextProtos)
		nextProto.proto = proto
		c.clientProtocol = proto
		c.clientProtocolFallback = fallback

		hs.finishedHash.Write(nextProto.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, nextProto.marshal()); err != nil {
			return err
		}
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

//// tls11SignatureSchemes contains the signature schemes that we synthesise for
//// a TLS <= 1.1 connection, based on the supported certificate types.
//var tls11SignatureSchemes = []SignatureScheme{ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512, PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1}
//
//const (
//	// tls11SignatureSchemesNumECDSA is the number of initial elements of
//	// tls11SignatureSchemes that use ECDSA.
//	tls11SignatureSchemesNumECDSA = 3
//	// tls11SignatureSchemesNumRSA is the number of trailing elements of
//	// tls11SignatureSchemes that use RSA.
//	tls11SignatureSchemesNumRSA = 4
//)

func (hs *clientHandshakeStateGM) getCertificate(certReq *certificateRequestMsgGM) (*Certificate, error) {
	c := hs.c

	if c.config.GetClientCertificate != nil {
		var signatureSchemes []SignatureScheme

		return c.config.GetClientCertificate(&CertificateRequestInfo{
			AcceptableCAs:    certReq.certificateAuthorities,
			SignatureSchemes: signatureSchemes,
		})
	}

	// RFC 4346 on the certificateAuthorities field: A list of the
	// distinguished names of acceptable certificate authorities.
	// These distinguished names may specify a desired
	// distinguished name for a root CA or for a subordinate CA;
	// thus, this message can be used to describe both known roots
	// and a desired authorization space. If the
	// certificate_authorities list is empty then the client MAY
	// send any certificate of the appropriate
	// ClientCertificateType, unless there is some external
	// arrangement to the contrary.

	// We need to search our list of client certs for one
	// where SignatureAlgorithm is acceptable to the server and the
	// Issuer is in certReq.certificateAuthorities
findCert:
	for i, chain := range c.config.Certificates {

		for j, cert := range chain.Certificate {
			x509Cert := chain.Leaf
			// parse the certificate if this isn't the leaf
			// node, or if chain.Leaf was nil
			if j != 0 || x509Cert == nil {
				var err error
				if x509Cert, err = x509.ParseCertificate(cert); err != nil {
					c.sendAlert(alertInternalError)
					return nil, errors.New("tls: failed to parse client certificate #" + strconv.Itoa(i) + ": " + err.Error())
				}
			}

			switch {
			case x509Cert.PublicKeyAlgorithm == x509.SM2:
			default:
				continue findCert
			}

			if len(certReq.certificateAuthorities) == 0 {
				// they gave us an empty list, so just take the
				// first cert from c.config.Certificates
				return &chain, nil
			}

			for _, ca := range certReq.certificateAuthorities {
				if bytes.Equal(x509Cert.RawIssuer, ca) {
					return &chain, nil
				}
			}
		}
	}

	// No acceptable certificate found. Don't send a certificate.
	return new(Certificate), nil
}
