// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !single_cert

package gmtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/x509"
)

// serverHandshakeStateGM contains details of a server handshake in progress.
// It's discarded once the handshake has completed.
type serverHandshakeStateGM struct {
	c                     *Conn
	clientHello           *clientHelloMsg
	hello                 *serverHelloMsg
	suite                 *cipherSuite
	sessionState          *sessionState
	finishedHash          finishedHash
	masterSecret          []byte
	certsFromClient       [][]byte
	cert                  []Certificate
	cachedClientHelloInfo *ClientHelloInfo
}

// serverHandshake performs a TLS handshake as a server.
func (c *Conn) serverHandshakeGM() error {
	// If this is the first server handshake, we generate a random key to
	// encrypt the tickets with.
	c.config.serverInitOnce.Do(func() { c.config.serverInit(nil) })

	hs := serverHandshakeStateGM{
		c: c,
	}
	isResume, err := hs.readClientHello()
	if err != nil {
		return err
	}

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

// readClientHello reads a ClientHello message from the client and decides
// whether we will perform session resumption.
func (hs *serverHandshakeStateGM) readClientHello() (isResume bool, err error) {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return false, err
	}
	var ok bool
	hs.clientHello, ok = msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return false, unexpectedMessageError(hs.clientHello, msg)
	}

	if c.config.GetConfigForClient != nil {
		if newConfig, err := c.config.GetConfigForClient(hs.clientHelloInfo()); err != nil {
			c.sendAlert(alertInternalError)
			return false, err
		} else if newConfig != nil {
			newConfig.serverInitOnce.Do(func() { newConfig.serverInit(c.config) })
			c.config = newConfig
		}
	}

	c.vers, ok = c.config.mutualVersion(hs.clientHello.vers)
	if !ok {
		c.sendAlert(alertProtocolVersion)
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
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: client does not support uncompressed connections")
	}

	hs.hello.vers = c.vers
	hs.hello.random = make([]byte, 32)
	_, err = io.ReadFull(c.config.rand(), hs.hello.random)
	if err != nil {
		c.sendAlert(alertInternalError)
		return false, err
	}

	if len(hs.clientHello.secureRenegotiation) != 0 {
		c.sendAlert(alertHandshakeFailure)
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

	// just for test
	c.config.getCertificate(hs.clientHelloInfo())
	hs.cert = c.config.Certificates

	// GMT0024
	if len(hs.cert) < 2 {
		c.sendAlert(alertInternalError)
		return false, fmt.Errorf("tls: amount of server certificates must be greater than 2, which will sign and encipher respectively")
	}

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
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: no cipher suite supported by both client and server")
	}

	// See https://tools.ietf.org/html/rfc7507.
	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// The client is doing a fallback connection.
			if hs.clientHello.vers < c.config.maxVersion() {
				c.sendAlert(alertInappropriateFallback)
				return false, errors.New("tls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	return false, nil
}

// checkForResumption reports whether we should perform resumption on this connection.
func (hs *serverHandshakeStateGM) checkForResumption() bool {
	c := hs.c

	if c.config.SessionTicketsDisabled {
		return false
	}

	var ok bool
	var sessionTicket = append([]uint8{}, hs.clientHello.sessionTicket...)
	if hs.sessionState, ok = c.decryptTicket(sessionTicket); !ok {
		return false
	}

	// Never resume a session for a different TLS version.
	if c.vers != hs.sessionState.vers {
		return false
	}

	cipherSuiteOk := false
	// Check that the client is still offering the ciphersuite in the session.
	for _, id := range hs.clientHello.cipherSuites {
		if id == hs.sessionState.cipherSuite {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return false
	}

	// Check that we also support the ciphersuite from the session.
	if !hs.setCipherSuite(hs.sessionState.cipherSuite, c.config.cipherSuites(), hs.sessionState.vers) {
		return false
	}

	sessionHasClientCerts := len(hs.sessionState.certificates) != 0
	needClientCerts := c.config.ClientAuth == RequireAnyClientCert || c.config.ClientAuth == RequireAndVerifyClientCert
	if needClientCerts && !sessionHasClientCerts {
		return false
	}
	if sessionHasClientCerts && c.config.ClientAuth == NoClientCert {
		return false
	}

	return true
}

func (hs *serverHandshakeStateGM) doResumeHandshake() error {
	c := hs.c

	hs.hello.cipherSuite = hs.suite.id
	// We echo the client's session ID in the ServerHello to let it know
	// that we're doing a resumption.
	hs.hello.sessionId = hs.clientHello.sessionId
	hs.hello.ticketSupported = hs.sessionState.usedOldKey
	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	if len(hs.sessionState.certificates) > 0 {
		if _, err := hs.processCertsFromClient(hs.sessionState.certificates); err != nil {
			return err
		}
	}

	hs.masterSecret = hs.sessionState.masterSecret

	return nil
}

func (hs *serverHandshakeStateGM) doFullHandshake() error {
	c := hs.c

	if hs.clientHello.ocspStapling && len(hs.cert[0].OCSPStaple) > 0 {
		hs.hello.ocspStapling = true
	}

	hs.hello.ticketSupported = hs.clientHello.ticketSupported && !c.config.SessionTicketsDisabled
	hs.hello.cipherSuite = hs.suite.id

	hs.finishedHash = newFinishedHashGM(hs.suite)
	if c.config.ClientAuth == NoClientCert {
		// No need to keep a full record of the handshake if client
		// certificates won't be used.
		hs.finishedHash.discardHandshakeBuffer()
	}
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	certMsg := new(certificateMsg)
	//certMsg.certificates = hs.cert.Certificate
	for i := 0; i < len(hs.cert); i++ {
		certMsg.certificates = append(certMsg.certificates, hs.cert[i].Certificate...)
	}
	hs.finishedHash.Write(certMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
		return err
	}

	if hs.hello.ocspStapling {
		certStatus := new(certificateStatusMsg)
		certStatus.statusType = statusTypeOCSP
		certStatus.response = hs.cert[0].OCSPStaple
		hs.finishedHash.Write(certStatus.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certStatus.marshal()); err != nil {
			return err
		}
	}

	keyAgreement := hs.suite.ka(c.vers)
	skx, err := keyAgreement.generateServerKeyExchange(c.config, &hs.cert[0], &hs.cert[1], hs.clientHello, hs.hello)
	if err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	if skx != nil {
		hs.finishedHash.Write(skx.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, skx.marshal()); err != nil {
			return err
		}
	}

	if c.config.ClientAuth >= RequestClientCert {
		// Request a client certificate
		certReq := new(certificateRequestMsgGM)
		certReq.certificateTypes = []byte{
			byte(certTypeRSASign),
			byte(certTypeECDSASign),
		}
		//if c.vers >= VersionTLS12 {
		//	certReq.hasSignatureAndHash = true
		//	certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms
		//}

		// An empty list of certificateAuthorities signals to
		// the client that it may send any certificate in response
		// to our request. When we know the CAs we trust, then
		// we can send them down, so that the client can choose
		// an appropriate certificate to give to us.
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}
		hs.finishedHash.Write(certReq.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certReq.marshal()); err != nil {
			return err
		}
	}

	helloDone := new(serverHelloDoneMsg)
	hs.finishedHash.Write(helloDone.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, helloDone.marshal()); err != nil {
		return err
	}

	if _, err := c.flush(); err != nil {
		return err
	}

	var pub crypto.PublicKey // public key for client auth, if any

	msg, err := c.readHandshake()
	if err != nil {
		fmt.Println("readHandshake error:", err)
		return err
	}

	var ok bool
	// If we requested a client certificate, then the client must send a
	// certificate message, even if it's empty.
	if c.config.ClientAuth >= RequestClientCert {
		if certMsg, ok = msg.(*certificateMsg); !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certMsg, msg)
		}
		hs.finishedHash.Write(certMsg.marshal())

		if len(certMsg.certificates) == 0 {
			// The client didn't actually send a certificate
			switch c.config.ClientAuth {
			case RequireAnyClientCert, RequireAndVerifyClientCert:
				c.sendAlert(alertBadCertificate)
				return errors.New("tls: client didn't provide a certificate")
			}
		}

		pub, err = hs.processCertsFromClient(certMsg.certificates)
		if err != nil {
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	// Get client key exchange
	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(ckx, msg)
	}
	hs.finishedHash.Write(ckx.marshal())

	preMasterSecret, err := keyAgreement.processClientKeyExchange(c.config, &hs.cert[1], ckx, c.vers)
	if err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.clientHello.random, hs.hello.random)
	if err := c.config.writeKeyLog(hs.clientHello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	// If we received a client cert in response to our certificate request message,
	// the client will send us a certificateVerifyMsg immediately after the
	// clientKeyExchangeMsg. This message is a digest of all preceding
	// handshake-layer messages that is signed using the private key corresponding
	// to the client's certificate. This allows us to verify that the client is in
	// possession of the private key of the certificate.
	if len(c.peerCertificates) > 0 {
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
		certVerify, ok := msg.(*certificateVerifyMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certVerify, msg)
		}

		// Determine the signature type.
		_, sigType, hashFunc, err := pickSignatureAlgorithm(pub, []SignatureScheme{certVerify.signatureAlgorithm}, supportedSignatureAlgorithms, c.vers)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return err
		}

		var digest []byte
		if digest, err = hs.finishedHash.hashForClientCertificate(sigType, hashFunc, hs.masterSecret); err == nil {
			err = verifyHandshakeSignature(sigType, pub, hashFunc, digest, certVerify.signature)
		}
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: could not validate signature of connection nonces: " + err.Error())
		}

		hs.finishedHash.Write(certVerify.marshal())
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *serverHandshakeStateGM) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)

	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction

	if hs.suite.aead == nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, true /* for reading */)
		clientHash = hs.suite.mac(c.vers, clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, false /* not for reading */)
		serverHash = hs.suite.mac(c.vers, serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, clientCipher, clientHash)
	c.out.prepareCipherSpec(c.vers, serverCipher, serverHash)

	return nil
}

func (hs *serverHandshakeStateGM) readFinished(out []byte) error {
	c := hs.c

	c.readRecord(recordTypeChangeCipherSpec)
	if c.in.err != nil {
		return c.in.err
	}

	if hs.hello.nextProtoNeg {
		msg, err := c.readHandshake()
		if err != nil {
			return err
		}
		nextProto, ok := msg.(*nextProtoMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(nextProto, msg)
		}
		hs.finishedHash.Write(nextProto.marshal())
		c.clientProtocol = nextProto.proto
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientFinished, msg)
	}

	verify := hs.finishedHash.clientSum(hs.masterSecret)
	if len(verify) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, clientFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: client's Finished message is incorrect")
	}

	hs.finishedHash.Write(clientFinished.marshal())
	copy(out, verify)
	return nil
}

func (hs *serverHandshakeStateGM) sendSessionTicket() error {
	if !hs.hello.ticketSupported {
		return nil
	}

	c := hs.c
	m := new(newSessionTicketMsg)

	var err error
	state := sessionState{
		vers:         c.vers,
		cipherSuite:  hs.suite.id,
		masterSecret: hs.masterSecret,
		certificates: hs.certsFromClient,
	}
	m.ticket, err = c.encryptTicket(&state)
	if err != nil {
		return err
	}

	hs.finishedHash.Write(m.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, m.marshal()); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateGM) sendFinished(out []byte) error {
	c := hs.c

	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}

	c.cipherSuite = hs.suite.id
	copy(out, finished.verifyData)

	return nil
}

// processCertsFromClient takes a chain of client certificates either from a
// Certificates message or from a sessionState and verifies them. It returns
// the public key of the leaf certificate.
func (hs *serverHandshakeStateGM) processCertsFromClient(certificates [][]byte) (crypto.PublicKey, error) {
	c := hs.c

	hs.certsFromClient = certificates
	certs := make([]*x509.Certificate, len(certificates))
	var err error
	for i, asn1Data := range certificates {
		if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, errors.New("tls: failed to parse client certificate: " + err.Error())
		}
	}

	if c.config.ClientAuth >= VerifyClientCertIfGiven && len(certs) > 0 {
		opts := x509.VerifyOptions{
			Roots:         c.config.ClientCAs,
			CurrentTime:   c.config.time(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}

		chains, err := certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, errors.New("tls: failed to verify client's certificate: " + err.Error())
		}

		c.verifiedChains = chains
	}

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, err
		}
	}

	if len(certs) == 0 {
		return nil, nil
	}

	var pub crypto.PublicKey
	switch key := certs[0].PublicKey.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, *sm2.PublicKey:
		pub = key
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return nil, fmt.Errorf("tls: client's certificate contains an unsupported public key of type %T", certs[0].PublicKey)
	}
	c.peerCertificates = certs
	return pub, nil
}

// setCipherSuite sets a cipherSuite with the given id as the serverHandshakeStateGM
// suite if that cipher suite is acceptable to use.
// It returns a bool indicating if the suite was set.
func (hs *serverHandshakeStateGM) setCipherSuite(id uint16, supportedCipherSuites []uint16, version uint16) bool {
	for _, supported := range supportedCipherSuites {
		if id == supported {
			var candidate *cipherSuite

			for _, s := range gmCipherSuites {
				if s.id == id {
					candidate = s
					break
				}
			}
			if candidate == nil {
				continue
			}
			if version < VersionTLS12 && candidate.flags&suiteTLS12 != 0 {
				continue
			}
			hs.suite = candidate
			return true
		}
	}
	return false
}

func (hs *serverHandshakeStateGM) clientHelloInfo() *ClientHelloInfo {
	if hs.cachedClientHelloInfo != nil {
		return hs.cachedClientHelloInfo
	}

	var supportedVersions []uint16
	if hs.clientHello.vers > VersionTLS12 {
		supportedVersions = suppVersArray[:]
	} else if hs.clientHello.vers >= VersionSSL30 {
		supportedVersions = suppVersArray[VersionTLS12-hs.clientHello.vers:]
	}

	hs.cachedClientHelloInfo = &ClientHelloInfo{
		CipherSuites:      hs.clientHello.cipherSuites,
		ServerName:        hs.clientHello.serverName,
		SupportedCurves:   hs.clientHello.supportedCurves,
		SupportedPoints:   hs.clientHello.supportedPoints,
		SignatureSchemes:  hs.clientHello.supportedSignatureAlgorithms,
		SupportedProtos:   hs.clientHello.alpnProtocols,
		SupportedVersions: supportedVersions,
		Conn:              hs.c.conn,
	}

	return hs.cachedClientHelloInfo
}
