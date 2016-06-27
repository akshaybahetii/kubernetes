// Copyright 2015 Apcera Inc. All rights reserved.

package sec

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/apcera/gossl"
)

// See http://goo.gl/7bRgZ for more details.
// TODO(oleg): update comments/documentation.

// There are two types of component interactions over NATS in
// Continuum:

// 1. Requesting a token from auth server.
// 2. Sending a message to another component.

// #2 requires having a token obtained from auth server as a result of
// #1. The flow for #1 and #2 is slightly different and it's handled
// by different functions in this package. Message and security
// envelope data structures are shared between #1 and #2 but some
// fields only make sense for one of them.

// Message is a data structure used to transfer a message along with
// the metadata about its security parameters (encryption/signature
// etc).
type Message struct {
	Envelope `json:"Sec"`

	// Body is a message body. Can be base64-encoded encrypted
	// payload, plain text payload, or an error message, depending on
	// the value of Sec.Type.
	Body string `json:"Body"`
}

// Envelope is a message security envelope. It contains details about
// message encryption (if any), message signature and other metadata
// required to securely transmit messages between Continuum
// components.
type Envelope struct {
	// Type is a message type.
	Type string `json:"typ"`

	// Alg is an algorithm name used for key exchange if the message
	// is encrypted.
	Alg string `json:"alg,omitempty"`

	// Enc is an algorithm used to encrypt the message.
	Enc string `json:"enc,omitempty"`

	// Epk is an ephemeral public key that can be used by the
	// recipient to generate a shared secret for message decryption
	// (required by 1-pass ECDH). Must be base64-encoded (URL
	// encoding) with padding removed.
	Epk string `json:"epk,omitempty"`

	// SenderID identifies the sender of the message. Currently
	// only used for the token request flow.
	SenderID string `json:"apu,omitempty"`

	// ReceiverID identifies the receiver of the message. Currently
	// only used for the token request flow.
	ReceiverID string `json:"apv,omitempty"`

	// Subject is a message subject. Needed for message integrity
	// calculations but doesn't get transmitted over the wire.
	Subject string `json:"subj,omitempty"`

	// Reply is a messsage reply inbox name. Needed for message integrity
	// calculations but doesn't get transmitted over the wire.
	Reply string `json:"repl,omitempty"`

	// InitVect is a random string used as initialization vector for
	// message encryption. Must be base64-encoded (URL encoding) with
	// padding removed.
	InitVect string `json:"iv,omitempty"`

	// Tag is a message integrity tag (only for encrypted messages).
	// Must be base64-encoded (URL encoding) with padding removed.
	Tag string `json:"tag,omitempty"`

	// Token is an encoded JWT. Used for component-to-component
	// interactions: recipient must validate that this token is valid
	// and signed by a known authority (auth server) in order to trust
	// that message actually came in from the sender.
	Token string `json:"tok,omitempty"`

	// OnBehalfOf is an encoded JWT. It is optional: if present,
	// message is being delivered on behalf of the that user. This
	// original user identity can be used instead of the identity
	// present in Token field. Note that any message recipient can
	// copy OnBehalfOf into its own message without an explicit
	// permission of any third party. E.g. if you send a message on
	// behalf of someone, any recipient can continue acting on behalf
	// of that someone. You still need to be a party known to auth
	// server: basically this implies all Continuum components can act
	// on behalf of any user as long as this user obtained a token
	// from auth server at some point and provided this token to API
	// server as a part of API request.
	OnBehalfOf string `json:"obo,omitempty"`

	// MsgID is an opaque message ID that can be used for replay
	// protection. Senders must use unique message IDs for all
	// messages. Recipients should reject any messages ID they've
	// already seen. Currently it's not used, and messages can be
	// replayed.
	MsgID string `json:"msgid,omitempty"`

	// Sig is a message signature. Sender signs message before sending
	// it, receiver must only act on the message if the signature is
	// valid. One notable exception is a token request message: the
	// message itself is not signed but contains a signed token in an
	// encrypted message body. Must be base64-encoded (URL encoding)
	// with padding removed.
	Sig string `json:"sig,omitempty"`
}

// TokenResponse is returned by the token issuer when it successfully
// issues a token to the requester. It can handle multiple token
// types. Token itself is returned as an opaque string.
type TokenResponse struct {
	// TokenType is the type of token issued by auth server.
	TokenType string `json:"token_type,omitempty"`

	// AccessToken is the issued token.
	AccessToken string `json:"access_token,omitempty"`

	// ExpiresIn is the stringified remaining lifetime of the token.
	ExpiresIn string `json:"expires_in,omitempty"`
}

// SignMessage signs a message with a sender private key. The original
// message is not modified, the signed copy is returned.
func SignMessage(
	m *Message,
	subject, reply string,
	suite *AlgorithmSuite,
	senderPrivKeyBytes []byte,
) (*Message, error) {
	if m.Sig != "" {
		return nil, errors.New("message is already signed")
	}

	authData, err := m.sigAuthData(subject, reply)
	if err != nil {
		return nil, err
	}

	senderPrivKey, err := ecPrivKey(suite.CurveBitSize, senderPrivKeyBytes)
	if err != nil {
		return nil, err
	}

	sig, err := signBytes(suite.DigestBitSize, authData, senderPrivKey)
	if err != nil {
		return nil, err
	}

	signedMsg := *m
	signedMsg.Sig = base64Encode(sig)

	return &signedMsg, nil
}

// VerifyMessage verifies message signature with a given public
// key. The original message is unmodified, the copy is returned with
// its signature cleared.
func VerifyMessage(
	m *Message,
	subject, reply string,
	suite *AlgorithmSuite,
	senderPubKeyBytes []byte,
) (*Message, error) {
	if m.Sig == "" {
		return nil, errors.New("message is not signed")
	}

	sig, err := base64Decode(m.Sig)
	if err != nil {
		return nil, err
	}

	authData, err := m.sigAuthData(subject, reply)
	if err != nil {
		return nil, err
	}

	senderPubKey, err := ecPubKey(suite.CurveBitSize, senderPubKeyBytes)
	if err != nil {
		return nil, err
	}

	if err := verifyBytes(suite.DigestBitSize, authData, sig, senderPubKey); err != nil {
		return nil, err
	}

	mc := *m
	mc.Sig = ""

	return &mc, nil
}

// EncryptMessage returns a new message with the body encrypted by a
// given public key. The original message is not modified, the
// encrypted message is returned.
func EncryptMessage(
	m *Message,
	subject, reply string,
	suite *AlgorithmSuite,
	receiverPubKeyBytes []byte,
) (*Message, error) {

	if m.Alg != "" || m.Enc != "" {
		return nil, errors.New("message is already encrypted")
	}

	if m.SenderID == "" {
		return nil, errors.New("sender ID is missing")
	}

	if m.ReceiverID == "" {
		return nil, errors.New("receiver ID is missing")
	}

	receiverPubKey, err := ecPubKey(suite.CurveBitSize, receiverPubKeyBytes)
	if err != nil {
		return nil, err
	}

	encryptedMsg := *m

	encryptedMsg.Alg = suite.KeyExchangeAlgorithm
	encryptedMsg.Enc = suite.EncAlgorithm

	ephKey, err := gossl.NewECKey(suite.CurveBitSize)
	if err != nil {
		return nil, err
	}
	defer ephKey.Free()

	if err := ephKey.Generate(); err != nil {
		return nil, err
	}

	ephPubKey, err := ephKey.PubKey()
	if err != nil {
		return nil, err
	}

	encryptedMsg.Epk = base64Encode(ephPubKey)

	aad, err := encryptedMsg.encAuthData(subject, reply)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, suite.IVSizeBytes)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	cipherText, tag, err := encryptBytes(suite.EncKeyBitSize, suite.DigestBitSize,
		[]byte(m.Body), iv, aad, receiverPubKey, ephKey, m.SenderID, m.ReceiverID)
	if err != nil {
		return nil, err
	}

	encryptedMsg.InitVect = base64Encode(iv)
	encryptedMsg.Tag = base64Encode(tag)
	encryptedMsg.Body = base64Encode(cipherText)

	return &encryptedMsg, nil
}

// DecryptMessage decrypts a message with a given private key. The
// original message is not modified. The resulting message is stripped
// of any metadata related to encryption and has the recovered plain text
// as its body.
func DecryptMessage(
	m *Message,
	subject, reply string,
	suite *AlgorithmSuite,
	receiverPrivKeyBytes []byte,
) (*Message, error) {

	if m.Enc == "" {
		return nil, errors.New("message is not encrypted")
	}

	if m.SenderID == "" {
		return nil, errors.New("sender ID is missing")
	}

	if m.ReceiverID == "" {
		return nil, errors.New("receiver ID is missing")
	}

	if m.Alg != suite.KeyExchangeAlgorithm {
		return nil, fmt.Errorf("unsupported key exchange algorithm %q", m.Alg)
	}
	if m.Enc != suite.EncAlgorithm {
		return nil, fmt.Errorf("unsupported encryption algorithm %q", m.Enc)
	}

	receiverPrivKey, err := ecPrivKey(suite.CurveBitSize, receiverPrivKeyBytes)
	if err != nil {
		return nil, err
	}

	epk, err := base64Decode(m.Epk)
	if err != nil {
		return nil, err
	}

	tag, err := base64Decode(m.Tag)
	if err != nil {
		return nil, err
	}

	iv, err := base64Decode(m.InitVect)
	if err != nil {
		return nil, err
	}

	aad, err := m.encAuthData(subject, reply)
	if err != nil {
		return nil, err
	}

	cipherText, err := base64Decode(m.Body)
	if err != nil {
		return nil, err
	}

	ephKey, err := gossl.NewECKey(suite.CurveBitSize)
	if err != nil {
		return nil, err
	}
	defer ephKey.Free()

	if err := ephKey.Generate(); err != nil {
		return nil, err
	}

	if err := ephKey.SetPubKey(epk); err != nil {
		return nil, err
	}

	plainText, err := decryptBytes(suite.EncKeyBitSize, suite.DigestBitSize, cipherText, iv, aad, tag,
		receiverPrivKey, ephKey, m.SenderID, m.ReceiverID)

	if err != nil {
		return nil, err
	}

	if len(plainText) == 0 {
		// This usually means that message has been tampered with: in
		// that case decryptBytes returns no error and empty
		// plaintext.
		return nil, errors.New("no plaintext recovered")
	}

	mc := *m
	mc.Body = string(plainText)
	mc.Epk = ""
	mc.Tag = ""
	mc.InitVect = ""

	return &mc, nil
}

// sigAuthData returns a blob of bytes that is used as a base
// for message signature. Signature is calculated over these bytes, so
// if anything in the message is changed, it is considered
// tampered with only if it was included into authenticatedData.
func (m *Message) sigAuthData(subject, reply string) ([]byte, error) {
	basePayload := &Message{
		Envelope: Envelope{
			// Copied from the original envelope.
			Type:       m.Type,
			Alg:        m.Alg,
			Enc:        m.Enc,
			Epk:        m.Epk,
			SenderID:   m.SenderID,
			ReceiverID: m.ReceiverID,
			InitVect:   m.InitVect,
			Tag:        m.Tag,
			Token:      m.Token,
			OnBehalfOf: m.OnBehalfOf,
			MsgID:      m.MsgID,

			// Set externally (as we don't send them over the wire).
			Subject: subject,
			Reply:   reply,

			// Values below are default but it's worth explicitly placing
			// them here to show that we don't include them into
			// authenticated data calculations.
			Sig: "",
		},
		Body: m.Body,
	}

	// TODO(oleg): we should not use JSON here, it's not stable across
	// different implementations. This would require the router change
	// though.
	return json.Marshal(basePayload)
}

// encAuthData returns a blob of bytes that is used as a base for the
// message Additional Authenticated data. It's used as one of the
// inputs for AES-GCM encryption and acts as message integrity check.
func (m *Message) encAuthData(subject, reply string) ([]byte, error) {
	basePayload := &Envelope{
		// Copied from the original envelope.
		Type:       m.Type,
		Alg:        m.Alg,
		Enc:        m.Enc,
		Epk:        m.Epk,
		SenderID:   m.SenderID,
		ReceiverID: m.ReceiverID,
		Token:      m.Token,
		OnBehalfOf: m.OnBehalfOf,
		MsgID:      m.MsgID,

		// Set externally (as we don't send them over the wire).
		Subject: subject,
		Reply:   reply,

		// Values below are default but it's worth explicitly placing
		// them here to show that we don't include them into
		// authenticated data calculations.
		InitVect: "",
		Tag:      "",
		Sig:      "",
	}

	// TODO(oleg): we should not use JSON here, it's not stable across
	// different implementations. This would require the router change
	// though.
	return json.Marshal(basePayload)
}
