// Copyright 2015 Apcera Inc. All rights reserved.

package sec

import "testing"

func TestSignVerifyMessage(t *testing.T) {
	signVerify(t, P256Suite, P384Suite)
	signVerify(t, P384Suite, P256Suite)
}

func signVerify(t *testing.T, suite *AlgorithmSuite, altSuite *AlgorithmSuite) {
	alicePub, alicePriv := prepareKeys(t, suite.CurveBitSize)
	bobPub, _ := prepareKeys(t, suite.CurveBitSize)

	m := &Message{
		Envelope: Envelope{
			Type: "test",
			Alg:  "none",
			Enc:  "none",
		},

		Body: "message in a bottle",
	}

	sm, err := SignMessage(m, "subject", "reply", suite, alicePriv)
	if err != nil {
		t.Fatalf("Error on SignMessage: %s", err)
	}
	if _, err := SignMessage(sm, "subject", "reply", suite, alicePriv); err == nil {
		t.Fatalf("Expected an error when signing a signed message")
	}
	if _, err := VerifyMessage(sm, "subject", "reply", suite, alicePub); err != nil {
		t.Fatalf("Error on VerifyMessage: %s", err)
	}
	if _, err := VerifyMessage(sm, "subject", "reply", suite, alicePub); err != nil {
		t.Fatalf("Error on second VerifyMessage: %s", err)
	}
	if _, err := VerifyMessage(sm, "subject", "badreply", suite, alicePub); err == nil {
		t.Fatalf("VerifyMessage didn't fail with a different reply")
	}
	if _, err := VerifyMessage(sm, "badsubject", "reply", suite, alicePub); err == nil {
		t.Fatalf("VerifyMessage didn't fail with a different subject")
	}
	if _, err := VerifyMessage(sm, "subject", "reply", suite, bobPub); err == nil {
		t.Fatalf("VerifyMessage didn't fail with a different public key")
	}
	if _, err := VerifyMessage(sm, "subject", "reply", altSuite, alicePub); err == nil {
		t.Fatalf("VerifyMessage didn't fail with a different algorithm suite")
	}

	// Tampering with the envelope.
	m1 := sm
	m1.Alg = "foo"
	if _, err := VerifyMessage(m1, "subject", "reply", suite, alicePub); err == nil {
		t.Fatalf("VerifyMessage didn't fail when message envelope was tampered with")
	}

	// Tampering with the body.
	m2 := sm
	m2.Body = "test"
	if _, err := VerifyMessage(m2, "subject", "reply", suite, alicePub); err == nil {
		t.Fatalf("VerifyMessage didn't fail when message body was tampered with")
	}

	// Tampering with the signature.
	m3 := sm
	m3.Sig = "bar"
	if _, err := VerifyMessage(m3, "subject", "reply", suite, alicePub); err == nil {
		t.Fatalf("VerifyMessage didn't fail when signature was tampered with")
	}
}

func TestMessageEncryptDecrypt(t *testing.T) {
	encryptDecrypt(t, P256Suite, P384Suite)
	encryptDecrypt(t, P384Suite, P256Suite)
}

func encryptDecrypt(t *testing.T, suite *AlgorithmSuite, altSuite *AlgorithmSuite) {
	_, alicePriv := prepareKeys(t, suite.CurveBitSize)
	bobPub, bobPriv := prepareKeys(t, suite.CurveBitSize)
	plainText := "message in a bottle"

	m := &Message{
		Envelope: Envelope{
			Type:       "test-enc",
			SenderID:   "alice",
			ReceiverID: "bob",
		},
		Body: plainText,
	}

	em, err := EncryptMessage(m, "subject", "reply", suite, bobPub)
	if err != nil {
		t.Fatalf("Error on EncryptMessage: %s", err)
	}

	dm, err := DecryptMessage(em, "subject", "reply", suite, bobPriv)
	if err != nil {
		t.Fatalf("Error on DecryptMessage: %s", err)
	}

	if dm.Body != plainText {
		t.Fatalf("Decrypted message body %q doesn't match plain text %q", dm.Body, plainText)
	}

	// Decrypt can be called multiple times on the same message with
	// the same result.
	dm2, err := DecryptMessage(em, "subject", "reply", suite, bobPriv)
	if err != nil {
		t.Fatalf("Error on second DecryptMessage: %s", err)
	}
	if dm2.Body != plainText {
		t.Fatalf("On second DecryptMessage, recovered text %q doesn't match plain text %q", dm2.Body, plainText)
	}

	if _, err := DecryptMessage(em, "subject", "badreply", suite, bobPriv); err == nil {
		t.Fatalf("DecryptMessage didn't fail with a different reply")
	}
	if _, err := DecryptMessage(em, "badsubject", "reply", suite, bobPriv); err == nil {
		t.Fatalf("DecryptMessage didn't fail with a different subject")
	}
	if _, err := DecryptMessage(em, "subject", "reply", suite, alicePriv); err == nil {
		t.Fatalf("DecryptMessage didn't fail with a different private key")
	}
	if _, err := DecryptMessage(em, "subject", "reply", altSuite, bobPriv); err == nil {
		t.Fatalf("DecryptMessage didn't fail with a different algorithm suite")
	}

	// Tampering with the envelope.
	em1 := em
	em1.SenderID = "mallory"
	if _, err := DecryptMessage(em1, "subject", "reply", suite, bobPriv); err == nil {
		t.Fatalf("DecryptMessage didn't fail when message envelope was tampered with")
	}

	// Tampering with the encryption details.
	em2 := em
	em2.Tag = base64Encode([]byte("bad-tag"))
	if _, err := DecryptMessage(em2, "subject", "reply", suite, bobPriv); err == nil {
		t.Fatalf("DecryptMessage didn't fail when encryption details were tampered with")
	}

	// Tampering with the message body.
	em3 := em
	em3.Body = base64Encode([]byte("body of lies"))
	if _, err := DecryptMessage(em3, "subject", "reply", suite, bobPriv); err == nil {
		t.Fatalf("DecryptMessage didn't fail when message body was tampered with")
	}
}

func TestEncryptSignVerifyDecrypt(t *testing.T) {
	encryptSignVerifyDecrypt(t, P256Suite)
	encryptSignVerifyDecrypt(t, P384Suite)
}

func encryptSignVerifyDecrypt(t *testing.T, suite *AlgorithmSuite) {
	alicePub, alicePriv := prepareKeys(t, suite.CurveBitSize)
	bobPub, bobPriv := prepareKeys(t, suite.CurveBitSize)

	plainText := "message in a bottle"

	m := &Message{}
	m.SenderID = "alice"
	m.ReceiverID = "bob"
	m.Body = plainText

	em, err := EncryptMessage(m, "subject", "reply", suite, bobPub)
	if err != nil {
		t.Fatalf("Error on EncryptMessage: %s", err)
	}

	sem, err := SignMessage(em, "subject", "reply", suite, alicePriv)
	if err != nil {
		t.Fatalf("Error on SignMessage: %s", err)
	}

	if _, err := VerifyMessage(sem, "subject", "reply", suite, alicePub); err != nil {
		t.Fatalf("Error on VerifyMessage: %s", err)
	}

	dm, err := DecryptMessage(sem, "subject", "reply", suite, bobPriv)
	if err != nil {
		t.Fatalf("Error on DecryptMessage: %s", err)
	}

	if dm.Body != plainText {
		t.Fatalf("Recovered text %q doesn't match plain text %q", dm.Body, plainText)
	}
}
