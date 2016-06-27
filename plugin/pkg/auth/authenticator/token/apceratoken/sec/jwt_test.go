// Copyright 2015 Apcera Inc. All rights reserved.

package sec

import (
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/apcera/continuum/common/pengine"
)

func TestSignVerifyToken(t *testing.T) {
	signVerifyToken(t, P256Suite)
	signVerifyToken(t, P384Suite)
}

func signVerifyToken(t *testing.T, suite *AlgorithmSuite) {
	alicePub, alicePriv := prepareKeys(t, suite.CurveBitSize)
	bobPub, _ := prepareKeys(t, suite.CurveBitSize)
	carolPub, _ := prepareKeys(t, suite.CurveBitSize)
	davePub, _ := prepareKeys(t, suite.CurveBitSize)

	issuer := "alice"
	audiences := []string{"continuum", "foo"}

	token := &JWT{
		JWTEnvelope: JWTEnvelope{
			Type:      suite.ProofKeyType,
			Algorithm: suite.SigAlgorithm,
		},
		Issuer:    issuer,
		Audience:  audiences[0],
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		UserID:    "tester",
		ProofKey:  "fakeProofKey",
		Claims: []pengine.Claim{
			*pengine.NewClaim("test", "k1", "v1"),
			*pengine.NewClaim("test", "k2", "v2"),
			*pengine.NewClaim("alice", "k3", "v3"),
		},
	}

	signedToken, err := SignEncodeToken(token, suite, alicePriv)
	if err != nil {
		t.Fatalf("Error on SignEncodeToken: %s", err)
	}

	token.OriginalToken = signedToken

	aliceMap := map[string][]byte{"bob": bobPub, "alice": alicePub, "carol": carolPub, "dave": davePub}
	verifiedToken, err := DecodeVerifyToken(signedToken, suite, aliceMap, audiences)
	if err != nil {
		t.Fatalf("Error on DecodeVerifyToken: %s", err)
	}
	if !reflect.DeepEqual(verifiedToken, token) {
		t.Fatalf("Verified token doesn't match the original token")
	}

	if _, err := DecodeVerifyToken("foobar", suite, aliceMap, audiences); err == nil {
		t.Fatalf("Expected an error on a malformed token")
	}
	if _, err := DecodeVerifyToken(signedToken, suite, map[string][]byte{issuer: bobPub}, audiences); err == nil {
		t.Fatalf("Expected an error on a wrong pulic key")
	}
	if _, err := DecodeVerifyToken(signedToken, suite, map[string][]byte{"bob": alicePub}, audiences); err == nil {
		t.Fatalf("Expected an error on a wrong issuer")
	}
	if _, err := DecodeVerifyToken(signedToken, suite, aliceMap, audiences[1:]); err == nil {
		t.Fatalf("Expected an error on an untrusted audience")
	}

	token2 := token
	token2.ExpiresAt = time.Now().Add(-1 * time.Second).Unix()

	signedToken2, err := SignEncodeToken(token, suite, alicePriv)
	if err != nil {
		t.Fatalf("Error on SignEncodeToken: %s", err)
	}
	if _, err := DecodeVerifyToken(signedToken2, suite, aliceMap, audiences); err == nil {
		t.Fatalf("Expected an error on an expired token")
	}
}

func TestTokenClaimList(t *testing.T) {
	token := &JWT{
		JWTEnvelope: JWTEnvelope{
			Type:      "someType",
			Algorithm: "someAlgorithm",
		},
		Issuer:    "alice",
		Audience:  "bob",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		UserID:    "tester",
		ProofKey:  "fakeProofKey",
		Claims: []pengine.Claim{
			*pengine.NewClaim("test", "k1", "v1"),
			*pengine.NewClaim("alice", "k2", "v2"),
		},
	}

	expectedClaims := []*pengine.Claim{
		pengine.NewClaim("alice", "name", "tester"),
		pengine.NewClaim("test", "k1", "v1"),
		pengine.NewClaim("alice", "k2", "v2"),
		pengine.NewClaim("alice", "issued_at", strconv.FormatInt(token.IssuedAt, 10)),
		pengine.NewClaim("alice", "expires_at", strconv.FormatInt(token.ExpiresAt, 10)),
	}

	actualList := token.ClaimList()
	expectedList := pengine.ClaimList(expectedClaims)

	if !reflect.DeepEqual(actualList, expectedList) {
		t.Logf("Token claim list:    %v", actualList)
		t.Logf("Expected claim list: %v", expectedList)
		t.Fatalf("Unexpected claim list")
	}
}
