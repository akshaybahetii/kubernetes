// Copyright 2012-2015 Apcera Inc. All rights reserved.

package sec

import (
	"testing"
	"time"
)

func BenchmarkSignTokenP256(b *testing.B) {
	signBenchmark(b, P256Suite)
}

func BenchmarkSignTokenP384(b *testing.B) {
	signBenchmark(b, P384Suite)
}

func BenchmarkVerifyTokenP256(b *testing.B) {
	verifyBenchmark(b, P256Suite)
}

func BenchmarkVerifyTokenP384(b *testing.B) {
	verifyBenchmark(b, P384Suite)
}

func signBenchmark(b *testing.B, suite *AlgorithmSuite) {
	b.StopTimer()
	_, priv := prepareKeys(b, suite.CurveBitSize)
	issuer := "tester"
	audiences := []string{"test1", "test2", "test3"}

	token := &JWT{
		Issuer:    issuer,
		Audience:  audiences[0],
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		UserID:    "tester",
	}

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, err := SignEncodeToken(token, suite, priv)
		if err != nil {
			b.Fatalf("Failed to sign token: %s", err)
		}
	}
}

func verifyBenchmark(b *testing.B, suite *AlgorithmSuite) {
	b.StopTimer()
	pub, priv := prepareKeys(b, suite.CurveBitSize)
	issuer := "tester"
	audiences := []string{"test1", "test2", "test3"}
	issuerPubKeys := map[string][]byte{issuer: pub}

	token := &JWT{
		Issuer:    issuer,
		Audience:  audiences[0],
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		UserID:    "tester",
	}

	signedToken, err := SignEncodeToken(token, suite, priv)
	if err != nil {
		b.Fatalf("Failed to sign token: %s", err)
	}

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, err := DecodeVerifyToken(signedToken, suite, issuerPubKeys, audiences)
		if err != nil {
			b.Fatalf("Failed to verify token: %s", err)
		}
	}
}
