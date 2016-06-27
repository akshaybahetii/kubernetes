// Copyright 2015 Apcera Inc. All rights reserved.

package sec

// AlgorithmSuite describes parameters used by Continuum components to
// secure their communication. Components using the same suite to pick
// key/digest sizes and algorithms should be able to talk to each
// other.
type AlgorithmSuite struct {
	Name string

	CurveBitSize  int
	DigestBitSize int
	EncKeyBitSize int

	SigAlgorithm string
	EncAlgorithm string

	KeyExchangeAlgorithm string

	ProofKeyType string
	PrivCredType string
	PubCredType  string

	IVSizeBytes int
}

// P256Suite is based on 256-bit EC (per NSA Suite B).
var P256Suite = &AlgorithmSuite{
	Name: "ES256|ECDH-ES|A128GCM|JWT-PK-ES256",

	CurveBitSize:  256,
	DigestBitSize: 256,
	EncKeyBitSize: 128,

	SigAlgorithm: "ES256",
	EncAlgorithm: "A128GCM",

	KeyExchangeAlgorithm: "ECDH-ES",

	ProofKeyType: "JWT-PK-ES256",
	PrivCredType: "eccp256priv",
	PubCredType:  "eccp256pub",

	IVSizeBytes: 12,
}

// P384Suite is based on 384-bit EC (per NSA Suite B).
var P384Suite = &AlgorithmSuite{
	Name: "ES384|ECDH-ES|A256GCM|JWT-PK-ES384",

	CurveBitSize:  384,
	DigestBitSize: 384,
	EncKeyBitSize: 256,

	SigAlgorithm: "ES384",
	EncAlgorithm: "A256GCM",

	KeyExchangeAlgorithm: "ECDH-ES",

	ProofKeyType: "JWT-PK-ES384",
	PrivCredType: "eccp384priv",
	PubCredType:  "eccp384pub",

	IVSizeBytes: 12,
}
