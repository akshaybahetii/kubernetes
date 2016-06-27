// Copyright 2012-2014 Apcera Inc. All rights reserved.

// Package Jwt provides primitives for creating, signing, encrypting, decrypting,
// encoding, decoding, and validating JSON web tokens. Internally, Jwt relies upon
// OpenSSL ECC support.
//
// For more, see github.com/apcera/continuum/common/jwt/doc.go
package sec

// An OAuth2SuccessResponse is returned by the auth server after a successful
// authentication attempt.
// Defined by: https://tools.ietf.org/html/rfc6749#section-5.1
type OAuth2SuccessResponse struct {
	// AccessToken is the issued token, signed and base 64 encoded.
	AccessToken string `json:"access_token,omitempty"`

	// TokenType indicates the type of token issued by the auth server. e.g.,
	// this field is different when returning an HTTP token to the user vs a new
	// nats token.
	TokenType string `json:"token_type,omitempty"`

	// ExpiresIn is the string-ified remaining lifetime of the token.
	ExpiresIn string `json:"expires_in,omitempty"`

	// RefreshToken is an extension of the success response that allows us to
	// return a Google refresh token.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Message is a message to display when returning the success response; its
	// presence is optional, and it is our extension.
	Message string `json:"message,omitempty"`
}
