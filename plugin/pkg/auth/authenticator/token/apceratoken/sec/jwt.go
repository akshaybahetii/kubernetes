// Copyright 2012-2015 Apcera Inc. All rights reserved.

package sec

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/claims"
)

// TokenTimeSkew is applied to token issuance time in order to
// compensate for potential clock skew between sender and receiver.
const TokenTimeSkew = -10 * time.Second

// TokenLifetime is a default lifetime of tokens issued to Continuum
// components.
const TokenLifetime = 3600 * time.Second

// JWT is a Json Web Token that is used for authentication within Continuum.
// Maps relatively closely to the Json Web Token and related specification in
// RFC draft form.
//
// Current draft: https://tools.ietf.org/html/draft-ietf-oauth-json-web-token
//
// Note: our implementation of JWT and JWTEnvelope generally conform
// to revision 31 of the JWT draft above.
type JWT struct {
	JWTEnvelope `json:"-"`

	// OriginalToken is an original token that's been parsed into this
	// JWT object. For manually constructed tokens it contains an
	// empty string.
	OriginalToken string `json:"-"`

	// Issuer is the entity that issued the token; generally, the auth
	// server.
	Issuer string `json:"iss"`

	// Audience defined the intended recipient or a group of
	// recipients of this JWT.
	Audience string `json:"aud"`

	// IssuedAt is the UNIX timestamp at which the token was issued.
	IssuedAt int64 `json:"iat"`

	// ExpiresAt is the UNIX timestapm time at which the token
	// expires.
	ExpiresAt int64 `json:"exp"`

	// UserID is the identifier of the user or component who holds the
	// token.
	UserID string `json:"prn,omitempty"`

	// ProofKey is a public key of the token holder. Token issuer has
	// been given a proof that this key really belongs to the token
	// holder before the token has been issued (by verifying that the
	// token request was signed by the private key corresponding to
	// this public key). If message receiver trusts the token issuer,
	// it can use this proof key to verify messages signed by this
	// key. Key must be base64-encoded (URL encoding) with padding
	// removed.
	ProofKey string `json:"pkey,omitempty"`

	// Claims are the claims minted on the token. These may indicate
	// auth type, policy roles, and other information.
	Claims []claims.Claim `json:"claims,omitempty"`
}

// JWTEnvelope denotes the encryption algorithm used to encode a
// token. It maps closely to the JOSE encryption standard.
//
// Current draft:
// https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-37
// https://tools.ietf.org/html/draft-ietf-jose-json-web-signature
type JWTEnvelope struct {
	// Type denotes the MIME media type of the envelope. Typical
	// values: 'JWT', 'JWT-PK-ES256', 'JWT-PK-ES384'.
	Type string `json:"typ"`

	// Algorithm identifies the cryptographic algorithm used to secure
	// the JWT.
	Algorithm string `json:"alg"`

	// Encryption identifies the algorithm used to encrypt JWT.
	Encryption string `json:"enc,omitempty"`
}

// effectiveClaimIssuer will substitute auth_server@apcera.me for all of the
// auth modules. This allows consistency in policy.
// NOTE(michael): this approach is temporary until a method that includes all
// necessary values in the token is created (such as using the Type value
// to determine the required keys to use for validation.
func effectiveClaimIssuer(iss string) string {
	return "KUBERNETES_AUTH_SERVER"
}

// ClaimList returns a list of claims defined on the token. In
// addition to claims copied from the token, additional claims are
// synthesized for token user id and other metadata.
func (j *JWT) ClaimList() claims.ClaimList {
	issuer := effectiveClaimIssuer(j.Issuer)

	claimList := claims.ClaimList{}
	claimList = append(claimList, claims.NewClaim(issuer, "TODO_NAME_CLAIM", j.UserID))

	for i := range j.Claims {
		claimList = append(claimList, &j.Claims[i])
	}

	claimList = append(claimList,
		claims.NewClaim(issuer, "issued_at", strconv.FormatInt(j.IssuedAt, 10)),
		claims.NewClaim(issuer, "expires_at", strconv.FormatInt(j.ExpiresAt, 10)))

	return claimList
}

// Token request/response.

// TODO(oleg): https://apcera.atlassian.net/browse/ENGT-376
// (json.Marshal might not be stable enough for signature/AAD
// calculations).

// SignEncodeToken returns an encoded representation of a JWT signed
// by the issuer private key.
func SignEncodeToken(token *JWT, suite *AlgorithmSuite, issuerPrivKeyBytes []byte) (string, error) {
	tokenEnvelopeBytes, err := json.Marshal(token.JWTEnvelope)
	if err != nil {
		return "", err
	}

	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	encodedToken := base64Encode(tokenEnvelopeBytes) + "." + base64Encode(tokenBytes)

	issuerPrivKey, err := ecPrivKey(suite.CurveBitSize, issuerPrivKeyBytes)
	if err != nil {
		return "", err
	}

	tokenSigBytes, err := signBytes(suite.DigestBitSize, []byte(encodedToken), issuerPrivKey)
	if err != nil {
		return "", err
	}

	return encodedToken + "." + base64Encode(tokenSigBytes), nil
}

// A TokenError is an error encountered during the verification of a token.
// TokenError messages should only be returned for errors that are safe to
// reveal; i.e. for expired tokens.
type TokenError struct {
	Message string
}

func (d *TokenError) Error() string {
	return d.Message
}

// DecodeVerifyToken decodes the encoded token, verifies its signature
// with an issuer public key and returns the extracted token. It takes
// a list of issuer keys from which it will determine the issuer of,
// and validate, the token.
func DecodeVerifyToken(
	encodedToken string,
	suite *AlgorithmSuite,
	pubKeys map[string][]byte,
	trustedAudiences []string,
) (*JWT, error) {

	lastDotPos := strings.LastIndex(encodedToken, ".")
	firstDotPos := strings.Index(encodedToken, ".")

	if lastDotPos <= firstDotPos {
		return nil, errors.New("malformed token")
	}

	if len(pubKeys) == 0 {
		return nil, errors.New("no public keys defined")
	}

	sig, err := base64Decode(encodedToken[lastDotPos+1:])
	if err != nil {
		return nil, err
	}

	sigPayload := encodedToken[0:lastDotPos]

	envBytes, err := base64Decode(encodedToken[0:firstDotPos])
	if err != nil {
		return nil, err
	}

	tokenBytes, err := base64Decode(encodedToken[firstDotPos+1 : lastDotPos])
	if err != nil {
		return nil, err
	}

	var token *JWT
	if err := json.Unmarshal(tokenBytes, &token); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(envBytes, &token.JWTEnvelope); err != nil {
		return nil, err
	}

	issuerPubKeyBytes := pubKeys[token.Issuer]
	if len(issuerPubKeyBytes) == 0 {
		return nil, &TokenError{fmt.Sprintf("token issued by an untrusted issuer %q", token.Issuer)}
	}

	issuerPubKey, err := ecPubKey(suite.CurveBitSize, issuerPubKeyBytes)
	if err != nil {
		return nil, err
	}

	if err := verifyBytes(suite.DigestBitSize, []byte(sigPayload), sig, issuerPubKey); err != nil {
		return nil, err
	}

	trusted := false
	for _, trustedAudience := range trustedAudiences {
		if token.Audience == trustedAudience {
			trusted = true
			break
		}
	}

	if !trusted {
		return nil, &TokenError{fmt.Sprintf("token audience %q is not trusted", token.Audience)}
	}

	if token.ExpiresAt < time.Now().Unix() {
		return nil, &TokenError{"token has expired"}
	}

	token.OriginalToken = encodedToken

	return token, nil
}
