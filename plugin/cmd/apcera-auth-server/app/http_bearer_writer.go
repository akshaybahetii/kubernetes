// Copyright 2012-2015 Apcera Inc. All rights reserved.

package app

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/claims"
	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/sec"
)

const CLUSTER_NAME = "apcera.me"
const TYP_BEARER = "JWT"

// HttpBearerES256 responds to the HTTP token request with a new token
// signed by auth server.
func (s *AuthServer) httpBearerES256(tr *http.Request, valid claims.ClaimList) ([]byte, error) {
	token := &sec.JWT{
		Issuer:   "PrincipalName",
		Audience: CLUSTER_NAME,
		IssuedAt: time.Now().Add(sec.TokenTimeSkew).Unix(),
	}

	//TODO Akshay add config param for token expiration.
	token.ExpiresAt = time.Now().Add(time.Duration(s.tokenExp*60) * time.Second).Unix()
	for i := range valid {
		token.Claims = append(token.Claims, *valid[i])

	}

	signedToken, err := sec.SignEncodeToken(token, s.suite, s.privKey)
	if err != nil {
		return nil, err
	}

	// generate the response message, return it to caller
	response := sec.OAuth2SuccessResponse{}
	response.AccessToken = signedToken
	response.TokenType = TYP_BEARER

	// the value in SuccessResponse must be close to the remaining
	// lifetime of the token. Get local Now in seconds. Subtract unix time
	// in the token (seconds)
	now := time.Now()
	nowUnix := now.Unix()
	// set the remaining lifetime in the response parameter
	response.ExpiresIn = strconv.FormatInt(token.ExpiresAt-nowUnix, 10)

	return json.Marshal(response)
}
