// Copyright 2012-2015 Apcera Inc. All rights reserved.

package app

import (
	"fmt"
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
func (s *AuthServer) httpBearerES256(tr *http.Request, valid claims.ClaimList) (string, error) {
	token := &sec.JWT{
		Issuer:   "PrincipalName",
		Audience: CLUSTER_NAME,
		IssuedAt: time.Now().Add(sec.TokenTimeSkew).Unix(),
	}
	/*	token, err := a.addLDAPInfoToToken(token, valid)
		erver.Requestgithub.com/apcera/continuum/api_server/converter"
			if err != nil {
				return tr.Req.NewFatalServerError("Failed to add LDAP related information to token: %s", err)
			}

			token, err = a.AddNameToToken(tr.Req.LogContext(), httpOAuth2Realm, token, valid)
			if err != nil {
				tr.Log.Errorf("Can't add name to token: %s", err)
				return tr.Req.NewFatalServerError("Failed to add name to token: %s", err)
			}
			token, err = a.addAuthTypeToToken(token, valid)
			if err != nil {
				tr.Log.Errorf("Can't add auth_type to token: %s", err)
				return tr.Req.NewFatalServerError("Failed to add auth type to token: %s", err)
			}

			exp, err := a.GetExpirationTime(httpOAuth2Realm, token)
			if err != nil {
				tr.Log.Error(err)
				return tr.Req.NewFatalServerError("Failed to retrieve expiration time from policy: %s", err)
			}
			token.ExpiresAt = exp
	*/
	for i := range valid {
		token.Claims = append(token.Claims, *valid[i])

	}

	signedToken, err := sec.SignEncodeToken(token, s.suite, s.privKey)
	if err != nil {
		return "", err
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

	return fmt.Sprintf("%q", response), nil
}
