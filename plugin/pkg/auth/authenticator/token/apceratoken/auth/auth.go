package auth

import (
	"net/http"

	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/claims"
)

type Auth interface {
	//Function given a claimlist creates a token with the auth server's signature.
	NewHttpResponseWriter(tr *http.Request, valid claims.ClaimList) ([]byte, error)
}
