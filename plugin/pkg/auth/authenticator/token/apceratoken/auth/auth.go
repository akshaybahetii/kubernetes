package auth

import (
	"net/http"

	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/claims"
)

type Auth interface {
	NewHttpResponseWriter(tr *http.Request, valid claims.ClaimList) (string, error)
}
