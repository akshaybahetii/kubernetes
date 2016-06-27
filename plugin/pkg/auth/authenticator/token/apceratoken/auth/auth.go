package auth

import (
	"net/http"

	"./../claims"
)

type Auth interface {
	NewHttpResponseWriter(tr *http.Request, valid claims.ClaimList) (string, error)
}
