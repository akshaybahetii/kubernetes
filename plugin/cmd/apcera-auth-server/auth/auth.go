package auth

import "../claims"
import "net/http"

type Auth interface {
	NewHttpResponseWriter(tr *http.Request, valid claims.ClaimList) (string, error)
}
