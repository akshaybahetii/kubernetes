package auth

import "../claims"

type HttpTokenRequest struct {

	// AuthType is the requested identity provider to authenticate with.
	AuthType         string
	AuthHeader       string
	AuthHeadPreamble string
	WriteCookie      bool
	ContentType      string
	RequestId        string
}
type Auth interface {
	NewHttpResponseWriter(tr *HttpTokenRequest, valid claims.ClaimList) (string, error)
}
