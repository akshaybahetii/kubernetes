package connector

import (
	"fmt"
	"net/http"

	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/auth"
	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/claims"
)

//LDAPConnector struct {
type LDAPConnector struct {
	authServer auth.Auth

	IDName               string `json:"id"`
	UseSSL               bool   `json:"useSSL"`
	SkipCertVerification bool   `json:"skipCertVerification"`
	BaseDN               string `json:"baseDN"`
	NameAttribute        string `json:"nameAttribute"`
	EmailAttribute       string `json:"emailAttribute"`
	SearchBeforeAuth     bool   `json:"searchBeforeAuth"`
	SearchFilter         string `json:"searchFilter"`
	SearchScope          string `json:"searchScope"`
	SearchBindDN         string `json:"searchBindDN"`
	SearchBindPw         string `json:"searchBindPw"`
}

func (LDAPCtr *LDAPConnector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Attempting LDAP login")

	//httpTokenRequestHandler. Present continuum/common/auth.
	//Validate the requets. Then perform LDAP Login check.

	claimList := []*claims.Claim{claims.NewClaim("AUTH", "AUTH_TYPE", "LDAP_BASIC"), claims.NewClaim("AUTH", "USERNAME", "AKSHAY")}

	// Once Login success and Claimlist generate.
	// Call httpResponseWriter from common/auth. It return's the token.
	token, _ := LDAPCtr.authServer.NewHttpResponseWriter(r, claimList)

	w.Write(token)
	return

}

//Setup configures connetor with config file parametes.
func (LDAPCtr *LDAPConnector) Setup(authServer auth.Auth) {
	//Save the auth interface for the auth-server in the connector.
	LDAPCtr.authServer = authServer
}
