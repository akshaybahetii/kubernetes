package connector

import (
	"fmt"
	"io"
	"net/http"

	"./../auth"
	"./../claims"
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

//ID returns the ID of the ConnectorConfig used to create the Connector.
func (LDAPCtr *LDAPConnector) ID() string {
	return "LDAP"
}

//Login returns if authorization was sucess and claim list.
func (LDAPCtr *LDAPConnector) Login(r *http.Request) (bool, error, []*claims.Claim) {
	fmt.Printf("Attempting LDAP login")
	claimList := []*claims.Claim{claims.NewClaim("AUTH", "AUTH_TYPE", "LDAP_BASIC"), claims.NewClaim("AUTH", "USERNAME", "AKSHAY")}

	//	username, password, _ := r.BasicAuth()
	return true, nil, claimList
}

func (LDAPCtr *LDAPConnector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Attempting LDAP login")

	//httpTokenRequestHandler. Present continuum/common/auth.
	//Validate the requets. Then perform LDAP Login check.

	claimList := []*claims.Claim{claims.NewClaim("AUTH", "AUTH_TYPE", "LDAP_BASIC"), claims.NewClaim("AUTH", "USERNAME", "AKSHAY")}

	// Once Login success and Claimlist generate.
	// Call httpResponseWriter from common/auth. It return's the token.
	fmt.Printf("test \n\n\n")
	token, _ := LDAPCtr.authServer.NewHttpResponseWriter(r, claimList)

	fmt.Printf("The token is [%s]", token)
	io.WriteString(w, token)
	return

}

//Setup configures connetor with config file parametes.
func (LDAPCtr *LDAPConnector) Setup(authServer auth.Auth) {
	LDAPCtr.authServer = authServer

	str, _ := LDAPCtr.authServer.NewHttpResponseWriter(nil, nil)
	fmt.Printf("hey in setup  %s", str)
}
