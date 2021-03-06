package connector

import (
	"fmt"
	"io"
	"net/http"

	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/auth"
	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/claims"
)

//LDAPConnector struct {
type BasicConnector struct {
	authServer auth.Auth

	IDName string `json:"id"`
}

type basicHandler struct{}

func (*basicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Attempting Basic login")

	//httpTokenRequestHandler. Present continuum/common/auth.
	//Validate the requets. Then perform Basic Login check.

	claimList := []*claims.Claim{claims.NewClaim("AUTH", "AUTH_TYPE", "BASIC"), claims.NewClaim("AUTH", "USERNAME", "AKSHAY")}

	username, password, _ := r.BasicAuth()
	fmt.Println("LDAP Login attempted.", claimList, username, password)

	// Once Login success and Claimlist generate.
	// Call httpResponseWriter from common/auth. It return's the token.
	io.WriteString(w, "Basic login success Token is ")
	return

}

//Setup configures connetor with config file parametes.
func (BasicCtr BasicConnector) Setup(authServer auth.Auth) {
	//Setup Basic connector.
	BasicCtr.authServer = authServer
}
