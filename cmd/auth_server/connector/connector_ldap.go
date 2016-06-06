package connector

import (
	"fmt"
	"net/http"
	"time"

	"../claims"
)

//LDAPConnector struct {
type LDAPConnector struct {
	IDName               string        `json:"id"`
	ServerHost           string        `json:"serverHost"`
	ServerPort           uint16        `json:"serverPort"`
	Timeout              time.Duration `json:"timeout"`
	UseTLS               bool          `json:"useTLS"`
	UseSSL               bool          `json:"useSSL"`
	CertFile             string        `json:"certFile"`
	KeyFile              string        `json:"keyFile"`
	CaFile               string        `json:"caFile"`
	SkipCertVerification bool          `json:"skipCertVerification"`
	BaseDN               string        `json:"baseDN"`
	NameAttribute        string        `json:"nameAttribute"`
	EmailAttribute       string        `json:"emailAttribute"`
	SearchBeforeAuth     bool          `json:"searchBeforeAuth"`
	SearchFilter         string        `json:"searchFilter"`
	SearchScope          string        `json:"searchScope"`
	SearchBindDN         string        `json:"searchBindDN"`
	SearchBindPw         string        `json:"searchBindPw"`
	BindTemplate         string        `json:"bindTemplate"`
	TrustedEmailProvider bool          `json:"trustedEmailProvider"`
}

//ID returns the ID of the ConnectorConfig used to create the Connector.
func (LDAPCtr LDAPConnector) ID() string {
	return "LDAP"
}

//Login returns if authorization was sucess and claim list.
func (LDAPCtr LDAPConnector) Login(r *http.Request) (bool, error, []*claims.Claim) {
	fmt.Printf("Attempting LDAP login")
	claimList := []*claims.Claim{claims.NewClaim("AUTH", "AUTH_TYPE", "LDAP_BASIC"), claims.NewClaim("AUTH", "USERNAME", "AKSHAY")}

	//	username, password, _ := r.BasicAuth()
	return true, nil, claimList
}

//Setup configures connetor with config file parametes.
func (LDAPCtr LDAPConnector) Setup() {

}
