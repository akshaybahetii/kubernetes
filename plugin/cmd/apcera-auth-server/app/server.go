/*
Copyright 2014 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package app does all of the work necessary to configure and run a
// Kubernetes app process.
package app

import (
	"net/http"
	"sync"

	"../auth"

	"../claims"
	"../connector"
	"./options"
)

//AuthServer type of server
type AuthServer struct {
	hostname string
	server   *http.Server

	// keyMutex should be held when reading/updating component keys.
	keyMutex          sync.RWMutex
	privKey           []byte
	pubKey            []byte
	authServerPubKeys map[string][]byte

	ldapConnector *connector.LDAPConnector
	//	basicConnector connector.Connector
	// May need to add a running flag that indicates server is running.
}

//NewAuthServer is contructor.
func NewAuthServer(host string) *AuthServer {
	authServer := &AuthServer{
		hostname: host,
		server:   &http.Server{},
		//Configure connectors based on configuration.
		//		basicConnector: connector.BasicConnector{IDName: "Basic"},
	}
	authServer.ldapConnector = &connector.LDAPConnector{}
	return authServer
}

//NewAuthServerDefault creates a new AuthServer object with default parameters.
func NewAuthServerDefault(*options.AuthServerConfig) (*AuthServer, error) {
	return NewAuthServer("apcera-host"), nil
}

func (*AuthServer) NewHttpResponseWriter(tr *auth.HttpTokenRequest, valid claims.ClaimList) (string, error) {
	return "Signed Token Yeah!!", nil
}

/*
//Call login with appropriate connector.
func (s *AuthServer) login(w http.ResponseWriter, r *http.Request, connector connector.Connector) {
	//Call http token request parser to token req structure. Most of the
	// components in the structure are not required.TODO
	_, _, claims := connector.Login(r)
	//Call auth.HttpResposeWriter with Claimlist and w.
	//It will add expiration time and Issuer. And also hash and sign token.
	io.WriteString(w, fmt.Sprintf("Success login claims are %x ", claims))
}
*/
/*
func (*handlers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, ok := httpHandlers[r.URL.String()]; ok {
		h(w, r)
		return
	}

	io.WriteString(w, "Error not a valid URI "+r.URL.String())
}*/

// Run runs the specified AuthServer.  This should never exit (unless CleanupAndExit is set).
func (s *AuthServer) Run() error {
	s.ldapConnector.Setup(s)
	//s.basicConnector.SetUp(auth.Auth(s))

	//	go http.ListenAndServe(":8081", http.Handler(s.basicConnector))
	http.ListenAndServe(":8082", http.Handler(s.ldapConnector))
	return nil
}
