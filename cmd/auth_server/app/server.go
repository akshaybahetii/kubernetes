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

	"../connector"
	"./options"
)

//AuthServer type of server
type AuthServer struct {
	name           string
	server         *http.Server
	ldapConnector  connector.Connector
	basicConnector connector.Connector
	// May need to add a running flag that indicates server is running.
}

var httpHandlers map[string]func(http.ResponseWriter, *http.Request)

//NewAuthServer is contructor.
func NewAuthServer(adminDN string) *AuthServer {
	return &AuthServer{
		name:   adminDN,
		server: &http.Server{},
		//Configure connectors based on configuration.
		ldapConnector:  connector.LDAPConnector{IDName: "LDAP"},
		basicConnector: connector.BasicConnector{IDName: "Basic"},
	}
}

//NewAuthServerDefault creates a new AuthServer object with default parameters.
func NewAuthServerDefault(*options.AuthServerConfig) (*AuthServer, error) {
	return NewAuthServer("cn=apcera"), nil
}

/* type HttpTokenRequest struct {
	Req *component.HttpRequest

	// AuthType is the requested identity provider to authenticate with.
	AuthType         string
	AuthHeader       string
	AuthHeadPreamble string
	GoogAccessToken  string
	GoogIdToken      string
	GoogUserInfo     *httpapi.GooglePlusUserInfo
	WriteCookie      bool
	Token            *sec.JWT
	ContentType      string
	RequestId        string
	Parameters       *url.Values
	Log              api.LogOnlyContext
	ParsedBody       interface{}
}*/
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
	//Http Handlers for different login types based on configuration.
	httpHandlers = make(map[string]func(http.ResponseWriter, *http.Request))

	go http.ListenAndServe(":8081", s.basicConnector.Handler())
	http.ListenAndServe(":8082", s.ldapConnector.Handler())
	return nil
}
