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
	"fmt"
	"io"
	"net/http"

	"k8s.io/kubernetes/cmd/auth-server/app/options"
)

//AuthServer type of server
type AuthServer struct {
	name   string
	server *http.Server
	/*    *auth.Auth
	      running      bool
	      runMutex     sync.RWMutex
	      shutdownChan chan bool

	      // LDAPConfig configures us to communicate with an LDAP server.
	      LDAPConfig *ldap.Config*/
}

/*func NewAuthServer(
	client *kubeclient.Client,
	config *options.ProxyServerConfig,
	iptInterface utiliptables.Interface,
	proxier proxy.ProxyProvider,
	broadcaster record.EventBroadcaster,
	recorder record.EventRecorder,
	conntracker Conntracker,
	proxyMode string,
) (*ProxyServer, error) {
	return &ProxyServer{
		Client:       client,
		Config:       config,
		IptInterface: iptInterface,
		Proxier:      proxier,
		Broadcaster:  broadcaster,
		Recorder:     recorder,
		Conntracker:  conntracker,
		ProxyMode:    proxyMode,
	}, nil
}
*/
var mux map[string]func(http.ResponseWriter, *http.Request)

type handlers struct{}

//NewAuthServer is contructor.
func NewAuthServer(adminDN string) *AuthServer {
	return &AuthServer{
		name: adminDN,
		server: &http.Server{
			Addr:    ":8000",
			Handler: &handlers{},
		},
	}
}

//NewAuthServerDefault creates a new AuthServer object with default parameters.
func NewAuthServerDefault(*options.AuthServerConfig) (*AuthServer, error) {
	return NewAuthServer("cn=apcera"), nil
}

func ldapLogin(w http.ResponseWriter, r *http.Request) {
	//username, password, ok := r.BasicAuth()
	username, _, _ := r.BasicAuth()
	//	resp := fmt.Sprintf("The recieved username and password is ", username, password, ok)
	io.WriteString(w, username)
}

func (*handlers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, ok := mux[r.URL.String()]; ok {
		h(w, r)
		return
	}

	io.WriteString(w, "Error not a valid URI "+r.URL.String())
}

func basicLogin(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "Trying basic login")
}

// Run runs the specified ProxyServer.  This should never exit (unless CleanupAndExit is set).
func (s *AuthServer) Run() error {
	fmt.Println("running auth server")
	mux = make(map[string]func(http.ResponseWriter, *http.Request))
	mux["/ldapLogin"] = ldapLogin
	mux["/basicLogin"] = basicLogin

	s.server.ListenAndServe()
	return nil
}
