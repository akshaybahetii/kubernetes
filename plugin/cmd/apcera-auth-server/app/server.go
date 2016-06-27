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
	"net/http"
	"sync"

	"github.com/apcera/gossl"

	"../../../pkg/auth/authenticator/token/apceratoken/claims"
	"../../../pkg/auth/authenticator/token/apceratoken/connector"
	"../../../pkg/auth/authenticator/token/apceratoken/sec"
	"./options"
)

//AuthServer type of server
type AuthServer struct {
	hostname string
	server   *http.Server

	// keyMutex should be held when reading/updating component keys.
	keyMutex sync.RWMutex
	privKey  []byte
	pubKey   []byte
	suite    *sec.AlgorithmSuite

	ldapConnector *connector.LDAPConnector
	//	basicConnector connector.Connector
	// May need to add a running flag that indicates server is running.
}

//TODO Temp function for testing will be removed.
func newEcKey(size int) (pub, priv []byte, err error) {
	key, err := gossl.NewECKey(size)
	if err != nil {
		return nil, nil, err

	}
	defer key.Free()
	err = key.Generate()
	if err != nil {
		return nil, nil, err

	}
	pub, err = key.PubKey()
	if err != nil {
		return nil, nil, err

	}
	priv, err = key.PrivKey()
	if err != nil {
		return nil, nil, err

	}
	return
}

//NewAuthServer is contructor.
func NewAuthServer(config *options.AuthServerConfig) (*AuthServer, error) {
	authServer := &AuthServer{
		hostname: config.Host,
		server:   &http.Server{},
		//Configure connectors based on configuration.
		//		basicConnector: connector.BasicConnector{IDName: "Basic"},
		suite: sec.P256Suite,
	}
	var pubKey []byte

	pubKey, authServer.privKey, _ = newEcKey(256)
	fmt.Printf("The public key is [%x]\n", string(pubKey))
	fmt.Printf("The private key is [%x]\n", string(authServer.privKey))
	authServer.privKey = []byte(config.PrivKey)

	authServer.ldapConnector = &connector.LDAPConnector{}
	return authServer, nil
}

func (s *AuthServer) NewHttpResponseWriter(tr *http.Request, valid claims.ClaimList) (string, error) {
	response, error := s.httpBearerES256(tr, valid)
	return response, error
}

// Run runs the specified AuthServer.  This should never exit (unless CleanupAndExit is set).
func (s *AuthServer) Run() error {
	s.ldapConnector.Setup(s)
	//s.basicConnector.SetUp(auth.Auth(s))

	//	go http.ListenAndServe(":8081", http.Handler(s.basicConnector))
	http.ListenAndServe(":8082", http.Handler(s.ldapConnector))
	return nil
}
