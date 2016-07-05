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
	"crypto"
	"crypto/tls"
	"fmt"
	"net/http"

	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/claims"
	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/connector"
	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/sec"

	"./options"
)

//AuthServer type of server
type AuthServer struct {
	hostname string
	server   *http.Server

	tokenExp int

	privKey   crypto.PrivateKey
	suite     *sec.AlgorithmSuite
	tlsConfig *tls.Config

	ldapConnector *connector.LDAPConnector
	//	basicConnector connector.Connector
	// May need to add a running flag that indicates server is running.
}

//NewAuthServer is contructor.
func NewAuthServer(config *options.AuthServerConfig) (*AuthServer, error) {
	authServer := &AuthServer{
		hostname: config.Host,
		server:   &http.Server{},
		suite:    sec.P256Suite,
		tokenExp: config.TokenExp,
	}

	fmt.Printf("The priv key is [%s] and cert is [%s]", config.PrivKey, config.CertFile)
	cer, err := tls.LoadX509KeyPair(config.CertFile, config.PrivKey)

	if err != nil {
		return nil, fmt.Errorf("Failed to load TLS priv file and TLS Cert file [%q]", err)
	}

	fmt.Printf("\nThe tls cert is [%q]\n", cer.PrivateKey)
	authServer.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cer}}
	authServer.privKey = cer.PrivateKey

	//Add connector based on auth type.
	authServer.ldapConnector = &connector.LDAPConnector{}
	return authServer, nil
}

func (s *AuthServer) NewHttpResponseWriter(tr *http.Request, valid claims.ClaimList) ([]byte, error) {
	response, error := s.httpBearerES256(tr, valid)
	return response, error
}

// Run runs the specified AuthServer.  This should never exit (unless CleanupAndExit is set).
func (s *AuthServer) Run() error {
	s.ldapConnector.Setup(s)
	//s.basicConnector.SetUp(auth.Auth(s))

	//	go http.ListenAndServe(":8081", http.Handler(s.basicConnector))
	err := http.ListenAndServeTLS(":8082", "cert.crt", "cert.key", http.Handler(s.ldapConnector))
	//err := http.ListenAndServe(":8082", http.Handler(s.ldapConnector))
	if err != nil {
		fmt.Printf("Failed to start http server [%q]", err)
	}
	return err
}
