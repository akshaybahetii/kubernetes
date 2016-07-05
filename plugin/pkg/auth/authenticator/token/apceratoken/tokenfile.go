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

package apceratoken

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"k8s.io/kubernetes/plugin/pkg/auth/authenticator/token/apceratoken/sec"

	"k8s.io/kubernetes/pkg/auth/user"
)

type TokenAuthenticator struct {
	//token string
	pubKey string
}

//Load the public key from the api-server options.
func NewPublicKey(pubKey string) (*TokenAuthenticator, error) {

	return &TokenAuthenticator{
		pubKey: pubKey,
	}, nil
}

func (a *TokenAuthenticator) AuthenticateToken(value string) (user.Info, bool, error) {
	pubKey := a.pubKey
	pubKeys := make(map[string][]byte)
	pubKeys["PrincipalName"] = []byte(pubKey)
	aud := []string{"apcera.me", "apcera"}

	cer, err := ioutil.ReadFile(a.pubKey)
	if err != nil {
		return nil, false, err
	}

	block, _ := pem.Decode([]byte(cer))
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	ePublicKey := cert.PublicKey.(*ecdsa.PublicKey)

	jwt, err := sec.DecodeVerifyToken(value, sec.P256Suite, ePublicKey, aud)

	if err != nil {
		return nil, false, err
	}

	user := &user.DefaultInfo{
		Name: jwt.Claims[1].Value.(string),
	}

	fmt.Printf("\n Token claims are  [%q]", jwt)
	return user, true, nil
}
