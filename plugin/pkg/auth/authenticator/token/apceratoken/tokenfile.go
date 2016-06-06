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
	"github.com/golang/glog"

	"k8s.io/kubernetes/pkg/auth/user"
)

type TokenAuthenticator struct {
	pubKey string
	//tokens map[string]*user.DefaultInfo
}

// NewPublicKey returns a TokenAuthenticator, populated from a CSV file.
func NewPublicKey(path string) (*TokenAuthenticator, error) {
	return &TokenAuthenticator{
		pubKey: path,
	}, nil

}

func (a *TokenAuthenticator) AuthenticateToken(value string) (user.Info, bool, error) {
	/*user, ok := a.tokens[value]
	if !ok {
		return nil, false, nil
	}*/
	user := &user.DefaultInfo{
		Name: "akshay",
		UID:  "akshay",
	}
	//	DecodeToken(value, []byte(a.pubKey))
	glog.Warningf("AKSHAY In function Authenticate Token in apcera token. [%s] [%s]", a.pubKey, value)
	return user, true, nil
}
