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

// Package options contains flags for initializing a proxy.
package options

import (
	"fmt"

	"github.com/spf13/pflag"
)

// AuthServerConfig configures and runs a Kubernetes proxy server
type AuthServerConfig struct {
	Host     string
	CertFile string
	PrivKey  string
}

//NewAuthConfig auth config struct
//TODO: need to figure out how config is structed for different aut mechanims.
func NewAuthConfig() *AuthServerConfig {
	return &AuthServerConfig{
		Host:     "default-apcera-host",
		PrivKey:  "cert.key",
		CertFile: "cert.crt",
	}
}

// AddFlags adds flags for a specific AuthServer to the specified FlagSet
func (s *AuthServerConfig) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.Host, "host", s.Host, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	fs.StringVar(&s.PrivKey, "priv-key", s.PrivKey, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	fs.StringVar(&s.CertFile, "cert-file", s.CertFile, "CertFile for the http server.")
	fmt.Printf("The flag set is [%q]", s)
}
