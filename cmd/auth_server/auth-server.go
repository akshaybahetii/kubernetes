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

package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/pflag"
	"k8s.io/kubernetes/pkg/util"
	"k8s.io/kubernetes/pkg/util/flag"
	"k8s.io/kubernetes/pkg/version/verflag"

	"./app"
	"./app/options"
)

func init() {
	fmt.Println("Initializing auth server.. ")
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	config := options.NewAuthConfig()
	config.AddFlags1(pflag.CommandLine)

	fmt.Println("The adminDN is ", config.AdminDN)

	flag.InitFlags()
	util.InitLogs()
	defer util.FlushLogs()

	verflag.PrintAndExitIfRequested()

	//config := options.NewAuthConfig()

	fmt.Println("Running Auth Server with default config.")
	s, err := app.NewAuthServerDefault(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	s.Run()
	fmt.Fprintf(os.Stderr, "%v\n", err)
	os.Exit(1)
}
