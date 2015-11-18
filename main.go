/*

Copyright 2015 All rights reserved.
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
	"os/signal"
	"syscall"
)

const (
	// Version is the version of the product
	Version = "0.0.1"
)

func main() {
	// step: validate the command line options
	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %s\n", err)
		os.Exit(1)
	}
	// step: create the openvpn auth service
	service, err := NewOpenVPNAuthd(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] failed to create the openvpn authd service, error: %s\n", err)
		os.Exit(1)
	}

	// step: start running the service
	if err := service.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[error] failed to start the service, error: %s\n", err)
		os.Exit(1)
	}

	// step: setup the termination signals
	signalChannel := make(chan os.Signal)
	signal.Notify(signalChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	<-signalChannel
}
