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

import "time"

// OpenVPNAuthd is the service responsible for shipping out the openvpn config
type OpenVPNAuthd interface {
	// run the service
	Run() error
}

// VaultService is the interface for speaking to vault
type VaultService interface {
	// authenticate the client
	Authenticate(string, string) error
	// Retrieve a certificate from vault
	GetCertificate(string, string, time.Duration) (*Certificate, error)
}

// Certificate is the certificate for openvpn authentication
type Certificate struct {
	// the certificate
	Certificate string
	// the private key
	PrivateKey string
	// the ca
	IssuingCA string
	// the ttl on the cert
	TTL time.Duration
	// the subject
	Subject string
}
