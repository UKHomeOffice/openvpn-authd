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
	"flag"
	"fmt"
	"net/url"
	"time"
	"strings"
)

// AuthConfig os the  configuration
type AuthConfig struct {
	ServiceBind string `yaml:"interface"`
	// the port to run the service on
	ServicePort int `yaml:"port"`
	// the external hostname:port of the vpn servers
	OpenVPNServers string `yaml:openvpn_servers"`
	// authentication subject header
	AuthHeader string `yaml:"auth_header"`
	// the service protocol
	VaultURL string `yaml:"vault_url"`
	// the vault username
	VaultUsername string `yaml:"vault_username"`
	// the vault password
	VaultPassword string `yaml:"vault_password"`
	// the vault path
	VaultPath string `yaml:"vault_path"`
	// skip the tls for vault service?
	VaultTLSVerify bool `yaml:"vault_skip_tls_verify"`
	// the session duration
	SessionDuration time.Duration
	// the ca file for vault service
	VaultCaFile string `yaml:"vault_cafile"`
	// the server list
	servers []string
}

// parseConfig performs some basic validation of the command line options
func parseConfig() (*AuthConfig, error) {
	cfg := &AuthConfig{}
	flag.IntVar(&cfg.ServicePort, "port", 8081, "the port to run the openvpn authd service on")
	flag.StringVar(&cfg.ServiceBind, "interface", "127.0.0.1", "the interface to run the service on")
	flag.StringVar(&cfg.AuthHeader, "auth-header", "X-Auth-Email", "the header containing the subject name")
	flag.StringVar(&cfg.OpenVPNServers, "openvpn-servers", "", "a comma separate list of vpn servers, HOSTNAME:PORT")
	flag.StringVar(&cfg.VaultURL, "vault-addr", getEnv("VAULT_ADDR", "http://127.0.0.1:8200"), "the full vault service url to issue certifications (VAULT_ADDR)")
	flag.StringVar(&cfg.VaultUsername, "vault-username", getEnv("VAULT_USER", "openvpn"), "the vault username to authenticate to the service with (VAULT_USER)")
	flag.StringVar(&cfg.VaultPassword, "vault-password", "", "the vault password to authentication to the service (VAULT_PASSWORD)")
	flag.StringVar(&cfg.VaultPath, "vault-pki-path", "", "the mount path in vault to issue the certificate")
	flag.BoolVar(&cfg.VaultTLSVerify, "vault-tls-verify", true, "whether to verify the certificate of the vault service")
	flag.DurationVar(&cfg.SessionDuration, "session", time.Duration(1*time.Hour), "the duration of a certificate for openvpv account")
	flag.StringVar(&cfg.VaultCaFile, "vault-cafile", getEnv("VAULT_CA_FILE", ""), "the path to a CA certificate used to verify vault service (VAULT_CA_FILE)")

	flag.Parse()

	if cfg.OpenVPNServers == "" {
		return nil, fmt.Errorf("you have not specified the openvpn servers")
	}

	defaultOpenVPNPort := "1194"
	for _, server := range strings.Split(cfg.OpenVPNServers, ",") {
		if !strings.Contains(server, ":") {
			server = server + " " + defaultOpenVPNPort
		} else {
			server = strings.Replace(server, ":", " ", -1)
		}
		cfg.servers = append(cfg.servers, server)
	}

	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("you have not specified the vault service url")
	}

	if _, err := url.Parse(cfg.VaultURL); err != nil {
		return nil, fmt.Errorf("the vault service url: %s is invaliad, error: %s", cfg.VaultURL, err)
	}

	if cfg.VaultUsername == "" {
		return nil, fmt.Errorf("you have not specified the vault username")
	}

	if cfg.VaultPassword == "" {
		return nil, fmt.Errorf("you have not specified the vault password to authenticate with")
	}

	if cfg.VaultPath == "" {
		return nil, fmt.Errorf("you have not specified the vault path the pki backend")
	}

	return cfg, nil
}
