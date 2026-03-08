package config

import (
	"bytes"
	"net"
	"text/template"
)

type ClientConfig struct {
	PrivateKey          string
	Address             string
	ServerPublicKey     string
	Endpoint            net.IP
	Port                int
	PersistentKeepalive int
	AllowedIPs          []net.IPNet
	DNS                 []string
}

type ServerPeerConfig struct {
	PublicKey  string
	AllowedIPs string
}

type ServerConfig struct {
	PrivateKey       string
	Address          string
	ListenPort       int
	Subnet           string
	ExternalIface    string
	Peers            []ServerPeerConfig
	DisabledPeerIPs  []string
}

func RenderClientConfig(cfg ClientConfig) (string, error) {
	var buf bytes.Buffer
	tmpl, err := template.ParseFS(templates, "templates/client.conf")
	if err != nil {
		return "", err
	}

	if err = tmpl.Execute(&buf, cfg); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func RenderServerConfig(cfg ServerConfig) (string, error) {
	var buf bytes.Buffer
	tmpl, err := template.ParseFS(templates, "templates/server.conf")
	if err != nil {
		return "", err
	}

	if err = tmpl.Execute(&buf, cfg); err != nil {
		return "", err
	}
	return buf.String(), nil
}
