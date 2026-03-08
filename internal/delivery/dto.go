package delivery

import "time"

type CreatePeerRequest struct {
	AllowedIPs []string `json:"allowed_ips" binding:"required"`
	DNS        []string `json:"dns,omitempty"`
}

type PeerPublicKeyRequest struct {
	PublicKey string `json:"public_key" binding:"required"`
}

type InitServerRequest struct {
	DeviceName string `json:"device_name" binding:"required"`
	Address    string `json:"address" binding:"required"`
	ListenPort int    `json:"listen_port" binding:"required"`
}

type PeerResponse struct {
	PublicKey     string    `json:"public_key"`
	AllowedIPs    []string  `json:"allowed_ips"`
	Endpoint      string    `json:"endpoint,omitempty"`
	TransmitBytes int64     `json:"transmit_bytes"`
	ReceiveBytes  int64     `json:"receive_bytes"`
	LastHandshake time.Time `json:"last_handshake"`
}

type PeersResponse struct {
	Peers []PeerResponse `json:"peers"`
}

type AvailableAddrsResponse struct {
	Count int `json:"count"`
}

type DevicesResponse struct {
	Devices []string `json:"devices"`
}

type ErrorResponse struct {
	Error  string `json:"error"`
	Status int    `json:"status"`
}
