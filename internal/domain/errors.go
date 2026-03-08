package domain

import "errors"

var (
	ErrDevice       = errors.New("this device is not WireGuard's or does not exist")
	ErrNoFreePeerIP = errors.New("the WireGuard subnet has run out of hosts")
	ErrInvalidKey       = errors.New("invalid public key format")
	ErrServerManagement = errors.New("server management is not configured")
	ErrPeerNotFound     = errors.New("peer not found")
	ErrPeerNotDisabled  = errors.New("peer is not disabled")
)
