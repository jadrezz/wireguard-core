package delivery

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	nethttp "net/http"
	"strings"

	"wireguard-core/internal/domain"
	"wireguard-core/internal/usecase"

	"github.com/gin-gonic/gin"
)

type WgHandlers struct {
	logger  *slog.Logger
	service usecase.WireGuardManagerService
}

func NewWgHandlers(logger *slog.Logger, service usecase.WireGuardManagerService) *WgHandlers {
	return &WgHandlers{logger: logger, service: service}
}

func (h *WgHandlers) HealthCheck(c *gin.Context) {
	if err := h.service.HealthCheck(); err != nil {
		h.logger.Error("health check failed", "request_id", GetRequestID(c), "error", err)
		c.JSON(nethttp.StatusServiceUnavailable, gin.H{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	h.logger.Info("health check ok", "request_id", GetRequestID(c))
	c.JSON(nethttp.StatusOK, gin.H{"status": "ok"})
}

func (h *WgHandlers) GetAllDevices(c *gin.Context) {
	devices, err := h.service.GetAllDevices()
	if err != nil {
		h.logger.Error("could not get devices", "request_id", GetRequestID(c), "error", err)
		c.JSON(nethttp.StatusInternalServerError, ErrorResponse{
			Error:  "Internal server error",
			Status: nethttp.StatusInternalServerError,
		})
		return
	}

	names := make([]string, 0, len(devices))
	for _, d := range devices {
		names = append(names, d.Name)
	}

	h.logger.Info("devices listed", "request_id", GetRequestID(c), "count", len(names))
	c.JSON(nethttp.StatusOK, DevicesResponse{Devices: names})
}

func peerToResponse(p domain.Peer) PeerResponse {
	allowedIPs := make([]string, 0, len(p.AllowedIPs))
	for _, ip := range p.AllowedIPs {
		allowedIPs = append(allowedIPs, ip.String())
	}
	var endpoint string
	if p.Endpoint != nil {
		endpoint = p.Endpoint.String()
	}
	return PeerResponse{
		PublicKey:     p.PublicKey,
		AllowedIPs:    allowedIPs,
		Endpoint:      endpoint,
		TransmitBytes: p.TransmitBytes,
		ReceiveBytes:  p.ReceiveBytes,
		LastHandshake: p.LastHandshake,
	}
}

func (h *WgHandlers) GetDevicePeers(c *gin.Context) {
	deviceName := c.Param("device")

	peers, err := h.service.GetDevicePeers(deviceName)
	if err != nil {
		h.logger.Error("could not get peers", "request_id", GetRequestID(c), "device", deviceName, "error", err)
		if errors.Is(err, domain.ErrDevice) {
			c.JSON(nethttp.StatusBadRequest, ErrorResponse{
				Error:  err.Error(),
				Status: nethttp.StatusBadRequest,
			})
			return
		}
		c.JSON(nethttp.StatusInternalServerError, ErrorResponse{
			Error:  "Internal server error",
			Status: nethttp.StatusInternalServerError,
		})
		return
	}

	response := make([]PeerResponse, 0, len(peers))
	for _, p := range peers {
		response = append(response, peerToResponse(p))
	}

	h.logger.Info("peers listed", "request_id", GetRequestID(c), "device", deviceName, "count", len(response))
	c.JSON(nethttp.StatusOK, PeersResponse{Peers: response})
}

func (h *WgHandlers) GetPeerInfo(c *gin.Context) {
	deviceName := c.Param("device")
	publicKey := base64QueryParam(c.Query("public_key"))
	if publicKey == "" {
		c.JSON(nethttp.StatusBadRequest, ErrorResponse{
			Error:  "public_key query parameter is required",
			Status: nethttp.StatusBadRequest,
		})
		return
	}

	peer, err := h.service.GetPeer(deviceName, publicKey)
	if err != nil {
		h.logger.Error("could not get peer", "request_id", GetRequestID(c), "device", deviceName, "error", err)
		if errors.Is(err, domain.ErrPeerNotFound) {
			c.JSON(nethttp.StatusNotFound, ErrorResponse{
				Error:  err.Error(),
				Status: nethttp.StatusNotFound,
			})
			return
		}
		if errors.Is(err, domain.ErrDevice) {
			c.JSON(nethttp.StatusBadRequest, ErrorResponse{
				Error:  err.Error(),
				Status: nethttp.StatusBadRequest,
			})
			return
		}
		c.JSON(nethttp.StatusInternalServerError, ErrorResponse{
			Error:  "Internal server error",
			Status: nethttp.StatusInternalServerError,
		})
		return
	}

	h.logger.Info("peer info returned", "request_id", GetRequestID(c), "device", deviceName)
	c.JSON(nethttp.StatusOK, peerToResponse(peer))
}

func (h *WgHandlers) GetAvailableAddrs(c *gin.Context) {
	deviceName := c.Param("device")

	count, err := h.service.CountFreeAddrs(deviceName)
	if err != nil {
		h.logger.Error("could not count free addresses", "request_id", GetRequestID(c), "device", deviceName, "error", err)
		if errors.Is(err, domain.ErrDevice) {
			c.JSON(nethttp.StatusBadRequest, ErrorResponse{
				Error:  err.Error(),
				Status: nethttp.StatusBadRequest,
			})
			return
		}
		c.JSON(nethttp.StatusInternalServerError, ErrorResponse{
			Error:  "Internal server error",
			Status: nethttp.StatusInternalServerError,
		})
		return
	}

	h.logger.Info("available addrs requested", "request_id", GetRequestID(c), "device", deviceName, "count", count)
	c.JSON(nethttp.StatusOK, AvailableAddrsResponse{Count: count})
}

func (h *WgHandlers) CreatePeer(c *gin.Context) {
	deviceName := c.Param("device")

	var req CreatePeerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("could not bind request", "request_id", GetRequestID(c), "error", err)
		c.JSON(nethttp.StatusBadRequest, ErrorResponse{
			Error:  "request body is not valid",
			Status: nethttp.StatusBadRequest,
		})
		return
	}

	allowedIPs, err := parseAllowedIPs(req.AllowedIPs)
	if err != nil {
		h.logger.Info("could not parse IP", "request_id", GetRequestID(c), "error", err)
		c.JSON(nethttp.StatusBadRequest, ErrorResponse{
			Error:  fmt.Sprintf("Invalid IP: %v", err),
			Status: nethttp.StatusBadRequest,
		})
		return
	}

	clientCfg, err := h.service.CreatePeer(deviceName, allowedIPs, req.DNS)
	if err != nil {
		h.logger.Error("could not create peer", "request_id", GetRequestID(c), "error", err, "device", deviceName)
		if errors.Is(err, domain.ErrDevice) {
			c.JSON(nethttp.StatusBadRequest, ErrorResponse{
				Error:  err.Error(),
				Status: nethttp.StatusBadRequest,
			})
			return
		}
		if errors.Is(err, domain.ErrNoFreePeerIP) {
			c.JSON(nethttp.StatusConflict, ErrorResponse{
				Error:  err.Error(),
				Status: nethttp.StatusConflict,
			})
			return
		}
		c.JSON(nethttp.StatusInternalServerError, ErrorResponse{
			Error:  "Internal server error",
			Status: nethttp.StatusInternalServerError,
		})
		return
	}

	h.logger.Info("new peer created successfully", "request_id", GetRequestID(c), "device", deviceName)
	c.String(nethttp.StatusCreated, clientCfg)
}

func base64QueryParam(s string) string {
	return strings.ReplaceAll(s, " ", "+")
}

func (h *WgHandlers) RemovePeer(c *gin.Context) {
	deviceName := c.Param("device")
	publicKey := base64QueryParam(c.Query("public_key"))
	if publicKey == "" {
		c.JSON(nethttp.StatusBadRequest, ErrorResponse{
			Error:  "public_key query parameter is required",
			Status: nethttp.StatusBadRequest,
		})
		return
	}

	if err := h.service.RemovePeer(deviceName, publicKey); err != nil {
		h.logger.Error("could not remove peer", "request_id", GetRequestID(c), "device", deviceName, "error", err)
		if errors.Is(err, domain.ErrDevice) {
			c.JSON(nethttp.StatusBadRequest, ErrorResponse{
				Error:  err.Error(),
				Status: nethttp.StatusBadRequest,
			})
			return
		}
		if errors.Is(err, domain.ErrInvalidKey) {
			c.JSON(nethttp.StatusBadRequest, ErrorResponse{
				Error:  err.Error(),
				Status: nethttp.StatusBadRequest,
			})
			return
		}
		c.JSON(nethttp.StatusInternalServerError, ErrorResponse{
			Error:  "Internal server error",
			Status: nethttp.StatusInternalServerError,
		})
		return
	}

	h.logger.Info("peer removed successfully", "request_id", GetRequestID(c), "device", deviceName)
	c.Status(nethttp.StatusNoContent)
}

func (h *WgHandlers) DisablePeer(c *gin.Context) {
	deviceName := c.Param("device")

	var req PeerPublicKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(nethttp.StatusBadRequest, ErrorResponse{
			Error:  "request body must include public_key",
			Status: nethttp.StatusBadRequest,
		})
		return
	}

	if err := h.service.DisablePeer(deviceName, req.PublicKey); err != nil {
		h.logger.Error("could not disable peer", "request_id", GetRequestID(c), "device", deviceName, "error", err)
		if errors.Is(err, domain.ErrDevice) || errors.Is(err, domain.ErrPeerNotFound) {
			c.JSON(nethttp.StatusBadRequest, ErrorResponse{
				Error:  err.Error(),
				Status: nethttp.StatusBadRequest,
			})
			return
		}
		c.JSON(nethttp.StatusInternalServerError, ErrorResponse{
			Error:  "Internal server error",
			Status: nethttp.StatusInternalServerError,
		})
		return
	}

	h.logger.Info("peer disabled successfully", "request_id", GetRequestID(c), "device", deviceName)
	c.Status(nethttp.StatusNoContent)
}

func (h *WgHandlers) EnablePeer(c *gin.Context) {
	deviceName := c.Param("device")

	var req PeerPublicKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(nethttp.StatusBadRequest, ErrorResponse{
			Error:  "request body must include public_key",
			Status: nethttp.StatusBadRequest,
		})
		return
	}

	if err := h.service.EnablePeer(deviceName, req.PublicKey); err != nil {
		h.logger.Error("could not enable peer", "request_id", GetRequestID(c), "device", deviceName, "error", err)
		if errors.Is(err, domain.ErrPeerNotDisabled) {
			c.JSON(nethttp.StatusBadRequest, ErrorResponse{
				Error:  err.Error(),
				Status: nethttp.StatusBadRequest,
			})
			return
		}
		if errors.Is(err, domain.ErrDevice) || errors.Is(err, domain.ErrPeerNotFound) {
			c.JSON(nethttp.StatusBadRequest, ErrorResponse{
				Error:  err.Error(),
				Status: nethttp.StatusBadRequest,
			})
			return
		}
		c.JSON(nethttp.StatusInternalServerError, ErrorResponse{
			Error:  "Internal server error",
			Status: nethttp.StatusInternalServerError,
		})
		return
	}

	h.logger.Info("peer enabled successfully", "request_id", GetRequestID(c), "device", deviceName)
	c.Status(nethttp.StatusNoContent)
}

func (h *WgHandlers) InitServer(c *gin.Context) {
	var req InitServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("could not bind request", "error", err)
		c.JSON(nethttp.StatusBadRequest, ErrorResponse{
			Error:  "request body is not valid",
			Status: nethttp.StatusBadRequest,
		})
		return
	}

	params := domain.ServerInitParams{
		DeviceName: req.DeviceName,
		Address:    req.Address,
		ListenPort: req.ListenPort,
	}

	if err := h.service.InitServer(params); err != nil {
		h.logger.Error("could not init server", "request_id", GetRequestID(c), "error", err)
		c.JSON(nethttp.StatusInternalServerError, ErrorResponse{
			Error:  fmt.Sprintf("failed to initialize server: %v", err),
			Status: nethttp.StatusInternalServerError,
		})
		return
	}

	h.logger.Info("server initialized successfully", "request_id", GetRequestID(c), "device", req.DeviceName)
	c.Status(nethttp.StatusCreated)
}

func (h *WgHandlers) ResetServer(c *gin.Context) {
	deviceName := c.Param("device")

	if err := h.service.ResetServer(deviceName); err != nil {
		h.logger.Error("could not reset server", "request_id", GetRequestID(c), "device", deviceName, "error", err)
		c.JSON(nethttp.StatusInternalServerError, ErrorResponse{
			Error:  fmt.Sprintf("failed to reset server: %v", err),
			Status: nethttp.StatusInternalServerError,
		})
		return
	}

	h.logger.Info("server reset successfully", "request_id", GetRequestID(c), "device", deviceName)
	c.Status(nethttp.StatusNoContent)
}

func parseAllowedIPs(ips []string) ([]net.IPNet, error) {
	result := make([]net.IPNet, 0, len(ips))
	for _, s := range ips {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		result = append(result, *ipnet)
	}
	return result, nil
}
