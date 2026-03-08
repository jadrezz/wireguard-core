package delivery

import (
	"log/slog"

	"wireguard-core/internal/usecase"

	"github.com/gin-gonic/gin"
)

func NewRouter(logger *slog.Logger, service usecase.WireGuardManagerService) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.Use(RequestIDMiddleware())
	handler := NewWgHandlers(logger, service)

	router.GET("/health", handler.HealthCheck)

	api := router.Group("/api/v1")
	{
		api.GET("/devices", handler.GetAllDevices)
		api.GET("/devices/:device/peer/info", handler.GetPeerInfo)

		peers := api.Group("/devices/:device/peers")
		{
			peers.GET("", handler.GetDevicePeers)
			peers.GET("/available", handler.GetAvailableAddrs)
			peers.POST("", handler.CreatePeer)
			peers.DELETE("", handler.RemovePeer)
			peers.POST("/disable", handler.DisablePeer)
			peers.POST("/enable", handler.EnablePeer)
		}

		server := api.Group("/server")
		{
			server.POST("/init", handler.InitServer)
			server.POST("/:device/reset", handler.ResetServer)
		}
	}

	return router
}
