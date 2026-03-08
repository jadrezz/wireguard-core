package api

import (
	_ "embed"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/swaggest/swgui/v5emb"
)

//go:embed openapi.yaml
var openAPISpec []byte

func RegisterSwagger(router *gin.Engine) {
	router.GET("/openapi.yaml", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/yaml", openAPISpec)
	})

	swaggerHandler := v5emb.New(
		"WireGuard Manager API",
		"/openapi.yaml",
		"/swagger/",
	)
	router.GET("/swagger/*any", gin.WrapH(swaggerHandler))
}
