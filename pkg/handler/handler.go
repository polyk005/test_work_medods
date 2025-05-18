package handler

import (
	"dz1/pkg/service"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	services *service.Service
}

func NewHandler(services service.Service) *Handler {
	return &Handler{services: &services}
}

func (h *Handler) InitRoutes() *gin.Engine {
	router := gin.New()

	auth := router.Group("/auth")
	{
		auth.POST("/sign-up", h.signUp)
		auth.POST("/refresh", h.refresh)
		auth.POST("/logout", h.logout)
	}

	api := router.Group("/api", h.authMiddleware)
	{
		api.GET("/guid", h.getGUID)
	}

	return router
}
