package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func (h *Handler) authMiddleware(c *gin.Context) {
	accessToken := c.GetHeader("Authorization")
	if accessToken == "" {
		newErrorResponse(c, http.StatusUnauthorized, "missing authorization header")
		return
	}

	// Remove "Bearer " prefix if present
	accessToken = strings.TrimPrefix(accessToken, "Bearer ")

	if _, err := h.services.Authorization.GetGUID(accessToken); err != nil {
		newErrorResponse(c, http.StatusUnauthorized, err.Error())
		return
	}

	c.Next()
}
