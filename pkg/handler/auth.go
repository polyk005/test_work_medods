package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type authInput struct {
	GUID string `json:"guid" binding:"required"`
}

type refreshInput struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h *Handler) signUp(c *gin.Context) {
	var input authInput
	if err := c.BindJSON(&input); err != nil {
		newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	// Validate GUID
	if _, err := uuid.Parse(input.GUID); err != nil {
		newErrorResponse(c, http.StatusBadRequest, "invalid GUID format")
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	tokenPair, err := h.services.Authorization.GenerateTokenPair(input.GUID, userAgent, ip)
	if err != nil {
		newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, tokenPair)
}

func (h *Handler) refresh(c *gin.Context) {
	var input refreshInput
	if err := c.BindJSON(&input); err != nil {
		newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	tokenPair, err := h.services.Authorization.RefreshTokenPair(input.RefreshToken, userAgent, ip)
	if err != nil {
		newErrorResponse(c, http.StatusUnauthorized, err.Error())
		return
	}

	c.JSON(http.StatusOK, tokenPair)
}

func (h *Handler) getGUID(c *gin.Context) {
	accessToken := c.GetHeader("Authorization")
	if accessToken == "" {
		newErrorResponse(c, http.StatusUnauthorized, "missing authorization header")
		return
	}

	// Remove "Bearer " prefix if present
	accessToken = strings.TrimPrefix(accessToken, "Bearer ")

	guid, err := h.services.Authorization.GetGUID(accessToken)
	if err != nil {
		newErrorResponse(c, http.StatusUnauthorized, err.Error())
		return
	}

	c.JSON(http.StatusOK, map[string]string{"guid": guid})
}

func (h *Handler) logout(c *gin.Context) {
	accessToken := c.GetHeader("Authorization")
	if accessToken == "" {
		newErrorResponse(c, http.StatusUnauthorized, "missing authorization header")
		return
	}

	// Remove "Bearer " prefix if present
	accessToken = strings.TrimPrefix(accessToken, "Bearer ")

	guid, err := h.services.Authorization.GetGUID(accessToken)
	if err != nil {
		newErrorResponse(c, http.StatusUnauthorized, err.Error())
		return
	}

	if err := h.services.Authorization.Logout(guid); err != nil {
		newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, statusResponse{Status: "ok"})
}
