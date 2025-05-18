package service

import (
	"encoding/base64"
	"errors"
	"time"

	"dz1/pkg/models"
	"dz1/pkg/repository"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 24 * time.Hour * 7
	bcryptCost      = 10
)

type authService struct {
	repo       repository.Authorization
	signingKey []byte
	webhookURL string
}

func NewAuthService(repo repository.Authorization, signingKey, webhookURL string) models.AuthService {
	return &authService{
		repo:       repo,
		signingKey: []byte(signingKey),
		webhookURL: webhookURL,
	}
}

func (s *authService) GenerateTokenPair(guid, userAgent, ip string) (models.TokenPair, error) {
	accessToken, err := s.generateAccessToken(guid)
	if err != nil {
		return models.TokenPair{}, err
	}

	refreshToken, refreshTokenHash, err := s.generateRefreshToken(guid)
	if err != nil {
		return models.TokenPair{}, err
	}

	if err := s.repo.CreateRefreshToken(guid, refreshTokenHash, userAgent, ip); err != nil {
		return models.TokenPair{}, err
	}

	return models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *authService) generateAccessToken(guid string) (string, error) {
	claims := &models.TokenClaims{
		GUID: guid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(accessTokenTTL).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(s.signingKey)
}

func (s *authService) generateRefreshToken(guid string) (string, string, error) {
	claims := &models.TokenClaims{
		GUID: guid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(refreshTokenTTL).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString(s.signingKey)
	if err != nil {
		return "", "", err
	}

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(tokenString), bcryptCost)
	if err != nil {
		return "", "", err
	}

	encodedToken := base64.StdEncoding.EncodeToString([]byte(tokenString))
	return encodedToken, string(hashedToken), nil
}

func (s *authService) RefreshTokenPair(refreshToken, userAgent, ip string) (models.TokenPair, error) {
	decodedToken, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		return models.TokenPair{}, errors.New("invalid refresh token format")
	}

	token, err := jwt.ParseWithClaims(string(decodedToken), &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.signingKey, nil
	})
	if err != nil {
		return models.TokenPair{}, errors.New("invalid refresh token")
	}

	claims, ok := token.Claims.(*models.TokenClaims)
	if !ok || !token.Valid {
		return models.TokenPair{}, errors.New("invalid refresh token claims")
	}

	storedHash, storedUserAgent, err := s.repo.GetRefreshToken(claims.GUID)
	if err != nil {
		return models.TokenPair{}, errors.New("refresh token not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), decodedToken); err != nil {
		_ = s.repo.DeleteRefreshToken(claims.GUID)
		return models.TokenPair{}, errors.New("invalid refresh token")
	}

	if storedUserAgent != userAgent {
		_ = s.repo.DeleteRefreshToken(claims.GUID)
		return models.TokenPair{}, errors.New("user agent mismatch")
	}

	return s.GenerateTokenPair(claims.GUID, userAgent, ip)
}

func (s *authService) GetGUID(accessToken string) (string, error) {
	token, err := jwt.ParseWithClaims(accessToken, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.signingKey, nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(*models.TokenClaims)
	if !ok || !token.Valid {
		return "", errors.New("invalid token claims")
	}

	return claims.GUID, nil
}

func (s *authService) Logout(guid string) error {
	return s.repo.DeleteRefreshToken(guid)
}
