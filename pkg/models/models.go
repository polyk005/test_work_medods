package models

import "github.com/dgrijalva/jwt-go"

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshInput struct {
	RefreshToken string `json:"refresh_token"`
}

type TokenClaims struct {
	GUID string `json:"guid"`
	jwt.StandardClaims
}

type RefreshToken struct {
	GUID      string `db:"guid"`
	TokenHash string `db:"token_hash"`
	UserAgent string `db:"user_agent"`
	IP        string `db:"ip"`
}

type AuthService interface {
	GenerateTokenPair(guid, userAgent, ip string) (TokenPair, error)
	RefreshTokenPair(refreshToken, userAgent, ip string) (TokenPair, error)
	GetGUID(accessToken string) (string, error)
	Logout(guid string) error
}
