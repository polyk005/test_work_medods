package service

import (
	"dz1/pkg/models"
	"dz1/pkg/repository"
)

type Service struct {
	Authorization models.AuthService
}

func NewService(repos *repository.Repository, signingKey, webhookURL string) *Service {
	return &Service{
		Authorization: NewAuthService(repos.Authorization, signingKey, webhookURL),
	}
}
