package repository

import "github.com/jmoiron/sqlx"

type Authorization interface {
	CreateRefreshToken(guid, tokenHash, userAgent, ip string) error
	GetRefreshToken(guid string) (string, string, error)
	DeleteRefreshToken(guid string) error
}

type Repository struct {
	Authorization
}

func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{
		Authorization: NewAuthPostgresDB(db),
	}
}
