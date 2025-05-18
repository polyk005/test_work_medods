package repository

import (
	"dz1/pkg/models"

	"github.com/jmoiron/sqlx"
)

type AuthPostgres struct {
	db *sqlx.DB
}

func NewAuthPostgresDB(db *sqlx.DB) *AuthPostgres {
	return &AuthPostgres{db: db}
}

func (r *AuthPostgres) CreateRefreshToken(guid, tokenHash, userAgent, ip string) error {
	query := `INSERT INTO refresh_tokens (guid, token_hash, user_agent, ip) 
              VALUES ($1, $2, $3, $4)
              ON CONFLICT (guid) 
              DO UPDATE SET token_hash = $2, user_agent = $3, ip = $4`
	_, err := r.db.Exec(query, guid, tokenHash, userAgent, ip)
	return err
}

func (r *AuthPostgres) GetRefreshToken(guid string) (string, string, error) {
	var token models.RefreshToken
	query := `SELECT token_hash, user_agent FROM refresh_tokens WHERE guid = $1`
	err := r.db.Get(&token, query, guid)
	return token.TokenHash, token.UserAgent, err
}

func (r *AuthPostgres) DeleteRefreshToken(guid string) error {
	query := `DELETE FROM refresh_tokens WHERE guid = $1`
	_, err := r.db.Exec(query, guid)
	return err
}
