package repository

import (
	"github.com/jmoiron/sqlx"
)

func InitDB(db *sqlx.DB) error {
	query := `
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        guid VARCHAR(36) PRIMARY KEY,
        token_hash TEXT NOT NULL,
        user_agent TEXT NOT NULL,
        ip TEXT NOT NULL
    )`
	_, err := db.Exec(query)
	return err
}
