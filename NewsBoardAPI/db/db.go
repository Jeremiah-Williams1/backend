package db

import (
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var DB *sql.DB // This is the global variable other packages will access

func Connect(connStr string) error {
	var err error

	// Assign the connection to the GLOBAL DB variable, not a local one
	DB, err = sql.Open("pgx", connStr)
	if err != nil {
		return err
	}

	// Check if the connection is actually alive
	err = DB.Ping()
	if err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	return nil
}

func InitializeSchema() error {
	const userSchema = `
    CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        username VARCHAR UNIQUE,
        password VARCHAR 
		email VARCHAR
		verified BOOL
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`

	const tokenSchema = `
    CREATE TABLE IF NOT EXISTS tokens (
        user_id UUID REFERENCES users(id),
        token VARCHAR NOT NULL UNIQUE,
		expires_at TIMESTAMPTZ NOT NULL
    );`

	_, err := DB.Exec(userSchema)
	if err != nil {
		return err
	}
	_, err = DB.Exec(tokenSchema)
	if err != nil {
		return err
	}
	return nil
}
