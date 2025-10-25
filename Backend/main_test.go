package main

import (
	"database/sql"
	"testing"
	"time"
)

func setupTestDB(t *testing.T) {
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}

	usersTable := `
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL
    );
    `
	if _, err = db.Exec(usersTable); err != nil {
		t.Fatalf("failed to create users table: %v", err)
	}

	serversTable := `
    CREATE TABLE IF NOT EXISTS servers (
        name TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL
    );
    `
	if _, err = db.Exec(serversTable); err != nil {
		t.Fatalf("failed to create servers table: %v", err)
	}
}

func TestUserCreateAndGet(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	username := "alice"
	hash := "hashed-password"

	if err := dbCreateUser(username, hash); err != nil {
		t.Fatalf("dbCreateUser failed: %v", err)
	}

	got, err := dbGetUserHash(username)
	if err != nil {
		t.Fatalf("dbGetUserHash failed: %v", err)
	}
	if got != hash {
		t.Fatalf("expected hash %q, got %q", hash, got)
	}
}

func TestServerCreateAndGet(t *testing.T) {
	setupTestDB(t)
	defer db.Close()

	name := "testserver"
	hash := "server-hash"

	if err := dbCreateServer(name, hash); err != nil {
		t.Fatalf("dbCreateServer failed: %v", err)
	}

	got, err := dbGetServerHash(name)
	if err != nil {
		t.Fatalf("dbGetServerHash failed: %v", err)
	}
	if got != hash {
		t.Fatalf("expected hash %q, got %q", hash, got)
	}
}

func TestTokenGenerationUniqueness(t *testing.T) {
	// Quick check that generateToken produces reasonably unique tokens
	a := generateToken()
	time.Sleep(1 * time.Nanosecond)
	b := generateToken()
	if a == b {
		t.Fatalf("expected tokens to differ, got same: %s", a)
	}
}
