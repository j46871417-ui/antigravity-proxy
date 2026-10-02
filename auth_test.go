package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthManager(t *testing.T) {
	tmpDir := t.TempDir()
	usersFile := filepath.Join(tmpDir, "users.json")

	initialJSON := `{"alice": "secret1", "bob": ["pass1", "pass2"]}`
	if err := os.WriteFile(usersFile, []byte(initialJSON), 0644); err != nil {
		t.Fatalf("Failed to write users file: %v", err)
	}

	auth := NewAuthManager(usersFile, "admin", "adminpass")

	// 1. Static credentials
	if !auth.Authenticate("admin", "adminpass") {
		t.Errorf("Expected admin to authenticate with adminpass")
	}
	if auth.Authenticate("admin", "wrong") {
		t.Errorf("Expected admin to fail with wrong pass")
	}

	// 2. Multi-user file string password
	if !auth.Authenticate("alice", "secret1") {
		t.Errorf("Expected alice to authenticate with secret1")
	}
	if auth.Authenticate("alice", "secret2") {
		t.Errorf("Expected alice to fail with secret2")
	}

	// 3. Multi-user file array password
	if !auth.Authenticate("bob", "pass1") {
		t.Errorf("Expected bob to authenticate with pass1")
	}
	if !auth.Authenticate("bob", "pass2") {
		t.Errorf("Expected bob to authenticate with pass2")
	}
	if auth.Authenticate("bob", "pass3") {
		t.Errorf("Expected bob to fail with pass3")
	}

	// 4. Hot reload
	time.Sleep(10 * time.Millisecond)
	updatedJSON := `{"charlie": "newpass"}`
	if err := os.WriteFile(usersFile, []byte(updatedJSON), 0644); err != nil {
		t.Fatalf("Failed to update users file: %v", err)
	}

	if !auth.Authenticate("charlie", "newpass") {
		t.Errorf("Expected charlie to authenticate after hot reload")
	}
	if auth.Authenticate("alice", "secret1") {
		t.Errorf("Expected alice to be removed after hot reload")
	}
}
