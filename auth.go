package main

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

type AuthManager struct {
	mu            sync.RWMutex
	usersFilePath string
	staticUser    string
	staticPass    string
	usersCache    map[string][]string
	lastModTime   time.Time
}

func NewAuthManager(usersFilePath, staticUser, staticPass string) *AuthManager {
	am := &AuthManager{
		usersFilePath: usersFilePath,
		staticUser:    staticUser,
		staticPass:    staticPass,
		usersCache:    make(map[string][]string),
	}
	am.reloadUsers()
	return am
}

func (am *AuthManager) reloadUsers() {
	if am.usersFilePath == "" {
		return
	}

	info, err := os.Stat(am.usersFilePath)
	if err != nil {
		return
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	if info.ModTime().Equal(am.lastModTime) {
		return
	}

	data, err := os.ReadFile(am.usersFilePath)
	if err != nil {
		log.Printf("[Auth] Error reading users file %s: %v", am.usersFilePath, err)
		return
	}

	// Unmarshal raw JSON to support both string and list of strings for passwords
	var rawUsers map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawUsers); err != nil {
		log.Printf("[Auth] Error parsing users JSON %s: %v", am.usersFilePath, err)
		return
	}

	newCache := make(map[string][]string, len(rawUsers))
	for user, rawVal := range rawUsers {
		var singlePass string
		if err := json.Unmarshal(rawVal, &singlePass); err == nil {
			newCache[user] = []string{singlePass}
			continue
		}

		var multiPass []string
		if err := json.Unmarshal(rawVal, &multiPass); err == nil {
			newCache[user] = multiPass
			continue
		}
	}

	am.usersCache = newCache
	am.lastModTime = info.ModTime()
	log.Printf("[Auth] Successfully loaded %d users from %s", len(newCache), am.usersFilePath)
}

// Authenticate verifies the user credentials against static config and hot-reloaded users.json.
func (am *AuthManager) Authenticate(user, pass string) bool {
	// 1. Check static credentials
	if am.staticUser != "" && am.staticPass != "" {
		if user == am.staticUser && pass == am.staticPass {
			return true
		}
	}

	// 2. Check multi-user file
	am.reloadUsers()

	am.mu.RLock()
	defer am.mu.RUnlock()

	validPasswords, found := am.usersCache[user]
	if !found {
		return false
	}

	for _, p := range validPasswords {
		if p == pass {
			return true
		}
	}

	return false
}
