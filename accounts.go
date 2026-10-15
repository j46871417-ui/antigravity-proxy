package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maxGeneratedAccounts = 100

func runUsersCommand(args []string) error {
	if len(args) == 0 || args[0] != "generate" {
		return fmt.Errorf("usage: antigravity-proxy users generate --host HOST [--port 50128] [--count 1] [--file users.json]")
	}

	defaultFile := os.Getenv("USERS_FILE")
	if defaultFile == "" {
		executable, err := os.Executable()
		if err == nil {
			defaultFile = filepath.Join(filepath.Dir(executable), "users.json")
		} else {
			defaultFile = "users.json"
		}
	}
	defaultPort := os.Getenv("PROXY_PORT")
	if defaultPort == "" {
		defaultPort = "50128"
	}

	flags := flag.NewFlagSet("users generate", flag.ContinueOnError)
	count := flags.Int("count", 1, "number of accounts to generate (1-100)")
	host := flags.String("host", os.Getenv("PROXY_PUBLIC_HOST"), "public proxy hostname or IP address")
	port := flags.String("port", defaultPort, "public proxy port")
	usersFile := flags.String("file", defaultFile, "users.json path (defaults to USERS_FILE or ./users.json)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *count < 1 || *count > maxGeneratedAccounts {
		return fmt.Errorf("--count must be between 1 and %d", maxGeneratedAccounts)
	}
	if strings.TrimSpace(*host) == "" || strings.ContainsAny(*host, "/?#@") {
		return fmt.Errorf("--host must be a hostname or IP address")
	}
	if strings.TrimSpace(*usersFile) == "" {
		return fmt.Errorf("--file cannot be empty")
	}
	portNumber, err := strconv.Atoi(*port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("--port must be an integer between 1 and 65535")
	}

	users, err := readUsers(*usersFile)
	if err != nil {
		return err
	}

	created := make([]struct{ username, password string }, 0, *count)
	for len(created) < *count {
		usernameSuffix, err := randomHex(6)
		if err != nil {
			return fmt.Errorf("generate username: %w", err)
		}
		username := "ag_" + usernameSuffix
		if _, exists := users[username]; exists {
			continue
		}
		password, err := randomHex(24)
		if err != nil {
			return fmt.Errorf("generate password: %w", err)
		}
		encodedPassword, err := json.Marshal(password)
		if err != nil {
			return err
		}
		users[username] = encodedPassword
		created = append(created, struct{ username, password string }{username, password})
	}

	if err := writeUsersAtomically(*usersFile, users); err != nil {
		return err
	}

	address := net.JoinHostPort(*host, strconv.Itoa(portNumber))
	for _, account := range created {
		connectionURL := (&url.URL{
			Scheme: "https",
			User:   url.UserPassword(account.username, account.password),
			Host:   address,
		}).String()
		fmt.Printf("%s\t%s\t%s\n", account.username, account.password, connectionURL)
	}
	return nil
}

func readUsers(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]json.RawMessage), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read users file %q: %w", path, err)
	}

	users := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("parse users file %q: %w", path, err)
	}
	if users == nil {
		users = make(map[string]json.RawMessage)
	}
	return users, nil
}

func writeUsersAtomically(path string, users map[string]json.RawMessage) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0750); err != nil {
		return fmt.Errorf("create users directory %q: %w", directory, err)
	}

	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return fmt.Errorf("encode users file: %w", err)
	}
	data = append(data, '\n')

	temp, err := os.CreateTemp(directory, ".users-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary users file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)

	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("secure temporary users file: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary users file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync temporary users file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary users file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace users file %q: %w", path, err)
	}
	return nil
}

func randomHex(byteCount int) (string, error) {
	value := make([]byte, byteCount)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
