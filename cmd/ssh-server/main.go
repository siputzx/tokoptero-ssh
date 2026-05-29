package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/siputzx/tokoptero-ssh/internal/config"
	"github.com/siputzx/tokoptero-ssh/internal/handlers"
)

// Rate limiter: max attempts per IP per window
type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	maxTries int
	window   time.Duration
}

func newRateLimiter(maxTries int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		attempts: make(map[string][]time.Time),
		maxTries: maxTries,
		window:   window,
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Clean old entries
	recent := make([]time.Time, 0)
	for _, t := range rl.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	rl.attempts[ip] = recent

	if len(recent) >= rl.maxTries {
		return false
	}

	rl.attempts[ip] = append(recent, now)
	return true
}

func checkWritePermission(dir string) error {
	testFile := filepath.Join(dir, ".write_test")
	err := os.WriteFile(testFile, []byte(""), 0600)
	if err != nil {
		return err
	}
	os.Remove(testFile)
	return nil
}

func generateRandomPassword() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func loadOrCreateHostKey() (gossh.Signer, error) {
	hostKeyPath := filepath.Join("/", "ssh_host_rsa_key")
	if err := checkWritePermission("/"); err != nil {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			homeDir = "/"
		}
		hostKeyPath = filepath.Join(homeDir, "ssh_host_rsa_key")
	}

	if _, err := os.Stat(hostKeyPath); os.IsNotExist(err) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		})
		err = os.WriteFile(hostKeyPath, privateKeyPEM, 0600)
		if err != nil {
			return nil, err
		}
		signer, err := gossh.NewSignerFromKey(privateKey)
		if err != nil {
			return nil, err
		}
		color.Yellow("Created new host key at %s", hostKeyPath)
		return signer, nil
	} else if err != nil {
		return nil, err
	}

	privateKeyBytes, err := os.ReadFile(hostKeyPath)
	if err != nil {
		return nil, err
	}
	signer, err := gossh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

func loadPublicKeys(authorizedKeysPath string) (map[string]bool, error) {
	if authorizedKeysPath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	keys := make(map[string]bool)
	for len(data) > 0 {
		pubKey, _, _, rest, err := gossh.ParseAuthorizedKey(data)
		if err != nil {
			break
		}
		keys[string(pubKey.Marshal())] = true
		data = rest
	}
	return keys, nil
}

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		color.Red("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	hostKey, err := loadOrCreateHostKey()
	if err != nil {
		color.Red("Failed to load/create host key: %v", err)
		os.Exit(1)
	}

	if cfg.SSH.Port == "" {
		cfg.SSH.Port = "2222"
	}

	var sshTimeout time.Duration
	if cfg.SSH.Timeout > 0 {
		sshTimeout = time.Duration(cfg.SSH.Timeout) * time.Second
	}

	// Load authorized keys for public key auth
	authorizedKeys, _ := loadPublicKeys(cfg.SSH.AuthorizedKeys)

	// Rate limiter: 5 attempts per IP per 60 seconds by default
	maxTries := cfg.SSH.MaxRetries
	if maxTries <= 0 {
		maxTries = 5
	}
	limiter := newRateLimiter(maxTries, 60*time.Second)

	server := &ssh.Server{
		Addr: ":" + cfg.SSH.Port,

		// Combined auth: try public key first, then password
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			ip, _, _ := net.SplitHostPort(ctx.RemoteAddr().String())

			if len(authorizedKeys) == 0 {
				return false // Reject public key, fall through to password
			}

			if !limiter.allow(ip) {
				color.Red("Rate limited: %s", ip)
				return false
			}

			success := cfg.SSH.User == ctx.User() && authorizedKeys[string(key.Marshal())]
			handlers.LogLoginAttempt(ip, ctx.User(), success, "publickey")
			return success
		},

		PasswordHandler: func(ctx ssh.Context, pass string) bool {
			ip, _, _ := net.SplitHostPort(ctx.RemoteAddr().String())

			if !limiter.allow(ip) {
				color.Red("Rate limited: %s", ip)
				return false
			}

			success := cfg.SSH.User == ctx.User() && config.CheckPassword(cfg.SSH.Password, pass)
			handlers.LogLoginAttempt(ip, ctx.User(), success, "password")
			return success
		},
	}

	server.AddHostKey(hostKey)

	if cfg.SFTP.Enable {
		sftpRoot := cfg.SFTP.Root
		if sftpRoot == "" {
			homeDir, _ := os.UserHomeDir()
			sftpRoot = homeDir
		}
		server.SubsystemHandlers = map[string]ssh.SubsystemHandler{
			"sftp": handlers.SFTPHandlerWithRoot(sftpRoot),
		}
	}

	if cfg.SSH.Password == "" && cfg.SSH.AuthorizedKeys == "" {
		server.PasswordHandler = nil
		server.PublicKeyHandler = nil
	}

	server.Handle(handlers.SessionHandler)

	if sshTimeout > 0 {
		server.MaxTimeout = sshTimeout
		server.IdleTimeout = sshTimeout
	}

	// Print startup info
	color.Blue("╔══════════════════════════════════════╗")
	color.Blue("║       Tokoptero SSH Server           ║")
	color.Blue("╚══════════════════════════════════════╝")
	color.Cyan("  Port: %s", cfg.SSH.Port)
	color.Cyan("  User: %s", cfg.SSH.User)
	if authorizedKeys != nil {
		color.Cyan("  Auth: public key (%d keys loaded)", len(authorizedKeys))
	}
	if config.IsBcryptHash(cfg.SSH.Password) {
		color.Cyan("  Auth: password (bcrypt)")
	} else if config.IsArgon2Hash(cfg.SSH.Password) {
		color.Cyan("  Auth: password (argon2)")
	} else if cfg.SSH.Password != "" {
		color.Cyan("  Auth: password (plaintext)")
	}
	color.Cyan("  SFTP: %v (root: %s)", cfg.SFTP.Enable, cfg.SFTP.Root)
	color.Cyan("  Rate limit: %d req/60s", maxTries)
	if sshTimeout > 0 {
		color.Cyan("  Timeout: %s", sshTimeout)
	}
	color.Yellow("  Type 'q' to exit")

	go func() {
		log.Fatal(server.ListenAndServe())
	}()

	// Handle graceful shutdown on SIGTERM/SIGINT
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	scanner := bufio.NewScanner(os.Stdin)
	go func() {
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "q" {
				sigCh <- syscall.SIGTERM
			}
		}
	}()

	<-sigCh
	color.Yellow("Shutting down SSH server...")
	server.Close()
	os.Exit(0)
}
