package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type Config struct {
	SSH struct {
		Port           string `yaml:"port"`
		User           string `yaml:"user"`
		Password       string `yaml:"password"`
		AuthorizedKeys string `yaml:"authorized_keys"`
		Timeout        int    `yaml:"timeout"`
		MaxRetries     int    `yaml:"max_retries"`
	} `yaml:"ssh"`
	SFTP struct {
		Enable bool   `yaml:"enable"`
		Root   string `yaml:"root"`
	} `yaml:"sftp"`
}

var configPath string

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

func init() {
	configPath = filepath.Join("/", "ssh_config.yml")
	if err := checkWritePermission("/"); err != nil {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			homeDir = "/"
		}
		configPath = filepath.Join(homeDir, "ssh_config.yml")
	}
}

// CreateDefaultConfig creates a default configuration file
func CreateDefaultConfig() error {
	defaultConfig := Config{}
	defaultConfig.SSH.Port = "2222"
	defaultConfig.SSH.User = "root"
	defaultConfig.SSH.Password = generateRandomPassword() // Random, not "password"!
	defaultConfig.SSH.Timeout = 300
	defaultConfig.SSH.MaxRetries = 5
	defaultConfig.SFTP.Enable = true
	defaultConfig.SFTP.Root = ""

	yamlData, err := yaml.Marshal(&defaultConfig)
	if err != nil {
		return err
	}

	color.Yellow("Generated random password. Save it before closing this terminal!")
	color.Yellow("Password: %s", defaultConfig.SSH.Password)

	return os.WriteFile(configPath, yamlData, 0600) // 0600 instead of 0644 for security
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}

	_, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		color.Yellow("Configuration file not found. Creating default config at %s", configPath)
		if err := CreateDefaultConfig(); err != nil {
			color.Red("Error creating default config: %v", err)
			return nil, err
		}
	} else if err != nil {
		color.Red("Error checking config file: %v", err)
		return nil, err
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		color.Red("Error reading config file: %v", err)
		return nil, err
	}

	if err := yaml.Unmarshal(content, cfg); err != nil {
		color.Red("Error parsing config: %v", err)
		return nil, err
	}

	return cfg, nil
}

func IsBcryptHash(str string) bool {
	return len(str) > 0 && (strings.HasPrefix(str, "$2a$") ||
		strings.HasPrefix(str, "$2b$") ||
		strings.HasPrefix(str, "$2y$"))
}

func CheckPassword(storedPassword, inputPassword string) bool {
	if IsArgon2Hash(storedPassword) {
		match, err := ComparePasswordAndHash(inputPassword, storedPassword)
		return err == nil && match
	}
	if IsBcryptHash(storedPassword) {
		err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
		return err == nil
	}
	return storedPassword == inputPassword
}
