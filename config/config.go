package config

import (
	"log"
	//"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server struct {
		Port string `toml:"port"`
	} `toml:"server"`
	Database struct {
		Host     string `toml:"host"`
		Port     string `toml:"port"`
		Name     string `toml:"name"`
		Username string `toml:"username"`
		Password string `toml:"password"`
	} `toml:"database"`
	Vault struct {
		Host           string `toml:"host"`
		Port           string `toml:"port"`
		Scheme         string `toml:"scheme"`
		Authentication string `toml:"authentication"`
		Mount          string `toml:"mount"`
		Role           string `toml:"role"`
		Namespace      string `toml:"namespace"`
		Credential     struct {
			RoleID         string `mapstructure:"role-id"`
			SecretID       string `mapstructure:"secret-id"`
			Token          string `toml:"token"`
			ServiceAccount string `toml:"serviceaccount"`
		} `toml:"credential"`
		Database struct {
			Mount string `toml:"mount"`
			Role  string `toml:"role"`
		} `toml:"database"`
		Transit struct {
			Key   string `toml:"key"`
			Mount string `toml:"mount"`
		} `toml:"transit"`
		Pki struct {
			Role  string `toml:"role"`
			CN    string `toml:"cn"`
			Mount string `toml:"mount"`
		} `toml:"pki"`
	} `toml:"vault"`
}

func (c *Config) Read() {
	viper.SetConfigName("config")
	viper.SetConfigType("toml")
	viper.AddConfigPath(".")
	//viper.AutomaticEnv()
	//viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	//Server Defaults
	viper.SetDefault("Server.Port", "8080")
	//Vault Defaults
	viper.SetDefault("Vault.Host", "127.0.0.1")
	viper.SetDefault("Vault.Port", "8200")
	viper.SetDefault("Vault.Scheme", "http")
	viper.SetDefault("Vault.Authentication", "token")
	//DB Defaults
	viper.SetDefault("Database.Host", "localhost")
	viper.SetDefault("Database.Port", "5432")
	viper.SetDefault("Database.Name", "postgres")
	//Read it
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}
	err := viper.Unmarshal(&c)
	if err != nil {
		log.Fatalf("unable to decode into struct, %v", err)
	}
}
