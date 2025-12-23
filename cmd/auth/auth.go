package main

import (
	"fmt"

	"portex/agent/pkg/config"

	"github.com/spf13/cobra"
)

var (
	apiKey    string
	apiSecret string
)

var AuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate with Portex server",
	Long:  `Save your API credentials to authenticate with the Portex server.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if apiKey == "" || apiSecret == "" {
			return fmt.Errorf("both --api-key and --api-secret are required")
		}

		cfg := &config.Config{}
		cfg.Server.APIKey = apiKey
		cfg.Server.APISecret = apiSecret
		cfg.Server.URL = "http://localhost:8000"
		cfg.Server.WSURL = "ws://localhost:8080/ws"

		if err := config.Save(cfg, ""); err != nil {
			return fmt.Errorf("failed to save configuration: %w", err)
		}

		fmt.Println("✓ Authentication successful!")
		fmt.Println("✓ Credentials saved to ~/.portex/config.yaml")
		return nil
	},
}

func init() {
	AuthCmd.Flags().StringVar(&apiKey, "api-key", "", "API key from Portex dashboard")
	AuthCmd.Flags().StringVar(&apiSecret, "api-secret", "", "API secret from Portex dashboard")
	AuthCmd.MarkFlagRequired("api-key")
	AuthCmd.MarkFlagRequired("api-secret")
}
