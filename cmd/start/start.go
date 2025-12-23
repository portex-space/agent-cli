package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	port      int
	subdomain string
)

var StartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start a tunnel",
	Long:  `Start a tunnel to expose your local service to the internet.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if port == 0 {
			return fmt.Errorf("--port is required")
		}

		fmt.Printf("Starting tunnel...\n")
		fmt.Printf("Local port: %d\n", port)
		if subdomain != "" {
			fmt.Printf("Subdomain: %s\n", subdomain)
		}
		fmt.Println("\nTunnel is not yet implemented. Coming soon!")

		return nil
	},
}

func init() {
	StartCmd.Flags().IntVarP(&port, "port", "p", 0, "Local port to forward")
	StartCmd.Flags().StringVarP(&subdomain, "subdomain", "s", "", "Custom subdomain (optional)")
	StartCmd.MarkFlagRequired("port")
}
