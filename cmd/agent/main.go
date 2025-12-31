package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"portex/agent/pkg/config"
	"portex/agent/pkg/deviceid"
	"portex/agent/pkg/forwarder"

	"github.com/mdp/qrterminal/v3"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "portex",
	Version: version,
	Short:   "Portex - Expose your local services to the internet",
	Long:    `Portex is a secure tunnel client that exposes your local services to the internet.`,
}

var version = "0.6.1"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Portex",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Portex version %s\n", version)
	},
}

// Auth command variables
var (
	apiKey    string
	apiSecret string
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Link this agent to your Portex dashboard",
	Long:  `Automatically log in and link this agent to your Portex account in the dashboard.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load config
		cfg, err := config.Load("")
		if err != nil {
			return fmt.Errorf("no agent configuration found. Please run 'portex start' first")
		}

		fmt.Println("🔐 Generating secure login link...")

		// Call API to create login token
		req, _ := http.NewRequest("POST", cfg.Server.URL+"/api/agent/create-login-token", nil)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s:%s", cfg.Server.APIKey, cfg.Server.APISecret))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to create login link: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to create login link (status %d): %s", resp.StatusCode, string(body))
		}

		var result struct {
			LoginURL  string `json:"login_url"`
			ExpiresIn int    `json:"expires_in"`
			Message   string `json:"message"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}

		fmt.Println("🔗 Opening browser for automatic login...")
		fmt.Printf("   Link expires in %d seconds\n", result.ExpiresIn)
		fmt.Printf("   If the browser doesn't open, please visit:\n   %s\n", result.LoginURL)

		// Open browser
		var openErr error
		switch runtime.GOOS {
		case "windows":
			openErr = exec.Command("rundll32", "url.dll,FileProtocolHandler", result.LoginURL).Start()
		case "darwin":
			openErr = exec.Command("open", result.LoginURL).Start()
		default: // linux, bsd, etc
			openErr = exec.Command("xdg-open", result.LoginURL).Start()
		}

		if openErr != nil {
			fmt.Printf("⚠️  Could not open browser: %v\n", openErr)
		}

		return nil
	},
}

// Start command variables
var (
	port       int
	subdomain  string
	pin        string
	allowedIPs []string
)

type TunnelResponse struct {
	Tunnel struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Subdomain string `json:"subdomain"`
		LocalPort int    `json:"local_port"`
		Protocol  string `json:"protocol"`
		PublicURL string `json:"public_url"`
		Status    string `json:"status"`
	} `json:"tunnel"`
	Message string `json:"message"`
}

type AgentRegistrationResponse struct {
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
	Message   string `json:"message"`
}

func registerNewAgent() (*AgentRegistrationResponse, error) {
	fmt.Println("⚙️  First time running? Configuring your agent identity...")

	// Get device ID
	deviceID, err := deviceid.GetDeviceID()
	if err != nil {
		return nil, fmt.Errorf("failed to get device ID: %w", err)
	}

	// Get hostname
	hostname, err := deviceid.GetHostname()
	if err != nil {
		hostname = "unknown"
	}

	// Get server URL from environment or use default
	serverURL := os.Getenv("PORTEX_SERVER_URL")
	if serverURL == "" {
		serverURL = "https://portex.space"
	}

	fmt.Printf("📡 Connecting to %s...\n", serverURL)
	fmt.Printf("🔑 Device ID: %s\n", deviceID)
	fmt.Printf("💻 Hostname: %s\n", hostname)

	// Prepare request body with device_id and hostname
	reqBody := map[string]string{
		"device_id": deviceID,
		"hostname":  hostname,
	}
	reqBodyJSON, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", serverURL+"/api/agent/register", bytes.NewBuffer(reqBodyJSON))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		// If production fails and we haven't specified a URL, maybe try localhost as fallback
		if os.Getenv("PORTEX_SERVER_URL") == "" && serverURL != "http://localhost:8000" {
			serverURL = "http://localhost:8000"
			req, _ = http.NewRequest("POST", serverURL+"/api/agent/register", bytes.NewBuffer(reqBodyJSON))
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Content-Type", "application/json")
			resp, err = http.DefaultClient.Do(req)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to reach Portex server: %w", err)
		}
	}

	defer resp.Body.Close()

	// Accept both 200 (existing) and 201 (new)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)

		return nil, fmt.Errorf("server rejected registration (status %d): %s", resp.StatusCode, string(body))
	}

	var regResp AgentRegistrationResponse

	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Determine WebSocket URL based on server URL
	wsURL := os.Getenv("PORTEX_WS_URL")

	if wsURL == "" {
		if strings.HasPrefix(serverURL, "https://") {
			wsURL = "wss://" + strings.TrimPrefix(serverURL, "https://") + "/ws"
		} else {
			// Handle http://localhost:8000 -> ws://localhost:8080/ws correctly
			// For local dev with Reverb, it's usually 8080
			host := strings.TrimPrefix(serverURL, "http://")
			if strings.Contains(host, "localhost:8000") {
				wsURL = "ws://localhost:8080/ws"
			} else {
				wsURL = "ws://" + host + "/ws"
			}
		}
	}

	// Save config
	cfg := &config.Config{}
	cfg.Server.APIKey = regResp.APIKey
	cfg.Server.APISecret = regResp.APISecret
	cfg.Server.URL = serverURL
	cfg.Server.WSURL = wsURL

	if err := config.Save(cfg, ""); err != nil {
		return nil, fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("✓ Agent registered and ready!\n")
	return &regResp, nil
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start a tunnel",
	Long:  `Start a tunnel to expose your local service to the internet.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if port == 0 {
			return fmt.Errorf("--port is required")
		}

		fmt.Println("\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
		fmt.Println("\033[1;32m  Portex Agent\033[0m")
		fmt.Println("\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
		fmt.Println()

		// Try to load config
		cfg, err := config.Load("")
		if err != nil {
			// Silently try to register
			reg, err := registerNewAgent()
			if err != nil {
				return fmt.Errorf("could not start without configuration: %w\nPlease check if the Portex server is running", err)
			}
			cfg = &config.Config{}
			cfg.Server.APIKey = reg.APIKey
			cfg.Server.APISecret = reg.APISecret
			cfg.Server.URL = os.Getenv("PORTEX_SERVER_URL")
			if cfg.Server.URL == "" {
				cfg.Server.URL = "https://portex.space"
			}
			// WS URL is handled inside the registerNewAgent or we can reload
			cfg, _ = config.Load("")
		}

		// Authenticate
		authReq := map[string]string{
			"api_key":    cfg.Server.APIKey,
			"api_secret": cfg.Server.APISecret,
		}
		authBody, _ := json.Marshal(authReq)

		req, _ := http.NewRequest("POST", cfg.Server.URL+"/api/agent/auth", bytes.NewBuffer(authBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to authenticate: %w", err)
		}

		// If credentials are invalid, re-register and try one more time
		if resp.StatusCode == 401 {
			resp.Body.Close()
			fmt.Println("⚠️  Stored credentials invalid, automatically re-registering...")

			regResp, err := registerNewAgent()
			if err != nil {
				return err
			}

			// Retry with new credentials
			cfg.Server.APIKey = regResp.APIKey
			cfg.Server.APISecret = regResp.APISecret

			authReq = map[string]string{
				"api_key":    cfg.Server.APIKey,
				"api_secret": cfg.Server.APISecret,
			}
			authBody, _ = json.Marshal(authReq)
			resp, err = http.Post(cfg.Server.URL+"/api/agent/auth", "application/json", bytes.NewBuffer(authBody))
			if err != nil {
				return fmt.Errorf("failed to authenticate after re-registration: %w", err)
			}
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("authentication failed (status %d): %s", resp.StatusCode, string(body))
		}

		// Create tunnel
		tunnelReq := map[string]interface{}{
			"local_port": port,
		}
		if subdomain != "" {
			tunnelReq["subdomain"] = subdomain
		}
		if pin != "" {
			tunnelReq["pin"] = pin
		}
		if len(allowedIPs) > 0 {
			tunnelReq["allowed_ips"] = allowedIPs
		}
		tunnelBody, _ := json.Marshal(tunnelReq)

		req, _ = http.NewRequest("POST", cfg.Server.URL+"/api/agent/tunnels", bytes.NewBuffer(tunnelBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s:%s", cfg.Server.APIKey, cfg.Server.APISecret))

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to create tunnel: %w", err)
		}
		defer resp.Body.Close()

		// Accept both 200 (updated) and 201 (created)
		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to create tunnel: %s", string(body))
		}

		var tunnelResp TunnelResponse
		if err := json.NewDecoder(resp.Body).Decode(&tunnelResp); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}

		// Generate login URL automatically
		loginReq, _ := http.NewRequest("POST", cfg.Server.URL+"/api/agent/create-login-token", nil)
		loginReq.Header.Set("Accept", "application/json")
		loginReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s:%s", cfg.Server.APIKey, cfg.Server.APISecret))

		loginResp, err := http.DefaultClient.Do(loginReq)
		var loginURL string
		if err == nil && loginResp.StatusCode == 200 {
			defer loginResp.Body.Close()
			var loginResult struct {
				LoginURL string `json:"login_url"`
			}
			if json.NewDecoder(loginResp.Body).Decode(&loginResult) == nil {
				loginURL = loginResult.LoginURL
			}
		}

		// Fetch usage stats
		statsReq, _ := http.NewRequest("GET", cfg.Server.URL+"/api/agent/usage-stats", nil)
		statsReq.Header.Set("Accept", "application/json")
		statsReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s:%s", cfg.Server.APIKey, cfg.Server.APISecret))

		var usageStats struct {
			Tier               string  `json:"tier"`
			UsedFormatted      string  `json:"used_formatted"`
			LimitFormatted     string  `json:"limit_formatted"`
			RemainingFormatted string  `json:"remaining_formatted"`
			PercentageUsed     float64 `json:"percentage_used"`
			IsPremium          bool    `json:"is_premium"`
		}

		statsResp, err := http.DefaultClient.Do(statsReq)
		if err == nil && statsResp.StatusCode == 200 {
			defer statsResp.Body.Close()
			json.NewDecoder(statsResp.Body).Decode(&usageStats)
		}

		// Modern ngrok-style output
		fmt.Println()
		fmt.Println("\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
		// Clear screen and show modern minimal header
		fmt.Print("\033[H\033[2J")
		fmt.Printf("\033[1;38;5;208m  PORTEX\033[0m \033[38;5;244m%s\033[0m\n", version)
		fmt.Println("\033[38;5;238m  ────────────────────────────────────────────────────────────\033[0m")

		fmt.Printf("  \033[1mStatus\033[0m        \033[32mOnline\033[0m\n")
		fmt.Printf("  \033[1mAccount\033[0m       \033[38;5;248m%s\033[0m\n", cfg.Server.APIKey[:15]+"...")
		if !usageStats.IsPremium && usageStats.UsedFormatted != "" {
			fmt.Printf("  \033[1mUsage\033[0m         \033[38;5;248m%s / %s (%.1f%%)\033[0m\n",
				usageStats.UsedFormatted, usageStats.LimitFormatted, usageStats.PercentageUsed)
		}
		if len(allowedIPs) > 0 {
			fmt.Printf("  \033[1mWhitelist\033[0m     \033[32mActive (%d IPs)\033[0m\n", len(allowedIPs))
		}
		fmt.Println()

		fmt.Println("  \033[1;38;5;208mACTIVE TUNNEL\033[0m")
		fmt.Printf("  \033[1;37m%s\033[0m\n", tunnelResp.Tunnel.PublicURL)
		fmt.Printf("  \033[38;5;244m↳ forwarding to http://localhost:%d\033[0m\n", tunnelResp.Tunnel.LocalPort)
		fmt.Println()

		// Show QR Code for mobile testing
		if strings.HasPrefix(tunnelResp.Tunnel.PublicURL, "http") {
			fmt.Println("  \033[1mSCAN FOR MOBILE\033[0m")
			config := qrterminal.Config{
				Level:     qrterminal.L,
				Writer:    os.Stdout,
				BlackChar: qrterminal.BLACK,
				WhiteChar: qrterminal.WHITE,
				QuietZone: 1,
			}
			qrterminal.GenerateWithConfig(tunnelResp.Tunnel.PublicURL, config)
			fmt.Println()
		}

		if loginURL != "" {
			fmt.Println("  \033[1mDASHBOARD\033[0m")
			fmt.Printf("  \033[34m%s\033[0m\n", loginURL)
			fmt.Println()
		}

		fmt.Println("\033[38;5;238m  ────────────────────────────────────────────────────────────\033[0m")
		fmt.Println("\033[1;90m  Press Ctrl+C to stop\033[0m")
		fmt.Println()
		forwarderInst := forwarder.New(
			port,
			cfg.Server.WSURL,
			tunnelResp.Tunnel.Subdomain,
			tunnelResp.Tunnel.ID,
		)

		if err := forwarderInst.Start(); err != nil {
			return fmt.Errorf("failed to start forwarder: %w", err)
		}

		fmt.Println()

		// Start heartbeat goroutine
		go func() {
			for {
				time.Sleep(10 * time.Second)
				req, _ := http.NewRequest("POST", cfg.Server.URL+"/api/agent/heartbeat", nil)
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s:%s", cfg.Server.APIKey, cfg.Server.APISecret))
				req.Header.Set("Accept", "application/json")

				resp, err := http.DefaultClient.Do(req)
				if err == nil {
					resp.Body.Close()
				}
			}
		}()

		// Keep running
		select {}
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored credentials",
	Long:  `Remove the stored API credentials and reset the agent.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}

		configPath := filepath.Join(home, ".portex", "config.yaml")

		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			fmt.Println("✓ No configuration found")
			return nil
		}

		if err := os.Remove(configPath); err != nil {
			return fmt.Errorf("failed to remove config: %w", err)
		}

		fmt.Println("✓ Logged out. Configuration removed.")
		return nil
	},
}

func init() {
	// Login command flags
	loginCmd.Flags().StringVar(&apiKey, "api-key", "", "API key from Portex dashboard")
	loginCmd.Flags().StringVar(&apiSecret, "api-secret", "", "API secret from Portex dashboard")

	// Start command flags
	startCmd.Flags().IntVarP(&port, "port", "p", 0, "Local port to forward")
	startCmd.Flags().StringVarP(&subdomain, "subdomain", "s", "", "Custom subdomain (optional)")
	startCmd.Flags().StringVar(&pin, "pin", "", "PIN protection (4 digits)")
	startCmd.Flags().StringSliceVarP(&allowedIPs, "allow-ip", "a", []string{}, "Allowed IP addresses for whitelisting")
	startCmd.MarkFlagRequired("port")

	// Share command flags
	shareCmd.Flags().StringVarP(&subdomain, "subdomain", "s", "", "Custom subdomain (optional)")
	shareCmd.Flags().StringVar(&pin, "pin", "", "PIN protection (4 digits)")
	shareCmd.Flags().StringSliceVarP(&allowedIPs, "allow-ip", "a", []string{}, "Allowed IP addresses for whitelisting")

	// Add commands to root
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(shareCmd)
	rootCmd.AddCommand(versionCmd)
}

var shareCmd = &cobra.Command{
	Use:   "share [directory]",
	Short: "Share a local directory over a tunnel",
	Long:  `Serve a local directory as a web server and expose it to the internet using a Portex tunnel.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := args[0]
		absDir, err := filepath.Abs(dir)
		if err != nil {
			return fmt.Errorf("invalid directory: %w", err)
		}

		if info, err := os.Stat(absDir); err != nil || !info.IsDir() {
			return fmt.Errorf("directory does not exist: %s", absDir)
		}

		// Start local server on a random available port
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("failed to start local server: %w", err)
		}
		localPort := listener.Addr().(*net.TCPAddr).Port
		listener.Close()

		go func() {
			fmt.Printf("📁 Serving directory: %s\n", absDir)
			err := http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", localPort), http.FileServer(http.Dir(absDir)))
			if err != nil {
				fmt.Printf("❌ Local server failed: %v\n", err)
				os.Exit(1)
			}
		}()

		// Set the port and call the start command logic
		port = localPort
		return startCmd.RunE(cmd, args)
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
