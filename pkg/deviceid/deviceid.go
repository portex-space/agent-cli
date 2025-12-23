package deviceid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// GetDeviceID returns a unique identifier for this device based on OS
func GetDeviceID() (string, error) {
	var id string
	var err error

	switch runtime.GOOS {
	case "darwin": // macOS
		id, err = getMacOSDeviceID()
	case "linux":
		id, err = getLinuxDeviceID()
	case "windows":
		id, err = getWindowsDeviceID()
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	if err != nil {
		return "", err
	}

	// Hash the ID to make it consistent length and format
	hash := sha256.Sum256([]byte(id))
	return hex.EncodeToString(hash[:])[:32], nil
}

// GetHostname returns the hostname of the device
func GetHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}
	return hostname, nil
}

func getMacOSDeviceID() (string, error) {
	// Use hardware UUID from system_profiler
	cmd := exec.Command("system_profiler", "SPHardwareDataType")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get macOS hardware info: %w", err)
	}

	// Parse UUID from output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Hardware UUID") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	return "", fmt.Errorf("could not find Hardware UUID")
}

func getLinuxDeviceID() (string, error) {
	// Try /etc/machine-id first (most modern Linux systems)
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	// Fallback to /var/lib/dbus/machine-id
	if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	// Last resort: use hostname + MAC address
	hostname, _ := os.Hostname()
	cmd := exec.Command("cat", "/sys/class/net/eth0/address")
	output, err := cmd.Output()
	if err != nil {
		// Try alternative network interface
		cmd = exec.Command("ip", "link", "show")
		output, _ = cmd.Output()
	}

	return hostname + "-" + strings.TrimSpace(string(output)), nil
}

func getWindowsDeviceID() (string, error) {
	// Use WMIC to get machine GUID
	cmd := exec.Command("wmic", "csproduct", "get", "UUID")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Windows machine GUID: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) >= 2 {
		uuid := strings.TrimSpace(lines[1])
		if uuid != "" {
			return uuid, nil
		}
	}

	return "", fmt.Errorf("could not find Windows machine GUID")
}
