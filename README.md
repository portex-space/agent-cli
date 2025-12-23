# Portex Agent 🚀

The Portex Agent is a high-performance, standalone CLI tool written in **Go**. It allows you to securely expose your local development environment to the internet with a single command.

## Key Features

- ⚡ **Zero Configuration**: Start tunneling in seconds without touching your network settings.
- 🔒 **Secure by Default**: All traffic is encrypted via TLS.
- 🛠️ **Developer-First**: Integrated traffic inspection and request logging.
- 📁 **Instant Sharing**: Serve any local directory as a website with `portex share`.
- 🔑 **PIN Protection**: Protect your tunnels with 4-digit PINs for private demos.
- 💻 **Cross-Platform**: Native support for macOS (Intel/M1), Linux, and Windows.

## Installation

### macOS & Linux
```bash
curl -fsSL https://portex.space/install.sh | bash
```

### Windows (PowerShell)
```powershell
iwr https://portex.space/install.ps1 | iex
```

## Quick Start

### 1. Expose a local port
Forward traffic from a public URL to your local port 3000:
```bash
portex start --port 3000
```

### 2. Use a custom subdomain
```bash
portex start --port 8000 --subdomain my-awesome-app
```

### 3. Protect with a PIN
```bash
portex start --port 8080 --pin 1234
```

### 4. Share a static directory
```bash
portex share ./dist
```

## Development

If you want to build the agent from source:

### Prerequisites
- Go 1.21 or higher

### Build
```bash
cd agent
go build -o portex ./cmd/agent
```

## How It Works

The agent establishes a persistent **Secure WebSocket (WSS)** connection to the Portex Cloud Gateway. When a request hits your public URL, the gateway proxies the data through this WebSocket tunnel to your local agent, which then forwards it to your local server.

## Licensing

Portex is open-source. See the project root for license information.

---
Built with intensity for developers who care about their tools. [portex.space](https://portex.space)
