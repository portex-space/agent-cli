package forwarder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/gorilla/websocket"
)

// Message types
const (
	MessageTypeHTTPRequest  = "http_request"
	MessageTypeHTTPResponse = "http_response"
	MessageTypePing         = "ping"
	MessageTypePong         = "pong"
)

type Message struct {
	Type      string          `json:"type"`
	RequestID string          `json:"request_id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

type HTTPRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body,omitempty"`
}

type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body,omitempty"`
}

type Forwarder struct {
	LocalPort int
	ServerURL string
	Subdomain string
	TunnelID  string
	conn      *websocket.Conn
	writeMu   sync.Mutex // Protect concurrent writes to WebSocket
}

func New(localPort int, serverURL, subdomain, tunnelID string) *Forwarder {
	return &Forwarder{
		LocalPort: localPort,
		ServerURL: serverURL,
		Subdomain: subdomain,
		TunnelID:  tunnelID,
	}
}

func (f *Forwarder) Start() error {
	// Build WebSocket URL
	u, err := url.Parse(f.ServerURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}

	// Convert http:// to ws://
	if u.Scheme == "http" {
		u.Scheme = "ws"
	} else if u.Scheme == "https" {
		u.Scheme = "wss"
	}

	u.Path = "/ws"
	q := u.Query()
	q.Set("subdomain", f.Subdomain)
	q.Set("tunnel_id", f.TunnelID)
	u.RawQuery = q.Encode()

	log.Printf("Connecting to WebSocket: %s", u.String())

	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}
	f.conn = conn

	log.Println("✓ Connected to server via WebSocket")
	log.Printf("✓ Forwarding traffic to localhost:%d", f.LocalPort)

	// Start reading messages
	go f.readPump()

	return nil
}

func (f *Forwarder) readPump() {
	defer f.conn.Close()

	for {
		var msg Message
		err := f.conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		switch msg.Type {
		case MessageTypeHTTPRequest:
			go f.handleHTTPRequest(msg.RequestID, msg.Data)
		case MessageTypePing:
			// Send pong (protected by mutex)
			f.writeMu.Lock()
			f.conn.WriteJSON(Message{Type: MessageTypePong})
			f.writeMu.Unlock()
		}
	}
}

func (f *Forwarder) handleHTTPRequest(requestID string, data json.RawMessage) {
	var req HTTPRequest
	if err := json.Unmarshal(data, &req); err != nil {
		log.Printf("Failed to unmarshal HTTP request: %v", err)
		return
	}

	// Forward to local port
	localURL := fmt.Sprintf("http://localhost:%d%s", f.LocalPort, req.Path)

	httpReq, err := http.NewRequest(req.Method, localURL, bytes.NewReader(req.Body))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	// Copy headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// Send request
	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("Failed to forward request: %v", err)
		// Send error response
		f.sendHTTPResponse(requestID, HTTPResponse{
			StatusCode: http.StatusBadGateway,
			Headers:    map[string]string{"Content-Type": "text/plain"},
			Body:       []byte("Failed to connect to local service"),
		})
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		return
	}

	// Convert headers to map
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// Send response back
	httpResp := HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
	}

	f.sendHTTPResponse(requestID, httpResp)

	log.Printf("Forwarded %s %s -> localhost:%d (status: %d)", req.Method, req.Path, f.LocalPort, resp.StatusCode)
}

func (f *Forwarder) sendHTTPResponse(requestID string, resp HTTPResponse) {
	data, _ := json.Marshal(resp)
	msg := Message{
		Type:      MessageTypeHTTPResponse,
		RequestID: requestID,
		Data:      data,
	}

	f.writeMu.Lock()
	defer f.writeMu.Unlock()

	if err := f.conn.WriteJSON(msg); err != nil {
		log.Printf("Failed to send HTTP response: %v", err)
	}
}

func (f *Forwarder) Close() error {
	if f.conn != nil {
		return f.conn.Close()
	}
	return nil
}
