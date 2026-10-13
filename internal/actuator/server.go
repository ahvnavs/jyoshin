// Copyright 2026 Kazeshini Authors
// SPDX-License-Identifier: Apache-2.0

package actuator

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// RequestPayload carries either an envelope to execute or a ping.
type RequestPayload struct {
	Command  string             `json:"command"` // "execute", "ping", "status"
	Envelope *ExecutionEnvelope `json:"envelope,omitempty"`
	Apply    bool               `json:"apply"`
}

// ResponsePayload returns the outcome over the unix domain socket.
type ResponsePayload struct {
	Success bool             `json:"success"`
	Error   string           `json:"error,omitempty"`
	Result  *ExecutionResult `json:"result,omitempty"`
	HostID  string           `json:"host_id,omitempty"`
}

// Server listens on a local root-owned Unix domain socket (mode 0600 or 0660).
type Server struct {
	socketPath string
	engine     *Engine
	listener   net.Listener
	mu         sync.Mutex
	closed     bool
}

// NewServer initializes a new unix socket daemon for the actuator.
func NewServer(socketPath string, engine *Engine) *Server {
	return &Server{
		socketPath: socketPath,
		engine:     engine,
	}
}

// Start binds to the socket path and processes connections.
func (s *Server) Start(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0755); err != nil {
		return fmt.Errorf("creating socket dir: %w", err)
	}
	_ = os.Remove(s.socketPath) // Clean up any stale socket

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listening on unix socket %s: %w", s.socketPath, err)
	}
	s.listener = ln

	// Restrict socket permissions strictly to 0600 (owner only)
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("setting socket permissions 0600: %w", err)
	}

	go func() {
		<-ctx.Done()
		s.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			isClosed := s.closed
			s.mu.Unlock()
			if isClosed {
				return nil
			}
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		if s.listener != nil {
			_ = s.listener.Close()
		}
		_ = os.Remove(s.socketPath)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var req RequestPayload
	if err := decoder.Decode(&req); err != nil {
		_ = encoder.Encode(ResponsePayload{
			Success: false,
			Error:   fmt.Sprintf("decoding request: %v", err),
		})
		return
	}

	switch req.Command {
	case "ping":
		_ = encoder.Encode(ResponsePayload{
			Success: true,
			HostID:  s.engine.cfg.CurrentHostID,
		})
	case "execute":
		if req.Envelope == nil {
			_ = encoder.Encode(ResponsePayload{
				Success: false,
				Error:   "missing execution envelope",
			})
			return
		}
		res, err := s.engine.ExecuteEnvelope(context.Background(), req.Envelope, req.Apply)
		if err != nil {
			_ = encoder.Encode(ResponsePayload{
				Success: false,
				Error:   err.Error(),
				Result:  res,
			})
			return
		}
		_ = encoder.Encode(ResponsePayload{
			Success: res.Status == StatusSucceeded,
			Result:  res,
		})
	default:
		_ = encoder.Encode(ResponsePayload{
			Success: false,
			Error:   fmt.Sprintf("unknown command %q", req.Command),
		})
	}
}

// Client connects to the actuator unix socket to inspect or submit plans.
type Client struct {
	socketPath string
}

// NewClient returns a unix domain socket client instance.
func NewClient(socketPath string) *Client {
	return &Client{socketPath: socketPath}
}

// IsAvailable checks if the actuator unix socket is currently active.
func (c *Client) IsAvailable() bool {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// Ping queries the actuator service.
func (c *Client) Ping() (string, error) {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(RequestPayload{Command: "ping"}); err != nil {
		return "", err
	}
	var resp ResponsePayload
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return "", err
	}
	if !resp.Success {
		return "", fmt.Errorf("ping error: %s", resp.Error)
	}
	return resp.HostID, nil
}

// SubmitEnvelope sends a signed envelope for execution.
func (c *Client) SubmitEnvelope(env *ExecutionEnvelope, apply bool) (*ExecutionResult, error) {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to actuator socket %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	req := RequestPayload{
		Command:  "execute",
		Envelope: env,
		Apply:    apply,
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("sending envelope: %w", err)
	}

	var resp ResponsePayload
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if !resp.Success && resp.Result == nil {
		return nil, fmt.Errorf("actuator error: %s", resp.Error)
	}

	return resp.Result, nil
}
